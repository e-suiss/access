//! The `direct` attestation formats and their revocation (§10.2.4, OP-159 m.3 (ll), WebAuthn
//! L3 §8), and the passkey algorithms with no post-quantum option (HL-19), through the
//! registration use case. Every chain, CRL and TPM structure is built at test time.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test fixtures"
)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use access_identity_webauthn::adapters::MemoryAttestationSources;
use access_identity_webauthn::app::RegistrationOutcome;
use access_identity_webauthn::domain::Rejection;
use access_identity_webauthn::domain::ceremony::{ClientExtensionResults, RegistrationResponse};
use access_identity_webauthn::domain::cose::ML_DSA;
use access_identity_webauthn::domain::credential::AttestationKind;
use access_identity_webauthn::domain::ids::{Aaguid, UserHandle};
use access_identity_webauthn::domain::mds::{MdsBlob, verify_blob};
use access_identity_webauthn::domain::options::{UserEntity, creation_options};
use access_identity_webauthn::domain::policy::{AttestationPolicy, RealmPolicy};
use access_identity_webauthn::ports::{AttestationSources, Pending};
use support::attest::{Credential, Flaw, Pki, android, apple, entry, packed, tpm, u2f, u2f_entry};
use support::*;

const MODEL: [u8; 16] = [0x5a; 16];

fn direct() -> RealmPolicy {
    RealmPolicy {
        attestation: AttestationPolicy::Direct {
            aaguids: vec![],
            enterprise: false,
        },
        ..RealmPolicy::default()
    }
}

fn metadata(entries: Vec<serde_json::Value>) -> MdsBlob {
    let signer = MdsSigner::new();
    verify_blob(
        &signer.blob(&mds_payload(9, "2026-12-01", entries)),
        &signer.root_der,
        NOW,
    )
    .unwrap()
}

fn sources(pki: &Pki, entries: Vec<serde_json::Value>) -> MemoryAttestationSources {
    MemoryAttestationSources {
        metadata: Some(metadata(entries)),
        crls: pki.crls(),
    }
}

async fn register(
    a: &mut Authenticator,
    policy: &RealmPolicy,
    sources: &(dyn AttestationSources + Sync),
) -> Result<AttestationKind, Rejection> {
    let s = service();
    let user = UserHandle::from_bytes([3; 64]);
    let start = s
        .start_registration(
            &rp(),
            policy,
            &UserEntity {
                handle: &user,
                name: "ann",
                display_name: "Ann",
            },
            false,
            None,
        )
        .await
        .unwrap();
    let (cdj, att) = a.register(RP_ID, ORIGIN, &start.state.challenge);
    let outcome = s
        .finish_registration(
            &rp(),
            policy,
            &start.state,
            &RegistrationResponse {
                raw_id: &a.credential_id,
                client_data_json: &cdj,
                attestation_object: &att,
                transports: &[],
                extensions: ClientExtensionResults::default(),
            },
            sources,
        )
        .await
        .unwrap();
    match outcome {
        RegistrationOutcome::Registered(r) => Ok(r.attestation),
        RegistrationOutcome::Rejected(r) => Err(r),
    }
}

fn authenticator(key: Key, attestation: Attestation) -> Authenticator {
    let mut a = Authenticator::new(key);
    a.aaguid = MODEL;
    a.attestation = attestation;
    a
}

// OP-159 m.3 (ll), §10.2.4, L3 §8.2
#[tokio::test]
async fn packed_statements_verify_through_an_intermediate() {
    let pki = Arc::new(Pki::new());
    let src = sources(&pki, vec![entry(MODEL, &pki.root_der)]);
    let mut a = authenticator(Key::es256(), packed(&pki, MODEL, Flaw::None));
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Ok(AttestationKind::Verified("packed".into()))
    );
    let mut a = authenticator(Key::es256(), packed(&pki, MODEL, Flaw::Binding));
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationStatement)
    );
    let mut a = authenticator(Key::es256(), packed(&pki, MODEL, Flaw::Certificate));
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationStatement)
    );
    let foreign = Pki::new();
    let elsewhere = sources(&pki, vec![entry(MODEL, &foreign.root_der)]);
    let mut a = authenticator(Key::es256(), packed(&pki, MODEL, Flaw::None));
    assert_eq!(
        register(&mut a, &direct(), &elsewhere).await,
        Err(Rejection::AttestationTrust)
    );
}

// OP-159 m.3 (ll), L3 §8.3
#[tokio::test]
async fn tpm_statements_certify_the_credential_key() {
    let pki = Arc::new(Pki::new());
    let src = sources(&pki, vec![entry(MODEL, &pki.root_der)]);
    let credential = Credential::new();
    let mut a = authenticator(
        credential.key(-7),
        tpm(&pki, MODEL, &credential, Flaw::None),
    );
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Ok(AttestationKind::Verified("tpm".into()))
    );
    let mut a = authenticator(
        credential.key(-7),
        tpm(&pki, MODEL, &credential, Flaw::Binding),
    );
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationStatement)
    );
    let mut a = authenticator(
        credential.key(-7),
        tpm(&pki, MODEL, &credential, Flaw::Certificate),
    );
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationStatement)
    );
    let other = Credential::new();
    let mut a = authenticator(other.key(-7), tpm(&pki, MODEL, &credential, Flaw::None));
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationStatement)
    );
}

// OP-159 m.3 (ll), L3 §8.4
#[tokio::test]
async fn android_key_statements_bind_the_challenge_and_this_rp() {
    let pki = Arc::new(Pki::new());
    let src = sources(&pki, vec![entry(MODEL, &pki.root_der)]);
    let credential = Arc::new(Credential::new());
    let mut a = authenticator(
        credential.key(-7),
        android(&pki, credential.clone(), Flaw::None),
    );
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Ok(AttestationKind::Verified("android-key".into()))
    );
    for flaw in [Flaw::Binding, Flaw::Certificate] {
        let mut a = authenticator(credential.key(-7), android(&pki, credential.clone(), flaw));
        assert_eq!(
            register(&mut a, &direct(), &src).await,
            Err(Rejection::AttestationStatement),
            "{flaw:?}"
        );
    }
}

// OP-159 m.3 (ll), L3 §8.8
#[tokio::test]
async fn apple_statements_bind_the_nonce_and_the_key() {
    let pki = Arc::new(Pki::new());
    let src = sources(&pki, vec![entry(MODEL, &pki.root_der)]);
    let credential = Arc::new(Credential::new());
    let mut a = authenticator(
        credential.key(-7),
        apple(&pki, credential.clone(), Flaw::None),
    );
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Ok(AttestationKind::Verified("apple".into()))
    );
    for flaw in [Flaw::Binding, Flaw::Certificate] {
        let mut a = authenticator(credential.key(-7), apple(&pki, credential.clone(), flaw));
        assert_eq!(
            register(&mut a, &direct(), &src).await,
            Err(Rejection::AttestationStatement),
            "{flaw:?}"
        );
    }
}

// OP-159 m.3 (ll), L3 §8.6
#[tokio::test]
async fn fido_u2f_statements_are_es256_and_found_by_key_identifier() {
    let pki = Arc::new(Pki::new());
    let credential = Credential::new();
    let probe = Authenticator::new(credential.key(-7));
    let point = credential.rc.public_key_raw().to_vec();
    let (good, key_id) = u2f(&pki, probe.credential_id.clone(), point.clone(), Flaw::None);
    let src = MemoryAttestationSources {
        metadata: Some(metadata(vec![u2f_entry(&key_id, &pki.root_der)])),
        crls: pki.crls(),
    };
    let mut a = Authenticator::new(credential.key(-7));
    a.aaguid = [0; 16];
    a.attestation = good;
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Ok(AttestationKind::Verified("fido-u2f".into()))
    );
    let (bad, _) = u2f(
        &pki,
        probe.credential_id.clone(),
        point.clone(),
        Flaw::Binding,
    );
    a.attestation = bad;
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationStatement)
    );
    let (esp, _) = u2f(&pki, probe.credential_id.clone(), point, Flaw::None);
    let mut b = Authenticator::new(credential.key(-9));
    b.aaguid = [0; 16];
    b.attestation = esp;
    assert_eq!(
        register(&mut b, &direct(), &src).await,
        Err(Rejection::AttestationFormat)
    );
    let unknown = MemoryAttestationSources {
        metadata: Some(metadata(vec![entry(MODEL, &pki.root_der)])),
        crls: pki.crls(),
    };
    a.attestation = u2f(
        &pki,
        probe.credential_id.clone(),
        credential.rc.public_key_raw().to_vec(),
        Flaw::None,
    )
    .0;
    assert_eq!(
        register(&mut a, &direct(), &unknown).await,
        Err(Rejection::AttestationTrust)
    );
}

// OP-159 m.3 (ll), §10.2.4
#[tokio::test]
async fn formats_outside_the_list_are_refused_under_direct() {
    let pki = Arc::new(Pki::new());
    let src = sources(&pki, vec![entry(MODEL, &pki.root_der)]);
    let build: support::attest::Build = Arc::new(|_, _| {
        (
            "android-safetynet".to_owned(),
            suiss_crypto::dcbor::Value::Map(vec![]),
        )
    });
    let mut a = authenticator(Key::es256(), Attestation::Statement(build));
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationFormat)
    );
}

// OP-159 m.3 (ll)
#[tokio::test]
async fn a_revoked_intermediate_is_refused() {
    let pki = Arc::new(Pki::new());
    let mut src = sources(&pki, vec![entry(MODEL, &pki.root_der)]);
    src.crls = vec![
        (pki.root_url.clone(), pki.root_crl(true)),
        (
            pki.intermediate_url.clone(),
            pki.intermediate_crl((2027, 6, 1)),
        ),
    ];
    let credential = Credential::new();
    let mut a = authenticator(
        credential.key(-7),
        tpm(&pki, MODEL, &credential, Flaw::None),
    );
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationRevoked)
    );
    let mut a = authenticator(Key::es256(), packed(&pki, MODEL, Flaw::None));
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationRevoked)
    );
}

/// Counts what is asked of it and gives the CRLs of `crls` only.
struct Counting {
    inner: MemoryAttestationSources,
    asked: AtomicUsize,
}

impl AttestationSources for Counting {
    fn metadata(&self) -> Pending<'_, Option<MdsBlob>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.inner.metadata()
    }

    fn crl<'a>(&'a self, url: &'a str) -> Pending<'a, Option<Vec<u8>>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.inner.crl(url)
    }
}

// OP-159 m.3 (ll), MD-8
#[tokio::test]
async fn unknown_revocation_fails_closed_under_direct_only() {
    let pki = Arc::new(Pki::new());
    let mut src = sources(&pki, vec![entry(MODEL, &pki.root_der)]);
    src.crls.retain(|(u, _)| *u != pki.intermediate_url);
    let mut a = authenticator(Key::es256(), packed(&pki, MODEL, Flaw::None));
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationRevocationUnknown)
    );
    src.crls = vec![
        (pki.root_url.clone(), pki.root_crl(false)),
        (
            pki.intermediate_url.clone(),
            pki.intermediate_crl((2026, 11, 2)),
        ),
    ];
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationRevocationUnknown)
    );
    let stranger = Pki::new();
    src.crls = vec![
        (pki.root_url.clone(), pki.root_crl(false)),
        (
            pki.intermediate_url.clone(),
            stranger.intermediate_crl((2027, 6, 1)),
        ),
    ];
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationRevocationUnknown)
    );
    src.crls = vec![(pki.intermediate_url.clone(), b"not a crl".to_vec())];
    assert_eq!(
        register(&mut a, &direct(), &src).await,
        Err(Rejection::AttestationRevocationUnknown)
    );

    let counting = Counting {
        inner: MemoryAttestationSources::default(),
        asked: AtomicUsize::new(0),
    };
    assert_eq!(
        register(&mut a, &RealmPolicy::default(), &counting).await,
        Ok(AttestationKind::Unverified("packed".into()))
    );
    assert_eq!(counting.asked.load(Ordering::SeqCst), 0);
}

// OP-159 m.3 (ll)
#[tokio::test]
async fn the_allowlist_and_the_zero_aaguid() {
    let pki = Arc::new(Pki::new());
    let src = sources(&pki, vec![entry(MODEL, &pki.root_der)]);
    let only_other = RealmPolicy {
        attestation: AttestationPolicy::Direct {
            aaguids: vec![Aaguid([0x77; 16])],
            enterprise: true,
        },
        ..RealmPolicy::default()
    };
    let mut a = authenticator(Key::es256(), packed(&pki, MODEL, Flaw::None));
    assert_eq!(
        register(&mut a, &only_other, &src).await,
        Err(Rejection::AaguidNotAllowed)
    );
    let zero = sources(&pki, vec![entry([0; 16], &pki.root_der)]);
    let mut a = authenticator(Key::es256(), packed(&pki, [0; 16], Flaw::None));
    a.aaguid = [0; 16];
    assert_eq!(
        register(&mut a, &direct(), &zero).await,
        Err(Rejection::AttestationTrust)
    );
}

// HL-19, CR-43
#[tokio::test]
async fn hl_19_passkeys_have_no_post_quantum_algorithm() {
    for alg in ML_DSA {
        for policy in [RealmPolicy::default(), direct()] {
            let mut a = Authenticator::new(Key::p256(alg));
            assert_eq!(
                register(&mut a, &policy, &MemoryAttestationSources::default()).await,
                Err(Rejection::Algorithm),
                "{alg}"
            );
        }
    }
    let user = UserHandle::from_bytes([3; 64]);
    let options = creation_options(
        &rp(),
        &RealmPolicy::default(),
        &UserEntity {
            handle: &user,
            name: "ann",
            display_name: "Ann",
        },
        &access_crypto::random::bytes::<32>().unwrap(),
        &[],
        false,
        None,
    );
    let offered: Vec<i64> = options["pubKeyCredParams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["alg"].as_i64().unwrap())
        .collect();
    assert_eq!(offered.first(), Some(&-9));
    assert!(offered.iter().all(|a| !ML_DSA.contains(a)), "{offered:?}");
}
