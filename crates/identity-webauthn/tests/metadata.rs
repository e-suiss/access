//! FIDO metadata blobs and the attestation policy (§10.2.4, OP-146 m.4 (d)).

#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test fixtures"
)]

mod support;

use access_identity_webauthn::WebAuthnError;
use access_identity_webauthn::adapters::{FileMdsSource, MemoryMdsCache};
use access_identity_webauthn::app::{fresh_metadata, refresh_metadata};
use access_identity_webauthn::domain::Rejection;
use access_identity_webauthn::domain::ceremony::{
    ClientExtensionResults, RegistrationResponse, RegistrationState, verify_registration,
};
use access_identity_webauthn::domain::credential::{AttestationKind, CredentialRecord};
use access_identity_webauthn::domain::ids::{Aaguid, UserHandle};
use access_identity_webauthn::domain::mds::{MdsBlob, MdsError, verify_blob};
use access_identity_webauthn::domain::policy::{AttestationPolicy, RealmPolicy};
use support::*;

const KEY_MODEL: [u8; 16] = [0x42; 16];

fn state() -> RegistrationState {
    RegistrationState {
        realm: REALM,
        user: UserHandle::from_bytes([1; 64]),
        challenge: [5; 32],
        conditional: false,
        expires_at: NOW + 60,
        prf_salt: None,
    }
}

fn direct(aaguids: Vec<Aaguid>) -> RealmPolicy {
    RealmPolicy {
        attestation: AttestationPolicy::Direct {
            aaguids,
            enterprise: false,
        },
        ..RealmPolicy::default()
    }
}

fn run(
    a: &mut Authenticator,
    policy: &RealmPolicy,
    metadata: Option<&MdsBlob>,
) -> Result<CredentialRecord, Rejection> {
    let st = state();
    let (cdj, att) = a.register(RP_ID, ORIGIN, &st.challenge);
    verify_registration(
        &rp(),
        policy,
        &st,
        &RegistrationResponse {
            raw_id: &a.credential_id,
            client_data_json: &cdj,
            attestation_object: &att,
            transports: &[],
            extensions: ClientExtensionResults::default(),
        },
        metadata,
        NOW,
    )
}

fn metadata_for(attester: &Attester, status: &str, next_update: &str) -> MdsBlob {
    let signer = MdsSigner::new();
    let payload = mds_payload(
        3,
        next_update,
        vec![
            mds_entry(KEY_MODEL, &attester.root_der, status),
            serde_json::json!({"aaidOrNothing": "u2f entry without aaguid", "statusReports": []}),
        ],
    );
    verify_blob(&signer.blob(&payload), &signer.root_der, NOW).unwrap()
}

fn key_with(attestation: Attestation) -> Authenticator {
    let mut a = Authenticator::new(Key::es256());
    a.aaguid = KEY_MODEL;
    a.attestation = attestation;
    a
}

// OP-146 m.4 (d), §10.2.4
#[test]
fn metadata_blob_verification() {
    let signer = MdsSigner::new();
    let attester = Attester::new(KEY_MODEL, "Authenticator Attestation");
    let payload = mds_payload(
        7,
        "2026-12-01",
        vec![mds_entry(
            KEY_MODEL,
            &attester.root_der,
            "FIDO_CERTIFIED_L1",
        )],
    );
    let blob = signer.blob(&payload);
    let parsed = verify_blob(&blob, &signer.root_der, NOW).unwrap();
    assert_eq!(parsed.serial, 7);
    let entry = parsed.entry(Aaguid(KEY_MODEL)).unwrap();
    assert!(!entry.compromised);
    assert_eq!(entry.roots, std::slice::from_ref(&attester.root_der));
    assert_eq!(entry.description.as_deref(), Some("Acme Key"));
    assert!(parsed.is_fresh(NOW));

    let other = MdsSigner::new();
    assert_eq!(
        verify_blob(&blob, &other.root_der, NOW),
        Err(MdsError::Certificate)
    );
    let mut tampered = blob.clone();
    let dot = tampered.iter().rposition(|b| *b == b'.').unwrap();
    tampered[dot + 5] = if tampered[dot + 5] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert_eq!(
        verify_blob(&tampered, &signer.root_der, NOW),
        Err(MdsError::Signature)
    );
    let stale = signer.blob(&mds_payload(8, "2026-11-01", vec![]));
    assert_eq!(
        verify_blob(&stale, &signer.root_der, NOW),
        Err(MdsError::Stale)
    );
    assert_eq!(
        verify_blob(b"a.b", &signer.root_der, NOW),
        Err(MdsError::Format)
    );
    let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
    let bad = signer.blob(&serde_json::json!({ "no": 1, "nextUpdate": "2026-12-01", "entries": [], "x": serde_json::from_str::<serde_json::Value>(&deep).unwrap() }));
    assert_eq!(
        verify_blob(&bad, &signer.root_der, NOW),
        Err(MdsError::Payload)
    );
}

// OP-146 m.4 (d)
#[tokio::test]
async fn refresh_job_with_file_source() {
    let dir = std::env::temp_dir().join(format!("access-mds-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("blob.jwt");
    let signer = MdsSigner::new();
    let cache = MemoryMdsCache::default();
    let clock = FixedClock::at(NOW);
    let source = FileMdsSource::new(path.clone());
    std::fs::write(&path, signer.blob(&mds_payload(5, "2026-12-01", vec![]))).unwrap();
    assert_eq!(
        refresh_metadata(&source, &cache, &signer.root_der, &clock)
            .await
            .unwrap()
            .serial,
        5
    );
    std::fs::write(&path, signer.blob(&mds_payload(4, "2026-12-01", vec![]))).unwrap();
    assert!(matches!(
        refresh_metadata(&source, &cache, &signer.root_der, &clock).await,
        Err(WebAuthnError::Mds(MdsError::Rollback))
    ));
    std::fs::write(&path, signer.blob(&mds_payload(6, "2026-12-01", vec![]))).unwrap();
    refresh_metadata(&source, &cache, &signer.root_der, &clock)
        .await
        .unwrap();
    assert_eq!(
        fresh_metadata(&cache, &clock)
            .await
            .unwrap()
            .map(|b| b.serial),
        Some(6)
    );
    clock.set(NOW + 40 * 86_400);
    assert_eq!(fresh_metadata(&cache, &clock).await.unwrap(), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

// §10.2.4
#[test]
fn none_policy_never_trusts_attestation() {
    let policy = RealmPolicy::default();
    let mut a = key_with(Attestation::PackedSelf);
    assert_eq!(
        run(&mut a, &policy, None).unwrap().attestation,
        AttestationKind::Unverified("packed".into())
    );
    let mut a = key_with(Attestation::None);
    assert_eq!(
        run(&mut a, &policy, None).unwrap().attestation,
        AttestationKind::None
    );
}

// §10.2.4, OP-146 m.4 (d)
#[test]
fn direct_policy_requires_verified_packed_attestation() {
    let attester = Attester::new(KEY_MODEL, "Authenticator Attestation");
    let fresh = metadata_for(&attester, "FIDO_CERTIFIED_L1", "2026-12-01");
    let policy = direct(vec![Aaguid(KEY_MODEL)]);
    let mut a = key_with(Attestation::Packed(Attester {
        root_der: attester.root_der.clone(),
        leaf_der: attester.leaf_der.clone(),
        leaf_key: attester.leaf_key,
    }));
    let record = run(&mut a, &policy, Some(&fresh)).unwrap();
    assert_eq!(record.attestation, AttestationKind::Verified);
    assert_eq!(record.aaguid, Aaguid(KEY_MODEL));

    assert_eq!(
        run(&mut a, &policy, None).unwrap_err(),
        Rejection::MetadataUnavailable
    );
    let mut stale = fresh.clone();
    stale.next_update = NOW - 2 * 86_400;
    assert_eq!(
        run(&mut a, &policy, Some(&stale)).unwrap_err(),
        Rejection::MetadataUnavailable
    );
    assert_eq!(
        run(&mut a, &direct(vec![Aaguid([9; 16])]), Some(&fresh)).unwrap_err(),
        Rejection::AaguidNotAllowed
    );
    let mut unknown_model = fresh.clone();
    unknown_model.entries.clear();
    assert_eq!(
        run(&mut a, &policy, Some(&unknown_model)).unwrap_err(),
        Rejection::AttestationTrust
    );

    let mut self_attested = key_with(Attestation::PackedSelf);
    assert_eq!(
        run(&mut self_attested, &policy, Some(&fresh)).unwrap_err(),
        Rejection::AttestationTrust
    );
    let mut none = key_with(Attestation::None);
    assert_eq!(
        run(&mut none, &policy, Some(&fresh)).unwrap_err(),
        Rejection::AttestationFormat
    );
}

// §10.2.4
#[test]
fn compromised_models_are_refused() {
    let attester = Attester::new(KEY_MODEL, "Authenticator Attestation");
    let revoked = metadata_for(&attester, "ATTESTATION_KEY_COMPROMISE", "2026-12-01");
    let mut a = key_with(Attestation::Packed(attester));
    assert_eq!(
        run(&mut a, &direct(vec![]), Some(&revoked)).unwrap_err(),
        Rejection::AuthenticatorStatus
    );
}

// L3 §8.2.1
#[test]
fn attestation_certificate_requirements() {
    let wrong_ou = Attester::new(KEY_MODEL, "Something Else");
    let fresh = metadata_for(&wrong_ou, "FIDO_CERTIFIED", "2026-12-01");
    let mut a = key_with(Attestation::Packed(wrong_ou));
    assert_eq!(
        run(&mut a, &direct(vec![]), Some(&fresh)).unwrap_err(),
        Rejection::AttestationStatement
    );

    let other_model = Attester::new([0x43; 16], "Authenticator Attestation");
    let fresh = metadata_for(&other_model, "FIDO_CERTIFIED", "2026-12-01");
    let mut a = key_with(Attestation::Packed(other_model));
    assert_eq!(
        run(&mut a, &direct(vec![]), Some(&fresh)).unwrap_err(),
        Rejection::AttestationStatement
    );

    let real = Attester::new(KEY_MODEL, "Authenticator Attestation");
    let foreign_root = Attester::new(KEY_MODEL, "Authenticator Attestation");
    let fresh = metadata_for(&foreign_root, "FIDO_CERTIFIED", "2026-12-01");
    let mut a = key_with(Attestation::Packed(real));
    assert_eq!(
        run(&mut a, &direct(vec![]), Some(&fresh)).unwrap_err(),
        Rejection::AttestationTrust
    );
}
