//! Registration and authentication ceremonies against the software authenticator.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test fixtures"
)]

mod support;

use access_identity_webauthn::app::{
    AuthenticationOutcome, AuthenticationStart, Identified, RegistrationOutcome,
};
use access_identity_webauthn::domain::Rejection;
use access_identity_webauthn::domain::assurance::{
    Aal, Binding, CtCeiling, HardwareKeyAdvice, hardware_key_rule, protection,
};
use access_identity_webauthn::domain::ceremony::{
    AssertionResponse, ClientExtensionResults, RegistrationResponse, Signal, sign_count_regressed,
};
use access_identity_webauthn::domain::credential::{AttestationKind, CredentialRecord};
use access_identity_webauthn::domain::ids::{CredentialId, UserHandle};
use access_identity_webauthn::domain::options::UserEntity;
use access_identity_webauthn::domain::policy::{RealmPolicy, SignCountAction, UserVerification};
use access_identity_webauthn::domain::prf::PrfSalt;
use access_identity_webauthn::ports::CredentialRegistry;
use access_parse::cbor::CborError;
use support::*;

const ALICE: UserHandle = UserHandle::from_bytes([0xa1; 64]);

fn user() -> UserEntity<'static> {
    UserEntity {
        handle: &ALICE,
        name: "alice@acme.example",
        display_name: "Alice",
    }
}

async fn register_with(
    s: &Service,
    policy: &RealmPolicy,
    a: &mut Authenticator,
    origin: &str,
    extensions: ClientExtensionResults,
) -> RegistrationOutcome {
    let start = s
        .start_registration(&rp(), policy, &user(), false, Some("vault"))
        .await
        .unwrap();
    let (cdj, att) = a.register(RP_ID, origin, &start.state.challenge);
    let id = a.credential_id.clone();
    let transports = vec!["internal".to_owned(), "future-transport".to_owned()];
    s.finish_registration(
        &rp(),
        policy,
        &start.state,
        &RegistrationResponse {
            raw_id: &id,
            client_data_json: &cdj,
            attestation_object: &att,
            transports: &transports,
            extensions,
        },
        None,
    )
    .await
    .unwrap()
}

async fn register(s: &Service, policy: &RealmPolicy, a: &mut Authenticator) -> CredentialRecord {
    match register_with(s, policy, a, ORIGIN, ClientExtensionResults::default()).await {
        RegistrationOutcome::Registered(r) => *r,
        RegistrationOutcome::Rejected(e) => panic!("rejected: {e:?}"),
    }
}

async fn start_for_alice(s: &Service, policy: &RealmPolicy) -> AuthenticationStart {
    s.start_authentication(
        &rp(),
        policy,
        Identified::Identifier {
            normalized: "alice@acme.example",
            user: Some(ALICE),
        },
        false,
    )
    .await
    .unwrap()
}

async fn authenticate(
    s: &Service,
    policy: &RealmPolicy,
    a: &mut Authenticator,
) -> AuthenticationOutcome {
    let start = start_for_alice(s, policy).await;
    let (cdj, ad, sig) = a.assert(RP_ID, ORIGIN, &start.state.challenge);
    let id = a.credential_id.clone();
    s.finish_authentication(
        &rp(),
        policy,
        &start.state,
        &AssertionResponse {
            raw_id: &id,
            client_data_json: &cdj,
            authenticator_data: &ad,
            signature: &sig,
            user_handle: Some(ALICE.as_bytes()),
        },
    )
    .await
    .unwrap()
}

fn rejected(o: &AuthenticationOutcome) -> Option<Rejection> {
    match o {
        AuthenticationOutcome::Rejected(r) => Some(*r),
        AuthenticationOutcome::Authenticated { .. } => None,
    }
}

// IDP-5, IDP-8, OP-146 m.3, §10.2.4
#[tokio::test]
async fn es256_device_bound_passkey_registers_and_authenticates_at_aal3() {
    let s = service();
    let policy = RealmPolicy::default();
    let mut a = Authenticator::new(Key::es256());
    let record = register(&s, &policy, &mut a).await;
    assert_eq!(record.attestation, AttestationKind::None);
    assert_eq!(record.cred_protect, Some(2));
    assert_eq!(record.transports, ["internal", "future-transport"]);
    assert!(!record.backup_eligible);
    let AuthenticationOutcome::Authenticated {
        user,
        assurance,
        signals,
        ..
    } = authenticate(&s, &policy, &mut a).await
    else {
        panic!("not authenticated");
    };
    assert_eq!(user, ALICE);
    assert_eq!(assurance.binding, Binding::DeviceBound);
    assert_eq!((assurance.aal, assurance.ct), (Aal::Aal3, CtCeiling::Ct3));
    assert_eq!(signals, []);
    let stored = s
        .registry
        .find(REALM, &CredentialId::new(&a.credential_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.sign_count, 1);
    assert_eq!(stored.last_used_at, Some(NOW));
}

// IDP-8, §10.2.4 algorithms, CR-5, CR-9
#[tokio::test]
async fn every_accepted_algorithm_round_trips() {
    for key in [
        Key::p256(-9),
        Key::ed25519(-19),
        Key::ed25519(-8),
        Key::rsa(),
    ] {
        let s = service();
        let policy = RealmPolicy::default();
        let mut a = Authenticator::synced(key);
        let record = register(&s, &policy, &mut a).await;
        let AuthenticationOutcome::Authenticated { assurance, .. } =
            authenticate(&s, &policy, &mut a).await
        else {
            panic!("not authenticated: {:?}", record.alg);
        };
        assert_eq!(assurance.binding, Binding::Synced);
        if record.alg.id() == -257 {
            assert!(assurance.session_login_only);
            assert_eq!(assurance.ct, CtCeiling::None);
        } else {
            assert_eq!((assurance.aal, assurance.ct), (Aal::Aal2, CtCeiling::Ct2));
        }
    }
}

// §10.2.4: RS256 only where the realm allows legacy authenticators
#[tokio::test]
async fn rs256_can_be_refused_by_policy() {
    let s = service();
    let policy = RealmPolicy {
        allow_rs256: false,
        ..RealmPolicy::default()
    };
    let mut a = Authenticator::new(Key::rsa());
    let out = register_with(
        &s,
        &policy,
        &mut a,
        ORIGIN,
        ClientExtensionResults::default(),
    )
    .await;
    assert_eq!(out, RegistrationOutcome::Rejected(Rejection::Algorithm));
}

// §10.2.4, TN-17
#[tokio::test]
async fn creation_options_order_algorithms_and_request_extensions() {
    let s = service();
    let start = s
        .start_registration(&rp(), &RealmPolicy::default(), &user(), true, None)
        .await
        .unwrap();
    let algs: Vec<i64> = start.options["pubKeyCredParams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["alg"].as_i64().unwrap())
        .collect();
    assert_eq!(algs, [-9, -7, -19, -8, -257]);
    assert_eq!(start.options["attestation"], "none");
    assert_eq!(start.options["extensions"]["credProps"], true);
    assert_eq!(
        start.options["extensions"]["credentialProtectionPolicy"],
        "userVerificationOptionalWithCredentialIDList"
    );
    assert_eq!(
        start.options["authenticatorSelection"]["userVerification"],
        "preferred"
    );
    assert_eq!(start.options["rp"]["id"], RP_ID);
    let handle = s.new_user_handle().unwrap();
    assert_eq!(handle.as_bytes().len(), 64);
}

// IDP-5, TN-17
#[tokio::test]
async fn registration_waits_for_a_pinned_rp_id() {
    let s = service();
    let policy = RealmPolicy::default();
    let mut unpinned = rp();
    unpinned.pinned = false;
    let start = s
        .start_registration(&unpinned, &policy, &user(), false, None)
        .await
        .unwrap();
    let mut a = Authenticator::new(Key::es256());
    let (cdj, att) = a.register(RP_ID, ORIGIN, &start.state.challenge);
    let out = s
        .finish_registration(
            &unpinned,
            &policy,
            &start.state,
            &RegistrationResponse {
                raw_id: &a.credential_id,
                client_data_json: &cdj,
                attestation_object: &att,
                transports: &[],
                extensions: ClientExtensionResults::default(),
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(out, RegistrationOutcome::Rejected(Rejection::RpIdNotPinned));
}

// TN-18, §10.2.4: subdomains and declared related origins only
#[tokio::test]
async fn origins_are_bound_to_the_rp() {
    let policy = RealmPolicy::default();
    for (origin, ok) in [
        ("https://login.acme.example", true),
        ("https://acme-shop.example", true),
        ("https://evil.example", false),
        ("https://acme.example.evil.example", false),
    ] {
        let s = service();
        let mut a = Authenticator::new(Key::es256());
        let out = register_with(
            &s,
            &policy,
            &mut a,
            origin,
            ClientExtensionResults::default(),
        )
        .await;
        assert_eq!(
            matches!(out, RegistrationOutcome::Registered(_)),
            ok,
            "{origin}"
        );
        if !ok {
            assert_eq!(out, RegistrationOutcome::Rejected(Rejection::Origin));
        }
    }
}

// §10.2.4: challenge, ceremony type, cross-origin and RP ID hash
#[tokio::test]
async fn client_data_and_rp_id_hash_are_checked() {
    let s = service();
    let policy = RealmPolicy::default();
    let mut a = Authenticator::new(Key::es256());
    register(&s, &policy, &mut a).await;
    let start = start_for_alice(&s, &policy).await;
    let id = a.credential_id.clone();
    let finish = |cdj: Vec<u8>, ad: Vec<u8>, sig: Vec<u8>| {
        let state = start.state.clone();
        let s = &s;
        let policy = &policy;
        let id = id.clone();
        async move {
            s.finish_authentication(
                &rp(),
                policy,
                &state,
                &AssertionResponse {
                    raw_id: &id,
                    client_data_json: &cdj,
                    authenticator_data: &ad,
                    signature: &sig,
                    user_handle: None,
                },
            )
            .await
            .unwrap()
        }
    };
    let (_, ad, sig) = a.assert(RP_ID, ORIGIN, &start.state.challenge);
    let wrong_challenge = client_data("webauthn.get", &[0; 32], ORIGIN);
    assert_eq!(
        rejected(&finish(wrong_challenge, ad.clone(), sig.clone()).await),
        Some(Rejection::Challenge)
    );
    let wrong_type = client_data("webauthn.create", &start.state.challenge, ORIGIN);
    assert_eq!(
        rejected(&finish(wrong_type, ad.clone(), sig.clone()).await),
        Some(Rejection::CeremonyType)
    );
    let cross = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":true}}"#,
        access_kernel::json::b64url_encode(&start.state.challenge)
    );
    assert_eq!(
        rejected(&finish(cross.into_bytes(), ad.clone(), sig.clone()).await),
        Some(Rejection::CrossOrigin)
    );
    let (cdj, ad, sig) = a.assert("other.example", ORIGIN, &start.state.challenge);
    assert_eq!(
        rejected(&finish(cdj, ad, sig).await),
        Some(Rejection::RpIdHash)
    );
    let (cdj, ad, mut sig) = a.assert(RP_ID, ORIGIN, &start.state.challenge);
    let last = sig.len() - 3;
    sig[last] ^= 1;
    assert_eq!(
        rejected(&finish(cdj, ad, sig).await),
        Some(Rejection::Signature)
    );
}

// §10.2.4 UV row: CT2+/AAL2+ need UV = 1; MD-11
#[tokio::test]
async fn user_verification_policy() {
    let s = service();
    let required = RealmPolicy {
        user_verification: UserVerification::Required,
        ..RealmPolicy::default()
    };
    let mut a = Authenticator::new(Key::es256());
    a.uv = false;
    let out = register_with(
        &s,
        &required,
        &mut a,
        ORIGIN,
        ClientExtensionResults::default(),
    )
    .await;
    assert_eq!(
        out,
        RegistrationOutcome::Rejected(Rejection::UserVerification)
    );
    let preferred = RealmPolicy::default();
    register(&s, &preferred, &mut a).await;
    let AuthenticationOutcome::Authenticated { assurance, .. } =
        authenticate(&s, &preferred, &mut a).await
    else {
        panic!();
    };
    assert_eq!((assurance.aal, assurance.ct), (Aal::Aal1, CtCeiling::Ct1));
    let start = s
        .start_authentication(&rp(), &preferred, Identified::Discoverable, true)
        .await
        .unwrap();
    let (cdj, ad, sig) = a.assert(RP_ID, ORIGIN, &start.state.challenge);
    let out = s
        .finish_authentication(
            &rp(),
            &preferred,
            &start.state,
            &AssertionResponse {
                raw_id: &a.credential_id,
                client_data_json: &cdj,
                authenticator_data: &ad,
                signature: &sig,
                user_handle: Some(ALICE.as_bytes()),
            },
        )
        .await
        .unwrap();
    assert_eq!(rejected(&out), Some(Rejection::UserVerification));
    a.uv = true;
    let md11 = RealmPolicy {
        platform_uv_is_factor: false,
        ..RealmPolicy::default()
    };
    let AuthenticationOutcome::Authenticated { assurance, .. } =
        authenticate(&s, &md11, &mut a).await
    else {
        panic!();
    };
    assert_eq!((assurance.aal, assurance.ct), (Aal::Aal1, CtCeiling::Ct1));
}

// §10.2.4 conditional create: UP may be 0 only there
#[tokio::test]
async fn user_presence_is_required_outside_conditional_create() {
    let s = service();
    let policy = RealmPolicy::default();
    let mut a = Authenticator::new(Key::es256());
    a.up = false;
    let out = register_with(
        &s,
        &policy,
        &mut a,
        ORIGIN,
        ClientExtensionResults::default(),
    )
    .await;
    assert_eq!(out, RegistrationOutcome::Rejected(Rejection::UserPresence));
    let start = s
        .start_registration(&rp(), &policy, &user(), true, None)
        .await
        .unwrap();
    let (cdj, att) = a.register(RP_ID, ORIGIN, &start.state.challenge);
    let out = s
        .finish_registration(
            &rp(),
            &policy,
            &start.state,
            &RegistrationResponse {
                raw_id: &a.credential_id,
                client_data_json: &cdj,
                attestation_object: &att,
                transports: &[],
                extensions: ClientExtensionResults::default(),
            },
            None,
        )
        .await
        .unwrap();
    assert!(matches!(out, RegistrationOutcome::Registered(_)));
    assert_eq!(
        rejected(&authenticate(&s, &policy, &mut a).await),
        Some(Rejection::UserPresence)
    );
}

// IDI-5: BE never changes, BE = 0 with BS = 1 is invalid, BS changes are signals; TN-63
#[tokio::test]
async fn backup_flags() {
    let policy = RealmPolicy::default();
    let s = service();
    let mut a = Authenticator::new(Key::es256());
    a.bs = true;
    let out = register_with(
        &s,
        &policy,
        &mut a,
        ORIGIN,
        ClientExtensionResults::default(),
    )
    .await;
    assert_eq!(out, RegistrationOutcome::Rejected(Rejection::BackupState));

    let s = service();
    let mut a = Authenticator::new(Key::es256());
    register(&s, &policy, &mut a).await;
    a.be = true;
    assert_eq!(
        rejected(&authenticate(&s, &policy, &mut a).await),
        Some(Rejection::BackupEligibility)
    );

    let s = service();
    let mut a = Authenticator::synced(Key::es256());
    register(&s, &policy, &mut a).await;
    a.bs = false;
    let AuthenticationOutcome::Authenticated { signals, .. } =
        authenticate(&s, &policy, &mut a).await
    else {
        panic!();
    };
    assert_eq!(signals, [Signal::BackupStateLost]);
    a.bs = true;
    let AuthenticationOutcome::Authenticated { signals, .. } =
        authenticate(&s, &policy, &mut a).await
    else {
        panic!();
    };
    assert_eq!(signals, [Signal::BackupStateGained]);
    assert_eq!(s.signals.taken().unwrap().len(), 2);

    let enterprise = RealmPolicy {
        require_device_bound: true,
        ..RealmPolicy::default()
    };
    let mut synced = Authenticator::synced(Key::es256());
    synced.credential_id = vec![0xc2; 32];
    let out = register_with(
        &s,
        &enterprise,
        &mut synced,
        ORIGIN,
        ClientExtensionResults::default(),
    )
    .await;
    assert_eq!(
        out,
        RegistrationOutcome::Rejected(Rejection::DeviceBoundRequired)
    );
}

// §10.2.4 sign count row, K14 sign-count signal
#[tokio::test]
async fn sign_count_policy() {
    assert!(sign_count_regressed(false, 5, 5));
    assert!(sign_count_regressed(false, 5, 0));
    assert!(!sign_count_regressed(false, 0, 0));
    assert!(!sign_count_regressed(false, 5, 6));
    assert!(!sign_count_regressed(true, 5, 0));

    let policy = RealmPolicy::default();
    let s = service();
    let mut a = Authenticator::new(Key::es256());
    a.counter = 10;
    register(&s, &policy, &mut a).await;
    a.counter = 3;
    let AuthenticationOutcome::Authenticated { signals, .. } =
        authenticate(&s, &policy, &mut a).await
    else {
        panic!();
    };
    assert_eq!(
        signals,
        [Signal::SignCountRegressed {
            stored: 10,
            presented: 4
        }]
    );
    let id = CredentialId::new(&a.credential_id).unwrap();
    assert_eq!(
        s.registry
            .find(REALM, &id)
            .await
            .unwrap()
            .unwrap()
            .sign_count,
        10
    );

    let strict = RealmPolicy {
        sign_count: SignCountAction::Reject,
        ..RealmPolicy::default()
    };
    a.counter = 0;
    assert_eq!(
        rejected(&authenticate(&s, &strict, &mut a).await),
        Some(Rejection::SignCount)
    );
    assert_eq!(
        s.signals.taken().unwrap().last().map(|(_, sig)| *sig),
        Some(Signal::SignCountRegressed {
            stored: 10,
            presented: 1
        })
    );

    let s = service();
    let mut synced = Authenticator::synced(Key::es256());
    register(&s, &strict, &mut synced).await;
    assert!(matches!(
        authenticate(&s, &strict, &mut synced).await,
        AuthenticationOutcome::Authenticated { .. }
    ));
}

// §10.2.4: the ceremony state expires; a credential is registered once
#[tokio::test]
async fn expiry_and_duplicates() {
    let s = service();
    let policy = RealmPolicy::default();
    let mut a = Authenticator::new(Key::es256());
    register(&s, &policy, &mut a).await;
    let out = register_with(
        &s,
        &policy,
        &mut a,
        ORIGIN,
        ClientExtensionResults::default(),
    )
    .await;
    assert_eq!(
        out,
        RegistrationOutcome::Rejected(Rejection::CredentialExists)
    );
    let start = start_for_alice(&s, &policy).await;
    s.clock.set(start.state.expires_at + 1);
    let (cdj, ad, sig) = a.assert(RP_ID, ORIGIN, &start.state.challenge);
    let out = s
        .finish_authentication(
            &rp(),
            &policy,
            &start.state,
            &AssertionResponse {
                raw_id: &a.credential_id,
                client_data_json: &cdj,
                authenticator_data: &ad,
                signature: &sig,
                user_handle: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(rejected(&out), Some(Rejection::Expired));
}

// TN-96, TN-97, §12.4.1: empty allowCredentials on the passkey path, deterministic decoys
#[tokio::test]
async fn passkey_enumeration_protection() {
    let s = service();
    let policy = RealmPolicy::default();
    let discoverable = s
        .start_authentication(&rp(), &policy, Identified::Discoverable, false)
        .await
        .unwrap();
    assert_eq!(
        discoverable.options["allowCredentials"],
        serde_json::json!([])
    );
    let ask = |user| {
        let s = &s;
        let policy = &policy;
        async move {
            s.start_authentication(
                &rp(),
                policy,
                Identified::Identifier {
                    normalized: "bob@acme.example",
                    user,
                },
                false,
            )
            .await
            .unwrap()
            .options["allowCredentials"]
                .clone()
        }
    };
    let none = ask(None).await;
    let again = ask(None).await;
    let no_passkeys = ask(Some(UserHandle::from_bytes([0xb0; 64]))).await;
    assert_eq!(none, again);
    assert_eq!(none, no_passkeys);
    let list = none.as_array().unwrap();
    assert!(!list.is_empty() && list.len() <= 2);
    for d in list {
        let id = access_kernel::json::b64url_decode(d["id"].as_str().unwrap()).unwrap();
        assert!([16, 32, 48, 64].contains(&id.len()));
        assert_eq!(d["type"], "public-key");
    }
    let other = s
        .start_authentication(
            &rp(),
            &policy,
            Identified::Identifier {
                normalized: "carol@acme.example",
                user: None,
            },
            false,
        )
        .await
        .unwrap();
    assert_ne!(other.options["allowCredentials"], none);
    let mut a = Authenticator::new(Key::es256());
    register(&s, &policy, &mut a).await;
    let alice = start_for_alice(&s, &policy).await;
    assert_eq!(
        alice.options["allowCredentials"][0]["id"],
        access_kernel::json::b64url_encode(&a.credential_id)
    );
}

// TN-96: the discoverable path needs the user handle; it must match the credential's account
#[tokio::test]
async fn user_handle_rules() {
    let s = service();
    let policy = RealmPolicy::default();
    let mut a = Authenticator::new(Key::es256());
    register(&s, &policy, &mut a).await;
    for (handle, expected) in [
        (None, Some(Rejection::UserHandle)),
        (Some([0xee_u8; 64].as_slice()), Some(Rejection::UserHandle)),
        (Some(ALICE.as_bytes().as_slice()), None),
    ] {
        let start = s
            .start_authentication(&rp(), &policy, Identified::Discoverable, false)
            .await
            .unwrap();
        let (cdj, ad, sig) = a.assert(RP_ID, ORIGIN, &start.state.challenge);
        let out = s
            .finish_authentication(
                &rp(),
                &policy,
                &start.state,
                &AssertionResponse {
                    raw_id: &a.credential_id,
                    client_data_json: &cdj,
                    authenticator_data: &ad,
                    signature: &sig,
                    user_handle: handle,
                },
            )
            .await
            .unwrap();
        assert_eq!(rejected(&out), expected);
    }
}

// OP-73: a soft-deleted credential no longer authenticates and stays in the registry
#[tokio::test]
async fn soft_deleted_credentials_are_unknown() {
    let s = service();
    let policy = RealmPolicy::default();
    let mut a = Authenticator::new(Key::es256());
    register(&s, &policy, &mut a).await;
    let id = CredentialId::new(&a.credential_id).unwrap();
    s.registry.soft_delete(REALM, &id, NOW).await.unwrap();
    assert_eq!(
        rejected(&authenticate(&s, &policy, &mut a).await),
        Some(Rejection::UnknownCredential)
    );
    assert!(
        s.registry
            .find(REALM, &id)
            .await
            .unwrap()
            .unwrap()
            .deleted_at
            .is_some()
    );
    assert_eq!(s.registry.list(REALM, &ALICE).await.unwrap(), []);
}

// §10.2.4 PRF row: salts and prf.enabled only, output never stored; credProps.rk
#[tokio::test]
async fn prf_and_cred_props() {
    let ext = ClientExtensionResults::from_json(
        br#"{"credProps":{"rk":true},"prf":{"enabled":true,"results":{"first":"c2VjcmV0"}}}"#,
    )
    .unwrap();
    assert_eq!(ext.cred_props_rk, Some(true));
    assert_eq!(ext.prf_enabled, Some(true));
    let s = service();
    let policy = RealmPolicy::default();
    let mut a = Authenticator::new(Key::es256());
    let RegistrationOutcome::Registered(record) =
        register_with(&s, &policy, &mut a, ORIGIN, ext).await
    else {
        panic!();
    };
    assert_eq!(record.discoverable, Some(true));
    let prf = record.prf.clone().unwrap();
    assert!(prf.enabled);
    assert!(!format!("{record:?}").contains("c2VjcmV0"));
    let next = PrfSalt::derive("vault", &[3; 32]);
    assert_ne!(next, PrfSalt::derive("signing", &[3; 32]));
    let rotating = prf.begin_rotation(next);
    assert_eq!(rotating.second, Some(next));
    let done = rotating.complete_rotation();
    assert_eq!((done.first, done.second), (next, None));
    assert!(ClientExtensionResults::from_json(&[b'['; 64]).is_err());
}

// TN-63, MKT-D7 independence groups; §10.2.5 hardware keys
#[tokio::test]
async fn independence_groups_and_hardware_keys() {
    let s = service();
    let policy = RealmPolicy::default();
    let mut synced_a = Authenticator::synced(Key::es256());
    synced_a.credential_id = vec![1; 16];
    let mut synced_b = Authenticator::synced(Key::es256());
    synced_b.credential_id = vec![2; 16];
    let one = register(&s, &policy, &mut synced_a).await;
    let two = register(&s, &policy, &mut synced_b).await;
    let p = protection(&[one.clone(), two.clone()], 0);
    assert_eq!(p.groups, 1);
    assert!(!p.fully_protected);
    assert!(protection(std::slice::from_ref(&one), 1).fully_protected);
    let mut key_a = Authenticator::new(Key::es256());
    key_a.credential_id = vec![3; 16];
    let hw_a = register(&s, &policy, &mut key_a).await;
    assert_eq!(protection(&[one.clone(), two, hw_a.clone()], 0).groups, 2);
    assert_eq!(
        hardware_key_rule(std::slice::from_ref(&hw_a), false),
        HardwareKeyAdvice::Recommended
    );
    assert_eq!(
        hardware_key_rule(&[hw_a.clone(), one], true),
        HardwareKeyAdvice::Required
    );
    let mut key_b = Authenticator::new(Key::es256());
    key_b.credential_id = vec![4; 16];
    let hw_b = register(&s, &policy, &mut key_b).await;
    assert_eq!(
        hardware_key_rule(&[hw_a, hw_b], true),
        HardwareKeyAdvice::Satisfied
    );
}

// CR-10, OP-125
#[tokio::test]
async fn oversized_and_malformed_attestation_objects_are_rejected() {
    let s = service();
    let policy = RealmPolicy::default();
    let start = s
        .start_registration(&rp(), &policy, &user(), false, None)
        .await
        .unwrap();
    let mut a = Authenticator::new(Key::es256());
    let (cdj, att) = a.register(RP_ID, ORIGIN, &start.state.challenge);
    let finish = |att: Vec<u8>| {
        let s = &s;
        let policy = &policy;
        let state = start.state.clone();
        let cdj = cdj.clone();
        let id = a.credential_id.clone();
        async move {
            s.finish_registration(
                &rp(),
                policy,
                &state,
                &RegistrationResponse {
                    raw_id: &id,
                    client_data_json: &cdj,
                    attestation_object: &att,
                    transports: &[],
                    extensions: ClientExtensionResults::default(),
                },
                None,
            )
            .await
            .unwrap()
        }
    };
    let mut big = att.clone();
    big.resize(9 * 1024, 0);
    assert_eq!(
        finish(big).await,
        RegistrationOutcome::Rejected(Rejection::Cbor(CborError::InputTooLarge))
    );
    let mut trailing = att.clone();
    trailing.push(0);
    assert_eq!(
        finish(trailing).await,
        RegistrationOutcome::Rejected(Rejection::Cbor(CborError::TrailingBytes))
    );
    assert!(matches!(
        finish(att).await,
        RegistrationOutcome::Registered(_)
    ));
}
