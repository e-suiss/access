//! The software authenticator of a local deployment against the real ceremonies (OP-149 m.26
//! (e), m.29 (b), §10.2.4).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

mod support;

use access_identity_webauthn::domain::assurance::Binding;
use access_identity_webauthn::domain::ceremony::{
    AssertionResponse, AuthenticationState, ClientExtensionResults, RegistrationResponse,
    RegistrationState, verify_assertion, verify_registration,
};
use access_identity_webauthn::domain::cose::CoseAlgorithm;
use access_identity_webauthn::domain::ids::UserHandle;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::software::{SOFTWARE_AAGUID, SoftwareAuthenticator};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use support::{NOW, ORIGIN, REALM, RP_ID, rp};

fn key() -> Ed25519KeyPair {
    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()
}

fn response(a: &access_identity_webauthn::domain::software::Assertion) -> AssertionResponse<'_> {
    AssertionResponse {
        raw_id: &a.id,
        client_data_json: &a.client_data_json,
        authenticator_data: &a.authenticator_data,
        signature: &a.signature,
        user_handle: None,
    }
}

// §10.2.4, §13.7.3, OP-149 m.26 (e): the software passkey registers with none attestation as a
// device-bound EdDSA credential under the fixed AAGUID, asserts with UP and UV over the given
// challenge with no counter, and a signature by another key or over another challenge is
// refused like any authenticator's
#[test]
fn the_software_passkey_passes_the_real_ceremonies() {
    let pair = key();
    let public = <[u8; 32]>::try_from(pair.public_key().as_ref()).unwrap();
    let passkey = SoftwareAuthenticator::ed25519(public);
    let user = UserHandle::from_bytes([7; 64]);
    let policy = RealmPolicy::default();
    let challenge = [0x5a; 32];
    let reg = passkey.registration(RP_ID, ORIGIN, &challenge);
    let state = RegistrationState {
        realm: REALM,
        user,
        challenge,
        conditional: false,
        expires_at: NOW + 60,
        prf_salt: None,
    };
    let record = verify_registration(
        &rp(),
        &policy,
        &state,
        &RegistrationResponse {
            raw_id: &reg.id,
            client_data_json: &reg.client_data_json,
            attestation_object: &reg.attestation_object,
            transports: &[String::from("internal")],
            extensions: ClientExtensionResults::default(),
        },
        None,
        NOW,
    )
    .unwrap();
    assert_eq!(record.id.as_bytes(), passkey.credential_id);
    assert_eq!(record.alg, CoseAlgorithm::EdDsa);
    assert_eq!(record.aaguid, SOFTWARE_AAGUID);
    assert!(!record.backup_eligible);
    assert!(record.user_verified);
    assert_eq!(record.sign_count, 0);

    let statement = [0xaa; 32];
    let assertion = passkey
        .assertion(RP_ID, ORIGIN, &statement, |m| {
            Ok::<_, ()>(pair.sign(m).as_ref().to_vec())
        })
        .unwrap();
    let auth = AuthenticationState {
        realm: REALM,
        challenge: statement,
        user: Some(user),
        allowed: Vec::new(),
        require_user_verification: true,
        expires_at: NOW + 60,
    };
    let verified =
        verify_assertion(&rp(), &policy, &auth, &response(&assertion), &record, NOW).unwrap();
    assert!(verified.assurance.user_verified);
    assert_eq!(verified.assurance.binding, Binding::DeviceBound);
    assert_eq!(verified.sign_count, 0);
    // a second assertion with no counter is still accepted (both zero, §10.2.4)
    let again = passkey
        .assertion(RP_ID, ORIGIN, &statement, |m| {
            Ok::<_, ()>(pair.sign(m).as_ref().to_vec())
        })
        .unwrap();
    verify_assertion(&rp(), &policy, &auth, &response(&again), &record, NOW).unwrap();
    // another key's signature, or the right key over another challenge, is refused
    let other = key();
    let forged = passkey
        .assertion(RP_ID, ORIGIN, &statement, |m| {
            Ok::<_, ()>(other.sign(m).as_ref().to_vec())
        })
        .unwrap();
    assert!(verify_assertion(&rp(), &policy, &auth, &response(&forged), &record, NOW).is_err());
    let elsewhere = passkey
        .assertion(RP_ID, ORIGIN, &[0xbb; 32], |m| {
            Ok::<_, ()>(pair.sign(m).as_ref().to_vec())
        })
        .unwrap();
    assert!(verify_assertion(&rp(), &policy, &auth, &response(&elsewhere), &record, NOW).is_err());
    let json = assertion.json();
    assert_eq!(json["type"], "public-key");
    assert!(json["response"].get("userHandle").is_none());
    assert_eq!(reg.json()["response"]["transports"][0], "internal");
}
