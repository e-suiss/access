//! The person-attribute issuer's rules (E55, IDP-21, PI-3; Ek B 4196, 5039): keys are made at run
//! time; the credential is checked with the Kernel's own SD-JWT verifier.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable,
    reason = "test code"
)]

use std::collections::BTreeSet;

use access_identity_vc::app::{Grant, Issuer, RequestError};
use access_identity_vc::ports::{Clock, Facts, Random, StatusList};

use access_identity_vc::domain::issue::{Credential, IssueError, issue, jwk};
use access_identity_vc::domain::metadata::{
    PRE_AUTHORIZED_GRANT, issuer_metadata, offer, offer_link,
};
use access_identity_vc::domain::proof::{Expect, Holder, ProofError, verify};
use access_identity_vc::domain::types::{ALL, PersonAttribute, TypeRefused};
use access_kernel::json::b64url_encode;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{Algorithm, KeySet};
use access_kernel::verify::jws::Origin;
use access_kernel::verify::key_scope::thumbprint;
use access_kernel::verify::sd_jwt::{self, Rules};
use serde_json::{Value, json};
use suiss_crypto::signer::{Signer, SoftSigner};

const ISSUER: &str = "https://acme.access.test";
const NOW: u64 = 1_794_312_000_000;

fn jws(signer: &dyn Signer, header: &Value, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(payload.to_string().as_bytes())
    );
    format!(
        "{input}.{}",
        b64url_encode(&signer.sign(input.as_bytes()).unwrap())
    )
}

fn alg(s: &dyn Signer) -> &'static str {
    if s.algorithm() == Algorithm::Ed25519 {
        "Ed25519"
    } else {
        "ES256"
    }
}

fn proof(s: &dyn Signer, with_jwk: bool, nonce: &str) -> String {
    let mut header = json!({ "typ": "openid4vci-proof+jwt", "alg": alg(s) });
    if with_jwk {
        header["jwk"] = jwk(&s.public_key()).unwrap();
    }
    jws(
        s,
        &header,
        &json!({ "aud": ISSUER, "iat": NOW / 1000, "nonce": nonce }),
    )
}

fn fresh16() -> [u8; 16] {
    let access_kernel::verify::cose::PublicKey::Ed25519(pk) =
        SoftSigner::generate_ed25519().unwrap().0.public_key()
    else {
        unreachable!()
    };
    let mut out = [0u8; 16];
    out.copy_from_slice(&suiss_crypto::digest::sha256(&pk)[..16]);
    out
}

fn expect() -> Expect<'static> {
    Expect {
        issuer: ISSUER,
        nonce: "c-nonce-1",
        now: NOW,
    }
}

// E55, Ek B 5039, 4836
#[test]
fn the_issuer_refuses_a_non_person_credential_type() {
    for name in ["diploma", "mdl", "membership", "verified_email", ""] {
        assert_eq!(PersonAttribute::parse(name), Err(TypeRefused));
    }
    assert_eq!(
        PersonAttribute::of_vct(ISSUER, "https://other.test/vc/age_over_18"),
        Err(TypeRefused)
    );
    assert_eq!(
        PersonAttribute::of_vct(ISSUER, &format!("{ISSUER}/vc/age_over_18")),
        Ok(PersonAttribute::AgeOver18)
    );
    let meta = issuer_metadata(ISSUER);
    let configured: BTreeSet<&str> = meta["credential_configurations_supported"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(configured, ALL.iter().map(|t| t.name()).collect());
    assert_eq!(
        meta["credential_endpoint"],
        format!("{ISSUER}/oid4vci/credential")
    );
    let o = offer(ISSUER, PersonAttribute::AgeOver18, "code-1");
    assert_eq!(
        o["grants"][PRE_AUTHORIZED_GRANT]["pre-authorized_code"],
        "code-1"
    );
    assert!(offer_link(&o).starts_with("openid-credential-offer://?credential_offer=%7B"));
}

fn present(sd_jwt: &str, holder: &dyn Signer, aud: &str, nonce: &str) -> String {
    let sd_hash = b64url_encode(&suiss_crypto::digest::sha256(sd_jwt.as_bytes()));
    let kb = jws(
        holder,
        &json!({ "alg": alg(holder), "typ": "kb+jwt" }),
        &json!({ "aud": aud, "nonce": nonce, "iat": NOW / 1000, "sd_hash": sd_hash }),
    );
    format!("{sd_jwt}{kb}")
}

// E55, IDP-21, PI-3, Ek B 4196
#[test]
fn an_sd_jwt_vc_issued_to_an_agent_key_binding_verifies_with_kb_jwt() {
    let realm = SoftSigner::generate_p256().unwrap().0;
    let agent = SoftSigner::generate_ed25519().unwrap().0;
    let bound = agent.public_key();
    let key = verify(
        &PureBackend,
        &proof(&agent, false, "c-nonce-1"),
        &Holder::KeyBinding(bound.clone()),
        &expect(),
    )
    .unwrap();
    assert_eq!(key, bound);
    let credential = issue(
        &realm,
        &Credential {
            issuer: ISSUER,
            attribute: PersonAttribute::AgeOver18,
            value: Value::Bool(true),
            holder: key,
            status: (7, "https://acme.access.test/status/vc/1"),
            now_ms: NOW,
            salt: fresh16(),
        },
    )
    .unwrap();
    let mut keys = KeySet::default();
    keys.insert(thumbprint(&realm.public_key()), realm.public_key())
        .unwrap();
    keys.allowed = BTreeSet::from([Algorithm::Es256, Algorithm::Ed25519]);
    let p = present(&credential, &agent, "https://rp.test", "rp-nonce");
    let v = sd_jwt::verify(
        &PureBackend,
        &p,
        &keys,
        &Rules {
            typ: "dc+sd-jwt",
            audience: "https://rp.test",
            nonce: "rp-nonce",
            now: NOW,
            skew_ms: 60_000,
        },
        Origin::External,
    )
    .unwrap();
    assert!(v.holder_bound);
    assert_eq!(
        v.claims.get("age_over_18"),
        Some(&access_kernel::json::Json::Bool(true))
    );
    assert_eq!(
        v.claims
            .get("vct")
            .and_then(access_kernel::json::Json::as_str),
        Some("https://acme.access.test/vc/age_over_18")
    );
    let other = SoftSigner::generate_ed25519().unwrap().0;
    let forged = present(&credential, &other, "https://rp.test", "rp-nonce");
    assert!(
        sd_jwt::verify(
            &PureBackend,
            &forged,
            &keys,
            &Rules {
                typ: "dc+sd-jwt",
                audience: "https://rp.test",
                nonce: "rp-nonce",
                now: NOW,
                skew_ms: 60_000,
            },
            Origin::External,
        )
        .is_err()
    );
}

// E55, Ek B 4196
#[test]
fn the_key_proof_binds_only_the_holders_key() {
    let device = SoftSigner::generate_p256().unwrap().0;
    let agent = SoftSigner::generate_ed25519().unwrap().0;
    let other = SoftSigner::generate_ed25519().unwrap().0;
    assert_eq!(
        verify(
            &PureBackend,
            &proof(&device, true, "c-nonce-1"),
            &Holder::Device,
            &expect()
        ),
        Ok(device.public_key())
    );
    assert_eq!(
        verify(
            &PureBackend,
            &proof(&device, false, "c-nonce-1"),
            &Holder::Device,
            &expect()
        ),
        Err(ProofError::Key)
    );
    assert_eq!(
        verify(
            &PureBackend,
            &proof(&other, true, "c-nonce-1"),
            &Holder::KeyBinding(agent.public_key()),
            &expect()
        ),
        Err(ProofError::Key)
    );
    assert_eq!(
        verify(
            &PureBackend,
            &proof(&device, true, "stale"),
            &Holder::Device,
            &expect()
        ),
        Err(ProofError::Claims)
    );
    let realm = SoftSigner::generate_p256().unwrap().0;
    let base = Credential {
        issuer: ISSUER,
        attribute: PersonAttribute::AgeOver21,
        value: Value::Bool(false),
        holder: device.public_key(),
        status: (1, "https://acme.access.test/status/vc/1"),
        now_ms: NOW,
        salt: fresh16(),
    };
    assert_eq!(issue(&realm, &base), Err(IssueError::Value));
    let named = Credential {
        attribute: PersonAttribute::VerifiedName,
        value: Value::from("Ada Lovelace"),
        ..base
    };
    assert!(issue(&realm, &named).is_ok());
}

struct Verified(bool);

impl Facts for Verified {
    fn value(&self, _subject: &[u8; 16], attribute: PersonAttribute) -> Option<Value> {
        (self.0 && attribute.boolean()).then_some(Value::Bool(true))
    }
}

struct List;

impl StatusList for List {
    fn allocate(&self) -> Option<(u64, String)> {
        Some((3, String::from("https://acme.access.test/status/vc/1")))
    }
}

struct Fixed;

impl Clock for Fixed {
    fn now(&self) -> Option<u64> {
        Some(NOW)
    }
}

struct Fresh;

impl Random for Fresh {
    fn bytes(&self) -> Option<[u8; 16]> {
        Some(fresh16())
    }
}

fn request(name: &str, proof: &str) -> access_kernel::json::Json {
    let body = json!({ "credential_configuration_id": name, "proofs": { "jwt": [proof] } });
    access_kernel::json::parse(body.to_string().as_bytes(), 16 * 1024).unwrap()
}

// E55, PI-3, Ek B 4196, 5039
#[test]
fn a_request_gets_only_the_granted_verified_person_attribute() {
    let realm = SoftSigner::generate_p256().unwrap().0;
    let device = SoftSigner::generate_p256().unwrap().0;
    let grant = Grant {
        subject: fresh16(),
        attribute: PersonAttribute::AgeOver18,
        holder: Holder::Device,
    };
    let issuer = Issuer {
        issuer: ISSUER,
        facts: Verified(true),
        status: List,
        clock: Fixed,
        random: Fresh,
        signer: &realm,
    };
    let p = proof(&device, true, "c-nonce-1");
    let sd = issuer
        .credential(&grant, &request("age_over_18", &p), "c-nonce-1")
        .unwrap();
    assert!(sd.ends_with('~'));
    assert_eq!(
        issuer.credential(&grant, &request("age_over_21", &p), "c-nonce-1"),
        Err(RequestError::Type)
    );
    assert_eq!(
        issuer.credential(&grant, &request("university_degree", &p), "c-nonce-1"),
        Err(RequestError::Type)
    );
    assert_eq!(
        issuer.credential(&grant, &request("age_over_18", &p), "c-nonce-2"),
        Err(RequestError::Proof(ProofError::Claims))
    );
    let unverified = Issuer {
        facts: Verified(false),
        ..issuer
    };
    assert_eq!(
        unverified.credential(&grant, &request("age_over_18", &p), "c-nonce-1"),
        Err(RequestError::NotVerified)
    );
}
