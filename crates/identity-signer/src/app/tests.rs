//! The realm key set over simulated time, its tokens checked by the Kernel's JWS verifier
//! against the JWKS as a relying party reads it.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "simulated clocks and counters in test code"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use access_kernel::verify::cose::KeySet;
use access_kernel::verify::jws::{JwsError, Origin, verify_compact};
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::{SignError, SoftSigner};

use super::*;
use crate::domain::TOKEN_MAX_MS;
use crate::ports::Generated;

const MINUTE: u64 = 60_000;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const TYP: &str = "at+jwt";
const LEAD: u64 = Policy::REALM.publish_lead_ms;

struct Factory {
    down: bool,
}

impl KeyFactory for Factory {
    fn generate(&mut self, alg: JwsAlg) -> Result<Generated, SignError> {
        if self.down {
            return Err(SignError::Key);
        }
        let (signer, doc) = match alg {
            JwsAlg::Es256 => SoftSigner::generate_p256()?,
            JwsAlg::Ed25519 => SoftSigner::generate_ed25519()?,
        };
        Ok(Generated {
            signer: Box::new(signer),
            sealed: doc.expose().clone(),
        })
    }

    fn load(&mut self, alg: JwsAlg, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError> {
        let doc = suiss_crypto::secret::Secret::new(sealed.to_vec());
        Ok(match alg {
            JwsAlg::Es256 => Box::new(SoftSigner::p256_from_pkcs8(&doc)?),
            JwsAlg::Ed25519 => Box::new(SoftSigner::ed25519_from_pkcs8(&doc)?),
        })
    }
}

fn member<'a>(members: &'a [(String, Json)], name: &str) -> &'a str {
    members
        .iter()
        .find(|(k, _)| k == name)
        .and_then(|(_, v)| v.as_str())
        .unwrap()
}

/// The JWKS as a relying party reads it: kid, alg and key of every entry.
fn read_jwks(doc: &str) -> Vec<(String, String, PublicKey)> {
    let Json::Object(top) = json::parse(doc.as_bytes(), 64 * 1024).unwrap() else {
        panic!("not an object");
    };
    assert_eq!(top.len(), 1);
    let Some((_, Json::Array(keys))) = top.iter().find(|(k, _)| k == "keys") else {
        panic!("no keys");
    };
    keys.iter()
        .map(|k| {
            let Json::Object(m) = k else {
                panic!("not an object")
            };
            assert_eq!(member(m, "use"), "sig");
            let x = b64url_decode(member(m, "x")).unwrap();
            let key = match member(m, "kty") {
                "EC" => {
                    assert_eq!(member(m, "crv"), "P-256");
                    let mut sec1 = vec![4];
                    sec1.extend(x);
                    sec1.extend(b64url_decode(member(m, "y")).unwrap());
                    PublicKey::P256(sec1)
                }
                "OKP" => {
                    assert_eq!(member(m, "crv"), "Ed25519");
                    PublicKey::Ed25519(x.try_into().unwrap())
                }
                other => panic!("unexpected kty {other}"),
            };
            (
                member(m, "kid").to_owned(),
                member(m, "alg").to_owned(),
                key,
            )
        })
        .collect()
}

fn key_set(doc: &str) -> KeySet {
    let mut set = KeySet::default();
    for (kid, alg, key) in read_jwks(doc) {
        let kid: [u8; 32] = b64url_decode(&kid).unwrap().try_into().unwrap();
        // CR-24
        assert_eq!(thumbprint(&key), kid);
        set.allowed.insert(match alg.as_str() {
            "ES256" => suiss_crypto::cose::Algorithm::Es256,
            "Ed25519" => suiss_crypto::cose::Algorithm::Ed25519,
            other => panic!("unexpected alg {other}"),
        });
        set.insert(kid, key).unwrap();
    }
    set
}

fn verify(doc: &str, token: &str) -> Result<Vec<u8>, JwsError> {
    verify_compact(&PureBackend, token, &key_set(doc), TYP, Origin::Native).map(|v| v.payload)
}

fn kids(doc: &str) -> BTreeSet<String> {
    read_jwks(doc).into_iter().map(|(kid, _, _)| kid).collect()
}

fn advance(ring: &mut Keyring, factory: &mut Factory, from: u64, to: u64, step: u64) {
    let mut now = from;
    while now <= to {
        let _ = ring.tick(factory, now, now / MINUTE);
        now += step;
    }
}

// MD-3, CR-2, CR-24: ES256 by default and Ed25519 when selected; the token verifies against
// the JWKS, whose kid is the key's RFC 7638 thumbprint
#[test]
fn tokens_verify_against_the_jwks() {
    for (alg, kty) in [(JwsAlg::Es256, "EC"), (JwsAlg::Ed25519, "OKP")] {
        let mut ring = Keyring::new(alg, Policy::REALM).unwrap();
        let mut factory = Factory { down: false };
        advance(&mut ring, &mut factory, 0, LEAD, MINUTE);
        let signed = ring.sign(TYP, br#"{"sub":"u1"}"#, LEAD).unwrap();
        assert_eq!(signed.alg, alg);
        assert_eq!(
            verify(ring.jwks(), &signed.token).unwrap(),
            br#"{"sub":"u1"}"#
        );
        let doc = ring.jwks();
        assert!(doc.contains(&format!(r#""kty":"{kty}""#)));
        assert!(doc.contains(&format!(r#""alg":"{}""#, alg.name())));
        assert!(!doc.contains("EdDSA"));
        assert!(!doc.contains("AKP"));
        assert!(!doc.contains(r#""d":"#));
        // CR-27, MD-6: the active key first, then a published backup
        let listed = read_jwks(doc);
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].0, b64url_encode(&signed.kid));
    }
}

// CR-59, CR-25, SAI-46, CR-23: the founding key signs before the lead has passed, published
// beside its backup; the backup neither signs nor rotates in before its lead, so once the
// founding key is dropped nothing is signed until the lead passes, then the backup signs
#[test]
fn the_founding_key_signs_before_the_lead_and_the_second_does_not() {
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut factory = Factory { down: false };
    let early = LEAD - MINUTE;
    advance(&mut ring, &mut factory, 0, early, MINUTE);
    assert_eq!(kids(ring.jwks()).len(), 2);
    let founding = ring.sign(TYP, b"{}", early).unwrap();
    verify(ring.jwks(), &founding.token).unwrap();
    let records = ring.keys();
    let first = records.iter().find(|k| k.kid == founding.kid).unwrap();
    assert!(first.founding);
    assert_eq!(first.valid_from, 0);
    assert_eq!(
        records.iter().filter(|k| k.founding).count(),
        1,
        "{records:?}"
    );
    let second = records.iter().find(|k| !k.founding).unwrap();
    assert_eq!((second.state, second.valid_from), (State::Published, LEAD));
    assert_eq!(
        ring.rotate(&mut factory, &founding.kid, early, 1)
            .map(|_| ()),
        Err(SignerError::NoBackup)
    );
    ring.drop_key(&mut factory, &founding.kid, early, 2)
        .unwrap();
    assert_eq!(ring.sign(TYP, b"{}", early), Err(SignerError::NoKey));
    advance(&mut ring, &mut factory, early, LEAD, MINUTE);
    let next = ring.sign(TYP, b"{}", LEAD).unwrap();
    assert_eq!(next.kid, second.kid);
    verify(ring.jwks(), &next.token).unwrap();
    assert!(
        ring.keys()
            .iter()
            .all(|k| k.founding == (k.kid == founding.kid))
    );
}

// CR-25, CR-27, CR-59, SAI-46, MD-6: over 400 days the realm signs from the minute it is
// opened; every signing key but the founding one was in the JWKS for at least the lead; the
// JWKS always holds the active key and a published backup
#[test]
fn rotation_runs_without_gaps() {
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut factory = Factory { down: false };
    let mut first_seen: BTreeMap<String, u64> = BTreeMap::new();
    let mut signing_kids = BTreeSet::new();
    let mut now = 0;
    while now <= 400 * DAY {
        let _ = ring.tick(&mut factory, now, now / HOUR);
        let listed = kids(ring.jwks());
        for kid in &listed {
            first_seen.entry(kid.clone()).or_insert(now);
        }
        let signed = ring.sign(TYP, br#"{"n":1}"#, now).unwrap();
        let kid = b64url_encode(&signed.kid);
        assert!(listed.contains(&kid));
        let records = ring.keys();
        let record = records.iter().find(|k| k.kid == signed.kid).unwrap();
        if record.founding {
            assert_eq!(first_seen[&kid], 0);
        } else {
            assert!(first_seen[&kid] + LEAD <= now, "{kid} used early at {now}");
        }
        signing_kids.insert(kid);
        if now % (10 * DAY) == 0 {
            verify(ring.jwks(), &signed.token).unwrap();
        }
        let count = |s: State| records.iter().filter(|k| k.state == s).count();
        assert_eq!(count(State::Active), 1, "at {now}");
        assert!(count(State::Published) >= 1, "at {now}");
        assert_eq!(count(State::Pending), 0, "at {now}");
        assert_eq!(records.iter().filter(|k| k.founding).count(), 1, "at {now}");
        assert!(listed.len() <= 4, "{} keys at {now}", listed.len());
        now += HOUR;
    }
    // CR-19: 90 days ±20 % per key
    assert!(
        (4..=6).contains(&signing_kids.len()),
        "{}",
        signing_kids.len()
    );
}

// CR-26, CR-27: a token signed with key N verifies while N is retiring and until at least
// T_token_max after N's last signature; once N is dropped it no longer verifies
#[test]
fn a_retiring_key_still_verifies() {
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut factory = Factory { down: false };
    advance(&mut ring, &mut factory, 0, LEAD, MINUTE);
    let first = ring.sign(TYP, b"{}", LEAD).unwrap().kid;
    let mut now = LEAD;
    let mut last = None;
    loop {
        now += HOUR;
        let _ = ring.tick(&mut factory, now, 1);
        let signed = ring.sign(TYP, b"{}", now).unwrap();
        if signed.kid != first {
            break;
        }
        last = Some((signed.token, now));
    }
    let (token, last_at) = last.unwrap();
    let retiring = ring.keys().into_iter().find(|k| k.kid == first).unwrap();
    assert_eq!(retiring.state, State::Retiring);
    verify(ring.jwks(), &token).unwrap();
    let name = b64url_encode(&first);
    let mut dropped_at = None;
    let mut hours = 0;
    while dropped_at.is_none() {
        now += HOUR;
        hours += 1;
        let _ = ring.tick(&mut factory, now, 1);
        if !kids(ring.jwks()).contains(&name) {
            assert_eq!(verify(ring.jwks(), &token), Err(JwsError::UnknownKid));
            dropped_at = Some(now);
        } else if hours % 24 == 0 {
            verify(ring.jwks(), &token).unwrap();
        }
    }
    assert!(dropped_at.unwrap() >= last_at + TOKEN_MAX_MS);
    let dropped = ring.keys().into_iter().find(|k| k.kid == first).unwrap();
    assert_eq!(dropped.state, State::Dropped);
    // CR-27, OP-73: the dropped key's private material is gone
    let saved = ring.saved();
    let s = saved.iter().find(|s| s.record.kid == first).unwrap();
    assert!(s.sealed.is_none());
}

// CR-23, G42: through a key-generation outage the realm signs to the end of the last key's
// window; after that nothing is signed, never an unsigned token
#[test]
fn an_outage_signs_to_the_window_end_then_refuses() {
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut factory = Factory { down: false };
    advance(&mut ring, &mut factory, 0, LEAD, MINUTE);
    factory.down = true;
    let end = ring.keys().iter().map(|k| k.valid_until).max().unwrap();
    let mut now = LEAD;
    let mut outage = false;
    let mut last_ok = 0;
    while now <= end + 2 * DAY {
        outage |= ring.tick(&mut factory, now, 1).outage;
        match ring.sign(TYP, b"{}", now) {
            Ok(signed) => {
                assert!(now <= end);
                last_ok = now;
                if now % (10 * DAY) < HOUR {
                    verify(ring.jwks(), &signed.token).unwrap();
                }
            }
            Err(e) => {
                assert_eq!(e, SignerError::NoKey);
                assert!(now > end, "refused at {now}, window ends {end}");
            }
        }
        now += HOUR;
    }
    assert!(outage);
    assert!(end - last_ok < HOUR);
}

// CR-25, CR-26, CR-27: policies that break the rules are refused when the key set is made
#[test]
fn incoherent_policies_are_refused() {
    assert!(matches!(
        Keyring::new(JwsAlg::Es256, Policy::AUTHORITY),
        Err(PolicyError::Lifetime)
    ));
}

// OP-149 m.8, CR-24: an artifact's COSE_Sign1 verifies with the realm key the JWKS lists
#[test]
fn artifacts_are_cose_signed_with_the_jwks_key() {
    const CT: &str = "application/access-auth-context+cbor";
    let payload = suiss_crypto::dcbor::encode(
        &suiss_crypto::dcbor::Value::Map(vec![(
            suiss_crypto::dcbor::Value::text("v"),
            suiss_crypto::dcbor::Value::Unsigned(1),
        )]),
        suiss_crypto::dcbor::Limits::CEILING,
    )
    .unwrap();
    for alg in [JwsAlg::Es256, JwsAlg::Ed25519] {
        let mut ring = Keyring::new(alg, Policy::REALM).unwrap();
        let mut factory = Factory { down: false };
        advance(&mut ring, &mut factory, 0, LEAD, MINUTE);
        let (sign1, kid) = ring.sign_cose(CT, &payload, LEAD).unwrap();
        let mut keys = key_set(ring.jwks());
        keys.allowed.insert(suiss_crypto::cose::Algorithm::Esp256);
        let verified = suiss_crypto::cose::verify_sign1(&PureBackend, &sign1, &keys, CT).unwrap();
        assert_eq!(verified.kid, kid);
        assert_eq!(verified.payload, payload);
        assert_eq!(
            ring.sign_cose("application/json", &payload, LEAD),
            Err(SignerError::Payload)
        );
        assert_eq!(
            ring.sign_cose(CT, b"{\"v\":1}", LEAD),
            Err(SignerError::Payload)
        );
    }
}

// TN-118, MD-6, CR-25, CR-59, SAI-46: a decided rotation makes the published backup past its
// lead sign at once; the old key retires and still verifies its tokens; without such a backup
// nothing changes
#[test]
fn a_decided_rotation_uses_the_ready_backup() {
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut factory = Factory { down: false };
    let early = LEAD - MINUTE;
    advance(&mut ring, &mut factory, 0, early, MINUTE);
    let first = ring.sign(TYP, b"{}", early).unwrap().kid;
    let before = ring.keys();
    assert_eq!(
        ring.rotate(&mut factory, &first, early, 1).map(|_| ()),
        Err(SignerError::NoBackup)
    );
    assert_eq!(ring.keys(), before);
    let now = LEAD;
    advance(&mut ring, &mut factory, early, now, MINUTE);
    let old = ring.sign(TYP, br#"{"n":1}"#, now).unwrap();
    assert_eq!(old.kid, first);
    let round = ring.rotate(&mut factory, &old.kid, now, 7).unwrap();
    assert!(
        round
            .applied
            .iter()
            .any(|s| matches!(s, Step::Retire(k) if *k == old.kid))
    );
    let new = ring.sign(TYP, br#"{"n":2}"#, now).unwrap();
    assert_ne!(new.kid, old.kid);
    assert!(verify(ring.jwks(), &old.token).is_ok());
    assert!(verify(ring.jwks(), &new.token).is_ok());
    let records = ring.keys();
    assert!(
        records
            .iter()
            .any(|k| k.state == State::Published && k.kid != new.kid)
    );
    assert_eq!(
        ring.rotate(&mut factory, &old.kid, now, 7)
            .map(|r| r.applied),
        Ok(Vec::new())
    );
    assert_eq!(ring.keys(), records);
    assert_eq!(
        ring.rotate(&mut factory, &[0; 32], now, 7).map(|_| ()),
        Err(SignerError::UnknownKey)
    );
}

// §13.2, CR-23, MD-7, OP-73: an emergency drop takes the key out of the JWKS at once and
// destroys its material, so its tokens stop verifying; with no backup past its lead nothing
// is signed until one is, and signing then resumes with a key that was published first
#[test]
fn an_emergency_drop_ends_a_key_at_once() {
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut factory = Factory { down: false };
    let early = LEAD - MINUTE;
    advance(&mut ring, &mut factory, 0, early, MINUTE);
    let stolen = ring.sign(TYP, br#"{"n":1}"#, early).unwrap();
    assert!(verify(ring.jwks(), &stolen.token).is_ok());
    ring.drop_key(&mut factory, &stolen.kid, early, 3).unwrap();
    assert!(!kids(ring.jwks()).contains(&b64url_encode(&stolen.kid)));
    assert!(verify(ring.jwks(), &stolen.token).is_err());
    assert_eq!(ring.sign(TYP, b"{}", early), Err(SignerError::NoKey));
    assert!(
        ring.saved()
            .iter()
            .any(|s| s.record.kid == stolen.kid && s.sealed.is_none())
    );
    assert_eq!(
        ring.drop_key(&mut factory, &stolen.kid, early, 3)
            .map(|r| r.applied),
        Ok(Vec::new())
    );
    assert_eq!(
        ring.drop_key(&mut factory, &[0; 32], early, 3).map(|_| ()),
        Err(SignerError::UnknownKey)
    );
    let later = LEAD + MINUTE;
    advance(&mut ring, &mut factory, early, later, MINUTE);
    let next = ring.sign(TYP, br#"{"n":2}"#, later).unwrap();
    assert_ne!(next.kid, stolen.kid);
    assert!(verify(ring.jwks(), &next.token).is_ok());
}

// TN-118, CR-26: a decided policy is checked like any other; one that would let a key sign
// shorter than a token lives is refused and the set keeps its policy
#[test]
fn a_decided_policy_is_checked() {
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut shorter = Policy::REALM;
    shorter.lifetime_ms = TOKEN_MAX_MS;
    assert_eq!(ring.set_policy(shorter), Err(PolicyError::Lifetime));
    assert_eq!(ring.policy(), Policy::REALM);
    let mut faster = Policy::REALM;
    faster.lifetime_ms = 30 * DAY;
    faster.window_ms = 60 * DAY;
    assert_eq!(ring.set_policy(faster), Ok(()));
    assert_eq!(ring.policy(), faster);
}

// §10.4.5, §12.1.2, TI-RT6: a realm key never signs an access token carrying authority, in
// any spelling of the type, nor one whose claims cannot be read; a protocol-scope-only access
// token and other types are signed
// TNI-2
#[test]
fn a_realm_key_refuses_authority_tokens() {
    let mut ring = Keyring::new(JwsAlg::Es256, Policy::REALM).unwrap();
    let mut factory = Factory { down: false };
    advance(&mut ring, &mut factory, 0, LEAD, MINUTE);
    let authority =
        br#"{"sub":"u1","authorization_details":[{"type":"door:open:1","kind":"bounds"}]}"#;
    for typ in ["at+jwt", "AT+JWT", "application/at+jwt"] {
        assert!(matches!(
            ring.sign(typ, authority, LEAD),
            Err(SignerError::Authority)
        ));
        assert!(matches!(
            ring.sign(typ, b"[]", LEAD),
            Err(SignerError::Authority)
        ));
    }
    assert!(
        ring.sign("at+jwt", br#"{"sub":"u1","scope":"openid"}"#, LEAD)
            .is_ok()
    );
    assert!(ring.sign("JWT", authority, LEAD).is_ok());
}

// OP-64 (A-13): a signed token prints its key and algorithm, never the token
#[test]
fn signed_tokens_do_not_print_the_token() {
    let signed = Signed {
        token: String::from("eyJhbGciOiJFUzI1NiJ9.secret-claims.sig"),
        kid: [4; 32],
        alg: JwsAlg::Es256,
    };
    let printed = format!("{signed:?}");
    assert!(!printed.contains("secret-claims"), "{printed}");
    assert!(printed.contains("Es256"));
}
