use access_kernel::json::{self, Json};
use access_kernel::verify::cose::{Algorithm, KeySet};
use access_kernel::verify::jws::Origin;
use access_kernel::verify::sd_jwt::{Rules, SdJwtError, verify};
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::SoftSigner;

use super::*;
use crate::jose::confirmation_jwk;

const TYP: &str = "access-pap+sd-jwt";
const NOW: u64 = 1_000_000;

fn keys(issuer: &dyn Signer) -> KeySet {
    let key = issuer.public_key();
    let mut set = KeySet::default();
    set.insert(thumbprint(&key), key).unwrap();
    set.allowed.extend([Algorithm::Ed25519, Algorithm::Es256]);
    set
}

fn rules() -> Rules<'static> {
    Rules {
        typ: TYP,
        audience: "pep:shop",
        nonce: "n-1",
        now: NOW,
        skew_ms: 60_000,
    }
}

fn counter() -> impl FnMut() -> Result<[u8; SALT_LEN], RandomError> {
    let mut n = 0u8;
    move || {
        n = n.wrapping_add(1);
        Ok([n; SALT_LEN])
    }
}

fn claims(holder: Option<&dyn Signer>) -> Vec<(String, Json)> {
    let mut c = vec![
        (String::from("iss"), output::text("sha-256:d")),
        (String::from("exp"), Json::Int(2000)),
        (String::from("given_name"), output::text("Ada \"\\ \u{1}")),
        (
            String::from("address"),
            Json::Object(vec![(String::from("region"), output::text("eu"))]),
        ),
        (String::from("level"), Json::Int(-3)),
    ];
    if let Some(h) = holder {
        let jwk = confirmation_jwk(&h.public_key()).unwrap();
        c.push((
            String::from("cnf"),
            Json::Object(vec![(String::from("jwk"), jwk)]),
        ));
    }
    c
}

fn names(n: &[&str]) -> BTreeSet<String> {
    n.iter().map(|s| String::from(*s)).collect()
}

// RFC 9901, L0-SIG-50: the Kernel applies exactly the revealed disclosures
#[test]
fn sd_jwts_verify_in_the_kernel() {
    let (issuer, _) = SoftSigner::generate_p256().unwrap();
    let sd_jwt = issue(
        &issuer,
        TYP,
        claims(None),
        &names(&["given_name", "address"]),
        &mut counter(),
    )
    .unwrap();
    assert_eq!(sd_jwt.disclosures.len(), 2);
    let all = present(&sd_jwt, &names(&["given_name", "address"]), None).unwrap();
    assert_eq!(all, sd_jwt.serialize());
    let v = verify(&PureBackend, &all, &keys(&issuer), &rules(), Origin::Native).unwrap();
    assert!(!v.holder_bound);
    assert_eq!(
        v.claims.get("given_name").and_then(Json::as_str),
        Some("Ada \"\\ \u{1}")
    );
    assert_eq!(v.claims.get("level").and_then(Json::as_int), Some(-3));
    let some = present(&sd_jwt, &names(&["address"]), None).unwrap();
    let v = verify(
        &PureBackend,
        &some,
        &keys(&issuer),
        &rules(),
        Origin::Native,
    )
    .unwrap();
    assert!(v.claims.get("given_name").is_none());
    assert!(v.claims.get("address").is_some());
    assert!(v.claims.get("_sd").is_none());
}

// L0-SIG-50: a domain always writes _sd_alg; _sd is sorted and only digests
#[test]
fn the_payload_carries_sorted_digests_and_sd_alg() {
    let (issuer, _) = SoftSigner::generate_ed25519().unwrap();
    let sd_jwt = issue(
        &issuer,
        TYP,
        claims(None),
        &names(&["given_name", "address", "level"]),
        &mut counter(),
    )
    .unwrap();
    let payload = sd_jwt.jwt.split('.').nth(1).unwrap();
    let payload = json::parse(&json::b64url_decode(payload).unwrap(), 1 << 16).unwrap();
    assert_eq!(
        payload.get("_sd_alg").and_then(Json::as_str),
        Some("sha-256")
    );
    let Some(Json::Array(sd)) = payload.get("_sd") else {
        panic!("no _sd");
    };
    let sd: Vec<&str> = sd.iter().filter_map(Json::as_str).collect();
    let mut sorted = sd.clone();
    sorted.sort_unstable();
    assert_eq!(sd, sorted);
    assert_eq!(sd.len(), 3);
    assert!(payload.get("given_name").is_none());
}

// RFC 9901 §4.3, L0-SIG-52: the key binding JWT is accepted with either holder algorithm
#[test]
fn holder_bound_presentations_verify() {
    let (issuer, _) = SoftSigner::generate_ed25519().unwrap();
    let (ed, _) = SoftSigner::generate_ed25519().unwrap();
    let (p256, _) = SoftSigner::generate_p256().unwrap();
    for holder in [&ed as &dyn Signer, &p256] {
        let sd_jwt = issue(
            &issuer,
            TYP,
            claims(Some(holder)),
            &names(&["given_name"]),
            &mut counter(),
        )
        .unwrap();
        let kb = KeyBinding {
            signer: holder,
            audience: "pep:shop",
            nonce: "n-1",
            iat: NOW,
        };
        let p = present(&sd_jwt, &names(&["given_name"]), Some(&kb)).unwrap();
        let v = verify(&PureBackend, &p, &keys(&issuer), &rules(), Origin::Native).unwrap();
        assert!(v.holder_bound);
        let unbound = present(&sd_jwt, &names(&["given_name"]), None).unwrap();
        assert_eq!(
            verify(
                &PureBackend,
                &unbound,
                &keys(&issuer),
                &rules(),
                Origin::Native
            )
            .map(|_| ()),
            Err(SdJwtError::KeyBinding)
        );
        let other = KeyBinding {
            audience: "pep:other",
            ..kb
        };
        let p = present(&sd_jwt, &BTreeSet::new(), Some(&other)).unwrap();
        assert!(verify(&PureBackend, &p, &keys(&issuer), &rules(), Origin::Native).is_err());
    }
}

// RFC 9901 §4.2, L0-SIG-51: reserved, repeated and verifier-checked claims are refused
#[test]
fn bad_claim_sets_are_refused() {
    let (issuer, _) = SoftSigner::generate_ed25519().unwrap();
    let mut repeated = claims(None);
    repeated.push((String::from("exp"), Json::Int(1)));
    let mut reserved = claims(None);
    reserved.push((String::from("_sd"), Json::Array(vec![])));
    for (c, d) in [
        (repeated, names(&[])),
        (reserved, names(&[])),
        (claims(None), names(&["iss"])),
        (claims(None), names(&["exp"])),
        (claims(None), names(&["missing"])),
    ] {
        assert_eq!(
            issue(&issuer, TYP, c, &d, &mut counter()),
            Err(SdJwtIssueError::Claim)
        );
    }
    assert_eq!(
        issue(&issuer, TYP, claims(None), &names(&["level"]), &mut || Err(
            RandomError
        )),
        Err(SdJwtIssueError::Random)
    );
    let sd_jwt = issue(&issuer, TYP, claims(None), &names(&[]), &mut counter()).unwrap();
    assert_eq!(
        present(&sd_jwt, &names(&["level"]), None),
        Err(SdJwtIssueError::Disclosure)
    );
}
