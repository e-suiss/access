extern crate std;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use ed25519_dalek::Signer as _;
use serde_json::Value as J;

use super::*;
use crate::json::{b64url_decode, b64url_encode};
use crate::model::{ActionRef, ActionSet, AuthoritySet, ResourceSelector, Structural};
use crate::validity::{ProfileVariant, Revalidation};
use crate::verify::cose::{Algorithm, PublicKey};
use crate::verify::key_scope::{METADATA_CONTENT_TYPE, thumbprint};

fn vectors(text: &str) -> J {
    serde_json::from_str(text).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    })
}

fn s<'a>(c: &'a J, k: &str) -> &'a str {
    c[k].as_str().unwrap()
}

fn cases(v: &J) -> &Vec<J> {
    v["cases"].as_array().unwrap()
}

fn key_set(
    keys: impl IntoIterator<Item = ([u8; 32], PublicKey)>,
    allowed: &[Algorithm],
) -> Vec<u8> {
    let mut set = KeySet::default();
    set.keys.extend(keys);
    set.allowed.extend(allowed.iter().copied());
    set.to_bytes().unwrap()
}

const EMPTY_CATALOG: &[u8] = &[0xa0];

// OP-116 m.6, OP-111
#[test]
fn decision_vectors() {
    let v = vectors(include_str!(
        "../../../../conformance/vectors/core/1/decision.json"
    ));
    let fuel = v["fuel"].as_u64().unwrap();
    for c in cases(&v) {
        let got = evaluate(&unhex(s(c, "input")), fuel);
        match c.get("decision") {
            Some(d) => assert_eq!(
                got.map(|b| hex(&b)),
                Ok(d.as_str().unwrap().to_string()),
                "{}",
                c["id"]
            ),
            None => assert_eq!(
                got.map_err(|e| e.name()),
                Err(s(c, "rejection").to_string()),
                "{}",
                c["id"]
            ),
        }
    }
    assert_eq!(cases(&v).len(), 34);
}

// OP-116 m.6, CR-57
#[test]
fn cve_regression_vectors() {
    let v = vectors(include_str!(
        "../../../../conformance/vectors/core/1/cve-regressions.json"
    ));
    let fuel = v["fuel"].as_u64().unwrap();
    for c in cases(&v) {
        match s(c, "operation") {
            "combinator.evaluate" => assert_eq!(
                evaluate(&unhex(s(c, "input")), fuel).map(|b| hex(&b)),
                Ok(s(c, "decision").to_string()),
                "{}",
                c["id"]
            ),
            "algebra.child_within_parent" => assert_eq!(
                child_within_parent(
                    &unhex(s(c, "child")),
                    &unhex(s(c, "parent")),
                    &unhex(s(c, "holder")),
                    EMPTY_CATALOG,
                ),
                Ok(c["within"].as_bool().unwrap()),
                "{}",
                c["id"]
            ),
            other => panic!("unknown operation {other}"),
        }
    }
}

fn cose_keys(v: &J) -> Vec<u8> {
    let keys = v["keys"].as_object().unwrap().iter().map(|(kid, key)| {
        (
            <[u8; 32]>::try_from(unhex(kid).as_slice()).unwrap(),
            PublicKey::from_bytes(&unhex(key.as_str().unwrap())).unwrap(),
        )
    });
    let allowed: Vec<Algorithm> = v["allowed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| Algorithm::from_cose(a.as_i64().unwrap()).unwrap())
        .collect();
    key_set(keys, &allowed)
}

// OP-116 m.6, CR-55
#[test]
fn cose_vectors() {
    let v = vectors(include_str!(
        "../../../../conformance/vectors/core/1/cose.json"
    ));
    let keys = cose_keys(&v);
    let ct = s(&v, "content_type");
    for c in cases(&v) {
        let got = verify_cose_sign1(&unhex(s(c, "sign1")), &keys, ct);
        if let Some(e) = c.get("error") {
            assert_eq!(
                got.map_err(|e| e.name()),
                Err(e.as_str().unwrap().to_string()),
                "{}",
                c["id"]
            );
        } else {
            let expect = map([
                ("kid", Some(Value::Bytes(unhex(s(c, "kid"))))),
                ("payload", Some(Value::Bytes(unhex(s(c, "payload"))))),
            ]);
            assert_eq!(
                got,
                Ok(dcbor::encode(&expect, Limits::CEILING).unwrap()),
                "{}",
                c["id"]
            );
        }
    }
}

// OP-116 m.6, CR-58
#[test]
fn key_scope_vectors() {
    let v = vectors(include_str!(
        "../../../../conformance/vectors/core/1/key-scope.json"
    ));
    for c in cases(&v) {
        let got = operational_key(
            &unhex(s(c, "metadata")),
            &unhex(s(c, "domain")),
            &unhex(s(c, "excerpt")),
            s(c, "usage"),
            c["iat"].as_u64().unwrap(),
        );
        match c.get("error") {
            Some(e) => assert_eq!(
                got.map_err(|e| e.name()),
                Err(e.as_str().unwrap().to_string()),
                "{}",
                c["id"]
            ),
            None => assert_eq!(
                got.map(|b| hex(&b)),
                Ok(s(c, "key").to_string()),
                "{}",
                c["id"]
            ),
        }
    }
}

fn jose_keys(v: &J) -> Vec<u8> {
    let keys = v["keys"].as_object().unwrap().iter().map(|(kid, key)| {
        let raw = b64url_decode(key.as_str().unwrap()).unwrap();
        let key = match <[u8; 32]>::try_from(raw.as_slice()) {
            Ok(ed) => PublicKey::Ed25519(ed),
            Err(_) => PublicKey::P256(raw),
        };
        (
            <[u8; 32]>::try_from(b64url_decode(kid).unwrap().as_slice()).unwrap(),
            key,
        )
    });
    key_set(keys, &[Algorithm::Ed25519, Algorithm::Es256])
}

// OP-116 m.6, CR-56
#[test]
fn jose_attack_class_vectors() {
    let v = vectors(include_str!(
        "../../../../conformance/vectors/core/1/jose-attack-classes.json"
    ));
    let keys = jose_keys(&v);
    let typ = s(&v, "typ");
    for c in cases(&v) {
        let got = verify_jws_compact(
            s(c, "token"),
            &keys,
            typ,
            "https://access.example",
            "pep:shop",
            1_500_000,
            60_000,
        );
        let got = match got {
            Ok(_) => "accept".to_string(),
            Err(e) => format!("reject: {e}"),
        };
        assert_eq!(got, s(c, "expect"), "{}", c["id"]);
    }
    let token = s(&cases(&v)[0], "token");
    assert_eq!(
        verify_jws_compact(
            token,
            &keys,
            typ,
            "https://evil",
            "pep:shop",
            1_500_000,
            60_000
        )
        .map_err(|e| (e.kind(), e.name())),
        Err((Kind::Issuer, "issuer".to_string()))
    );
    assert_eq!(
        verify_jws_compact(
            token,
            &keys,
            typ,
            "https://access.example",
            "pep:shop",
            3_000_000,
            0
        )
        .map_err(|e| e.name()),
        Err("expired".to_string())
    );
}

// OP-116 m.6, OP-106 m.18
#[test]
fn merkle_vectors() {
    let v = vectors(include_str!(
        "../../../../conformance/vectors/core/1/merkle.json"
    ));
    let leaves: Vec<Vec<u8>> = v["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| unhex(l.as_str().unwrap()))
        .collect();
    let roots: BTreeMap<u64, Vec<u8>> = v["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["size"].as_u64().unwrap(), unhex(s(r, "root"))))
        .collect();
    let path = |c: &J| -> Vec<u8> {
        c["path"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|p| unhex(p.as_str().unwrap()))
            .collect()
    };
    let inclusion = v["inclusion"].as_array().unwrap();
    for c in inclusion {
        let (index, size) = (c["index"].as_u64().unwrap(), c["size"].as_u64().unwrap());
        let leaf = digest::leaf_hash(&leaves[usize::try_from(index).unwrap()]);
        let root = &roots[&size];
        assert_eq!(
            verify_inclusion(index, size, &leaf, &path(c), root),
            Ok(true)
        );
        assert_eq!(
            verify_inclusion(size, size, &leaf, &path(c), root),
            Ok(false)
        );
        let mut longer = path(c);
        longer.extend([0; 32]);
        assert_eq!(
            verify_inclusion(index, size, &leaf, &longer, root),
            Ok(false)
        );
    }
    let consistency = v["consistency"].as_array().unwrap();
    for c in consistency {
        let (a, b) = (c["first"].as_u64().unwrap(), c["second"].as_u64().unwrap());
        assert_eq!(
            verify_consistency(a, b, &roots[&a], &roots[&b], &path(c)),
            Ok(true)
        );
        if a > 0 && a < b {
            assert_eq!(
                verify_consistency(a, b, &roots[&b], &roots[&b], &path(c)),
                Ok(false)
            );
        }
    }
    assert_eq!((inclusion.len(), consistency.len()), (36, 36));
    let root = &roots[&1];
    assert_eq!(
        verify_inclusion(0, 1, &[0; 31], &[], root),
        Err(Error::Input)
    );
    assert_eq!(
        verify_inclusion(0, 1, root, &[0; 33], root),
        Err(Error::Input)
    );
    assert_eq!(
        verify_consistency(1, 1, root, &[0; 33], &[]),
        Err(Error::Input)
    );
}

fn first_decision_input() -> Vec<u8> {
    let v = vectors(include_str!(
        "../../../../conformance/vectors/core/1/decision.json"
    ));
    unhex(s(&cases(&v)[0], "input"))
}

// OP-116 m.5, OP-108 m.11
#[test]
fn fuel_above_the_ceiling_is_an_input_rejection() {
    let input = first_decision_input();
    assert!(evaluate(&input, MAX_FUEL).is_ok());
    assert_eq!(evaluate(&input, MAX_FUEL + 1), Err(Error::Input));
    assert_eq!(evaluate(&input, 0), Err(Error::Fuel));
    assert_eq!(evaluate(&[0xa0], 10), Err(Error::Input));
}

// OP-106 m.22
#[test]
fn intent_digest_matches_the_kernel() {
    let v = vectors(include_str!(
        "../../../../conformance/vectors/core/1/decision.json"
    ));
    for c in cases(&v) {
        let Ok(owned) = OwnedInput::from_bytes(&unhex(s(c, "input"))) else {
            continue;
        };
        let expect = intent::intent_digest(&owned.intent).unwrap();
        assert_eq!(
            intent_digest(&owned.intent.to_bytes().unwrap()),
            Ok(dcbor::encode(&expect.to_value(), Limits::CEILING).unwrap())
        );
    }
    assert_eq!(intent_digest(&[0xa0]), Err(Error::Input));
}

// OP-116 m.2
#[test]
fn key_set_decoding_is_strict() {
    let ed = PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes(),
    );
    let bytes = key_set(
        [([1; 32], ed.clone())],
        &[Algorithm::Ed25519, Algorithm::Esp256],
    );
    let back = KeySet::from_bytes(&bytes).unwrap();
    assert_eq!(back.to_bytes().unwrap(), bytes);
    let entry = |kid: Vec<u8>| (Value::Bytes(kid), ed.to_value());
    let raw = |keys: Vec<(Value, Value)>, allowed: Vec<i64>| {
        dcbor::encode(
            &map([
                ("keys", Some(Value::Map(keys))),
                (
                    "allowed",
                    Some(Value::Array(allowed.into_iter().map(Value::int).collect())),
                ),
            ]),
            Limits::CEILING,
        )
        .unwrap()
    };
    assert!(KeySet::from_bytes(&raw(vec![entry(vec![1; 32])], vec![-9, -19])).is_ok());
    assert!(KeySet::from_bytes(&raw(vec![entry(vec![1; 32])], vec![-19, -9])).is_err());
    assert!(KeySet::from_bytes(&raw(vec![entry(vec![1; 32])], vec![])).is_err());
    assert!(KeySet::from_bytes(&raw(vec![entry(vec![1; 32])], vec![-8])).is_err());
    assert!(KeySet::from_bytes(&raw(vec![], vec![-19])).is_err());
    assert!(KeySet::from_bytes(&raw(vec![entry(vec![1; 31])], vec![-19])).is_err());
    let small = (
        Value::Bytes(vec![1; 32]),
        PublicKey::Ed25519([0; 32]).to_value(),
    );
    assert!(KeySet::from_bytes(&raw(vec![small], vec![-19])).is_err());
    assert_eq!(verify_cose_sign1(&[0xd2], &[0xa0], "x"), Err(Error::Input));
}

fn sign1(seed: u8, kid: [u8; 32], content_type: &str, payload: &[u8]) -> Vec<u8> {
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::int(Algorithm::Ed25519.cose())),
            (Value::Unsigned(3), Value::text(content_type)),
            (Value::Unsigned(4), Value::Bytes(kid.to_vec())),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let tbs = cose::to_be_signed(&prot, payload);
    let sig = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).sign(&tbs);
    let body = Value::Array(vec![
        Value::Bytes(prot),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig.to_bytes().to_vec()),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

// CR-58 m.3
#[test]
fn metadata_is_verified_against_the_trusted_binding_keys() {
    let v = vectors(include_str!(
        "../../../../conformance/vectors/core/1/key-scope.json"
    ));
    let metadata = unhex(s(&cases(&v)[0], "metadata"));
    let binding = PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes(),
    );
    let kid = thumbprint(&binding);
    let trusted = key_set([(kid, binding)], &[Algorithm::Ed25519]);
    let signed = sign1(1, kid, METADATA_CONTENT_TYPE, &metadata);
    assert_eq!(verify_metadata(&signed, &trusted), Ok(metadata.clone()));
    let wrong = sign1(2, kid, METADATA_CONTENT_TYPE, &metadata);
    assert_eq!(
        verify_metadata(&wrong, &trusted).map_err(|e| e.name()),
        Err("signature".to_string())
    );
    let other_ct = sign1(1, kid, "application/x", &metadata);
    assert_eq!(
        verify_metadata(&other_ct, &trusted).map_err(|e| e.name()),
        Err("content-type".to_string())
    );
    assert_eq!(
        verify_metadata(&signed[1..], &trusted).map_err(|e| e.name()),
        Err("cbor".to_string())
    );
    assert_eq!(verify_metadata(&signed, &[0xa0]), Err(Error::Input));
    assert_eq!(
        operational_key(&metadata, &[0xa0], &signed, "pap", 0),
        Err(Error::Input)
    );
    let domain = unhex(s(&cases(&v)[0], "domain"));
    assert_eq!(
        operational_key(&metadata, &domain, &signed, "other", 0),
        Err(Error::Input)
    );
}

fn jwt(key: &ed25519_dalek::SigningKey, header: &str, payload: &str) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    format!(
        "{input}.{}",
        b64url_encode(&key.sign(input.as_bytes()).to_bytes())
    )
}

// RFC 9901, CR-55 m.7
#[test]
fn sd_jwt_presentation_returns_disclosed_claims() {
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let keys = key_set(
        [(
            [1; 32],
            PublicKey::Ed25519(issuer.verifying_key().to_bytes()),
        )],
        &[Algorithm::Ed25519],
    );
    let disclosure = b64url_encode(br#"["s1","given_name","Ada \"A\"\n"]"#);
    let digest = b64url_encode(&<sha2::Sha256 as sha2::Digest>::digest(
        disclosure.as_bytes(),
    ));
    let header = format!(
        r#"{{"alg":"Ed25519","kid":"{}","typ":"access-pap+sd-jwt"}}"#,
        b64url_encode(&[1; 32])
    );
    let payload = format!(
        r#"{{"iss":"https://access.example","_sd_alg":"sha-256","_sd":["{digest}"],"n":-3,"ok":true,"z":null}}"#
    );
    let token = jwt(&issuer, &header, &payload);
    let run = |p: &str| {
        verify_sd_jwt(
            p,
            &keys,
            "access-pap+sd-jwt",
            "pep:shop",
            "n-1",
            1_000_000,
            60_000,
        )
    };
    assert_eq!(
        run(&format!("{token}~{disclosure}~")),
        Ok(r#"{"iss":"https://access.example","n":-3,"ok":true,"z":null,"given_name":"Ada \"A\"\n"}"#.to_string())
    );
    assert_eq!(
        run(&format!("{token}~")).map(|c| c.contains("given_name")),
        Ok(false)
    );
    let bad = run(&format!("{token}~{disclosure}~{disclosure}~")).unwrap_err();
    assert_eq!(
        (bad.kind(), bad.name()),
        (Kind::Duplicate, "duplicate disclosure".to_string())
    );
    let bad = run("x").unwrap_err();
    assert_eq!(
        (bad.kind(), bad.name()),
        (Kind::Format, "not an SD-JWT presentation".to_string())
    );
    assert_eq!(
        run(&format!("{token}.x~")).map_err(|e| e.name()),
        Err("jws: not a compact JWS".to_string())
    );
}

fn contract(variant: ProfileVariant) -> Vec<u8> {
    let d = |n: u8| Digest([n; 32]);
    ValidityContract {
        issuing_exercise: d(1),
        basis_ref: vec![9, 9],
        holder: d(2),
        audience: ["pep:shop".to_string()].into_iter().collect(),
        bounds: AuthoritySet {
            actions: ActionSet {
                exact: [ActionRef {
                    namespace: "pay".to_string(),
                    name: "refund".to_string(),
                    major: 1,
                    schema: d(3),
                }]
                .into_iter()
                .collect(),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: "shop".to_string(),
                prefix: vec![],
                kind: None,
                attrs: BTreeMap::new(),
            }),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        class: variant.class(),
        variant,
        params: BTreeMap::new(),
        horizon: 10_000,
        max_staleness_ms: (variant == ProfileVariant::BoundedStaleness).then_some(1_000),
        freshness_sources: BTreeSet::new(),
        revalidation: Revalidation::default(),
        offline_slice: BTreeSet::new(),
        local_requirements: BTreeSet::new(),
        verifier_profile_ref: d(4),
        clock_source: "ntp".to_string(),
        clock_skew_ms: 60_000,
        must_understand: ["geo".to_string()].into_iter().collect(),
    }
    .to_bytes()
    .unwrap()
}

// §9.12
#[test]
fn validity_is_checked_at_the_moment_of_use() {
    let geo = || vec!["geo".to_string()];
    let strict = contract(ProfileVariant::OnlineStrict);
    let stale = contract(ProfileVariant::BoundedStaleness);
    let name = |r: Result<(), Error>| r.map_err(|e| e.name());
    assert_eq!(
        check_validity(&strict, 5_000, "pep:shop", geo(), None, true, 60_000),
        Ok(())
    );
    assert_eq!(
        name(check_validity(
            &strict,
            5_000,
            "pep:shop",
            vec![],
            None,
            true,
            60_000
        )),
        Err("must-understand".to_string())
    );
    assert_eq!(
        name(check_validity(
            &strict,
            5_000,
            "pep:bank",
            geo(),
            None,
            true,
            60_000
        )),
        Err("audience".to_string())
    );
    assert_eq!(
        name(check_validity(
            &strict,
            70_001,
            "pep:shop",
            geo(),
            None,
            true,
            60_000
        )),
        Err("expired".to_string())
    );
    assert_eq!(
        name(check_validity(
            &strict,
            5_000,
            "pep:shop",
            geo(),
            None,
            false,
            60_000
        )),
        Err("online-required".to_string())
    );
    assert_eq!(
        check_validity(&stale, 5_000, "pep:shop", geo(), Some(4_500), false, 60_000),
        Ok(())
    );
    assert_eq!(
        name(check_validity(
            &stale,
            5_000,
            "pep:shop",
            geo(),
            Some(3_000),
            false,
            60_000
        )),
        Err("stale".to_string())
    );
    assert_eq!(
        name(check_validity(
            &stale,
            5_000,
            "pep:shop",
            geo(),
            None,
            false,
            60_000
        )),
        Err("stale".to_string())
    );
    assert_eq!(
        check_validity(&[0xa0], 0, "pep:shop", geo(), None, true, 60_000),
        Err(Error::Input)
    );
}

// OP-116 m.1
#[test]
fn api_version_and_names() {
    assert_eq!(api_version(), "0.0");
    assert_eq!(Error::Input.name(), "input");
    assert_eq!(
        Error::Validity(ValidityError::Overflow).kind(),
        Kind::Overflow
    );
    assert_eq!(
        Error::KeyScope(KeyScopeError::Payload(crate::codec::ModelError::Shape)).name(),
        "payload"
    );
    assert_eq!(
        Error::KeyScope(KeyScopeError::Signature(CoseError::Crit)).kind(),
        Kind::Crit
    );
    assert_eq!(
        Error::Jws(JwsError::Signature(SignatureError::HighS)).name(),
        "signature: high-S signature"
    );
}
