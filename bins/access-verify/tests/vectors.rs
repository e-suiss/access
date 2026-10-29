//! Runs the Reference Verifier binary over the core track 1 conformance vectors.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use access_kernel::codec::Canonical;
use access_kernel::digest::{self, Digest};
use access_kernel::json::b64url_decode;
use access_kernel::verify::cose::{Algorithm, KeySet, PublicKey, to_be_signed};
use access_kernel::verify::key_scope::{
    EXCERPT_CONTENT_TYPE, METADATA_CONTENT_TYPE, OperationalKey, thumbprint,
};
use ed25519_dalek::Signer as _;
use serde_json::Value as J;
use suiss_crypto::dcbor::{self, Limits, Value};

fn vectors(name: &str) -> J {
    let path = format!(
        "{}/../../conformance/vectors/core/1/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cases(v: &J) -> &Vec<J> {
    v["cases"].as_array().unwrap()
}

fn s<'a>(c: &'a J, k: &str) -> &'a str {
    c[k].as_str().unwrap()
}

fn n(c: &J, k: &str) -> String {
    c[k].as_u64().unwrap().to_string()
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    })
}

struct Dir(PathBuf);

impl Dir {
    fn new(test: &str) -> Self {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("access-verify")
            .join(test);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    }
}

struct Run {
    code: i32,
    out: String,
}

impl Run {
    fn first(&self) -> &str {
        self.out.lines().next().unwrap_or("")
    }

    fn output(&self, name: &str) -> Option<&str> {
        self.out
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(": "))
    }

    fn rejection(&self) -> Option<&str> {
        self.first().strip_prefix("reject: ")
    }

    fn accepted(&self) -> bool {
        let ok = self.first() == "accept";
        assert_eq!(self.code, i32::from(!ok), "{}", self.out);
        ok
    }
}

fn verify(args: &[&str]) -> Run {
    let out = Command::new(env!("CARGO_BIN_EXE_access-verify"))
        .args(args)
        .env_clear()
        .output()
        .unwrap();
    Run {
        code: out.status.code().unwrap(),
        out: String::from_utf8(out.stdout).unwrap(),
    }
}

fn algorithms(allowed: &J) -> Vec<Algorithm> {
    allowed
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let id = a.as_i64().unwrap();
            [Algorithm::Ed25519, Algorithm::Esp256, Algorithm::Es256]
                .into_iter()
                .find(|alg| alg.cose() == id)
                .unwrap()
        })
        .collect()
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

fn jose_keys(v: &J, allowed: &J) -> Vec<u8> {
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
    key_set(keys, &algorithms(allowed))
}

fn ed(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn ed_pub(seed: u8) -> PublicKey {
    PublicKey::Ed25519(ed(seed).verifying_key().to_bytes())
}

fn sign1(seed: u8, content_type: &str, payload: &[u8]) -> Vec<u8> {
    let kid = thumbprint(&ed_pub(seed));
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::int(Algorithm::Ed25519.cose())),
            (Value::Unsigned(3), Value::text(content_type)),
            (Value::Unsigned(4), Value::Bytes(kid.to_vec())),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let sig = ed(seed).sign(&to_be_signed(&prot, payload));
    let body = Value::Array(vec![
        Value::Bytes(prot),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig.to_bytes().to_vec()),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

fn domain_hex(c: &J) -> String {
    hex(&Digest::from_bytes(&unhex(s(c, "domain"))).unwrap().0)
}

// L0-SIG-10…L0-SIG-21, CR-55
#[test]
fn cose_vectors() {
    let v = vectors("cose");
    let dir = Dir::new("cose");
    let keys = v["keys"].as_object().unwrap().iter().map(|(kid, key)| {
        (
            <[u8; 32]>::try_from(unhex(kid).as_slice()).unwrap(),
            PublicKey::from_bytes(&unhex(key.as_str().unwrap())).unwrap(),
        )
    });
    let keys = dir.file("keys.cbor", &key_set(keys, &algorithms(&v["allowed"])));
    for c in cases(&v) {
        let sign1 = dir.file("sign1.cbor", &unhex(s(c, "sign1")));
        let r = verify(&[
            "cose",
            "--sign1",
            &sign1,
            "--content-type",
            s(&v, "content_type"),
            "--keys",
            &keys,
        ]);
        if let Some(e) = c.get("error") {
            assert_eq!(r.rejection(), e.as_str(), "{}", c["id"]);
        } else {
            assert!(r.accepted(), "{}", c["id"]);
            assert_eq!(r.output("kid"), Some(s(c, "kid")), "{}", c["id"]);
            assert_eq!(r.output("payload"), Some(s(c, "payload")), "{}", c["id"]);
        }
    }
    assert_eq!(cases(&v).len(), 17);
}

fn key_args(dir: &Dir, c: &J, domain: &str) -> Vec<String> {
    vec![
        "--metadata".into(),
        dir.file("metadata.cbor", &unhex(s(c, "metadata"))),
        "--domain".into(),
        domain.into(),
        "--excerpt".into(),
        dir.file("excerpt.cbor", &unhex(s(c, "excerpt"))),
        "--usage".into(),
        s(c, "usage").into(),
        "--iat".into(),
        n(c, "iat"),
    ]
}

fn verify_owned(command: &str, args: &[String]) -> Run {
    let all: Vec<&str> = std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .collect();
    verify(&all)
}

// L0-SIG-60…L0-SIG-72, CR-58 m.5
#[test]
fn key_scope_vectors() {
    let v = vectors("key-scope");
    let dir = Dir::new("key-scope");
    for c in cases(&v) {
        let domain = domain_hex(c);
        let r = verify_owned("key", &key_args(&dir, c, &domain));
        if let Some(e) = c.get("error") {
            assert_eq!(r.rejection(), e.as_str(), "{}", c["id"]);
        } else {
            assert!(r.accepted(), "{}", c["id"]);
            assert_eq!(r.output("key"), Some(s(c, "key")), "{}", c["id"]);
        }
    }
    assert_eq!(cases(&v).len(), 29);
}

// CR-58 m.3, m.5, TI-17: signed metadata, then the excerpt, then the artefact
#[test]
fn artefact_chain_from_trusted_binding_keys() {
    let v = vectors("key-scope");
    let dir = Dir::new("chain");
    let binding = ed_pub(1);
    let trusted = dir.file(
        "trusted.cbor",
        &key_set([(thumbprint(&binding), binding)], &[Algorithm::Ed25519]),
    );
    let receipt = "application/access-receipt+cbor";
    let artefact = dir.file("artefact.cbor", &sign1(7, receipt, b"receipt"));
    let forged = dir.file("forged.cbor", &sign1(8, receipt, b"receipt"));
    for c in cases(&v) {
        let metadata = unhex(s(c, "metadata"));
        let signed = dir.file("signed.cbor", &sign1(1, METADATA_CONTENT_TYPE, &metadata));
        let error = c.get("error").and_then(J::as_str);
        let r = verify(&["metadata", "--signed", &signed, "--trusted", &trusted]);
        if r.accepted() {
            assert_eq!(r.output("metadata"), Some(s(c, "metadata")));
        } else {
            assert_eq!(r.rejection(), error, "{}", c["id"]);
        }

        let domain = domain_hex(c);
        let mut args = key_args(&dir, c, &domain);
        args[1] = signed;
        args.extend([
            "--trusted".into(),
            trusted.clone(),
            "--content-type".into(),
            receipt.into(),
        ]);
        let with = |sign1: &str| {
            let mut a = args.clone();
            a.extend(["--sign1".into(), sign1.into()]);
            verify_owned("cose", &a)
        };
        let r = with(&artefact);
        match (error, s(c, "id")) {
            (Some(e), _) => assert_eq!(r.rejection(), Some(e), "{}", c["id"]),
            (None, id)
                if OperationalKey::from_bytes(&unhex(s(c, "key"))).unwrap().key != ed_pub(7) =>
            {
                assert_eq!(r.rejection(), Some("algorithm"), "{id}");
            }
            (None, id) => {
                assert!(r.accepted(), "{id}");
                assert_eq!(r.output("payload"), Some(hex(b"receipt").as_str()));
                assert_eq!(r.output("kid"), Some(hex(&thumbprint(&ed_pub(7))).as_str()));
                assert_eq!(with(&forged).rejection(), Some("unknown-kid"));
            }
        }
    }
    let c = &cases(&v)[0];
    let metadata = unhex(s(c, "metadata"));
    let other = dir.file("other.cbor", &sign1(2, METADATA_CONTENT_TYPE, &metadata));
    let r = verify(&["metadata", "--signed", &other, "--trusted", &trusted]);
    assert_eq!(r.rejection(), Some("unknown-binding"));
    let mut tampered = sign1(1, METADATA_CONTENT_TYPE, &metadata);
    *tampered.last_mut().unwrap() ^= 1;
    let tampered = dir.file("tampered.cbor", &tampered);
    let r = verify(&["metadata", "--signed", &tampered, "--trusted", &trusted]);
    assert_eq!(r.rejection(), Some("signature"));
    let excerpt = dir.file("not-excerpt.cbor", &sign1(1, EXCERPT_CONTENT_TYPE, b"x"));
    let domain = domain_hex(c);
    let mut args = key_args(&dir, c, &domain);
    args[5] = excerpt;
    assert_eq!(verify_owned("key", &args).rejection(), Some("payload"));
}

// L0-SIG-30…L0-SIG-42, CR-56; L0-SIG-41…L0-SIG-41b, OP-122 m.7
#[test]
fn jws_vectors() {
    let dir = Dir::new("jws");
    let attack = vectors("jose-attack-classes");
    let claims = vectors("jwt-claims");
    let mut checked = 0;
    for v in [&attack, &claims] {
        let shared = jose_keys(v, &v["allowed"]);
        for c in cases(v) {
            let keys = c
                .get("allowed")
                .map_or_else(|| shared.clone(), |a| jose_keys(v, a));
            let ctx = c
                .get("claims")
                .or_else(|| v.get("claims"))
                .cloned()
                .unwrap_or_else(|| {
                    serde_json::json!({
                        "issuer": "https://access.example",
                        "audience": "pep:shop",
                        "now": 1_500_000,
                        "skew_ms": 60_000,
                    })
                });
            let r = verify(&[
                "jws",
                "--token",
                &dir.file("token.txt", s(c, "token").as_bytes()),
                "--keys",
                &dir.file("keys.cbor", &keys),
                "--typ",
                s(v, "typ"),
                "--issuer",
                s(&ctx, "issuer"),
                "--audience",
                s(&ctx, "audience"),
                "--now",
                &n(&ctx, "now"),
                "--skew-ms",
                &n(&ctx, "skew_ms"),
            ]);
            assert_eq!(r.first(), s(c, "expect"), "{}", c["id"]);
            if r.accepted() {
                assert!(r.output("payload").is_some_and(|p| p.starts_with('{')));
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 38 + 24);
}

// L0-SIG-50…L0-SIG-53, RFC 9901
#[test]
fn sd_jwt_vectors() {
    let v = vectors("sd-jwt");
    let dir = Dir::new("sd-jwt");
    let keys = dir.file("keys.cbor", &jose_keys(&v, &v["allowed"]));
    let ctx = &v["context"];
    for c in cases(&v) {
        let r = verify(&[
            "sd-jwt",
            "--presentation",
            &dir.file("presentation.txt", s(c, "presentation").as_bytes()),
            "--keys",
            &keys,
            "--typ",
            s(ctx, "typ"),
            "--audience",
            s(ctx, "audience"),
            "--nonce",
            s(ctx, "nonce"),
            "--now",
            &n(ctx, "now"),
            "--skew-ms",
            &n(ctx, "skew_ms"),
        ]);
        match c.get("claims") {
            Some(want) => {
                assert!(r.accepted(), "{}", c["id"]);
                let got: J = serde_json::from_str(r.output("claims").unwrap()).unwrap();
                assert_eq!(&got, want, "{}", c["id"]);
            }
            None => assert_eq!(r.rejection(), Some(s(c, "error")), "{}", c["id"]),
        }
    }
    assert_eq!(cases(&v).len(), 27);
}

// L0-VAL-10…L0-VAL-16b, OP-118 m.4
#[test]
fn validity_vectors() {
    let v = vectors("validity");
    let dir = Dir::new("validity");
    for c in cases(&v) {
        let contract = unhex(s(c.get("contract").map_or(&v, |_| c), "contract"));
        let online = c.get("online").unwrap_or(&v["online"]).as_bool().unwrap();
        let mut args = vec![
            "--contract".to_owned(),
            dir.file("contract.cbor", &contract),
            "--now".into(),
            n(c, "now"),
            "--audience".into(),
            s(&v, "audience").into(),
            "--online".into(),
            online.to_string(),
            "--skew-ms".into(),
            n(&v, "skew_ms"),
            "--iat".into(),
            n(c, "iat"),
            "--horizon-cap-ms".into(),
            n(c, "horizon_cap_ms"),
        ];
        if c.get("last_refresh").is_some() {
            args.extend(["--last-refresh".into(), n(c, "last_refresh")]);
        }
        let r = verify_owned("validity", &args);
        match c.get("error") {
            Some(e) => assert_eq!(r.rejection(), e.as_str(), "{}", c["id"]),
            None => assert!(r.accepted(), "{}", c["id"]),
        }
    }
    assert_eq!(cases(&v).len(), 25);
}

fn path(c: &J) -> String {
    c["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(",")
}

// L0-ENC-30…L0-ENC-33, RFC 9162
#[test]
fn merkle_vectors() {
    let v = vectors("merkle");
    let dir = Dir::new("merkle");
    let leaves: Vec<&str> = v["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect();
    let root = |size: u64| -> String {
        let r = v["roots"].as_array().unwrap().iter();
        s(
            r.clone()
                .find(|r| r["size"].as_u64() == Some(size))
                .unwrap(),
            "root",
        )
        .to_owned()
    };
    let inclusion = v["inclusion"].as_array().unwrap();
    for c in inclusion {
        let (index, size) = (c["index"].as_u64().unwrap(), c["size"].as_u64().unwrap());
        let data = unhex(leaves[usize::try_from(index).unwrap()]);
        let leaf = dir.file("leaf.bin", &data);
        let (idx, sz, rt, p) = (index.to_string(), size.to_string(), root(size), path(c));
        let base = ["inclusion", "--size", &sz, "--root", &rt, "--path", &p];
        let with = |extra: &[&str]| verify(&[&base[..], extra].concat());
        assert!(with(&["--index", &idx, "--leaf", &leaf]).accepted());
        let lh = hex(&digest::leaf_hash(&data));
        assert!(with(&["--index", &idx, "--leaf-hash", &lh]).accepted());
        assert_eq!(
            with(&["--index", &sz, "--leaf", &leaf]).rejection(),
            Some("range")
        );
        let other = hex(&digest::leaf_hash(b"other"));
        assert_eq!(
            with(&["--index", &idx, "--leaf-hash", &other]).rejection(),
            Some("mismatch")
        );
    }
    let consistency = v["consistency"].as_array().unwrap();
    for c in consistency {
        let (a, b) = (c["first"].as_u64().unwrap(), c["second"].as_u64().unwrap());
        let (fa, fb, p) = (a.to_string(), b.to_string(), path(c));
        let run = |first_root: &str| {
            verify(&[
                "consistency",
                "--first",
                &fa,
                "--second",
                &fb,
                "--first-root",
                first_root,
                "--second-root",
                &root(b),
                "--path",
                &p,
            ])
        };
        assert!(run(&root(a)).accepted(), "{a} {b}");
        if a > 0 && a < b {
            assert!(!run(&root(b)).accepted(), "{a} {b}");
        }
    }
    assert_eq!((inclusion.len(), consistency.len()), (36, 36));
}

// L0-ENC-25…L0-ENC-29d, OP-106 m.10–m.15, §17.6.1
#[test]
fn record_vectors() {
    let v = vectors("record");
    let dir = Dir::new("record");
    let (size, root) = (n(&v["log"], "size"), s(&v["log"], "root"));
    let (mut envelopes, mut disclosures, mut rejections) = (0, 0, 0);
    for c in cases(&v) {
        let (option, bytes) = match (c.get("cbor"), c.get("data"), c.get("record_disclosure")) {
            (Some(b), None, None) | (None, Some(b), None) => ("--envelope", b),
            (None, None, Some(b)) => ("--disclosure", b),
            _ => panic!("{}", c["id"]),
        };
        let file = dir.file("record.cbor", &unhex(bytes.as_str().unwrap()));
        let r = verify(&["record", option, &file]);
        if let Some(e) = c.get("error") {
            assert_eq!(r.rejection(), e.as_str(), "{}", c["id"]);
            rejections += 1;
            continue;
        }
        assert!(r.accepted(), "{}", c["id"]);
        assert_eq!(
            r.output("leaf_hash"),
            Some(s(c, "leaf_hash")),
            "{}",
            c["id"]
        );
        if option == "--envelope" {
            assert_eq!(r.output("domain"), Some(domain_hex(c).as_str()));
            envelopes += 1;
        } else {
            let p = path(c);
            let proof = |root: &str| {
                verify(&[
                    "record", option, &file, "--size", &size, "--root", root, "--path", &p,
                ])
            };
            assert!(proof(root).accepted(), "{}", c["id"]);
            let other = hex(&digest::leaf_hash(b"other"));
            assert_eq!(proof(&other).rejection(), Some("inclusion: mismatch"));
            disclosures += 1;
        }
    }
    assert_eq!((envelopes, disclosures, rejections), (4, 3, 20));
}

#[test]
fn usage_errors_exit_with_two_and_print_nothing() {
    let dir = Dir::new("usage");
    let file = dir.file("x.cbor", &[0xa0]);
    for args in [
        &[][..],
        &["unknown"],
        &["record", "--envelope"],
        &["record", "--envelope", &file, "--envelope", &file],
        &["record", "--bogus", "x"],
        &["record", "--envelope", &file, "--size", "1"],
        &[
            "inclusion",
            "--index",
            "0",
            "--size",
            "1",
            "--root",
            "zz",
            "--path",
            "",
            "--leaf",
            &file,
        ],
        &["validity", "--contract", &file, "--online", "yes"],
        &["metadata", "--signed", "/nonexistent/x", "--trusted", &file],
    ] {
        let r = verify(args);
        assert_eq!((r.code, r.out.as_str()), (2, ""), "{args:?}");
    }
    let help = verify(&["--help"]);
    assert_eq!(help.code, 0);
    assert!(help.out.contains("consistency"));
}
