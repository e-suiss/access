//! The Reference Verifier's artefact subcommands over the conformance vectors: PAP uses,
//! receipts, offline reports, status lists and checkpoints (§18.7 B3, CMP-17, T34).

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test helpers")]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::status::{CWT_CONTENT_TYPE, ListToken};
use access_kernel::verify::cose::{Algorithm, PublicKey, to_be_signed};
use access_kernel::verify::key_scope::{
    BindingKey, BindingScope, DomainMetadata, EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage,
    OperationalKey, SpecVersions, thumbprint,
};
use ed25519_dalek::Signer as _;
use serde_json::Value as J;
use suiss_crypto::dcbor::{self, Limits, Value};

fn vectors(track: &str, name: &str) -> J {
    let path = format!(
        "{}/../../conformance/vectors/{track}/1/{name}.json",
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
            .join("access-verify-artefacts")
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

fn raw_digest(cbor_hex: &str) -> String {
    hex(&Digest::from_bytes(&unhex(cbor_hex)).unwrap().0)
}

fn expect(r: &Run, c: &J, output: &str) {
    if let Some(e) = c.get("error").and_then(J::as_str) {
        assert_eq!(r.rejection(), Some(e), "{}", c["id"]);
    } else {
        assert!(r.accepted(), "{}: {}", c["id"], r.out);
        assert_eq!(r.output(output), Some(s(c, output)), "{}", c["id"]);
    }
}

// L2-PAP-3, §9.10, CMP-17
#[test]
fn pap_vectors() {
    // G58
    let v = vectors("core", "pap");
    let dir = Dir::new("pap");
    let metadata = dir.file("metadata.cbor", &unhex(s(&v, "metadata")));
    let catalog = dir.file("catalog.cbor", &unhex(s(&v, "catalog")));
    for c in cases(&v) {
        let understood: Vec<&str> = c["understood"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect();
        let files = [
            ("pap", "sign1"),
            ("excerpt", "excerpt"),
            ("presentation", "presentation"),
            ("intent", "intent"),
            ("satisfied", "satisfied"),
            ("remaining", "remaining"),
        ]
        .map(|(opt, key)| (opt, dir.file(&format!("{opt}.cbor"), &unhex(s(c, key)))));
        let mut args: Vec<String> = vec![
            "pap".into(),
            "--metadata".into(),
            metadata.clone(),
            "--catalog".into(),
            catalog.clone(),
        ];
        for (opt, path) in files {
            args.extend([format!("--{opt}"), path]);
        }
        let domain = raw_digest(s(c, "domain"));
        let (now, skew, cap) = (n(c, "now"), n(c, "skew_ms"), n(c, "horizon_cap_ms"));
        for (opt, value) in [
            ("--domain", domain.as_str()),
            ("--audience", s(c, "audience")),
            ("--nonce", s(c, "nonce")),
            ("--now", now.as_str()),
            (
                "--fresh",
                if c["fresh"] == J::Bool(true) {
                    "true"
                } else {
                    "false"
                },
            ),
            (
                "--online",
                if c["online"] == J::Bool(true) {
                    "true"
                } else {
                    "false"
                },
            ),
            ("--skew-ms", skew.as_str()),
            ("--horizon-cap-ms", cap.as_str()),
            ("--understood", &understood.join(",")),
        ] {
            args.extend([opt.into(), value.into()]);
        }
        if let Some(t) = c["last_refresh"].as_u64() {
            args.extend(["--last-refresh".into(), t.to_string()]);
        }
        let all: Vec<&str> = args.iter().map(String::as_str).collect();
        expect(&verify(&all), c, "pap");
    }
}

// L2-RCP-3, §9.8
#[test]
fn receipt_vectors() {
    let v = vectors("core", "receipt");
    let dir = Dir::new("receipt");
    let metadata = dir.file("metadata.cbor", &unhex(s(&v, "metadata")));
    for c in cases(&v) {
        let receipt = dir.file("receipt.cbor", &unhex(s(c, "sign1")));
        let excerpt = dir.file("excerpt.cbor", &unhex(s(c, "excerpt")));
        let (domain, intent, now) = (
            raw_digest(s(c, "domain")),
            raw_digest(s(c, "intent")),
            n(c, "now"),
        );
        let r = verify(&[
            "receipt",
            "--metadata",
            &metadata,
            "--receipt",
            &receipt,
            "--excerpt",
            &excerpt,
            "--domain",
            &domain,
            "--audience",
            s(c, "audience"),
            "--intent",
            &intent,
            "--now",
            &now,
        ]);
        expect(&r, c, "receipt");
    }
}

// L2-RPT-1, L2-RPT-2, L2-RPT-3, U4
#[test]
fn report_vectors() {
    let v = vectors("core", "report");
    let dir = Dir::new("report");
    for c in cases(&v) {
        let report = dir.file("report.cbor", &unhex(s(c, "report")));
        let r = verify(&["report", "--report", &report]);
        if let Some(e) = c.get("error").and_then(J::as_str) {
            assert_eq!(r.rejection(), Some(e), "{}", c["id"]);
            continue;
        }
        assert!(r.accepted(), "{}", c["id"]);
        assert_eq!(r.output("head"), Some(s(c, "head")));
        assert_eq!(r.output("next_seq"), Some(n(c, "next_seq").as_str()));
        let drawn: Vec<String> = c["drawn"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| format!("{}:{}", p[0].as_str().unwrap(), p[1]))
            .collect();
        assert_eq!(r.output("drawn"), Some(drawn.join(",").as_str()));
    }
}

// L2-STL-3
#[test]
fn status_vectors() {
    let v = vectors("core", "status-list");
    let dir = Dir::new("status");
    for c in cases(&v) {
        let payload = dir.file("payload.cbor", &unhex(s(c, "token")));
        let list = dir.file("list.bin", &unhex(s(c, "list")));
        let decoded = dcbor::decode(&unhex(s(c, "reference")), Limits::CEILING).unwrap();
        let Some(inner) = decoded.get("status_list") else {
            continue;
        };
        let (Some(Value::Unsigned(idx)), Some(Value::Text(uri))) =
            (inner.get("idx"), inner.get("uri"))
        else {
            continue;
        };
        let idx = idx.to_string();
        let r = verify(&[
            "status",
            "--payload",
            &payload,
            "--list",
            &list,
            "--uri",
            uri,
            "--idx",
            &idx,
        ]);
        match c["invalid"].as_bool() {
            Some(i) => {
                assert!(r.accepted(), "{}", c["id"]);
                assert_eq!(r.output("invalid"), Some(i.to_string().as_str()));
            }
            None => assert_eq!(r.rejection(), Some(s(c, "error")), "{}", c["id"]),
        }
    }
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
    let sig = ed(seed).sign(&to_be_signed(&prot, payload).unwrap());
    let body = Value::Array(vec![
        Value::Bytes(prot),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig.to_bytes().to_vec()),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

const HOUR: u64 = 3_600_000;

fn list_key() -> OperationalKey {
    let key = ed_pub(2);
    OperationalKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        valid_from: 10 * HOUR,
        valid_until: 11 * HOUR,
        usage: [KeyUsage::StatusList].into_iter().collect(),
    }
}

fn metadata() -> DomainMetadata {
    let key = ed_pub(1);
    let b = BindingKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        scope: BindingScope::Domain,
        superseded: None,
    };
    DomainMetadata {
        domain: Digest([1; 32]),
        genesis: Digest([9; 32]),
        issued_at: 10 * HOUR,
        binding: [(b.kid, b)].into_iter().collect(),
        algorithms: [Algorithm::Ed25519].into_iter().collect(),
        operational_window_max_ms: HOUR,
        operational_keys: vec![list_key()],
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
        declared: access_kernel::verify::key_scope::Declarations::default(),
    }
}

// L2-STL-2, L2-STL-3, OP-150 m.6 (d), INV-24
#[test]
fn a_signed_status_list_is_verified_inflated_and_read() {
    let dir = Dir::new("status-signed");
    let uri = "https://access.example/status/1";
    let iat = 10 * HOUR + HOUR / 2;
    let token = ListToken {
        uri: uri.to_owned(),
        iat: iat / 1_000,
        exp: None,
        ttl: None,
        lst: miniz_oxide::deflate::compress_to_vec_zlib(&[0b0000_0100, 0], 6),
        aggregation_uri: None,
        as_of: 7,
    };
    let signed = dir.file(
        "list.cose",
        &sign1(2, CWT_CONTENT_TYPE, &token.to_bytes().unwrap()),
    );
    let excerpt = KeyExcerpt {
        domain: Digest([1; 32]),
        key: list_key(),
    };
    let excerpt = dir.file(
        "excerpt.cose",
        &sign1(1, EXCERPT_CONTENT_TYPE, &excerpt.to_bytes().unwrap()),
    );
    let md = dir.file("metadata.cbor", &metadata().to_bytes().unwrap());
    let run = |idx: &str, extra: &[&str]| {
        let mut args = vec![
            "status",
            "--metadata",
            &md,
            "--token",
            &signed,
            "--excerpt",
            &excerpt,
            "--uri",
            uri,
            "--idx",
            idx,
        ];
        args.extend_from_slice(extra);
        verify(&args)
    };
    let r = run("2", &[]);
    assert!(r.accepted());
    assert_eq!(r.output("invalid"), Some("true"));
    assert_eq!(r.output("as_of"), Some("7"));
    assert_eq!(run("3", &[]).output("invalid"), Some("false"));
    assert_eq!(run("16", &[]).rejection(), Some("status-index"));
    let now = (iat + 60_000).to_string();
    assert!(run("3", &["--now", &now, "--max-age-ms", "60000"]).accepted());
    assert_eq!(
        run("3", &["--now", &now, "--max-age-ms", "59999"]).rejection(),
        Some("status-stale")
    );
    let pap_key = dir.file(
        "pap.cose",
        &sign1(9, CWT_CONTENT_TYPE, &token.to_bytes().unwrap()),
    );
    let r = verify(&[
        "status",
        "--metadata",
        &md,
        "--token",
        &pap_key,
        "--excerpt",
        &excerpt,
        "--uri",
        uri,
        "--idx",
        "2",
    ]);
    assert_eq!(r.rejection(), Some("status-signature"));
}

// L2-CKP-1, L2-CKP-2, L2-CKP-3, L2-CKP-4, TI-RT5
#[test]
fn checkpoint_vectors() {
    let v = vectors("exchange", "checkpoint");
    let dir = Dir::new("checkpoint");
    let cosigners: Vec<&str> = v["cosigners"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    let cosigners = cosigners.join(",");
    for c in cases(&v) {
        let note = dir.file("note.txt", s(c, "note").as_bytes());
        let r = verify(&[
            "checkpoint",
            "--note",
            &note,
            "--origin",
            s(&v, "origin"),
            "--log",
            s(&v, "log"),
            "--cosigners",
            &cosigners,
        ]);
        if let Some(e) = c.get("error").and_then(J::as_str) {
            assert_eq!(r.rejection(), Some(e), "{}", c["id"]);
            continue;
        }
        assert!(r.accepted(), "{}", c["id"]);
        assert_eq!(r.output("size"), Some(n(c, "size").as_str()));
        assert_eq!(r.output("root"), Some(s(c, "root")));
        assert_eq!(r.output("extensions"), Some(n(c, "extensions").as_str()));
        let cosigned: Vec<String> = c["cosigned"]
            .as_array()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(r.output("cosigned"), Some(cosigned.join(",").as_str()));
    }
}
