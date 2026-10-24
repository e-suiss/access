use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits};

use super::*;
use crate::verify::PureBackend;
use crate::verify::cose::to_be_signed;

const HOUR: u64 = 60 * 60 * 1000;

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn ed(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn ed_pub(seed: u8) -> PublicKey {
    PublicKey::Ed25519(ed(seed).verifying_key().to_bytes())
}

fn p_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_slice(&[9; 32]).unwrap()
}

fn p_pub() -> PublicKey {
    PublicKey::P256(
        p_key()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
    )
}

enum Signer {
    Ed(u8),
    P256,
}

fn sign1(signer: &Signer, kid: [u8; 32], content_type: &str, payload: &[u8]) -> Vec<u8> {
    let alg = match signer {
        Signer::Ed(_) => Algorithm::Ed25519,
        Signer::P256 => Algorithm::Esp256,
    };
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::int(alg.cose())),
            (Value::Unsigned(3), Value::text(content_type)),
            (Value::Unsigned(4), Value::Bytes(kid.to_vec())),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let tbs = to_be_signed(&prot, payload);
    let sig = match signer {
        Signer::Ed(seed) => {
            use ed25519_dalek::Signer as _;
            ed(*seed).sign(&tbs).to_bytes().to_vec()
        }
        Signer::P256 => {
            use p256::ecdsa::signature::Signer as _;
            let s: p256::ecdsa::Signature = p_key().sign(&tbs);
            s.normalize_s().to_bytes().to_vec()
        }
    };
    let body = Value::Array(vec![
        Value::Bytes(prot),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

fn binding(seed: u8, scope: BindingScope) -> BindingKey {
    let key = ed_pub(seed);
    BindingKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        scope,
        superseded: None,
    }
}

fn op_key(key: PublicKey, alg: Algorithm) -> OperationalKey {
    OperationalKey {
        kid: thumbprint(&key),
        alg,
        key,
        valid_from: 10 * HOUR,
        valid_until: 11 * HOUR,
        usage: BTreeSet::from([KeyUsage::Pap, KeyUsage::Receipt]),
    }
}

struct Case {
    metadata: DomainMetadata,
    excerpt: KeyExcerpt,
    signer: Signer,
    signer_kid: [u8; 32],
    content_type: &'static str,
    domain: Digest,
    usage: KeyUsage,
    iat: TrustedTime,
}

impl Case {
    fn new() -> Self {
        let b = binding(1, BindingScope::Domain);
        let kid = b.kid;
        Self {
            metadata: DomainMetadata {
                domain: d(1),
                genesis: d(9),
                issued_at: 10 * HOUR,
                binding: BTreeMap::from([(kid, b)]),
                algorithms: BTreeSet::from([Algorithm::Ed25519, Algorithm::Esp256]),
                operational_window_max_ms: HOUR,
                operational_keys: Vec::new(),
                min_versions: SpecVersions {
                    core: 1,
                    meta_schema: 1,
                    ..SpecVersions::default()
                },
                caps: Some(VerifierCaps {
                    horizon_max_ms: Some(72 * HOUR),
                    slice_max: BTreeMap::new(),
                }),
                hybrid: None,
                discovery: Some(vec![1, 2, 3]),
            },
            excerpt: KeyExcerpt {
                domain: d(1),
                key: op_key(ed_pub(7), Algorithm::Ed25519),
            },
            signer: Signer::Ed(1),
            signer_kid: kid,
            content_type: EXCERPT_CONTENT_TYPE,
            domain: d(1),
            usage: KeyUsage::Pap,
            iat: 10 * HOUR + 1,
        }
    }

    fn excerpt_bytes(&self) -> Vec<u8> {
        sign1(
            &self.signer,
            self.signer_kid,
            self.content_type,
            &self.excerpt.to_bytes().unwrap(),
        )
    }

    fn run(&self) -> Result<OperationalKey, KeyScopeError> {
        operational_key(
            &PureBackend,
            &self.metadata,
            &self.domain,
            &self.excerpt_bytes(),
            self.usage,
            self.iat,
        )
    }

    fn binding_mut(&mut self) -> &mut BindingKey {
        self.metadata.binding.values_mut().next().unwrap()
    }
}

fn scenarios() -> Vec<(&'static str, Case)> {
    let mut out = Vec::new();
    out.push(("valid-ed25519", Case::new()));
    let mut c = Case::new();
    c.excerpt.key = op_key(p_pub(), Algorithm::Esp256);
    out.push(("valid-esp256", c));
    let mut c = Case::new();
    c.iat = 10 * HOUR;
    out.push(("valid-window-start", c));
    let mut c = Case::new();
    c.iat = 11 * HOUR;
    out.push(("valid-window-end", c));
    let mut c = Case::new();
    c.binding_mut().scope = BindingScope::Provider(BTreeSet::from([d(1), d(3)]));
    c.domain = d(3);
    c.excerpt.domain = d(3);
    out.push(("valid-provider-scope", c));
    let mut c = Case::new();
    c.domain = d(2);
    c.excerpt.domain = d(2);
    out.push(("storm-0558-other-domain", c));
    let mut c = Case::new();
    c.binding_mut().scope = BindingScope::Provider(BTreeSet::from([d(1), d(3)]));
    c.domain = d(2);
    c.excerpt.domain = d(2);
    out.push(("provider-scope-out", c));
    let mut c = Case::new();
    c.excerpt.domain = d(2);
    out.push(("excerpt-domain-mismatch", c));
    let mut c = Case::new();
    c.usage = KeyUsage::StatusList;
    out.push(("usage-not-declared", c));
    let mut c = Case::new();
    c.iat = 10 * HOUR - 1;
    out.push(("iat-before-window", c));
    let mut c = Case::new();
    c.iat = 11 * HOUR + 1;
    out.push(("iat-after-window", c));
    let mut c = Case::new();
    c.excerpt.key.valid_until = 11 * HOUR + 1;
    out.push(("window-too-long", c));
    let mut c = Case::new();
    c.metadata.operational_window_max_ms = MAX_WINDOW_MS;
    c.excerpt.key.valid_until = 10 * HOUR + MAX_WINDOW_MS + 1;
    c.iat = 20 * HOUR;
    out.push(("window-over-24h", c));
    let mut c = Case::new();
    c.excerpt.key.valid_from = 12 * HOUR;
    out.push(("window-inverted", c));
    let mut c = Case::new();
    c.excerpt.key.kid = [0; 32];
    out.push(("kid-not-thumbprint", c));
    let mut c = Case::new();
    c.metadata.algorithms.remove(&Algorithm::Esp256);
    c.excerpt.key = op_key(p_pub(), Algorithm::Esp256);
    out.push(("alg-not-allowed", c));
    let mut c = Case::new();
    c.excerpt.key.alg = Algorithm::Esp256;
    out.push(("alg-key-type-mismatch", c));
    let mut c = Case::new();
    c.excerpt.key = op_key(ed_pub(7), Algorithm::Es256);
    c.excerpt.key.key = ed_pub(7);
    out.push(("alg-es256-on-ed25519-key", c));
    let mut c = Case::new();
    c.binding_mut().superseded = Some(Superseded {
        at: d(5),
        cited: d(4),
    });
    out.push(("binding-superseded", c));
    let mut c = Case::new();
    c.signer = Signer::Ed(2);
    c.signer_kid = thumbprint(&ed_pub(2));
    out.push(("binding-unknown", c));
    let mut c = Case::new();
    c.signer = Signer::Ed(2);
    out.push(("binding-wrong-signer", c));
    let mut c = Case::new();
    c.binding_mut().alg = Algorithm::Esp256;
    out.push(("binding-alg-mismatch", c));
    let mut c = Case::new();
    c.content_type = METADATA_CONTENT_TYPE;
    out.push(("excerpt-content-type", c));
    out
}

fn error_name(e: KeyScopeError) -> String {
    match e {
        KeyScopeError::Signature(CoseError::UnknownKid) => "unknown-binding".into(),
        KeyScopeError::Signature(CoseError::ContentType) => "content-type".into(),
        KeyScopeError::Signature(CoseError::Signature(_)) => "signature".into(),
        KeyScopeError::Signature(other) => alloc::format!("cose:{other}"),
        KeyScopeError::Payload(other) => alloc::format!("payload:{other}"),
        KeyScopeError::Superseded => "superseded".into(),
        KeyScopeError::OutOfScope => "outside-binding-scope".into(),
        KeyScopeError::DomainMismatch => "domain-mismatch".into(),
        KeyScopeError::Thumbprint => "thumbprint".into(),
        KeyScopeError::Algorithm => "algorithm".into(),
        KeyScopeError::Usage => "usage".into(),
        KeyScopeError::Window => "window".into(),
    }
}

// CR-58 m.5, TI-RT6, HL-8
#[test]
fn each_step_rejects_its_case() {
    let expect = [
        ("valid-ed25519", None),
        ("valid-esp256", None),
        ("valid-window-start", None),
        ("valid-window-end", None),
        ("valid-provider-scope", None),
        ("storm-0558-other-domain", Some(KeyScopeError::OutOfScope)),
        ("provider-scope-out", Some(KeyScopeError::OutOfScope)),
        (
            "excerpt-domain-mismatch",
            Some(KeyScopeError::DomainMismatch),
        ),
        ("usage-not-declared", Some(KeyScopeError::Usage)),
        ("iat-before-window", Some(KeyScopeError::Window)),
        ("iat-after-window", Some(KeyScopeError::Window)),
        ("window-too-long", Some(KeyScopeError::Window)),
        ("window-over-24h", Some(KeyScopeError::Window)),
        ("window-inverted", Some(KeyScopeError::Window)),
        ("kid-not-thumbprint", Some(KeyScopeError::Thumbprint)),
        ("alg-not-allowed", Some(KeyScopeError::Algorithm)),
        ("alg-key-type-mismatch", Some(KeyScopeError::Algorithm)),
        ("alg-es256-on-ed25519-key", Some(KeyScopeError::Algorithm)),
        ("binding-superseded", Some(KeyScopeError::Superseded)),
        (
            "binding-unknown",
            Some(KeyScopeError::Signature(CoseError::UnknownKid)),
        ),
        (
            "binding-wrong-signer",
            Some(KeyScopeError::Signature(CoseError::Signature(
                crate::verify::SignatureError::Invalid,
            ))),
        ),
        ("binding-alg-mismatch", Some(KeyScopeError::Algorithm)),
        (
            "excerpt-content-type",
            Some(KeyScopeError::Signature(CoseError::ContentType)),
        ),
    ];
    let all = scenarios();
    assert_eq!(all.len(), expect.len());
    for ((id, case), (want_id, want)) in all.iter().zip(expect) {
        assert_eq!(*id, want_id);
        match (case.run(), want) {
            (Ok(key), None) => assert_eq!(key, case.excerpt.key, "{id}"),
            (got, want) => assert_eq!(got.err(), want, "{id}"),
        }
    }
}

// CR-58 m.5: the resolved key verifies the artefact, and only for its own kid
#[test]
fn resolved_key_verifies_the_artefact() {
    let case = Case::new();
    let key = case.run().unwrap();
    let pap = sign1(
        &Signer::Ed(7),
        key.kid,
        "application/access-pap+cbor",
        b"pap",
    );
    let v = verify_sign1(
        &PureBackend,
        &pap,
        &key.key_set(),
        "application/access-pap+cbor",
    )
    .unwrap();
    assert_eq!(v.payload, b"pap");
    let mut p = Case::new();
    p.excerpt.key = op_key(p_pub(), Algorithm::Esp256);
    let pk = p.run().unwrap();
    let pap = sign1(&Signer::P256, pk.kid, "application/access-pap+cbor", b"pap");
    assert!(
        verify_sign1(
            &PureBackend,
            &pap,
            &pk.key_set(),
            "application/access-pap+cbor"
        )
        .is_ok()
    );
    let forged = sign1(
        &Signer::Ed(1),
        key.kid,
        "application/access-pap+cbor",
        b"pap",
    );
    assert!(
        verify_sign1(
            &PureBackend,
            &forged,
            &key.key_set(),
            "application/access-pap+cbor"
        )
        .is_err()
    );
}

// CR-24: RFC 7638 §3.1 example key, as Ed25519 from RFC 8037 §A.3
#[test]
fn thumbprint_matches_rfc_8037() {
    let x = crate::json::b64url_decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo").unwrap();
    let key = PublicKey::Ed25519(x.try_into().unwrap());
    assert_eq!(
        crate::json::b64url_encode(&thumbprint(&key)),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
}

// CR-58 m.3, SAI-40
#[test]
fn metadata_round_trips_and_is_signed_by_a_trusted_binding() {
    let case = Case::new();
    let payload = case.metadata.to_bytes().unwrap();
    assert_eq!(DomainMetadata::from_bytes(&payload).unwrap(), case.metadata);
    let kid = case.signer_kid;
    let signed = sign1(&Signer::Ed(1), kid, METADATA_CONTENT_TYPE, &payload);
    let mut trusted = KeySet::default();
    trusted.insert(kid, ed_pub(1)).unwrap();
    trusted.allowed.insert(Algorithm::Ed25519);
    assert_eq!(
        verify_metadata(&PureBackend, &signed, &trusted).unwrap(),
        case.metadata
    );

    let other = sign1(&Signer::Ed(2), kid, METADATA_CONTENT_TYPE, &payload);
    assert!(verify_metadata(&PureBackend, &other, &trusted).is_err());

    let mut stale = case.metadata.clone();
    stale.binding.values_mut().next().unwrap().superseded = Some(Superseded {
        at: d(5),
        cited: d(4),
    });
    let signed = sign1(
        &Signer::Ed(1),
        kid,
        METADATA_CONTENT_TYPE,
        &stale.to_bytes().unwrap(),
    );
    assert_eq!(
        verify_metadata(&PureBackend, &signed, &trusted),
        Err(KeyScopeError::Superseded)
    );
}

// CR-58 m.1, m.3, T20, OP-108 m.4
#[test]
fn metadata_decoding_is_strict() {
    let case = Case::new();
    let mut long = case.metadata.clone();
    long.operational_window_max_ms = MAX_WINDOW_MS + 1;
    assert_eq!(
        DomainMetadata::from_bytes(&long.to_bytes().unwrap()),
        Err(ModelError::Range)
    );

    let mut bad_kid = case.metadata.clone();
    let mut b = bad_kid.binding.pop_first().unwrap().1;
    b.kid = [0; 32];
    bad_kid.binding.insert(b.kid, b);
    assert_eq!(
        DomainMetadata::from_bytes(&bad_kid.to_bytes().unwrap()),
        Err(ModelError::Range)
    );

    let Value::Map(mut entries) = case.metadata.to_value() else {
        panic!("metadata is a map")
    };
    entries.push((Value::text("zzz_endpoint"), Value::text("https://x")));
    let bytes = dcbor::encode(&Value::Map(entries), Limits::CEILING).unwrap();
    assert_eq!(DomainMetadata::from_bytes(&bytes), Err(ModelError::Unknown));

    let mut empty_usage = case.excerpt.clone();
    empty_usage.key.usage.clear();
    assert_eq!(
        KeyExcerpt::from_bytes(&empty_usage.to_bytes().unwrap()),
        Err(ModelError::Range)
    );
}

// CR-58, OP-106 m.24
#[test]
fn key_scope_vectors_match() {
    extern crate std;
    use core::fmt::Write as _;
    let hex = |b: &[u8]| {
        b.iter().fold(String::new(), |mut h, x| {
            let _ = write!(h, "{x:02x}");
            h
        })
    };
    let usage = |u: KeyUsage| match word_of(u, &USAGES) {
        Value::Text(t) => t,
        _ => String::new(),
    };
    let mut json = String::from(
        "{\n \"rule\": \"CR-58\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"key_scope.operational_key\",\n \"cases\": [\n",
    );
    let all = scenarios();
    for (i, (id, c)) in all.iter().enumerate() {
        let expect = match c.run() {
            Ok(k) => alloc::format!("\"key\": \"{}\"", hex(&k.to_bytes().unwrap())),
            Err(e) => alloc::format!("\"error\": \"{}\"", error_name(e)),
        };
        let sep = if i + 1 == all.len() { "" } else { "," };
        let _ = writeln!(
            json,
            "  {{\"id\": \"{id}\", \"metadata\": \"{}\", \"domain\": \"{}\", \"excerpt\": \"{}\", \"usage\": \"{}\", \"iat\": {}, {expect}}}{sep}",
            hex(&c.metadata.to_bytes().unwrap()),
            hex(&dcbor::encode(&c.domain.to_value(), Limits::CEILING).unwrap()),
            hex(&c.excerpt_bytes()),
            usage(c.usage),
            c.iat,
        );
    }
    json.push_str(" ]\n}\n");
    #[cfg(not(target_os = "wasi"))]
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../conformance/vectors/core/1/key-scope.json"
            ),
            &json,
        )
        .unwrap();
        return;
    }
    assert_eq!(
        include_str!("../../../../../conformance/vectors/core/1/key-scope.json"),
        json
    );
}
