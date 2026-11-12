//! CR-54: the aws-lc-rs and pure-Rust backends give the same result on every vector.

#[cfg(test)]
mod vectors {
    use access_crypto::AwsLcBackend;
    use access_kernel::verify::{self, PureBackend};

    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn load(path: &str) -> serde_json::Value {
        let full = format!(
            "{}/../../conformance/vectors/{path}",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(full).unwrap()).unwrap()
    }

    fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
        v[k].as_str().unwrap()
    }

    // CR-53, CR-54
    #[test]
    fn ed25519_backends_agree() {
        let mut n = 0;
        for c in load("core/1/ed25519-strict.json")["cases"]
            .as_array()
            .unwrap()
        {
            let (pk, m, sig) = (
                bytes(s(c, "public_key")),
                bytes(s(c, "message")),
                bytes(s(c, "signature")),
            );
            let a = verify::ed25519(&AwsLcBackend, &pk, &m, &sig);
            assert_eq!(
                a,
                verify::ed25519(&PureBackend, &pk, &m, &sig),
                "{}",
                s(c, "id")
            );
            assert_eq!(a.is_ok(), s(c, "result") == "accept", "{}", s(c, "id"));
            n += 1;
        }
        for g in load("external/wycheproof-ed25519_test.json")["testGroups"]
            .as_array()
            .unwrap()
        {
            let pk = bytes(s(&g["publicKey"], "pk"));
            for t in g["tests"].as_array().unwrap() {
                let (m, sig) = (bytes(s(t, "msg")), bytes(s(t, "sig")));
                let a = verify::ed25519(&AwsLcBackend, &pk, &m, &sig);
                assert_eq!(
                    a,
                    verify::ed25519(&PureBackend, &pk, &m, &sig),
                    "tcId {}",
                    t["tcId"]
                );
                assert_eq!(a.is_ok(), s(t, "result") == "valid", "tcId {}", t["tcId"]);
                n += 1;
            }
        }
        assert_eq!(n, 163);
    }

    // CR-54, CR-55 m.1
    #[test]
    fn p256_backends_agree() {
        let mut n = 0;
        for g in load("external/wycheproof-ecdsa_secp256r1_sha256_p1363_test.json")["testGroups"]
            .as_array()
            .unwrap()
        {
            let pk = bytes(s(&g["publicKey"], "uncompressed"));
            for t in g["tests"].as_array().unwrap() {
                let (m, sig) = (bytes(s(t, "msg")), bytes(s(t, "sig")));
                for native in [false, true] {
                    let a = verify::p256(&AwsLcBackend, &pk, &m, &sig, native);
                    assert_eq!(
                        a,
                        verify::p256(&PureBackend, &pk, &m, &sig, native),
                        "tcId {} native {native}",
                        t["tcId"]
                    );
                }
                n += 1;
            }
        }
        assert!(n > 200);
    }

    fn ml_dsa(alg: &str, pk: &[u8], m: &[u8], sig: &[u8]) -> bool {
        use aws_lc_rs::signature::{ML_DSA_44, ML_DSA_65, ML_DSA_87, UnparsedPublicKey};
        let (verifier, key_len, sig_len) = match alg {
            "ML-DSA-44" => (&ML_DSA_44, 1312, 2420),
            "ML-DSA-65" => (&ML_DSA_65, 1952, 3309),
            "ML-DSA-87" => (&ML_DSA_87, 2592, 4627),
            _ => return false,
        };
        pk.len() == key_len
            && sig.len() == sig_len
            && UnparsedPublicKey::new(verifier, pk).verify(m, sig).is_ok()
    }

    // CR-41, CR-51, RR-37, L0-SIG-8, OP-159 m.3 (n)
    #[test]
    fn ml_dsa_aws_lc_agrees_with_the_vectors() {
        let mut n = 0;
        for c in load("core/1/ml-dsa.json")["cases"].as_array().unwrap() {
            let got = ml_dsa(
                s(c, "algorithm"),
                &bytes(s(c, "public_key")),
                &bytes(s(c, "message")),
                &bytes(s(c, "signature")),
            );
            assert_eq!(got, s(c, "result") == "accept", "{}", s(c, "id"));
            n += 1;
        }
        assert_eq!(n, 56);
        for size in ["44", "65", "87"] {
            let w = load(&format!(
                "external/wycheproof-mldsa_{size}_verify_test.json"
            ));
            for g in w["testGroups"].as_array().unwrap() {
                let pk = bytes(s(g, "publicKey"));
                for t in g["tests"].as_array().unwrap() {
                    if t.get("ctx").is_some_and(|c| c.as_str() != Some("")) {
                        continue;
                    }
                    let got = ml_dsa(
                        s(&w, "algorithm"),
                        &pk,
                        &bytes(s(t, "msg")),
                        &bytes(s(t, "sig")),
                    );
                    assert_eq!(got, s(t, "result") == "valid", "{size} tcId {}", t["tcId"]);
                    n += 1;
                }
            }
        }
        let acvp = load("external/acvp-ml-dsa-sigver-fips204.json");
        for g in acvp["groups"].as_array().unwrap() {
            if s(g, "signatureInterface") != "external" {
                continue;
            }
            for t in g["tests"].as_array().unwrap() {
                if !s(t, "context").is_empty() {
                    continue;
                }
                let got = ml_dsa(
                    s(g, "parameterSet"),
                    &bytes(s(t, "pk")),
                    &bytes(s(t, "message")),
                    &bytes(s(t, "signature")),
                );
                assert_eq!(
                    got,
                    t["testPassed"].as_bool().unwrap(),
                    "tcId {}",
                    t["tcId"]
                );
                n += 1;
            }
        }
        assert!(n > 600, "{n}");
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next().checked_rem(u64::try_from(n).unwrap()).unwrap()).unwrap()
        }

        fn fill(&mut self, out: &mut [u8]) {
            for b in out {
                *b = self.next().to_le_bytes()[0];
            }
        }
    }

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write as _;
        b.iter().fold(String::new(), |mut h, x| {
            let _ = write!(h, "{x:02x}");
            h
        })
    }

    // RR-37, OP-159 m.3 (n)
    #[test]
    #[ignore = "writes vectors for the nightly DRT under ACCESS_RANDOM_VECTORS"]
    fn ml_dsa_random_inputs_for_f0() {
        use aws_lc_rs::signature::{
            KeyPair as _, ML_DSA_44_SIGNING, ML_DSA_65_SIGNING, ML_DSA_87_SIGNING, PqdsaKeyPair,
        };
        let Some(dir) = std::env::var_os("ACCESS_RANDOM_VECTORS") else {
            return;
        };
        let count: usize = std::env::var("ACCESS_RANDOM_ML_DSA_COUNT")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(100);
        let seed: u64 = std::env::var("ACCESS_RANDOM_SEED")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(0x005e_edac_ce55)
            | 1;
        let mut r = Rng(seed);
        let algs = [
            ("ML-DSA-44", &ML_DSA_44_SIGNING),
            ("ML-DSA-65", &ML_DSA_65_SIGNING),
            ("ML-DSA-87", &ML_DSA_87_SIGNING),
        ];
        let mut cases = Vec::new();
        for i in 0..count {
            let (name, alg) = algs[r.below(algs.len())];
            let mut key_seed = vec![0x5a; 32];
            r.fill(&mut key_seed);
            let pair = PqdsaKeyPair::from_seed(alg, &key_seed).unwrap();
            let mut message = vec![0x5a; r.below(64)];
            r.fill(&mut message);
            let mut sig = vec![0x5a; alg.signature_len()];
            let n = pair.sign(&message, &mut sig).unwrap();
            sig.truncate(n);
            let pk = pair.public_key().as_ref().to_vec();
            match r.below(5) {
                0 => {}
                1 => {
                    let at = r.below(sig.len());
                    sig[at] ^= 1 << r.below(8);
                }
                2 => {
                    let at = sig.len().saturating_sub(r.below(90)).saturating_sub(1);
                    sig[at] = r.next().to_le_bytes()[0];
                }
                3 => message.push(0),
                _ => sig.truncate(r.below(sig.len())),
            }
            let result = if ml_dsa(name, &pk, &message, &sig) {
                "accept"
            } else {
                "reject"
            };
            cases.push(format!(
                "  {{\"id\": \"r{i}\", \"algorithm\": \"{name}\", \"public_key\": \"{}\", \"message\": \"{}\", \"signature\": \"{}\", \"result\": \"{result}\"}}",
                hex(&pk),
                hex(&message),
                hex(&sig)
            ));
        }
        let json = format!(
            "{{\n \"rule\": \"CR-51\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"verify.ml_dsa\",\n \"seed\": {seed},\n \"cases\": [\n{}\n ]\n}}\n",
            cases.join(",\n")
        );
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ml-dsa-random.json"), json).unwrap();
    }
}

#[cfg(test)]
mod ml_dsa_layer {
    use access_kernel::json::b64url_encode;
    use access_kernel::verify::cose::{
        ALG, Algorithm, CONTENT_TYPE, CoseError, KID, KeySet, PublicKey, to_be_signed, verify_sign1,
    };
    use access_kernel::verify::jws::{JwsError, Origin, verify_compact};
    use access_kernel::verify::{Backend, PureBackend, SignatureError};
    use aws_lc_rs::signature::{
        KeyPair as _, ML_DSA_44, ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87, PqdsaKeyPair,
        UnparsedPublicKey,
    };
    use suiss_crypto::dcbor::{self, Limits, Value};

    const CT: &str = "application/access-receipt+cbor";

    struct PqBackend;

    impl Backend for PqBackend {
        fn ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            PureBackend.ed25519(public_key, message, signature)
        }

        fn p256(&self, public_key_sec1: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
            PureBackend.p256(public_key_sec1, message, signature)
        }

        fn ml_dsa(
            &self,
            alg: Algorithm,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> bool {
            let verifier = match alg {
                Algorithm::MlDsa44 => &ML_DSA_44,
                Algorithm::MlDsa65 => &ML_DSA_65,
                Algorithm::MlDsa87 => &ML_DSA_87,
                _ => return false,
            };
            UnparsedPublicKey::new(verifier, public_key)
                .verify(message, signature)
                .is_ok()
        }

        fn supports(&self, _: Algorithm) -> bool {
            true
        }
    }

    fn pair() -> PqdsaKeyPair {
        PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap()
    }

    fn sign(pair: &PqdsaKeyPair, message: &[u8]) -> Vec<u8> {
        let mut sig = vec![0x5a; 3309];
        let n = pair.sign(message, &mut sig).unwrap();
        sig.truncate(n);
        sig
    }

    fn sign1(
        pair: &PqdsaKeyPair,
        alg: i64,
        payload: &[u8],
        tamper: impl Fn(&mut Vec<u8>),
    ) -> Vec<u8> {
        let protected = dcbor::encode(
            &Value::Map(vec![
                (Value::Unsigned(ALG), Value::int(alg)),
                (Value::Unsigned(CONTENT_TYPE), Value::text(CT)),
                (Value::Unsigned(KID), Value::Bytes(vec![3; 32])),
            ]),
            Limits::CEILING,
        )
        .unwrap();
        let mut sig = sign(pair, &to_be_signed(&protected, payload).unwrap());
        tamper(&mut sig);
        let body = Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(sig),
        ]);
        [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
    }

    fn keys(pair: &PqdsaKeyPair, alg: Algorithm) -> KeySet {
        let mut k = KeySet::default();
        k.keys.insert(
            [3; 32],
            PublicKey::MlDsa(alg, pair.public_key().as_ref().to_vec()),
        );
        k.allowed.insert(Algorithm::MlDsa65);
        k
    }

    // L0-SIG-8, L0-SIG-15, CR-41, OP-159 m.3 (c)
    #[test]
    fn an_ml_dsa_cose_sign1_verifies_only_with_a_provider() {
        let p = pair();
        let good = sign1(&p, -49, b"payload", |_| {});
        let ks = keys(&p, Algorithm::MlDsa65);
        let v = verify_sign1(&PqBackend, &good, &ks, CT).unwrap();
        assert_eq!(
            (v.algorithm, v.payload.as_slice()),
            (Algorithm::MlDsa65, &b"payload"[..])
        );
        assert_eq!(
            verify_sign1(&PureBackend, &good, &ks, CT).map(|_| ()),
            Err(CoseError::Algorithm)
        );
        let mut narrow = ks.clone();
        narrow.allowed.clear();
        narrow.allowed.insert(Algorithm::Ed25519);
        assert_eq!(
            verify_sign1(&PqBackend, &good, &narrow, CT).map(|_| ()),
            Err(CoseError::Algorithm)
        );
        let wrong = keys(&p, Algorithm::MlDsa44);
        assert_eq!(
            verify_sign1(&PqBackend, &good, &wrong, CT).map(|_| ()),
            Err(CoseError::KeyType)
        );
        assert_eq!(
            verify_sign1(&PqBackend, &good, &ks, "application/access-pap+cbor").map(|_| ()),
            Err(CoseError::ContentType)
        );
        let flipped = sign1(&p, -49, b"payload", |s| s[0] ^= 1);
        assert_eq!(
            verify_sign1(&PqBackend, &flipped, &ks, CT).map(|_| ()),
            Err(CoseError::Signature(SignatureError::Invalid))
        );
        let short = sign1(&p, -49, b"payload", |s| {
            s.pop();
        });
        assert_eq!(
            verify_sign1(&PqBackend, &short, &ks, CT).map(|_| ()),
            Err(CoseError::Signature(SignatureError::Length))
        );
    }

    // SAI-44, CR-42 m.2, OP-159 m.3 (u)
    #[test]
    fn composite_and_provisional_code_points_are_unknown() {
        let p = pair();
        let ks = keys(&p, Algorithm::MlDsa65);
        for alg in -59..=-51 {
            let s = sign1(&p, alg, b"payload", |_| {});
            assert_eq!(
                verify_sign1(&PqBackend, &s, &ks, CT).map(|_| ()),
                Err(CoseError::Algorithm),
                "{alg}"
            );
        }
    }

    fn jws(pair: &PqdsaKeyPair, alg: &str) -> String {
        let h = b64url_encode(
            format!(
                r#"{{"alg":"{alg}","kid":"{}","typ":"TYP"}}"#,
                b64url_encode(&[3; 32])
            )
            .as_bytes(),
        );
        let input = format!("{h}.{}", b64url_encode(b"{}"));
        let sig = sign(pair, input.as_bytes());
        format!("{input}.{}", b64url_encode(&sig))
    }

    // L0-SIG-8, CR-55 m.8, OP-159 m.3 (c)
    #[test]
    fn an_ml_dsa_jws_verifies_only_with_a_provider() {
        let p = pair();
        let ks = keys(&p, Algorithm::MlDsa65);
        let token = jws(&p, "ML-DSA-65");
        assert!(verify_compact(&PqBackend, &token, &ks, "TYP", Origin::Native).is_ok());
        assert_eq!(
            verify_compact(&PureBackend, &token, &ks, "TYP", Origin::Native).map(|_| ()),
            Err(JwsError::Algorithm)
        );
        for composite in ["ML-DSA-65-Ed25519", "ML-DSA-65-ES256", "MLDSA65"] {
            assert_eq!(
                verify_compact(&PqBackend, &jws(&p, composite), &ks, "TYP", Origin::Native)
                    .map(|_| ()),
                Err(JwsError::Algorithm),
                "{composite}"
            );
        }
        let wrong = keys(&p, Algorithm::MlDsa44);
        assert_eq!(
            verify_compact(&PqBackend, &token, &wrong, "TYP", Origin::Native).map(|_| ()),
            Err(JwsError::KeyType)
        );
    }
}

#[cfg(test)]
mod hybrid {
    use std::collections::{BTreeMap, BTreeSet};

    use access_kernel::codec::Canonical as _;
    use access_kernel::digest::Digest;
    use access_kernel::verify::cose::{ALG, Algorithm, CONTENT_TYPE, KID, PublicKey, to_be_signed};
    use access_kernel::verify::hybrid::{Component, Expected, HybridError, verify};
    use access_kernel::verify::key_scope::{
        BindingKey, BindingScope, DomainMetadata, EXCERPT_CONTENT_TYPE, Hybrid, KeyExcerpt,
        KeyScopeError, KeyUsage, OperationalKey, SpecVersions, operational_key, thumbprint,
    };
    use access_kernel::verify::{Backend, PureBackend};
    use aws_lc_rs::signature::{
        Ed25519KeyPair, KeyPair as _, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
    };
    use std::fmt::Write as _;
    use suiss_crypto::dcbor::{self, Limits, Value};

    const CT: &str = "application/access-receipt+cbor";
    const IAT: u64 = 1_000;

    struct PqBackend;

    impl Backend for PqBackend {
        fn ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            PureBackend.ed25519(public_key, message, signature)
        }

        fn p256(&self, public_key_sec1: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
            PureBackend.p256(public_key_sec1, message, signature)
        }

        fn ml_dsa(
            &self,
            alg: Algorithm,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> bool {
            alg == Algorithm::MlDsa65
                && UnparsedPublicKey::new(&ML_DSA_65, public_key)
                    .verify(message, signature)
                    .is_ok()
        }

        fn supports(&self, _: Algorithm) -> bool {
            true
        }
    }

    enum Key {
        Ed(Ed25519KeyPair),
        Pq(PqdsaKeyPair),
    }

    impl Key {
        fn public(&self) -> PublicKey {
            match self {
                Self::Ed(k) => PublicKey::Ed25519(k.public_key().as_ref().try_into().unwrap()),
                Self::Pq(k) => {
                    PublicKey::MlDsa(Algorithm::MlDsa65, k.public_key().as_ref().to_vec())
                }
            }
        }

        fn alg(&self) -> Algorithm {
            match self {
                Self::Ed(_) => Algorithm::Ed25519,
                Self::Pq(_) => Algorithm::MlDsa65,
            }
        }

        fn sign1(&self, content_type: &str, payload: &[u8]) -> Vec<u8> {
            let protected = dcbor::encode(
                &Value::Map(vec![
                    (Value::Unsigned(ALG), Value::int(self.alg().cose())),
                    (Value::Unsigned(CONTENT_TYPE), Value::text(content_type)),
                    (
                        Value::Unsigned(KID),
                        Value::Bytes(thumbprint(&self.public()).to_vec()),
                    ),
                ]),
                Limits::CEILING,
            )
            .unwrap();
            let tbs = to_be_signed(&protected, payload).unwrap();
            let sig = match self {
                Self::Ed(k) => k.sign(&tbs).as_ref().to_vec(),
                Self::Pq(k) => {
                    let mut s = vec![0x5a; 3309];
                    let n = k.sign(&tbs, &mut s).unwrap();
                    s.truncate(n);
                    s
                }
            };
            let body = Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(vec![]),
                Value::Bytes(payload.to_vec()),
                Value::Bytes(sig),
            ]);
            [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
        }
    }

    struct World {
        metadata: DomainMetadata,
        binding: Key,
        classic: Key,
        pq: Key,
    }

    fn world(policy: Option<Hybrid>) -> World {
        let binding = Key::Ed(Ed25519KeyPair::generate().unwrap());
        let b = BindingKey {
            kid: thumbprint(&binding.public()),
            alg: Algorithm::Ed25519,
            key: binding.public(),
            scope: BindingScope::Domain,
            superseded: None,
        };
        let versions = SpecVersions {
            core: 1,
            meta_schema: 1,
            ..SpecVersions::default()
        };
        World {
            metadata: DomainMetadata {
                domain: Digest([1; 32]),
                genesis: Digest([2; 32]),
                issued_at: IAT,
                binding: BTreeMap::from([(b.kid, b)]),
                algorithms: BTreeSet::from([Algorithm::Ed25519, Algorithm::MlDsa65]),
                operational_window_max_ms: 3_600_000,
                operational_keys: Vec::new(),
                min_versions: versions.clone(),
                adopted: versions,
                caps: None,
                hybrid: policy,
                discovery: None,
                declared: access_kernel::verify::key_scope::Declarations::default(),
            },
            binding,
            classic: Key::Ed(Ed25519KeyPair::generate().unwrap()),
            pq: Key::Pq(PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap()),
        }
    }

    impl World {
        fn excerpt(&self, key: &Key) -> Vec<u8> {
            let op = OperationalKey {
                kid: thumbprint(&key.public()),
                alg: key.alg(),
                key: key.public(),
                valid_from: 0,
                valid_until: 3_600_000,
                usage: BTreeSet::from([KeyUsage::Receipt]),
            };
            let excerpt = KeyExcerpt {
                domain: self.metadata.domain,
                key: op,
            };
            self.binding
                .sign1(EXCERPT_CONTENT_TYPE, &excerpt.to_bytes().unwrap())
        }
    }

    fn expected(domain: &Digest) -> Expected<'_> {
        Expected::new(domain, KeyUsage::Receipt, IAT, CT)
    }

    // CR-42 m.2, m.4, SAI-44, L0-SIG-75a, OP-159 m.3 (e)
    #[test]
    fn both_requires_two_valid_signatures_over_one_payload() {
        let w = world(Some(Hybrid::Both));
        let (ce, pe) = (w.excerpt(&w.classic), w.excerpt(&w.pq));
        let (cs, ps) = (w.classic.sign1(CT, b"receipt"), w.pq.sign1(CT, b"receipt"));
        let c = Some(Component::new(&cs, &ce));
        let p = Some(Component::new(&ps, &pe));
        let d = w.metadata.domain;
        assert_eq!(
            verify(&PqBackend, &w.metadata, c, p, &expected(&d))
                .unwrap()
                .payload,
            b"receipt"
        );
        assert_eq!(
            verify(&PqBackend, &w.metadata, c, None, &expected(&d)).map(|_| ()),
            Err(HybridError::Missing)
        );
        assert_eq!(
            verify(&PqBackend, &w.metadata, None, p, &expected(&d)).map(|_| ()),
            Err(HybridError::Missing)
        );
        let other = w.pq.sign1(CT, b"another receipt");
        assert_eq!(
            verify(
                &PqBackend,
                &w.metadata,
                c,
                Some(Component::new(&other, &pe)),
                &expected(&d)
            )
            .map(|_| ()),
            Err(HybridError::Payload)
        );
        assert_eq!(
            verify(&PqBackend, &w.metadata, p, c, &expected(&d)).map(|_| ()),
            Err(HybridError::Key(KeyScopeError::Algorithm))
        );
        assert_eq!(
            verify(&PureBackend, &w.metadata, c, p, &expected(&d)).map(|_| ()),
            Err(HybridError::Key(KeyScopeError::Algorithm))
        );
        for excerpt in [&ce, &pe] {
            assert_eq!(
                operational_key(
                    &PqBackend,
                    &w.metadata,
                    &d,
                    excerpt,
                    KeyUsage::Receipt,
                    IAT,
                    None
                ),
                Err(KeyScopeError::Algorithm),
                "a single signature never satisfies both"
            );
        }
    }

    // L0-SIG-75a, HL-19, OP-159 m.3 (c), (e)
    #[test]
    fn pq_and_classic_require_their_own_component() {
        let world = world(Some(Hybrid::Pq));
        let (ce, pe) = (world.excerpt(&world.classic), world.excerpt(&world.pq));
        let (cs, ps) = (world.classic.sign1(CT, b"pap"), world.pq.sign1(CT, b"pap"));
        let d = world.metadata.domain;
        let p = Some(Component::new(&ps, &pe));
        let c = Some(Component::new(&cs, &ce));
        assert!(verify(&PqBackend, &world.metadata, None, p, &expected(&d)).is_ok());
        assert!(verify(&PqBackend, &world.metadata, c, p, &expected(&d)).is_ok());
        assert_eq!(
            verify(&PqBackend, &world.metadata, c, None, &expected(&d)).map(|_| ()),
            Err(HybridError::Missing)
        );
        assert_eq!(
            verify(&PureBackend, &world.metadata, None, p, &expected(&d)).map(|_| ()),
            Err(HybridError::Key(KeyScopeError::Algorithm)),
            "a pq-only domain's artefact is refused by a verifier without ML-DSA"
        );
        assert!(
            operational_key(
                &PqBackend,
                &world.metadata,
                &d,
                &pe,
                KeyUsage::Receipt,
                IAT,
                None
            )
            .is_ok()
        );
        for policy in [None, Some(Hybrid::Classic)] {
            let mut meta = world.metadata.clone();
            meta.hybrid = policy;
            assert!(verify(&PqBackend, &meta, c, None, &expected(&d)).is_ok());
            assert!(verify(&PqBackend, &meta, c, p, &expected(&d)).is_ok());
            assert_eq!(
                verify(&PqBackend, &meta, None, p, &expected(&d)).map(|_| ()),
                Err(HybridError::Missing)
            );
            assert_eq!(
                operational_key(&PqBackend, &meta, &d, &pe, KeyUsage::Receipt, IAT, None),
                Err(KeyScopeError::Algorithm)
            );
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().fold(String::new(), |mut h, x| {
            let _ = write!(h, "{x:02x}");
            h
        })
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i.saturating_add(2)], 16).unwrap())
            .collect()
    }

    fn name(e: HybridError) -> &'static str {
        use access_kernel::verify::cose::CoseError;
        match e {
            HybridError::Missing => "hybrid-missing",
            HybridError::Payload => "hybrid-payload",
            HybridError::Carrier => "hybrid-carrier",
            HybridError::Key(KeyScopeError::Algorithm)
            | HybridError::Signature(CoseError::Algorithm) => "algorithm",
            HybridError::Key(KeyScopeError::Signature(CoseError::Signature(_)))
            | HybridError::Signature(CoseError::Signature(_)) => "signature",
            other => panic!("{other:?}"),
        }
    }

    type Parts = (Option<(Vec<u8>, Vec<u8>)>, Option<(Vec<u8>, Vec<u8>)>);

    fn cases() -> Vec<(&'static str, World, Parts, bool)> {
        let mut out = Vec::new();
        for (policy, label) in [
            (Some(Hybrid::Both), "both"),
            (Some(Hybrid::Pq), "pq"),
            (None, "classic"),
        ] {
            let w = world(policy);
            let c = (w.classic.sign1(CT, b"receipt"), w.excerpt(&w.classic));
            let p = (w.pq.sign1(CT, b"receipt"), w.excerpt(&w.pq));
            let mut bad = p.clone();
            let at = bad.0.len().saturating_sub(10);
            bad.0[at] ^= 1;
            let other = (w.pq.sign1(CT, b"another"), p.1.clone());
            let id =
                |s: &str| -> &'static str { Box::leak(format!("{label}-{s}").into_boxed_str()) };
            let set: Vec<(&'static str, Parts, bool)> = vec![
                (id("two-valid"), (Some(c.clone()), Some(p.clone())), true),
                (
                    id("two-valid-no-ml-dsa"),
                    (Some(c.clone()), Some(p.clone())),
                    false,
                ),
                (id("classic-only"), (Some(c.clone()), None), true),
                (id("pq-only"), (None, Some(p.clone())), true),
                (id("pq-tampered"), (Some(c.clone()), Some(bad)), true),
                (id("payload-mismatch"), (Some(c.clone()), Some(other)), true),
                (
                    id("components-swapped"),
                    (Some(p.clone()), Some(c.clone())),
                    true,
                ),
            ];
            for (id, parts, ml) in set {
                out.push((id, world_clone(&w), parts, ml));
            }
        }
        out
    }

    fn world_clone(w: &World) -> World {
        World {
            metadata: w.metadata.clone(),
            binding: Key::Ed(Ed25519KeyPair::generate().unwrap()),
            classic: Key::Ed(Ed25519KeyPair::generate().unwrap()),
            pq: Key::Ed(Ed25519KeyPair::generate().unwrap()),
        }
    }

    fn component(v: &serde_json::Value, k: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        v.get(k).map(|c| {
            (
                unhex(c["sign1"].as_str().unwrap()),
                unhex(c["excerpt"].as_str().unwrap()),
            )
        })
    }

    fn raw_carrier(classic: &[u8], pq: &[u8]) -> Vec<u8> {
        dcbor::encode(
            &Value::Array(vec![
                Value::Bytes(classic.to_vec()),
                Value::Bytes(pq.to_vec()),
            ]),
            Limits::CEILING,
        )
        .unwrap()
    }

    /// A case's input: a carrier with the two excerpts, or the single component it carries.
    enum Input {
        Carrier(Vec<u8>, Vec<u8>, Vec<u8>),
        Single(Parts),
    }

    fn input(parts: Parts) -> Input {
        match parts {
            (Some((cs, ce)), Some((ps, pe))) => Input::Carrier(raw_carrier(&cs, &ps), ce, pe),
            single => Input::Single(single),
        }
    }

    fn read(v: &serde_json::Value) -> Input {
        match v.get("carrier") {
            Some(c) => Input::Carrier(
                unhex(c.as_str().unwrap()),
                unhex(v["classic_excerpt"].as_str().unwrap()),
                unhex(v["pq_excerpt"].as_str().unwrap()),
            ),
            None => Input::Single((component(v, "classic"), component(v, "pq"))),
        }
    }

    fn run(metadata: &DomainMetadata, input: &Input, ml: bool) -> Result<Vec<u8>, &'static str> {
        use access_kernel::verify::hybrid::decode_carrier;
        let d = metadata.domain;
        let parts: Parts = match input {
            Input::Carrier(bytes, ce, pe) => {
                let (cs, ps) = decode_carrier(bytes).map_err(name)?;
                (Some((cs, ce.clone())), Some((ps, pe.clone())))
            }
            Input::Single(p) => p.clone(),
        };
        let c = parts.0.as_ref().map(|(s, e)| Component::new(s, e));
        let p = parts.1.as_ref().map(|(s, e)| Component::new(s, e));
        let got = if ml {
            verify(&PqBackend, metadata, c, p, &expected(&d))
        } else {
            verify(&PureBackend, metadata, c, p, &expected(&d))
        };
        got.map(|v| v.payload).map_err(name)
    }

    // TI-RT12, L0-SIG-18, L0-SIG-75a, OP-159 m.3 (e)
    #[test]
    fn hybrid_vectors_hold() {
        let path = format!(
            "{}/../../conformance/vectors/core/1/hybrid.json",
            env!("CARGO_MANIFEST_DIR")
        );
        if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
            let mut lines = Vec::new();
            for (id, w, parts, ml) in cases() {
                let mut line = format!(
                    "  {{\"id\": \"{id}\", \"metadata\": \"{}\", \"domain\": \"{}\"",
                    hex(&w.metadata.to_bytes().unwrap()),
                    hex(&dcbor::encode(&w.metadata.domain.to_value(), Limits::CEILING).unwrap())
                );
                let input = input(parts);
                match &input {
                    Input::Carrier(bytes, ce, pe) => {
                        let _ = write!(
                            line,
                            ", \"carrier\": \"{}\", \"classic_excerpt\": \"{}\", \"pq_excerpt\": \"{}\"",
                            hex(bytes),
                            hex(ce),
                            hex(pe)
                        );
                    }
                    Input::Single(parts) => {
                        for (k, part) in [("classic", &parts.0), ("pq", &parts.1)] {
                            if let Some((s, e)) = part {
                                let _ = write!(
                                    line,
                                    ", \"{k}\": {{\"sign1\": \"{}\", \"excerpt\": \"{}\"}}",
                                    hex(s),
                                    hex(e)
                                );
                            }
                        }
                    }
                }
                let _ = write!(line, ", \"ml_dsa\": {ml}, ");
                match run(&w.metadata, &input, ml) {
                    Ok(p) => {
                        let _ = write!(line, "\"payload\": \"{}\"}}", hex(&p));
                    }
                    Err(e) => {
                        let _ = write!(line, "\"error\": \"{e}\"}}");
                    }
                }
                lines.push(line);
            }
            let json = format!(
                "{{\n \"rule\": \"CR-42\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"key_scope.hybrid\",\n \"rules\": [\"L0-SIG-18\", \"L0-SIG-75a\"],\n \"content_type\": \"{CT}\",\n \"usage\": \"receipt\",\n \"iat\": {IAT},\n \"cases\": [\n{}\n ]\n}}\n",
                lines.join(",\n")
            );
            std::fs::write(&path, json).unwrap();
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let mut n = 0;
        for c in doc["cases"].as_array().unwrap() {
            let metadata =
                DomainMetadata::from_bytes(&unhex(c["metadata"].as_str().unwrap())).unwrap();
            let input = read(c);
            let got = run(&metadata, &input, c["ml_dsa"].as_bool().unwrap());
            let want = match c.get("payload") {
                Some(p) => Ok(unhex(p.as_str().unwrap())),
                None => Err(c["error"].as_str().unwrap()),
            };
            assert_eq!(got, want, "{}", c["id"]);
            if c["ml_dsa"].as_bool().unwrap() && metadata.hybrid.is_some() && got.is_ok() {
                assert_eq!(
                    run(&metadata, &input, false),
                    Err("algorithm"),
                    "{}",
                    c["id"]
                );
            }
            n += 1;
        }
        assert_eq!(n, 21);
    }
}

#[cfg(test)]
mod retired {
    use std::collections::BTreeMap;

    use access_kernel::digest::Digest;
    use access_kernel::record::{Disclosure, Header, Opened, RecordKind};
    use access_kernel::verify::cose::{ALG, Algorithm, CONTENT_TYPE, KID, PublicKey, to_be_signed};
    use access_kernel::verify::key_scope::{
        ARTEFACT_FIELD, ARTIFACTS_FIELD, KeyScopeError, Witness, thumbprint,
    };
    use access_kernel::verify::pq::PqAnchor;
    use access_kernel::verify::reanchor::{
        CHECKPOINT_CONTENT_TYPE, COSIGN_CONTENT_TYPE, PqBundle, PqCosign, accept_retired,
    };
    use access_kernel::verify::{Backend, PureBackend};
    use aws_lc_rs::signature::{
        KeyPair as _, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey,
    };
    use suiss_crypto::dcbor::{self, Limits, Value};
    use suiss_crypto::note::{Checkpoint, base64_encode};

    struct PqBackend;

    impl Backend for PqBackend {
        fn ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
            PureBackend.ed25519(public_key, message, signature)
        }

        fn p256(&self, public_key_sec1: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
            PureBackend.p256(public_key_sec1, message, signature)
        }

        fn ml_dsa(
            &self,
            alg: Algorithm,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> bool {
            alg == Algorithm::MlDsa65
                && UnparsedPublicKey::new(&ML_DSA_65, public_key)
                    .verify(message, signature)
                    .is_ok()
        }

        fn supports(&self, _: Algorithm) -> bool {
            true
        }
    }

    const DOMAIN: Digest = Digest([0x0d; 32]);

    fn origin() -> String {
        format!("sha-256:{}", base64_encode(&DOMAIN.0))
    }

    fn public(k: &PqdsaKeyPair) -> PublicKey {
        PublicKey::MlDsa(Algorithm::MlDsa65, k.public_key().as_ref().to_vec())
    }

    fn sign1(k: &PqdsaKeyPair, content_type: &str, payload: &[u8]) -> Vec<u8> {
        let protected = dcbor::encode(
            &Value::Map(vec![
                (Value::Unsigned(ALG), Value::int(Algorithm::MlDsa65.cose())),
                (Value::Unsigned(CONTENT_TYPE), Value::text(content_type)),
                (
                    Value::Unsigned(KID),
                    Value::Bytes(thumbprint(&public(k)).to_vec()),
                ),
            ]),
            Limits::CEILING,
        )
        .unwrap();
        let tbs = to_be_signed(&protected, payload).unwrap();
        let mut sig = vec![0x5a; 3309];
        let n = k.sign(&tbs, &mut sig).unwrap();
        sig.truncate(n);
        let body = Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(sig),
        ]);
        [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
    }

    fn record(artefact: Digest) -> Disclosure {
        Disclosure {
            header: Header {
                domain: Some(DOMAIN),
                pos: 1,
                kind: RecordKind::Decision,
                recorded_at: 1_000,
                prev: Some(Digest([1; 32])),
            },
            opened: BTreeMap::from([(
                String::from(ARTEFACT_FIELD),
                Opened {
                    value: artefact.to_value(),
                    salt: [0x5a; 32],
                },
            )]),
            withheld: BTreeMap::new(),
        }
    }

    // CR-45 RA-5, RA-7, L0-SIG-81, OP-159 m.3 (h)
    #[test]
    fn a_retired_classical_artefact_needs_a_pinned_anchor_and_a_pq_bundle() {
        let log = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let witness = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
        let artefact = Digest([0xa1; 32]);
        let rec = record(artefact);
        let root = rec.leaf_hash().unwrap();
        let body = Checkpoint {
            origin: origin(),
            size: 2,
            root: suiss_crypto::digest::node_hash(&[0x11; 32], &root),
            extensions: Vec::new(),
        }
        .to_body()
        .unwrap();
        let checkpoint = sign1(&log, CHECKPOINT_CONTENT_TYPE, body.as_bytes());
        let mut cosigned = body.as_bytes().to_vec();
        cosigned.extend_from_slice(&7_u64.to_be_bytes());
        let cosign = sign1(&witness, COSIGN_CONTENT_TYPE, &cosigned);
        let w = Witness::new(
            "witness.example".to_owned(),
            public(&witness),
            Algorithm::MlDsa65,
            "independent".to_owned(),
            true,
        );
        let anchor = PqAnchor::new(DOMAIN, thumbprint(&public(&log)), public(&log), vec![w], 1);
        let cosigns = [PqCosign::new("witness.example", 7, &cosign)];
        let bundle = PqBundle::new(&rec, &[[0x11; 32]], &checkpoint, &cosigns);
        let o = origin();
        assert_eq!(
            accept_retired(
                &PqBackend,
                std::slice::from_ref(&anchor),
                (&DOMAIN, &o),
                &artefact,
                Some(&bundle)
            ),
            Ok(())
        );
        assert_eq!(
            accept_retired(&PqBackend, &[], (&DOMAIN, &o), &artefact, Some(&bundle)),
            Err(KeyScopeError::PqAnchorMissing)
        );
        assert_eq!(
            accept_retired(
                &PqBackend,
                std::slice::from_ref(&anchor),
                (&DOMAIN, &o),
                &artefact,
                None
            ),
            Err(KeyScopeError::Superseded)
        );
        assert_eq!(
            accept_retired(
                &PqBackend,
                std::slice::from_ref(&anchor),
                (&DOMAIN, &o),
                &Digest([0xa2; 32]),
                Some(&bundle)
            ),
            Err(KeyScopeError::Superseded)
        );
        assert_eq!(
            accept_retired(
                &PureBackend,
                std::slice::from_ref(&anchor),
                (&DOMAIN, &o),
                &artefact,
                Some(&bundle)
            ),
            Err(KeyScopeError::Superseded)
        );
        let none: [PqCosign<'_>; 0] = [];
        let uncosigned = PqBundle::new(&rec, &[[0x11; 32]], &checkpoint, &none);
        assert_eq!(
            accept_retired(
                &PqBackend,
                &[anchor],
                (&DOMAIN, &o),
                &artefact,
                Some(&uncosigned)
            ),
            Err(KeyScopeError::Superseded)
        );
    }

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write as _;
        b.iter().fold(String::new(), |mut h, x| {
            let _ = write!(h, "{x:02x}");
            h
        })
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i.saturating_add(2)], 16).unwrap())
            .collect()
    }

    fn name(r: Result<(), KeyScopeError>) -> &'static str {
        match r {
            Ok(()) => "ok",
            Err(KeyScopeError::PqAnchorMissing) => "pq-anchor-missing",
            Err(KeyScopeError::Superseded) => "superseded",
            Err(other) => panic!("{other:?}"),
        }
    }

    // TI-RT12, L0-SIG-81, OP-159 m.3 (h)
    #[test]
    #[allow(
        clippy::too_many_lines,
        clippy::type_complexity,
        clippy::format_push_string,
        reason = "one generator and check of a vector file"
    )]
    fn pq_inclusion_vectors_hold() {
        use access_kernel::codec::Canonical as _;
        let path = format!(
            "{}/../../conformance/vectors/core/1/pq-inclusion.json",
            env!("CARGO_MANIFEST_DIR")
        );
        if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
            let log = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
            let witness = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).unwrap();
            let rec = record(Digest([0xa1; 32]));
            let signed = |r: &Disclosure| {
                let body = Checkpoint {
                    origin: origin(),
                    size: 2,
                    root: suiss_crypto::digest::node_hash(&[0x11; 32], &r.leaf_hash().unwrap()),
                    extensions: Vec::new(),
                }
                .to_body()
                .unwrap();
                let mut cosigned = body.as_bytes().to_vec();
                cosigned.extend_from_slice(&7_u64.to_be_bytes());
                (
                    body.clone(),
                    sign1(&log, CHECKPOINT_CONTENT_TYPE, body.as_bytes()),
                    sign1(&witness, COSIGN_CONTENT_TYPE, &cosigned),
                )
            };
            let (body, checkpoint, cosign) = signed(&rec);
            // OP-159 m.15 (a)
            let listed = |value: Value| {
                let mut r = record(Digest([0; 32]));
                r.opened = BTreeMap::from([(
                    String::from(ARTIFACTS_FIELD),
                    Opened {
                        value,
                        salt: [0x5a; 32],
                    },
                )]);
                r
            };
            let member = listed(Value::Array(vec![
                Digest([0xa9; 32]).to_value(),
                Digest([0xa1; 32]).to_value(),
            ]));
            let empty = listed(Value::Array(Vec::new()));
            let mut missing = record(Digest([0; 32]));
            missing.opened = BTreeMap::from([(
                String::from("intent"),
                Opened {
                    value: Digest([0xa1; 32]).to_value(),
                    salt: [0x5a; 32],
                },
            )]);
            let (_, m_cp, m_cs) = signed(&member);
            let (_, e_cp, e_cs) = signed(&empty);
            let (_, x_cp, x_cs) = signed(&missing);
            let other = sign1(&witness, CHECKPOINT_CONTENT_TYPE, body.as_bytes());
            let w = |independent| {
                Witness::new(
                    "witness.example".to_owned(),
                    public(&witness),
                    Algorithm::MlDsa65,
                    "independent".to_owned(),
                    independent,
                )
            };
            let anchor = |independent| {
                PqAnchor::new(
                    DOMAIN,
                    thumbprint(&public(&log)),
                    public(&log),
                    vec![w(independent)],
                    1,
                )
                .to_bytes()
                .unwrap()
            };
            let cases: Vec<(
                &str,
                Option<Vec<u8>>,
                &Disclosure,
                &[u8],
                Option<&[u8]>,
                [u8; 32],
                bool,
            )> = vec![
                (
                    "bundle-reaches-the-anchor",
                    Some(anchor(true)),
                    &rec,
                    &checkpoint,
                    Some(&cosign),
                    [0xa1; 32],
                    true,
                ),
                (
                    "no-anchor",
                    None,
                    &rec,
                    &checkpoint,
                    Some(&cosign),
                    [0xa1; 32],
                    true,
                ),
                (
                    "no-bundle",
                    Some(anchor(true)),
                    &rec,
                    &checkpoint,
                    Some(&cosign),
                    [0xa1; 32],
                    false,
                ),
                (
                    "other-artefact",
                    Some(anchor(true)),
                    &rec,
                    &checkpoint,
                    Some(&cosign),
                    [0xa2; 32],
                    true,
                ),
                (
                    "no-cosign",
                    Some(anchor(true)),
                    &rec,
                    &checkpoint,
                    None,
                    [0xa1; 32],
                    true,
                ),
                (
                    "dependent-witness",
                    Some(anchor(false)),
                    &rec,
                    &checkpoint,
                    Some(&cosign),
                    [0xa1; 32],
                    true,
                ),
                (
                    "checkpoint-not-by-the-anchor",
                    Some(anchor(true)),
                    &rec,
                    &other,
                    Some(&cosign),
                    [0xa1; 32],
                    true,
                ),
                (
                    "artifacts-member",
                    Some(anchor(true)),
                    &member,
                    &m_cp,
                    Some(&m_cs),
                    [0xa1; 32],
                    true,
                ),
                (
                    "artifacts-non-member",
                    Some(anchor(true)),
                    &member,
                    &m_cp,
                    Some(&m_cs),
                    [0xee; 32],
                    true,
                ),
                (
                    "artifacts-empty",
                    Some(anchor(true)),
                    &empty,
                    &e_cp,
                    Some(&e_cs),
                    [0xa1; 32],
                    true,
                ),
                (
                    "artifacts-missing",
                    Some(anchor(true)),
                    &missing,
                    &x_cp,
                    Some(&x_cs),
                    [0xa1; 32],
                    true,
                ),
            ];
            let mut lines = Vec::new();
            for (id, a, rec, cp, cs, art, with_bundle) in cases {
                let anchors: Vec<PqAnchor> =
                    a.iter().map(|b| PqAnchor::from_bytes(b).unwrap()).collect();
                let cosigns: Vec<PqCosign<'_>> = cs
                    .iter()
                    .map(|c| PqCosign::new("witness.example", 7, c))
                    .collect();
                let bundle = PqBundle::new(rec, &[[0x11; 32]], cp, &cosigns);
                let got = accept_retired(
                    &PqBackend,
                    &anchors,
                    (&DOMAIN, &origin()),
                    &Digest(art),
                    with_bundle.then_some(&bundle),
                );
                let mut line = format!("  {{\"id\": \"{id}\", \"rules\": [\"L0-SIG-81\"]");
                if let Some(a) = &a {
                    line.push_str(&format!(", \"anchor\": \"{}\"", hex(a)));
                }
                line.push_str(&format!(", \"artefact\": \"{}\"", hex(&art)));
                if with_bundle {
                    line.push_str(&format!(
                        ", \"bundle\": {{\"record\": \"{}\", \"path\": [\"{}\"], \"checkpoint\": \"{}\", \"cosigns\": [{}]}}",
                        hex(&rec.to_bytes().unwrap()),
                        hex(&[0x11; 32]),
                        hex(cp),
                        cs.map(|c| format!("{{\"name\": \"witness.example\", \"timestamp\": 7, \"sign1\": \"{}\"}}", hex(c))).unwrap_or_default()
                    ));
                }
                line.push_str(&format!(", \"result\": \"{}\"}}", name(got)));
                lines.push(line);
            }
            let json = format!(
                "{{\n \"rule\": \"CR-45\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"reanchor.accept_retired\",\n \"rules\": [\"L0-SIG-81\"],\n \"domain\": \"{}\",\n \"origin\": \"{}\",\n \"cases\": [\n{}\n ]\n}}\n",
                hex(&DOMAIN.0),
                origin(),
                lines.join(",\n")
            );
            std::fs::write(&path, json).unwrap();
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for c in doc["cases"].as_array().unwrap() {
            let anchors: Vec<PqAnchor> = c
                .get("anchor")
                .map(|a| PqAnchor::from_bytes(&unhex(a.as_str().unwrap())).unwrap())
                .into_iter()
                .collect();
            let artefact = Digest(unhex(c["artefact"].as_str().unwrap()).try_into().unwrap());
            let got = match c.get("bundle") {
                None => accept_retired(&PqBackend, &anchors, (&DOMAIN, &origin()), &artefact, None),
                Some(b) => {
                    let rec =
                        Disclosure::from_bytes(&unhex(b["record"].as_str().unwrap())).unwrap();
                    let cp = unhex(b["checkpoint"].as_str().unwrap());
                    let raw: Vec<(String, u64, Vec<u8>)> = b["cosigns"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| {
                            (
                                x["name"].as_str().unwrap().to_owned(),
                                x["timestamp"].as_u64().unwrap(),
                                unhex(x["sign1"].as_str().unwrap()),
                            )
                        })
                        .collect();
                    let cosigns: Vec<PqCosign<'_>> = raw
                        .iter()
                        .map(|(n, t, s)| PqCosign::new(n, *t, s))
                        .collect();
                    let bundle = PqBundle::new(&rec, &[[0x11; 32]], &cp, &cosigns);
                    accept_retired(
                        &PqBackend,
                        &anchors,
                        (&DOMAIN, &origin()),
                        &artefact,
                        Some(&bundle),
                    )
                }
            };
            assert_eq!(name(got), c["result"].as_str().unwrap(), "{}", c["id"]);
        }
    }
}
