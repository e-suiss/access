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
