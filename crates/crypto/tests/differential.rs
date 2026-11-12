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

    // CR-41, CR-51 V9, RR-37, OP-159 m.3 (n): aws-lc agrees with the norm and hint edge
    // vectors and with the empty-context Wycheproof and ACVP cases F0 also checks
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
}
