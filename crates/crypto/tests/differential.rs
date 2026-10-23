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
}
