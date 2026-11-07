//! TN-135, TN-136, E42: the Suiss webhook profile vectors Relay verifies too.

#[cfg(test)]
mod vectors {
    use access_crypto::webhook::{WebhookPublicKey, WebhookSecret, WebhookSigningKey};
    use serde_json::Value;

    fn bytes(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    fn load() -> Value {
        let full = format!(
            "{}/../../conformance/vectors/webhook/1/signature.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(full).unwrap()).unwrap()
    }

    fn s<'a>(v: &'a Value, k: &str) -> &'a str {
        v[k].as_str().unwrap()
    }

    // TN-136, E42: v1a (Ed25519) and v1 (HMAC) signatures are exact and verify
    #[test]
    fn tn_136_webhook_signatures_match_the_shared_vectors() {
        let v = load();
        let sk = WebhookSigningKey::parse(s(&v["keys"], "ed25519_signing_key")).unwrap();
        let pk = WebhookPublicKey::parse(s(&v["keys"], "ed25519_public_key")).unwrap();
        let hs = WebhookSecret::parse(s(&v["keys"], "hmac_secret")).unwrap();
        assert_eq!(sk.public_key(), pk);
        assert_eq!(pk.text(), s(&v["keys"], "ed25519_public_key"));
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 3);
        for c in cases {
            let (id, ts, body) = (
                s(c, "webhook_id"),
                c["webhook_timestamp"].as_u64().unwrap(),
                bytes(s(c, "body_hex")),
            );
            assert_eq!(sk.sign(id, ts, &body), s(c, "v1a"), "{}", s(c, "name"));
            assert_eq!(hs.sign(id, ts, &body), s(c, "v1"), "{}", s(c, "name"));
            assert!(pk.verify(id, ts, &body, s(c, "v1a"), ts));
            assert!(hs.verify(id, ts, &body, s(c, "v1"), ts));
            let both = format!("{} {}", s(c, "v1"), s(c, "v1a"));
            assert!(pk.verify(id, ts, &body, &both, ts));
            assert!(hs.verify(id, ts, &body, &both, ts));
        }
    }

    // TN-135, TN-136: tampering, another id, a stale timestamp and swapped tags are refused
    #[test]
    fn tn_136_webhook_rejections_match_the_shared_vectors() {
        let v = load();
        let pk = WebhookPublicKey::parse(s(&v["keys"], "ed25519_public_key")).unwrap();
        let hs = WebhookSecret::parse(s(&v["keys"], "hmac_secret")).unwrap();
        let cases = v["cases"].as_array().unwrap();
        for r in v["rejections"].as_array().unwrap() {
            let base = cases.iter().find(|c| c["name"] == r["case"]).unwrap();
            let id = r["webhook_id"].as_str().unwrap_or(s(base, "webhook_id"));
            let ts = base["webhook_timestamp"].as_u64().unwrap();
            let now = r["now"].as_u64().unwrap_or(ts);
            let body = bytes(r["body_hex"].as_str().unwrap_or(s(base, "body_hex")));
            let (mut a, mut h) = (s(base, "v1a").to_owned(), s(base, "v1").to_owned());
            if r["swap_versions"].as_bool() == Some(true) {
                a = a.replacen("v1a,", "v1,", 1);
                h = h.replacen("v1,", "v1a,", 1);
            }
            let header = format!("{a} {h}");
            assert!(!pk.verify(id, ts, &body, &header, now), "{}", s(r, "name"));
            assert!(!hs.verify(id, ts, &body, &header, now), "{}", s(r, "name"));
        }
    }
}
