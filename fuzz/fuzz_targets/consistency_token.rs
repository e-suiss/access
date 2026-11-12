//! SA-T9, OP-141 m.22 (f), OP-159 m.3 (cc): the consistency token reader never panics, opens
//! only what this key sealed for this domain and kind, and gives the sealed position back.
#![no_main]

use std::sync::OnceLock;

use access_crypto::secret::Secret;
use access_crypto::token::TokenKey;
use libfuzzer_sys::fuzz_target;

const KIND: &str = "consistency";

type Keyed = (TokenKey, [u8; 32], [u8; 32]);

fn key() -> Option<&'static Keyed> {
    static KEY: OnceLock<Option<Keyed>> = OnceLock::new();
    KEY.get_or_init(|| {
        let secret = access_crypto::random::bytes::<32>().ok()?;
        let domain = access_crypto::random::bytes::<32>().ok()?;
        let other = access_crypto::random::bytes::<32>().ok()?;
        Some((TokenKey::new(Secret::new(secret)), domain, other))
    })
    .as_ref()
}

fuzz_target!(|data: &[u8]| {
    let Some((tokens, domain, other)) = key() else {
        return;
    };
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(body) = tokens.open(domain, KIND, text) {
            assert!(body.len() <= text.len());
        }
    }
    if data.len() >= 16 {
        let body = data.get(..16).unwrap_or_default();
        if let Ok(sealed) = tokens.seal(domain, KIND, body) {
            assert_eq!(tokens.open(domain, KIND, &sealed).ok().as_deref(), Some(body));
            assert!(tokens.open(other, KIND, &sealed).is_err());
            assert!(tokens.open(domain, "basis_ref", &sealed).is_err());
        }
    }
});
