//! JWE towards a client (CR-4, RR-36, OP-155 m.3 (k)): its encryption key, picked from the
//! encryption JWKS it registered for the algorithm it chose. The authority plane never uses JWE.

use access_crypto::jwe::{KeyAlg, RecipientKey};
use access_kernel::json::{self, Json, b64url_decode};

use crate::domain::jwt::{MAX_JWKS, MAX_KEYS};

const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// What a nested JWE carries: a signed JWT (RFC 7519 §5.2).
pub const NESTED_CTY: &str = "JWT";

fn bytes(m: &Json, name: &str) -> Option<Vec<u8>> {
    m.get(name)
        .and_then(Json::as_str)
        .and_then(|s| b64url_decode(s).ok())
}

fn key_of(m: &Json, alg: KeyAlg) -> Option<RecipientKey> {
    if m.get("use")
        .and_then(Json::as_str)
        .is_some_and(|u| u != "enc")
    {
        return None;
    }
    if m.get("alg")
        .and_then(Json::as_str)
        .is_some_and(|a| a != alg.name())
    {
        return None;
    }
    let kty = m.get("kty").and_then(Json::as_str);
    match alg {
        KeyAlg::EcdhEsA256kw => {
            if kty != Some("EC") || m.get("crv").and_then(Json::as_str) != Some("P-256") {
                return None;
            }
            let (x, y) = (bytes(m, "x")?, bytes(m, "y")?);
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            let mut sec1 = vec![4];
            sec1.extend(x);
            sec1.extend(y);
            Some(RecipientKey::P256(sec1))
        }
        KeyAlg::RsaOaep256 => {
            if kty != Some("RSA") {
                return None;
            }
            Some(RecipientKey::Rsa {
                n: bytes(m, "n")?,
                e: bytes(m, "e")?,
            })
        }
    }
}

/// The one key of `jwks` that serves `alg`, with its `kid`: `use` absent or `enc`, `alg` absent
/// or `alg`, and of the matching type. No key, more than one, or a document holding private
/// material is `None` (fail closed).
#[must_use]
pub fn encryption_key(jwks: &[u8], alg: KeyAlg) -> Option<(RecipientKey, Option<String>)> {
    let top = json::parse(jwks, MAX_JWKS).ok()?;
    let Some(Json::Array(keys)) = top.get("keys") else {
        return None;
    };
    let mut found = Vec::new();
    for k in keys.iter().take(MAX_KEYS) {
        let Json::Object(members) = k else {
            return None;
        };
        if members
            .iter()
            .any(|(n, _)| PRIVATE_MEMBERS.contains(&n.as_str()))
        {
            return None;
        }
        if let Some(key) = key_of(k, alg) {
            found.push((key, k.get("kid").and_then(Json::as_str).map(String::from)));
        }
    }
    let mut it = found.into_iter();
    match (it.next(), it.next()) {
        (Some(one), None) => Some(one),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    const X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    // CR-4
    #[test]
    fn picks_the_one_encryption_key_of_the_chosen_algorithm() {
        let doc = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","use":"sig","x":"{X}","y":"{Y}"}},{{"kty":"EC","crv":"P-256","use":"enc","kid":"e1","x":"{X}","y":"{Y}"}}]}}"#
        );
        let (key, kid) = encryption_key(doc.as_bytes(), KeyAlg::EcdhEsA256kw).unwrap();
        assert!(matches!(key, RecipientKey::P256(_)));
        assert_eq!(kid.as_deref(), Some("e1"));
        assert!(encryption_key(doc.as_bytes(), KeyAlg::RsaOaep256).is_none());
        let two = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}"}},{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}"}}]}}"#
        );
        assert!(encryption_key(two.as_bytes(), KeyAlg::EcdhEsA256kw).is_none());
        let private =
            format!(r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}","d":"{X}"}}]}}"#);
        assert!(encryption_key(private.as_bytes(), KeyAlg::EcdhEsA256kw).is_none());
        let rsa15 = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","alg":"RSA1_5","x":"{X}","y":"{Y}"}}]}}"#
        );
        assert!(encryption_key(rsa15.as_bytes(), KeyAlg::EcdhEsA256kw).is_none());
    }
}
