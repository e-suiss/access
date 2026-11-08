//! Apple's client secret (IDP-31, OP-153 m.3 (l)): not a stored string but a short ES256 JWT
//! signed with the realm's Sign in with Apple key (`.p8`). The secret store holds the key
//! material; Access signs a fresh assertion for every code exchange.
//!
//! The secret a reference names is the `.p8` file as Apple issues it, preceded by two lines:
//!
//! ```text
//! team_id=ABCDE12345
//! key_id=XYZ9876543
//! -----BEGIN PRIVATE KEY-----
//! …
//! -----END PRIVATE KEY-----
//! ```

use access_crypto::Secret;
use access_kernel::json::b64url_decode;
use suiss_crypto::signer::SoftSigner;

/// Apple's audience for the client assertion.
pub const AUDIENCE: &str = "https://appleid.apple.com";

/// How long one assertion lives; Apple allows up to six months, Access signs one per exchange.
pub const LIFETIME_S: u64 = 300;

/// The key material is not the documented form or not a P-256 PKCS#8 key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("apple key material")]
pub struct KeyMaterial;

/// A Sign in with Apple key.
pub struct AppleKey {
    /// The Apple Developer team.
    pub team_id: String,
    /// The key's id.
    pub key_id: String,
    signer: SoftSigner,
}

impl core::fmt::Debug for AppleKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppleKey")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

fn apple_id(v: &str) -> bool {
    v.len() == 10
        && v.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn pem_body(pem: &str) -> Option<Vec<u8>> {
    let rest = pem.trim().strip_prefix("-----BEGIN PRIVATE KEY-----")?;
    let body = rest.strip_suffix("-----END PRIVATE KEY-----")?;
    let mut url = String::with_capacity(body.len());
    for c in body.chars().filter(|c| !c.is_ascii_whitespace()) {
        match c {
            '+' => url.push('-'),
            '/' => url.push('_'),
            '=' => {}
            c if c.is_ascii_alphanumeric() => url.push(c),
            _ => return None,
        }
    }
    b64url_decode(&url).ok()
}

impl AppleKey {
    /// Reads the material a secret reference names.
    ///
    /// # Errors
    /// [`KeyMaterial`].
    pub fn parse(material: &Secret<String>) -> Result<Self, KeyMaterial> {
        let text = material.expose();
        let mut lines = text.splitn(3, '\n');
        let (Some(team), Some(key), Some(pem)) = (lines.next(), lines.next(), lines.next()) else {
            return Err(KeyMaterial);
        };
        let field = |line: &str, name: &str| {
            line.trim_end_matches('\r')
                .strip_prefix(name)
                .and_then(|r| r.strip_prefix('='))
                .filter(|v| apple_id(v))
                .map(String::from)
        };
        let (Some(team_id), Some(key_id)) = (field(team, "team_id"), field(key, "key_id")) else {
            return Err(KeyMaterial);
        };
        let der = Secret::new(pem_body(pem).ok_or(KeyMaterial)?);
        let signer = SoftSigner::p256_from_pkcs8(&der).map_err(|_| KeyMaterial)?;
        Ok(Self {
            team_id,
            key_id,
            signer,
        })
    }

    /// The client assertion for `client_id` (the Services ID), issued at `now_s`.
    ///
    /// # Errors
    /// [`KeyMaterial`] when signing fails.
    pub fn client_secret(&self, client_id: &str, now_s: u64) -> Result<String, KeyMaterial> {
        let claims = serde_json::json!({
            "iss": self.team_id,
            "iat": now_s,
            "exp": now_s.saturating_add(LIFETIME_S),
            "aud": AUDIENCE,
            "sub": client_id,
        })
        .to_string();
        access_crypto::jose::sign_compact_assigned(&self.signer, &self.key_id, claims.as_bytes())
            .map_err(|_| KeyMaterial)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
        UnparsedPublicKey,
    };
    use serde_json::Value;

    use super::*;

    fn pem(der: &[u8]) -> String {
        let b64 = access_kernel::json::b64url_encode(der)
            .replace('-', "+")
            .replace('_', "/");
        let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(core::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        out
    }

    // IDP-31, OP-153 m.3 (l)
    #[test]
    fn the_client_secret_is_an_es256_assertion_of_the_team_for_the_services_id() {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.as_ref()).unwrap();
        let material = format!(
            "team_id=ABCDE12345\nkey_id=XYZ9876543\n{}",
            pem(doc.as_ref())
        );
        let key = AppleKey::parse(&Secret::new(material)).unwrap();
        let jwt = key.client_secret("com.example.web", 1_800_000_000).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let header: Value = serde_json::from_slice(&b64url_decode(parts[0]).unwrap()).unwrap();
        assert_eq!(
            header,
            serde_json::json!({ "alg": "ES256", "kid": "XYZ9876543" })
        );
        let claims: Value = serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            claims,
            serde_json::json!({ "iss": "ABCDE12345", "iat": 1_800_000_000_u64,
                                "exp": 1_800_000_300_u64, "aud": AUDIENCE,
                                "sub": "com.example.web" })
        );
        let input = format!("{}.{}", parts[0], parts[1]);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pair.public_key().as_ref())
            .verify(input.as_bytes(), &b64url_decode(parts[2]).unwrap())
            .unwrap();
    }

    // MD-8
    #[test]
    fn material_outside_the_form_is_refused() {
        for m in [
            "",
            "team_id=ABCDE12345\nkey_id=XYZ9876543\nnot a pem",
            "team_id=abc\nkey_id=XYZ9876543\n-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
            "key_id=XYZ9876543\nteam_id=ABCDE12345\n-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
        ] {
            assert_eq!(
                AppleKey::parse(&Secret::new(String::from(m))).unwrap_err(),
                KeyMaterial
            );
        }
    }
}
