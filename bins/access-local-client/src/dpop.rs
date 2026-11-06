//! The client's keys and proofs (RFC 7636, RFC 9449, RFC 7523): a fresh P-256 key per run for
//! DPoP, the PKCE verifier and challenge, and ES256 compact JWS over the proof and assertion
//! payloads.

use std::time::{SystemTime, UNIX_EPOCH};

use access_kernel::json::{b64url_decode, b64url_encode};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_json::{Value, json};

use crate::ClientError;

/// Seconds since the Unix epoch, by the local clock.
#[must_use]
pub fn now_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `N` random bytes, base64url.
///
/// # Errors
/// [`ClientError::Key`] when the random source fails.
pub fn random_text<const N: usize>() -> Result<String, ClientError> {
    access_crypto::random::bytes::<N>()
        .map(|b| b64url_encode(&b))
        .map_err(|_| ClientError::Key(String::from("random source")))
}

/// A P-256 signing key with its public JWK.
pub struct Es256Key {
    pair: EcdsaKeyPair,
}

impl Es256Key {
    /// A fresh key, for one run's DPoP proofs.
    ///
    /// # Errors
    /// [`ClientError::Key`].
    pub fn generate() -> Result<Self, ClientError> {
        EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
            .map(|pair| Self { pair })
            .map_err(|_| ClientError::Key(String::from("key generation")))
    }

    /// A key from a private P-256 JWK (`kty` EC, `crv` P-256, `x`, `y`, `d`): a product's
    /// client key, for its RFC 7523 assertions.
    ///
    /// # Errors
    /// [`ClientError::Key`].
    pub fn from_private_jwk(text: &str) -> Result<Self, ClientError> {
        let bad = |what: &str| ClientError::Key(format!("private JWK: {what}"));
        let v: Value = serde_json::from_str(text).map_err(|_| bad("not JSON"))?;
        if v.get("kty").and_then(Value::as_str) != Some("EC")
            || v.get("crv").and_then(Value::as_str) != Some("P-256")
        {
            return Err(bad("not a P-256 EC key"));
        }
        let part = |k: &str| -> Result<Vec<u8>, ClientError> {
            v.get(k)
                .and_then(Value::as_str)
                .and_then(|s| b64url_decode(s).ok())
                .filter(|b| b.len() == 32)
                .ok_or_else(|| bad(&format!("{k} is not 32 bytes")))
        };
        let (x, y, d) = (part("x")?, part("y")?, part("d")?);
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        EcdsaKeyPair::from_private_key_and_public_key(&ECDSA_P256_SHA256_FIXED_SIGNING, &d, &sec1)
            .map(|pair| Self { pair })
            .map_err(|_| bad("the key does not verify"))
    }

    /// The public JWK.
    #[must_use]
    pub fn jwk(&self) -> Value {
        let p = self.pair.public_key().as_ref();
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": b64url_encode(p.get(1..33).unwrap_or(&[])),
            "y": b64url_encode(p.get(33..65).unwrap_or(&[])),
        })
    }

    /// The RFC 7638 thumbprint of the public key, base64url: `dpop_jkt` and `cnf.jkt`.
    #[must_use]
    pub fn jkt(&self) -> String {
        let key =
            access_kernel::verify::cose::PublicKey::P256(self.pair.public_key().as_ref().to_vec());
        b64url_encode(&access_kernel::verify::key_scope::thumbprint(&key))
    }

    /// A compact ES256 JWS over `payload` with `header`.
    ///
    /// # Errors
    /// [`ClientError::Key`].
    pub fn jws(&self, header: &Value, payload: &Value) -> Result<String, ClientError> {
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(payload.to_string().as_bytes())
        );
        let signature = self
            .pair
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|_| ClientError::Key(String::from("signing")))?;
        Ok(format!("{input}.{}", b64url_encode(signature.as_ref())))
    }

    /// A DPoP proof for `htm htu` (RFC 9449 §4.2), with the server's `nonce` when it gave one
    /// and `ath` when it presents `access_token`.
    ///
    /// # Errors
    /// [`ClientError::Key`].
    pub fn proof(
        &self,
        htm: &str,
        htu: &str,
        nonce: Option<&str>,
        access_token: Option<&str>,
    ) -> Result<String, ClientError> {
        let mut payload = json!({
            "jti": random_text::<16>()?,
            "htm": htm,
            "htu": htu,
            "iat": now_s(),
        });
        if let (Some(n), Some(m)) = (nonce, payload.as_object_mut()) {
            m.insert("nonce".into(), n.into());
        }
        if let (Some(t), Some(m)) = (access_token, payload.as_object_mut()) {
            m.insert(
                "ath".into(),
                b64url_encode(&suiss_crypto::digest::sha256(t.as_bytes())).into(),
            );
        }
        self.jws(
            &json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk() }),
            &payload,
        )
    }

    /// An RFC 7523 client assertion of `client_id` for `aud`, valid for one minute.
    ///
    /// # Errors
    /// [`ClientError::Key`].
    pub fn assertion(&self, client_id: &str, aud: &str) -> Result<String, ClientError> {
        let now = now_s();
        self.jws(
            &json!({ "alg": "ES256", "typ": "JWT" }),
            &json!({
                "iss": client_id,
                "sub": client_id,
                "aud": aud,
                "iat": now,
                "exp": now.saturating_add(60),
                "jti": random_text::<16>()?,
            }),
        )
    }
}

/// A PKCE verifier and its S256 challenge (RFC 7636 §4).
///
/// # Errors
/// [`ClientError::Key`].
pub fn pkce() -> Result<(String, String), ClientError> {
    let verifier = random_text::<32>()?;
    let challenge = b64url_encode(&suiss_crypto::digest::sha256(verifier.as_bytes()));
    Ok((verifier, challenge))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    // RFC 7636 §4.2, RFC 9449 §4.2, RFC 7638: the challenge is the verifier's S256, the proof
    // names its key and the thumbprint is of that key
    #[test]
    fn proofs_and_challenges_follow_the_rfcs() {
        let (verifier, challenge) = pkce().unwrap();
        assert_eq!(verifier.len(), 43);
        assert!(access_crypto::oauth::pkce_matches(
            &<[u8; 32]>::try_from(b64url_decode(&challenge).unwrap()).unwrap(),
            &verifier
        ));
        let key = Es256Key::generate().unwrap();
        let proof = key
            .proof("POST", "https://id.test/token", Some("n1"), None)
            .unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value = serde_json::from_slice(&b64url_decode(parts[0]).unwrap()).unwrap();
        let payload: Value = serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["jwk"], key.jwk());
        assert_eq!(payload["nonce"], "n1");
        assert_eq!(payload["htu"], "https://id.test/token");
        let jwk = key.jwk();
        let private = json!({
            "kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"],
            "d": b64url_encode(&[7; 32]),
        });
        assert!(Es256Key::from_private_jwk(&private.to_string()).is_err());
        assert_eq!(key.jkt().len(), 43);
    }
}
