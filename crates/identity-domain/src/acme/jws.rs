//! The JWS of ACME requests (RFC 8555 §6.2): flattened JSON serialization, ES256, a protected
//! header of `alg`, `nonce`, `url` and either the account's `jwk` (new account) or its `kid`
//! (every later request). The account JWK's RFC 7638 thumbprint makes the key authorization of
//! a challenge (§8.1), whose SHA-256 the TLS-ALPN-01 certificate carries (RFC 8737 §3).

use access_kernel::json::b64url_encode;
use suiss_crypto::digest::sha256;

use super::AcmeError;

/// Who the protected header says signed: the new account's key, or the account URL.
#[derive(Clone, Copy, Debug)]
pub enum Signer<'a> {
    /// `jwk`, for `newAccount` (§7.3).
    Jwk(&'a [u8]),
    /// `kid`, the account URL.
    Kid(&'a str),
}

fn coordinates(point: &[u8]) -> Result<(&[u8], &[u8]), AcmeError> {
    match point.split_first() {
        Some((4, xy)) if xy.len() == 64 => Ok(xy.split_at(32)),
        _ => Err(AcmeError::Key),
    }
}

/// The account's public JWK, members in RFC 7638 order: `{"crv","kty","x","y"}`.
///
/// # Errors
/// [`AcmeError::Key`] for anything but an uncompressed P-256 point.
pub fn jwk(point: &[u8]) -> Result<String, AcmeError> {
    let (x, y) = coordinates(point)?;
    Ok(format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        b64url_encode(x),
        b64url_encode(y)
    ))
}

/// The RFC 7638 thumbprint of the account key.
///
/// # Errors
/// [`AcmeError::Key`].
pub fn thumbprint(point: &[u8]) -> Result<[u8; 32], AcmeError> {
    Ok(sha256(jwk(point)?.as_bytes()))
}

/// The key authorization of a challenge `token` (§8.1).
///
/// # Errors
/// [`AcmeError`] for a token that is not base64url or a bad key.
pub fn key_authorization(token: &str, point: &[u8]) -> Result<String, AcmeError> {
    let ok = !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        return Err(AcmeError::Protocol("challenge token"));
    }
    Ok(format!("{token}.{}", b64url_encode(&thumbprint(point)?)))
}

/// The SHA-256 of a key authorization, as the TLS-ALPN-01 certificate carries it.
#[must_use]
pub fn alpn_digest(key_authorization: &str) -> [u8; 32] {
    sha256(key_authorization.as_bytes())
}

fn quoted(s: &str) -> Result<String, AcmeError> {
    serde_json::to_string(s).map_err(|_| AcmeError::Protocol("encode"))
}

/// The protected header and the JWS signing input of a request to `url` with `payload`
/// (`None` for POST-as-GET, §6.3).
///
/// # Errors
/// [`AcmeError`].
pub fn signing_input(
    signer: Signer<'_>,
    nonce: &str,
    url: &str,
    payload: Option<&[u8]>,
) -> Result<(String, String), AcmeError> {
    let who = match signer {
        Signer::Jwk(point) => format!(r#""jwk":{}"#, jwk(point)?),
        Signer::Kid(kid) => format!(r#""kid":{}"#, quoted(kid)?),
    };
    let header = format!(
        r#"{{"alg":"ES256",{who},"nonce":{},"url":{}}}"#,
        quoted(nonce)?,
        quoted(url)?
    );
    let protected = b64url_encode(header.as_bytes());
    let payload = payload.map(b64url_encode).unwrap_or_default();
    let input = format!("{protected}.{payload}");
    Ok((input, payload))
}

/// The flattened JWS body: `{"protected","payload","signature"}` for a signing `input` (as
/// [`signing_input`] made it) and the raw `r ‖ s` `signature`.
///
/// # Errors
/// [`AcmeError::Key`] for a signature that is not 64 bytes.
pub fn body(input: &str, signature: &[u8]) -> Result<Vec<u8>, AcmeError> {
    if signature.len() != 64 {
        return Err(AcmeError::Key);
    }
    let (protected, payload) = input.split_once('.').ok_or(AcmeError::Key)?;
    Ok(format!(
        r#"{{"protected":"{protected}","payload":"{payload}","signature":"{}"}}"#,
        b64url_encode(signature)
    )
    .into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use access_kernel::json::b64url_decode;
    use suiss_crypto::signer::{Signer as _, SoftSigner};

    // RFC 8555 §6.2, RFC 7638 §3.1
    #[test]
    fn requests_are_flattened_es256_jws_with_nonce_and_url() {
        let (key, _) = SoftSigner::generate_p256().unwrap();
        let suiss_crypto::cose::PublicKey::P256(point) = key.public_key() else {
            panic!("p256");
        };
        let (input, _) = signing_input(
            Signer::Kid("https://acme.example/acct/1"),
            "n0nce",
            "https://acme.example/order",
            Some(br#"{"identifiers":[]}"#),
        )
        .unwrap();
        let sig = key.sign(input.as_bytes()).unwrap();
        let jws: serde_json::Value = serde_json::from_slice(&body(&input, &sig).unwrap()).unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&b64url_decode(jws["protected"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["nonce"], "n0nce");
        assert_eq!(header["url"], "https://acme.example/order");
        assert_eq!(header["kid"], "https://acme.example/acct/1");
        assert!(header.get("jwk").is_none());
        let (get, payload) =
            signing_input(Signer::Jwk(&point), "n", "https://acme.example/x", None).unwrap();
        assert!(payload.is_empty() && get.ends_with('.'));
        let ka = key_authorization("tok-en_1", &point).unwrap();
        assert!(ka.starts_with("tok-en_1."));
        assert_eq!(alpn_digest(&ka), sha256(ka.as_bytes()));
        assert!(key_authorization("bad token", &point).is_err());
    }
}
