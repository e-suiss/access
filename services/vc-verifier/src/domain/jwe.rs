//! The encrypted wallet response (`direct_post.jwt`, OID4VP 1.0 §8.3; HAIP): a compact JWE with
//! `alg` `ECDH-ES` on P-256 and `enc` `A128GCM` or `A256GCM`, to the request's own response key.
//! A request's key is derived from the verifier's response secret and the request id, so no
//! private key is stored per request. The key agreement and AEAD are `esuiss-crypto`'s.

use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use suiss_crypto::ecdh_es::{EcdhKey, Enc};
use suiss_crypto::secret::Secret;

/// Largest JWE accepted.
pub const MAX_JWE: usize = 512 * 1024;

const KEY_CONTEXT: &[u8] = b"access-vc-verifier/response-key/v1";

/// Why a response is not decrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JweError {
    /// Not a compact JWE in the profile.
    #[error("response-malformed")]
    Malformed,
    /// `alg`, `enc` or `kid` outside the profile.
    #[error("response-alg")]
    Algorithm,
    /// The response does not decrypt.
    #[error("response-decrypt")]
    Decrypt,
    /// No key could be made.
    #[error("response-key")]
    Key,
}

/// The `enc` values offered (HAIP).
pub const ENC_VALUES: [&str; 2] = ["A128GCM", "A256GCM"];

/// The response key of `request`, derived from `secret`.
///
/// # Errors
/// [`JweError::Key`].
pub fn response_key(secret: &Secret<[u8; 32]>, request: &[u8; 16]) -> Result<EcdhKey, JweError> {
    let mut context = KEY_CONTEXT.to_vec();
    context.extend_from_slice(request);
    EcdhKey::derive(secret, &context).map_err(|_| JweError::Key)
}

/// The public key's JWK coordinates and RFC 7638 thumbprint.
///
/// # Errors
/// [`JweError::Key`].
pub fn public_jwk(key: &EcdhKey) -> Result<(String, String, [u8; 32]), JweError> {
    let sec1 = key.public_point().map_err(|_| JweError::Key)?;
    let (x, y) = match sec1.as_slice() {
        [0x04, rest @ ..] if rest.len() == 64 => rest.split_at(32),
        _ => return Err(JweError::Key),
    };
    let (x, y) = (b64url_encode(x), b64url_encode(y));
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    Ok((x, y, suiss_crypto::digest::sha256(canonical.as_bytes())))
}

fn epk_point(epk: &Json) -> Result<Vec<u8>, JweError> {
    let field = |n: &str| {
        epk.get(n)
            .and_then(Json::as_str)
            .and_then(|s| b64url_decode(s).ok())
            .filter(|b| b.len() == 32)
    };
    if epk.get("kty").and_then(Json::as_str) != Some("EC")
        || epk.get("crv").and_then(Json::as_str) != Some("P-256")
    {
        return Err(JweError::Algorithm);
    }
    let (x, y) = (
        field("x").ok_or(JweError::Malformed)?,
        field("y").ok_or(JweError::Malformed)?,
    );
    Ok([&[0x04][..], &x, &y].concat())
}

fn bytes_member(header: &Json, name: &str) -> Result<Vec<u8>, JweError> {
    header.get(name).map_or(Ok(Vec::new()), |v| {
        v.as_str()
            .and_then(|s| b64url_decode(s).ok())
            .ok_or(JweError::Malformed)
    })
}

/// Decrypts a compact JWE to the request's key; `kid` is the key's thumbprint as published.
///
/// # Errors
/// [`JweError`].
pub fn decrypt(compact: &str, key: &EcdhKey, kid: &str) -> Result<Vec<u8>, JweError> {
    if compact.len() > MAX_JWE {
        return Err(JweError::Malformed);
    }
    let mut parts = compact.split('.');
    let (Some(h), Some(ek), Some(iv), Some(ct), Some(tag), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(JweError::Malformed);
    };
    if !ek.is_empty() {
        return Err(JweError::Algorithm);
    }
    let header = json::parse(&b64url_decode(h).map_err(|_| JweError::Malformed)?, 4096)
        .map_err(|_| JweError::Malformed)?;
    let Json::Object(members) = &header else {
        return Err(JweError::Malformed);
    };
    if members.iter().any(|(k, _)| {
        !matches!(
            k.as_str(),
            "alg" | "enc" | "epk" | "kid" | "apu" | "apv" | "typ" | "cty"
        )
    }) {
        return Err(JweError::Algorithm);
    }
    if header.get("alg").and_then(Json::as_str) != Some("ECDH-ES")
        || header
            .get("kid")
            .and_then(Json::as_str)
            .is_some_and(|k| k != kid)
    {
        return Err(JweError::Algorithm);
    }
    let enc = header
        .get("enc")
        .and_then(Json::as_str)
        .and_then(Enc::parse)
        .ok_or(JweError::Algorithm)?;
    let point = epk_point(header.get("epk").ok_or(JweError::Malformed)?)?;
    let (apu, apv) = (bytes_member(&header, "apu")?, bytes_member(&header, "apv")?);
    let iv: [u8; 12] = b64url_decode(iv)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(JweError::Malformed)?;
    let mut sealed = b64url_decode(ct).map_err(|_| JweError::Malformed)?;
    let tag = b64url_decode(tag).map_err(|_| JweError::Malformed)?;
    if tag.len() != 16 {
        return Err(JweError::Malformed);
    }
    sealed.extend_from_slice(&tag);
    key.open(&point, (enc, &apu, &apv), iv, h.as_bytes(), sealed)
        .map_err(|_| JweError::Decrypt)
}

/// Encrypts `plaintext` to `recipient` (uncompressed P-256 point) as a wallet does, with a
/// fresh ephemeral key.
///
/// # Errors
/// [`JweError`].
pub fn encrypt(
    plaintext: &[u8],
    recipient: &[u8],
    kid: &str,
    enc: Enc,
) -> Result<String, JweError> {
    let ephemeral = EcdhKey::generate().map_err(|_| JweError::Key)?;
    let (x, y, _) = public_jwk(&ephemeral)?;
    let header = format!(
        r#"{{"alg":"ECDH-ES","enc":"{}","kid":"{kid}","epk":{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}}}"#,
        enc.name()
    );
    let h = b64url_encode(header.as_bytes());
    let (iv, mut sealed) = ephemeral
        .seal(recipient, enc, h.as_bytes(), plaintext)
        .map_err(|_| JweError::Key)?;
    let tag = sealed.split_off(sealed.len().saturating_sub(16));
    Ok(format!(
        "{h}..{}.{}.{}",
        b64url_encode(&iv),
        b64url_encode(&sealed),
        b64url_encode(&tag)
    ))
}
