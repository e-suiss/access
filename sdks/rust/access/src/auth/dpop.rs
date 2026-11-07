//! DPoP proofs on the client (RFC 9449 §4): `typ` `dpop+jwt`, the public key as `jwk`, `jti`
//! from the random port, `htm`, the normalised `htu` without query and fragment, `iat`, and
//! `ath` and `nonce` when given. The key signs through the [`ProofKey`] port, so it can stay in
//! a platform key store; the proof verifies with the same Kernel check a resource server runs.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use access_kernel::json::b64url_encode;
use access_kernel::model::TrustedTime;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::dpop::{DPOP_TYP, ath, normalize_htu};
use access_kernel::verify::key_scope::thumbprint;

use super::{Random, random_text};

/// The signer port: the public key and a signature over the JWS signing input (`Ed25519`, or
/// `ES256` as the 64-byte `r ‖ s`).
pub trait ProofKey {
    /// The public key.
    fn public_key(&self) -> &PublicKey;
    /// Signs `input`; `None` when the key store did not answer.
    fn sign(&self, input: &[u8]) -> Option<Vec<u8>>;
}

/// Why no proof was built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofError {
    /// The key type has no JOSE algorithm here.
    #[error("dpop-key")]
    Key,
    /// The URI is not an absolute `http(s)` URI.
    #[error("dpop-uri")]
    Uri,
    /// No randomness.
    #[error("dpop-random")]
    Random,
    /// The signer did not answer.
    #[error("dpop-signer")]
    Signer,
}

/// The request a proof is for.
#[derive(Clone, Copy, Debug)]
pub struct ProofFor<'a> {
    /// The method, as sent.
    pub method: &'a str,
    /// The target URI.
    pub uri: &'a str,
    /// The access token sent with the proof, for `ath`.
    pub access_token: Option<&'a str>,
    /// The server's latest `DPoP-Nonce`.
    pub nonce: Option<&'a str>,
}

fn text(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The public JWK of `key` (RFC 7638 members only) and its JOSE algorithm.
///
/// # Errors
/// [`ProofError::Key`].
pub fn jwk(key: &PublicKey) -> Result<(String, &'static str), ProofError> {
    match key {
        PublicKey::Ed25519(x) => Ok((
            alloc::format!(
                r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                b64url_encode(x)
            ),
            "Ed25519",
        )),
        PublicKey::P256(sec1) => {
            let (Some(x), Some(y)) = (sec1.get(1..33), sec1.get(33..65)) else {
                return Err(ProofError::Key);
            };
            if sec1.len() != 65 || sec1.first() != Some(&4) {
                return Err(ProofError::Key);
            }
            Ok((
                alloc::format!(
                    r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                    b64url_encode(x),
                    b64url_encode(y)
                ),
                "ES256",
            ))
        }
        PublicKey::MlDsa(..) => Err(ProofError::Key),
    }
}

/// The key's RFC 7638 thumbprint as `dpop_jkt` / `cnf.jkt` text.
#[must_use]
pub fn jkt(key: &PublicKey) -> String {
    b64url_encode(&thumbprint(key))
}

/// Builds a proof for `request` at trusted time `now` (milliseconds).
///
/// # Errors
/// [`ProofError`].
pub fn proof(
    key: &impl ProofKey,
    request: &ProofFor<'_>,
    now: TrustedTime,
    rng: &impl Random,
) -> Result<String, ProofError> {
    let (jwk, alg) = jwk(key.public_key())?;
    let htu = normalize_htu(request.uri).ok_or(ProofError::Uri)?;
    let jti = random_text::<16>(rng).map_err(|_| ProofError::Random)?;
    let header = alloc::format!(r#"{{"typ":"{DPOP_TYP}","alg":"{alg}","jwk":{jwk}}}"#);
    let mut claims = String::from("{\"jti\":");
    text(&mut claims, &jti);
    claims.push_str(",\"htm\":");
    text(&mut claims, request.method);
    claims.push_str(",\"htu\":");
    text(&mut claims, &htu);
    let _ = write!(claims, ",\"iat\":{}", now / 1000);
    if let Some(token) = request.access_token {
        claims.push_str(",\"ath\":");
        text(&mut claims, &ath(token));
    }
    if let Some(nonce) = request.nonce {
        claims.push_str(",\"nonce\":");
        text(&mut claims, nonce);
    }
    claims.push('}');
    let mut out = b64url_encode(header.as_bytes());
    out.push('.');
    out.push_str(&b64url_encode(claims.as_bytes()));
    let signature = key.sign(out.as_bytes()).ok_or(ProofError::Signer)?;
    out.push('.');
    out.push_str(&b64url_encode(&signature));
    Ok(out)
}
