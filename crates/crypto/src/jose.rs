//! JOSE signature production (CR-5, CR-6 c, OP-5): compact JWS with a protected header of
//! exactly `alg`, `kid` and `typ` (`alg` and `typ` for a key binding JWT), and public JWKs.
//! Verification is the Kernel's (`verify::jws`).

pub mod output;

use access_kernel::json::{self, Json, b64url_encode};
use access_kernel::verify::jws::MAX_PAYLOAD;
use suiss_crypto::cose::{Algorithm, PublicKey};
use suiss_crypto::signer::{SignError, Signer};

/// A JWS algorithm Access signs with, by its fully-specified name (CR-5, MD-3); `EdDSA` is
/// never produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JwsAlg {
    /// ECDSA P-256 with SHA-256, `r ‖ s` with low S.
    Es256,
    /// Ed25519.
    Ed25519,
}

impl JwsAlg {
    /// The JOSE `alg` value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Ed25519 => "Ed25519",
        }
    }

    /// The Kernel algorithm a verifier allows for it.
    #[must_use]
    pub const fn algorithm(self) -> Algorithm {
        match self {
            Self::Es256 => Algorithm::Es256,
            Self::Ed25519 => Algorithm::Ed25519,
        }
    }

    /// The algorithm a public key signs with.
    #[must_use]
    pub const fn of(key: &PublicKey) -> Option<Self> {
        match key {
            PublicKey::P256(_) => Some(Self::Es256),
            PublicKey::Ed25519(_) => Some(Self::Ed25519),
            PublicKey::MlDsa(..) => None,
        }
    }
}

/// Why a JWS or JWK could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JoseError {
    /// `typ` is empty, too long or not a media type token.
    #[error("typ")]
    Type,
    /// The payload is not a JSON object within the Kernel's size limit.
    #[error("payload")]
    Payload,
    /// The key is not one Access signs JWS with, or not a valid encoding.
    #[error("key")]
    Key,
    /// The signer failed.
    #[error("sign: {0}")]
    Sign(#[from] SignError),
}

impl JoseError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Type => "jose-typ",
            Self::Payload => "jose-payload",
            Self::Key => "jose-key",
            Self::Sign(e) => e.code(),
        }
    }
}

const MAX_TYP: usize = 64;

fn typ_ok(typ: &str) -> bool {
    !typ.is_empty()
        && typ.len() <= MAX_TYP
        && typ
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+/".contains(&b))
}

fn coordinates(key: &PublicKey) -> Result<(&[u8], &[u8]), JoseError> {
    match key {
        PublicKey::P256(sec1) if sec1.len() == 65 && sec1.first() == Some(&4) => sec1
            .get(1..)
            .and_then(|xy| xy.split_at_checked(32))
            .ok_or(JoseError::Key),
        _ => Err(JoseError::Key),
    }
}

/// A compact JWS over a JSON object `payload` with the protected header
/// `{"alg","kid","typ"}`; `kid` is the base64url of the key's RFC 7638 thumbprint (CR-24).
///
/// # Errors
/// [`JoseError`].
pub fn sign_compact(
    signer: &dyn Signer,
    kid: &[u8; 32],
    typ: &str,
    payload: &[u8],
) -> Result<String, JoseError> {
    sign(signer, Kid::Thumbprint(kid), Some(typ), payload)
}

/// A compact JWS whose protected header is exactly `{"alg","typ"}`: a key binding JWT, which
/// is verified with the key the issuer named (RFC 9901 §4.3, L0-SIG-52).
///
/// # Errors
/// [`JoseError`].
pub fn sign_compact_unkeyed(
    signer: &dyn Signer,
    typ: &str,
    payload: &[u8],
) -> Result<String, JoseError> {
    sign(signer, Kid::None, Some(typ), payload)
}

/// A compact JWS whose protected header is exactly `{"alg","kid"}` with a `kid` another party
/// assigned (1 to 64 ASCII letters and digits): the client assertion a provider such as Apple
/// expects from a key it issued (OP-153 m.3 (l)).
///
/// # Errors
/// [`JoseError`]; [`JoseError::Key`] for a `kid` outside that shape.
pub fn sign_compact_assigned(
    signer: &dyn Signer,
    kid: &str,
    payload: &[u8],
) -> Result<String, JoseError> {
    if !(1..=64).contains(&kid.len()) || !kid.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(JoseError::Key);
    }
    sign(signer, Kid::Assigned(kid), None, payload)
}

enum Kid<'a> {
    None,
    Thumbprint(&'a [u8; 32]),
    Assigned(&'a str),
}

fn sign(
    signer: &dyn Signer,
    kid: Kid<'_>,
    typ: Option<&str>,
    payload: &[u8],
) -> Result<String, JoseError> {
    if typ.is_some_and(|t| !typ_ok(t)) {
        return Err(JoseError::Type);
    }
    if !matches!(json::parse(payload, MAX_PAYLOAD), Ok(Json::Object(_))) {
        return Err(JoseError::Payload);
    }
    let key = signer.public_key();
    let alg = JwsAlg::of(&key).ok_or(JoseError::Key)?;
    let consistent = match alg {
        JwsAlg::Es256 => matches!(signer.algorithm(), Algorithm::Es256 | Algorithm::Esp256),
        JwsAlg::Ed25519 => signer.algorithm() == Algorithm::Ed25519,
    };
    if !consistent {
        return Err(JoseError::Key);
    }
    let header = match (kid, typ) {
        (Kid::Thumbprint(kid), Some(typ)) => format!(
            r#"{{"alg":"{}","kid":"{}","typ":"{typ}"}}"#,
            alg.name(),
            b64url_encode(kid)
        ),
        (Kid::None, Some(typ)) => format!(r#"{{"alg":"{}","typ":"{typ}"}}"#, alg.name()),
        (Kid::Assigned(kid), None) => format!(r#"{{"alg":"{}","kid":"{kid}"}}"#, alg.name()),
        _ => return Err(JoseError::Type),
    };
    let mut out = b64url_encode(header.as_bytes());
    out.push('.');
    out.push_str(&b64url_encode(payload));
    // CR-9
    let signature = signer.sign(out.as_bytes())?;
    out.push('.');
    out.push_str(&b64url_encode(&signature));
    Ok(out)
}

/// The RFC 7638 members of `key`'s public JWK, for `cnf.jwk` (RFC 7800).
///
/// # Errors
/// [`JoseError::Key`].
pub fn confirmation_jwk(key: &PublicKey) -> Result<Json, JoseError> {
    let member = |name: &str, value: String| (String::from(name), Json::Str(value));
    if let PublicKey::Ed25519(x) = key {
        return Ok(Json::Object(vec![
            member("crv", String::from("Ed25519")),
            member("kty", String::from("OKP")),
            member("x", b64url_encode(x)),
        ]));
    }
    let (x, y) = coordinates(key)?;
    Ok(Json::Object(vec![
        member("crv", String::from("P-256")),
        member("kty", String::from("EC")),
        member("x", b64url_encode(x)),
        member("y", b64url_encode(y)),
    ]))
}

/// The public JWK of `key` with its `kid`, `alg` and `use: "sig"`: EC P-256 or OKP Ed25519
/// (RFC 7517, RFC 8037). `AKP` keys are not published (MD-3, closed by default).
///
/// # Errors
/// [`JoseError::Key`].
pub fn public_jwk(kid: &[u8; 32], key: &PublicKey) -> Result<String, JoseError> {
    let alg = JwsAlg::of(key).ok_or(JoseError::Key)?;
    let kid = b64url_encode(kid);
    if let PublicKey::Ed25519(x) = key {
        return Ok(format!(
            r#"{{"kty":"OKP","crv":"Ed25519","x":"{}","kid":"{kid}","alg":"{}","use":"sig"}}"#,
            b64url_encode(x),
            alg.name()
        ));
    }
    let (x, y) = coordinates(key)?;
    Ok(format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","kid":"{kid}","alg":"{}","use":"sig"}}"#,
        b64url_encode(x),
        b64url_encode(y),
        alg.name()
    ))
}

#[cfg(test)]
mod tests;
