//! Compact JWS reading for federation artefacts: the header profile, key selection by `kid`
//! and signature verification under the ES256/RS256 allowlist (MD-3).

use access_crypto::oauth::{ClientAlg, verify_client_signature};
use access_kernel::json::{self, Json, b64url_decode};

use crate::statement::{Jwk, OidfError};

/// Largest protected header read.
pub(crate) const MAX_HEADER: usize = 16 * 1024;

/// A split compact JWS.
pub(crate) struct Parts<'a> {
    pub(crate) header: Json,
    pub(crate) payload: Json,
    pub(crate) input: &'a str,
    pub(crate) signature: Vec<u8>,
}

/// Splits `token` and parses its header and payload without verifying anything.
pub(crate) fn split(token: &str, max: usize) -> Result<Parts<'_>, OidfError> {
    if token.len() > max {
        return Err(OidfError::Size);
    }
    let mut it = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(OidfError::Format);
    };
    let end = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(OidfError::Format)?;
    let decode = |part: &str| b64url_decode(part).map_err(|_| OidfError::Format);
    let header = json::parse(&decode(h)?, MAX_HEADER).map_err(|_| OidfError::Header)?;
    let payload = json::parse(&decode(p)?, max).map_err(|_| OidfError::Claims)?;
    if !matches!(header, Json::Object(_)) {
        return Err(OidfError::Header);
    }
    if !matches!(payload, Json::Object(_)) {
        return Err(OidfError::Claims);
    }
    Ok(Parts {
        header,
        payload,
        input: token.get(..end).ok_or(OidfError::Format)?,
        signature: decode(s)?,
    })
}

/// The header profile: `alg` from the allowlist, `kid` required, `typ` one of `typ` when given,
/// and no member outside `alg`, `kid`, `typ` and `extra`.
pub(crate) fn check_header(
    header: &Json,
    typ: Option<&[&str]>,
    extra: &[&str],
) -> Result<(ClientAlg, String), OidfError> {
    let Json::Object(members) = header else {
        return Err(OidfError::Header);
    };
    if members
        .iter()
        .any(|(k, _)| !matches!(k.as_str(), "alg" | "kid" | "typ") && !extra.contains(&k.as_str()))
    {
        return Err(OidfError::Header);
    }
    let alg = header
        .get("alg")
        .and_then(Json::as_str)
        .and_then(ClientAlg::from_name)
        .filter(|a| matches!(a, ClientAlg::Es256 | ClientAlg::Rs256))
        .ok_or(OidfError::Algorithm)?;
    let found = header
        .get("typ")
        .map(|t| t.as_str().ok_or(OidfError::Typ))
        .transpose()?;
    if let Some(allowed) = typ
        && !found.is_some_and(|t| allowed.contains(&t))
    {
        return Err(OidfError::Typ);
    }
    let kid = header
        .get("kid")
        .and_then(Json::as_str)
        .filter(|k| !k.is_empty())
        .ok_or(OidfError::Key)?;
    Ok((alg, String::from(kid)))
}

/// Verifies the signature of `parts` with the one key of `keys` whose `kid` the header names.
pub(crate) fn verify(
    parts: &Parts<'_>,
    alg: ClientAlg,
    kid: &str,
    keys: &[Jwk],
) -> Result<(), OidfError> {
    let mut matching = keys.iter().filter(|k| k.kid.as_deref() == Some(kid));
    let (Some(key), None) = (matching.next(), matching.next()) else {
        return Err(OidfError::Key);
    };
    verify_client_signature(alg, &key.key, parts.input.as_bytes(), &parts.signature)
        .map_err(|_| OidfError::Signature)
}

/// A `NumericDate` claim in milliseconds.
pub(crate) fn time_ms(claims: &Json, name: &str) -> Result<Option<u64>, OidfError> {
    claims
        .get(name)
        .map(|v| {
            v.as_int()
                .and_then(|s| u64::try_from(s).ok())
                .and_then(|s| s.checked_mul(1000))
                .ok_or(OidfError::Time)
        })
        .transpose()
}

/// The strings of a JSON array; anything else is `err`.
pub(crate) fn strings(v: &Json, err: OidfError) -> Result<Vec<String>, OidfError> {
    let Json::Array(items) = v else {
        return Err(err);
    };
    items
        .iter()
        .map(|i| i.as_str().map(String::from).ok_or(err))
        .collect()
}
