//! DID resolution on the verifier side (Ek B 4837; §10.7.2): `did:jwk` is read from the DID
//! itself and `did:web` from its `did.json` over HTTPS; every other method is refused. A key is
//! used only when the document lists it under `assertionMethod`.

use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::verify::cose::PublicKey;

use super::sd_jwt_vc::jwk_p256;

/// Largest DID document.
pub const MAX_DOCUMENT: usize = 64 * 1024;

/// Why a DID is not resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DidError {
    /// A method other than `did:web` and `did:jwk`.
    #[error("did-method-unsupported")]
    Method,
    /// A malformed DID or DID URL.
    #[error("did-malformed")]
    Malformed,
    /// No P-256 verification method with that id under `assertionMethod`.
    #[error("did-key")]
    Key,
}

/// What a DID needs to be resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    /// `did:jwk`: the key is in the DID.
    Jwk(PublicKey),
    /// `did:web`: fetch this `https` URL and pick the key from the document.
    Web(String),
}

/// Splits a DID URL into the DID and its fragment.
#[must_use]
pub fn split(did_url: &str) -> (&str, Option<&str>) {
    did_url
        .split_once('#')
        .map_or((did_url, None), |(d, f)| (d, Some(f)))
}

fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
}

/// What resolving `did` takes.
///
/// # Errors
/// [`DidError`].
pub fn resolution(did: &str) -> Result<Resolution, DidError> {
    if did.len() > 2048 {
        return Err(DidError::Malformed);
    }
    if let Some(encoded) = did.strip_prefix("did:jwk:") {
        let raw = b64url_decode(encoded).map_err(|_| DidError::Malformed)?;
        let jwk = json::parse(&raw, 4096).map_err(|_| DidError::Malformed)?;
        if jwk
            .get("use")
            .and_then(Json::as_str)
            .is_some_and(|u| u != "sig")
        {
            return Err(DidError::Key);
        }
        return jwk_p256(&jwk).map(Resolution::Jwk).ok_or(DidError::Key);
    }
    let Some(rest) = did.strip_prefix("did:web:") else {
        return Err(DidError::Method);
    };
    let mut segments = rest.split(':');
    let authority = segments.next().ok_or(DidError::Malformed)?;
    let (host, port) = match authority.split_once("%3A") {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
        Some(_) => return Err(DidError::Malformed),
        None => (authority, None),
    };
    if !host_ok(host) {
        return Err(DidError::Malformed);
    }
    let path: Vec<&str> = segments.collect();
    if path.iter().any(|s| {
        s.is_empty()
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            || *s == "."
            || *s == ".."
    }) {
        return Err(DidError::Malformed);
    }
    let mut url = format!("https://{host}");
    if let Some(p) = port {
        url.push(':');
        url.push_str(p);
    }
    if path.is_empty() {
        url.push_str("/.well-known/did.json");
    } else {
        for s in path {
            url.push('/');
            url.push_str(s);
        }
        url.push_str("/did.json");
    }
    Ok(Resolution::Web(url))
}

fn listed(doc: &Json, relation: &str, id: &str) -> bool {
    let Some(Json::Array(items)) = doc.get(relation) else {
        return false;
    };
    items.iter().any(|i| match i {
        Json::Str(s) => s == id,
        Json::Object(_) => i.get("id").and_then(Json::as_str) == Some(id),
        _ => false,
    })
}

/// The key `did_url` names in the `did:web` document `body`, read for `did`.
///
/// # Errors
/// [`DidError`].
pub fn key_in_document(body: &[u8], did: &str, did_url: &str) -> Result<PublicKey, DidError> {
    let doc = json::parse(body, MAX_DOCUMENT).map_err(|_| DidError::Malformed)?;
    if doc.get("id").and_then(Json::as_str) != Some(did) {
        return Err(DidError::Malformed);
    }
    let (_, fragment) = split(did_url);
    let fragment = fragment.ok_or(DidError::Key)?;
    let full = format!("{did}#{fragment}");
    let relative = format!("#{fragment}");
    let matches = |id: &str| id == full || id == relative;
    let assertion =
        listed(&doc, "assertionMethod", &full) || listed(&doc, "assertionMethod", &relative);
    if !assertion {
        return Err(DidError::Key);
    }
    let methods = match doc.get("verificationMethod") {
        Some(Json::Array(items)) => items.as_slice(),
        _ => &[],
    };
    let embedded = match doc.get("assertionMethod") {
        Some(Json::Array(items)) => items.as_slice(),
        _ => &[],
    };
    methods
        .iter()
        .chain(embedded.iter())
        .filter(|m| m.get("id").and_then(Json::as_str).is_some_and(matches))
        .find_map(|m| m.get("publicKeyJwk").and_then(jwk_p256))
        .ok_or(DidError::Key)
}
