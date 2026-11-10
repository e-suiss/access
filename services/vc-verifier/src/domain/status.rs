//! Credential status (Ek B 4921, §4.4 K14): the IETF Token Status List
//! (`application/statuslist+jwt`) a credential names in `status.status_list`, and the W3C
//! Bitstring Status List a VC names in `credentialStatus`, secured as VC-JOSE (`vc+jwt`). Only
//! "valid" admits a credential: revoked, suspended, any other value, an expired list, a list for
//! another URI or an index past the end all refuse it.

use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::model::TrustedTime;
use access_kernel::verify::Backend;
use access_kernel::verify::cose::PublicKey;

use super::sd_jwt_vc::standard_b64_decode;
use super::time::rfc3339_ms;

/// Largest inflated list: 2^25 bytes.
pub const MAX_LIST: usize = 1 << 25;
/// Largest list token.
pub const MAX_TOKEN: usize = 4 * 1024 * 1024;
/// The Token Status List JWT `typ`.
pub const STATUS_TYP: &str = "statuslist+jwt";
/// The VC-JOSE `typ` of a Bitstring Status List credential.
pub const VC_TYP: &str = "vc+jwt";

/// Why a status check refuses a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StatusError {
    /// The credential's status reference is malformed.
    #[error("status-reference")]
    Reference,
    /// The list could not be read, is unsigned by the issuer, or has the wrong shape.
    #[error("status-list")]
    List,
    /// The list is expired.
    #[error("status-stale")]
    Stale,
    /// The index lies past the end of the list.
    #[error("status-index")]
    Index,
    /// The credential is revoked.
    #[error("status-revoked")]
    Revoked,
    /// The credential is suspended, or its status is a value other than valid.
    #[error("status-suspended")]
    Suspended,
}

impl StatusError {
    /// Stable code.
    #[must_use]
    pub fn code(self) -> String {
        self.to_string()
    }
}

/// Where a credential's status is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reference {
    /// A Token Status List entry.
    TokenList {
        /// The index.
        idx: u64,
        /// The list token's URI.
        uri: String,
    },
    /// A Bitstring Status List entry.
    Bitstring {
        /// The index.
        idx: u64,
        /// The status list credential's URL.
        uri: String,
        /// `revocation` or `suspension`.
        purpose: Purpose,
    },
}

/// A Bitstring Status List purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// A set bit is a revocation.
    Revocation,
    /// A set bit is a suspension.
    Suspension,
}

impl Reference {
    /// The list's URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        match self {
            Self::TokenList { uri, .. } | Self::Bitstring { uri, .. } => uri,
        }
    }
}

fn https(uri: &str) -> Result<String, StatusError> {
    if uri.starts_with("https://") && uri.len() <= 2048 && !uri.contains(['#', ' ']) {
        Ok(String::from(uri))
    } else {
        Err(StatusError::Reference)
    }
}

/// The status reference of a credential's claims, if any: `status.status_list` (Token Status
/// List) or `credentialStatus` of type `BitstringStatusListEntry`.
///
/// # Errors
/// [`StatusError::Reference`].
pub fn reference(claims: &Json) -> Result<Option<Reference>, StatusError> {
    if let Some(status) = claims.get("status") {
        let list = status.get("status_list").ok_or(StatusError::Reference)?;
        let idx = list
            .get("idx")
            .and_then(Json::as_int)
            .and_then(|i| u64::try_from(i).ok())
            .ok_or(StatusError::Reference)?;
        let uri = https(
            list.get("uri")
                .and_then(Json::as_str)
                .ok_or(StatusError::Reference)?,
        )?;
        return Ok(Some(Reference::TokenList { idx, uri }));
    }
    if let Some(entry) = claims.get("credentialStatus") {
        if entry.get("type").and_then(Json::as_str) != Some("BitstringStatusListEntry") {
            return Err(StatusError::Reference);
        }
        let purpose = match entry.get("statusPurpose").and_then(Json::as_str) {
            Some("revocation") => Purpose::Revocation,
            Some("suspension") => Purpose::Suspension,
            _ => return Err(StatusError::Reference),
        };
        let idx = entry
            .get("statusListIndex")
            .and_then(Json::as_str)
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .ok_or(StatusError::Reference)?;
        let uri = https(
            entry
                .get("statusListCredential")
                .and_then(Json::as_str)
                .ok_or(StatusError::Reference)?,
        )?;
        return Ok(Some(Reference::Bitstring { idx, uri, purpose }));
    }
    Ok(None)
}

/// A list token or list credential read but not verified.
#[derive(Clone, Debug)]
pub struct ListJwt<'a> {
    /// `x5c`, DER, leaf first.
    pub x5c: Vec<Vec<u8>>,
    /// `kid`.
    pub kid: Option<String>,
    /// The payload.
    pub payload: Json,
    typ: String,
    signing_input: &'a str,
    signature: Vec<u8>,
}

/// Reads a list JWT.
///
/// # Errors
/// [`StatusError::List`].
pub fn parse(token: &str) -> Result<ListJwt<'_>, StatusError> {
    if token.len() > MAX_TOKEN {
        return Err(StatusError::List);
    }
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(StatusError::List);
    };
    let end = h
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_add(p.len()))
        .ok_or(StatusError::List)?;
    let header = json::parse(&b64url_decode(h).map_err(|_| StatusError::List)?, 16 * 1024)
        .map_err(|_| StatusError::List)?;
    let Json::Object(members) = &header else {
        return Err(StatusError::List);
    };
    let (mut typ, mut kid, mut x5c, mut alg) = (None, None, Vec::new(), None);
    for (k, v) in members {
        match (k.as_str(), v) {
            ("alg", Json::Str(a)) => alg = Some(a.as_str()),
            ("typ", Json::Str(t)) => typ = Some(t.clone()),
            ("kid", Json::Str(t)) => kid = Some(t.clone()),
            ("x5c", Json::Array(items)) if items.len() <= 4 => {
                for i in items {
                    x5c.push(
                        i.as_str()
                            .and_then(standard_b64_decode)
                            .ok_or(StatusError::List)?,
                    );
                }
            }
            _ => return Err(StatusError::List),
        }
    }
    if alg != Some("ES256") {
        return Err(StatusError::List);
    }
    let payload = json::parse(&b64url_decode(p).map_err(|_| StatusError::List)?, MAX_TOKEN)
        .map_err(|_| StatusError::List)?;
    Ok(ListJwt {
        x5c,
        kid,
        payload,
        typ: typ.ok_or(StatusError::List)?,
        signing_input: token.get(..end).ok_or(StatusError::List)?,
        signature: b64url_decode(s).map_err(|_| StatusError::List)?,
    })
}

fn millis(v: Option<&Json>) -> Option<u64> {
    u64::try_from(v?.as_int()?).ok()?.checked_mul(1000)
}

fn bit_value(bytes: &[u8], idx: u64, bits: u64) -> Result<u8, StatusError> {
    let at = idx.checked_mul(bits).ok_or(StatusError::Index)?;
    let byte = usize::try_from(at / 8).map_err(|_| StatusError::Index)?;
    let shift = u32::try_from(at % 8).map_err(|_| StatusError::Index)?;
    let b = bytes.get(byte).ok_or(StatusError::Index)?;
    let mask = u8::try_from((1_u16 << bits).saturating_sub(1)).map_err(|_| StatusError::List)?;
    Ok((b >> shift) & mask)
}

/// Gunzips a Bitstring Status List (RFC 1952), within [`MAX_LIST`].
///
/// # Errors
/// [`StatusError::List`].
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>, StatusError> {
    let [0x1f, 0x8b, 0x08, flags, _, _, _, _, _, _, rest @ ..] = data else {
        return Err(StatusError::List);
    };
    if flags & 0xe0 != 0 {
        return Err(StatusError::List);
    }
    let mut body = rest;
    if flags & 0x04 != 0 {
        let [lo, hi, tail @ ..] = body else {
            return Err(StatusError::List);
        };
        let n = usize::from(u16::from_le_bytes([*lo, *hi]));
        body = tail.get(n..).ok_or(StatusError::List)?;
    }
    for flag in [0x08, 0x10] {
        if flags & flag != 0 {
            let end = body.iter().position(|b| *b == 0).ok_or(StatusError::List)?;
            body = body.get(end.saturating_add(1)..).ok_or(StatusError::List)?;
        }
    }
    if flags & 0x02 != 0 {
        body = body.get(2..).ok_or(StatusError::List)?;
    }
    let deflated_len = body.len().checked_sub(8).ok_or(StatusError::List)?;
    let (deflated, trailer) = body.split_at(deflated_len);
    let out = miniz_oxide::inflate::decompress_to_vec_with_limit(deflated, MAX_LIST)
        .map_err(|_| StatusError::List)?;
    let size = trailer
        .get(4..8)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes)
        .ok_or(StatusError::List)?;
    if u32::try_from(out.len()).ok() != Some(size) {
        return Err(StatusError::List);
    }
    Ok(out)
}

impl ListJwt<'_> {
    /// Verifies the list's signature with `key` and answers the credential's status at `idx`.
    ///
    /// # Errors
    /// [`StatusError`].
    pub fn check(
        &self,
        backend: &impl Backend,
        key: &PublicKey,
        reference: &Reference,
        now: TrustedTime,
    ) -> Result<(), StatusError> {
        let PublicKey::P256(sec1) = key else {
            return Err(StatusError::List);
        };
        access_kernel::verify::p256(
            backend,
            sec1,
            self.signing_input.as_bytes(),
            &self.signature,
            false,
        )
        .map_err(|_| StatusError::List)?;
        match reference {
            Reference::TokenList { idx, uri } => self.token_list(*idx, uri, now),
            Reference::Bitstring { idx, uri, purpose } => self.bitstring(*idx, uri, *purpose, now),
        }
    }

    fn token_list(&self, idx: u64, uri: &str, now: TrustedTime) -> Result<(), StatusError> {
        if self.typ != STATUS_TYP {
            return Err(StatusError::List);
        }
        let p = &self.payload;
        if p.get("sub").and_then(Json::as_str) != Some(uri) {
            return Err(StatusError::List);
        }
        millis(p.get("iat")).ok_or(StatusError::List)?;
        if let Some(exp) = p.get("exp")
            && millis(Some(exp)).is_none_or(|e| now > e)
        {
            return Err(StatusError::Stale);
        }
        let list = p.get("status_list").ok_or(StatusError::List)?;
        let bits = list
            .get("bits")
            .and_then(Json::as_int)
            .and_then(|b| u64::try_from(b).ok())
            .filter(|b| matches!(b, 1 | 2 | 4 | 8))
            .ok_or(StatusError::List)?;
        let compressed = list
            .get("lst")
            .and_then(Json::as_str)
            .and_then(|s| b64url_decode(s).ok())
            .ok_or(StatusError::List)?;
        let bytes = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&compressed, MAX_LIST)
            .map_err(|_| StatusError::List)?;
        match bit_value(&bytes, idx, bits)? {
            0 => Ok(()),
            1 => Err(StatusError::Revoked),
            _ => Err(StatusError::Suspended),
        }
    }

    fn bitstring(
        &self,
        idx: u64,
        uri: &str,
        purpose: Purpose,
        now: TrustedTime,
    ) -> Result<(), StatusError> {
        if self.typ != VC_TYP {
            return Err(StatusError::List);
        }
        let vc = &self.payload;
        super::w3c::secured_by_jose(vc).map_err(|_| StatusError::List)?;
        let types = vc.get("type").ok_or(StatusError::List)?;
        if !super::w3c::has_type(types, "BitstringStatusListCredential") {
            return Err(StatusError::List);
        }
        if vc
            .get("id")
            .and_then(Json::as_str)
            .is_some_and(|id| id != uri)
        {
            return Err(StatusError::List);
        }
        if let Some(until) = vc.get("validUntil") {
            let until = until
                .as_str()
                .and_then(rfc3339_ms)
                .ok_or(StatusError::List)?;
            if now > until {
                return Err(StatusError::Stale);
            }
        }
        let subject = vc.get("credentialSubject").ok_or(StatusError::List)?;
        let listed = match subject.get("statusPurpose").and_then(Json::as_str) {
            Some("revocation") => Purpose::Revocation,
            Some("suspension") => Purpose::Suspension,
            _ => return Err(StatusError::List),
        };
        if listed != purpose
            || subject.get("type").and_then(Json::as_str) != Some("BitstringStatusList")
        {
            return Err(StatusError::List);
        }
        let encoded = subject
            .get("encodedList")
            .and_then(Json::as_str)
            .and_then(|s| s.strip_prefix('u'))
            .and_then(|s| b64url_decode(s).ok())
            .ok_or(StatusError::List)?;
        let bytes = gunzip(&encoded)?;
        let byte = usize::try_from(idx / 8).map_err(|_| StatusError::Index)?;
        let shift = u32::try_from(7_u64.saturating_sub(idx % 8)).map_err(|_| StatusError::Index)?;
        let b = bytes.get(byte).ok_or(StatusError::Index)?;
        if (b >> shift) & 1 == 0 {
            Ok(())
        } else if purpose == Purpose::Revocation {
            Err(StatusError::Revoked)
        } else {
            Err(StatusError::Suspended)
        }
    }
}
