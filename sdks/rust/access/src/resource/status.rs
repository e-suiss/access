//! The Token Status List at the resource server (L2-STL-1 to L2-STL-3, §9.12.4, PI-9, OP-150
//! m.7 (e), m.10 (b), (c)): the list the token's `status` claim names, verified as a CWT under
//! the domain's `status-list` key, from its excerpt or its Domain Metadata, read within Δ of the
//! canonical position it reflects. A set bit is DENY; a list that cannot be read or is older
//! than Δ is DENY; the list never extends anything.

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::json::{self, Json, b64url_decode};
use access_kernel::model::TrustedTime;
use access_kernel::status::{self, CWT_CONTENT_TYPE, ListToken, StatusRef};
use access_kernel::verify::PureBackend;
use alloc::collections::BTreeSet;

use access_kernel::verify::cose::{Algorithm, parse_sign1, verify_sign1};
use access_kernel::verify::jws::{MAX_PAYLOAD, Origin, verify_compact};
use access_kernel::verify::key_scope::{DomainMetadata, KeyUsage, operational_key};

use super::Denied;
use crate::transport::{Answer, Response};

/// `typ` of a list token in JWT form.
pub const JWT_TYP: &str = "statuslist+jwt";

/// Largest inflated list, in bytes: 2^25 one-bit entries (OP-150 m.7 (g)).
pub const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;

/// The status list port: fetches the list at `uri`.
pub trait StatusSource {
    /// The list token, as served.
    fn list(&self, uri: &str) -> Answer;
}

/// What the resource server verifies lists with: the domain's verified Domain Metadata, whose
/// `status-list` keys sign both forms (CR-58 m.2, TI-RT6); a realm key signs no list.
#[derive(Clone, Copy, Debug)]
pub struct ListKeys<'a> {
    /// Verified Domain Metadata.
    pub metadata: &'a DomainMetadata,
    /// Signature algorithms the resource server allows (MD-3).
    pub allowed: &'a BTreeSet<Algorithm>,
}

fn inflate(lst: &[u8]) -> Result<Vec<u8>, Denied> {
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(lst, MAX_LIST_BYTES)
        .map_err(|_| Denied::StatusMalformed)
}

fn cwt(response: &Response, keys: &ListKeys<'_>) -> Result<(ListToken, Vec<u8>), Denied> {
    let metadata = keys.metadata;
    let Some(excerpt) = &response.key_excerpt else {
        return Err(Denied::StatusKey);
    };
    let unverified = parse_sign1(&response.body)
        .ok()
        .and_then(|s| s.payload)
        .ok_or(Denied::StatusMalformed)?;
    let claimed = ListToken::from_bytes(&unverified).map_err(|_| Denied::StatusMalformed)?;
    let iat = claimed
        .iat
        .checked_mul(1000)
        .ok_or(Denied::StatusMalformed)?;
    let key = operational_key(
        &PureBackend,
        metadata,
        &metadata.domain,
        excerpt,
        KeyUsage::StatusList,
        iat,
    )
    .map_err(|_| Denied::StatusKey)?;
    let verified = verify_sign1(
        &PureBackend,
        &response.body,
        &key.key_set(),
        CWT_CONTENT_TYPE,
    )
    .map_err(|_| Denied::StatusSignature)?;
    let token = ListToken::from_bytes(&verified.payload).map_err(|_| Denied::StatusMalformed)?;
    let bits = inflate(&token.lst)?;
    Ok((token, bits))
}

fn uint(v: &Json, name: &str) -> Option<u64> {
    v.get(name)
        .and_then(Json::as_int)
        .and_then(|i| u64::try_from(i).ok())
}

fn jwt(response: &Response, keys: &ListKeys<'_>) -> Result<(ListToken, Vec<u8>), Denied> {
    let text = core::str::from_utf8(&response.body).map_err(|_| Denied::StatusMalformed)?;
    let list_keys = super::keys::usage_keys(keys.metadata, KeyUsage::StatusList, keys.allowed);
    let verified = verify_compact(
        &PureBackend,
        text.trim(),
        &list_keys,
        JWT_TYP,
        Origin::Native,
    )
    .map_err(|_| Denied::StatusSignature)?;
    let claims =
        json::parse(&verified.payload, MAX_PAYLOAD).map_err(|_| Denied::StatusMalformed)?;
    // §9.10 step 1
    let signed_at = uint(&claims, "iat").ok_or(Denied::StatusMalformed)?;
    if !super::keys::live_at(
        keys.metadata,
        &verified.kid,
        KeyUsage::StatusList,
        signed_at,
    ) {
        return Err(Denied::StatusKey);
    }
    let uri = claims
        .get("sub")
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty() && s.len() <= status::MAX_URI)
        .ok_or(Denied::StatusMalformed)?;
    let list = claims.get("status_list").ok_or(Denied::StatusMalformed)?;
    if uint(list, "bits") != Some(status::BITS) {
        return Err(Denied::StatusMalformed);
    }
    let compressed = list
        .get("lst")
        .and_then(Json::as_str)
        .and_then(|s| b64url_decode(s).ok())
        .ok_or(Denied::StatusMalformed)?;
    let token = ListToken {
        uri: String::from(uri),
        iat: uint(&claims, "iat").ok_or(Denied::StatusMalformed)?,
        exp: uint(&claims, "exp"),
        ttl: uint(&claims, "ttl"),
        lst: compressed,
        aggregation_uri: None,
        as_of: uint(&claims, "as_of").unwrap_or(0),
    };
    let bits = inflate(&token.lst)?;
    Ok((token, bits))
}

/// How fresh the list must be: the contract's Δ when it declares one, else the list's own
/// `ttl`, else its `exp` − `iat`; a list that declares none cannot be trusted for freshness.
fn freshness_ms(token: &ListToken, max_staleness_ms: Option<u64>) -> Result<u64, Denied> {
    if let Some(delta) = max_staleness_ms {
        return Ok(delta);
    }
    if let Some(ttl) = token.ttl {
        return ttl.checked_mul(1000).ok_or(Denied::StatusMalformed);
    }
    token
        .exp
        .and_then(|exp| exp.checked_sub(token.iat))
        .and_then(|s| s.checked_mul(1000))
        .ok_or(Denied::StatusStale)
}

/// Verifies the list `answer` for `reference` and reads the entry (L2-STL-2, L2-STL-3): the
/// list must be the referenced one, signed, no older than Δ measured from the `recorded_at` it
/// reflects, and the bit clear. The Kernel's `as_of` of the list is returned.
///
/// # Errors
/// [`Denied`].
pub fn check(
    answer: Answer,
    reference: &StatusRef,
    keys: &ListKeys<'_>,
    now: TrustedTime,
    max_staleness_ms: Option<u64>,
) -> Result<u64, Denied> {
    let response = match answer {
        Answer::Unanswered(fault) => return Err(Denied::StatusUnavailable(fault)),
        Answer::Response(r) if r.status != 200 => return Err(Denied::StatusStatus(r.status)),
        Answer::Response(r) => r,
    };
    let is_cwt = match &response.content_type {
        Some(ct) => ct.contains("statuslist+cwt"),
        None => response.body.first() == Some(&0xd2),
    };
    let (token, bits) = if is_cwt {
        cwt(&response, keys)?
    } else {
        jwt(&response, keys)?
    };
    // PI-9, T24: freshness is measured from the position's recorded_at, never the fetch
    let recorded_at = token.iat.checked_mul(1000).ok_or(Denied::StatusMalformed)?;
    let age = now.checked_sub(recorded_at).ok_or(Denied::StatusStale)?;
    if age > freshness_ms(&token, max_staleness_ms)? {
        return Err(Denied::StatusStale);
    }
    if token
        .exp
        .and_then(|e| e.checked_mul(1000))
        .is_some_and(|exp| exp <= now)
    {
        return Err(Denied::StatusStale);
    }
    match status::lookup(&token, &bits, reference) {
        Ok(false) => Ok(token.as_of),
        Ok(true) => Err(Denied::Revoked),
        Err(status::StatusError::Uri) => Err(Denied::StatusUri),
        Err(_) => Err(Denied::StatusIndex),
    }
}
