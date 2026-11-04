//! The product client API's JSON (OP-149 m.4, m.5, OP-65): requests into terms and answers out.
//! Positions travel as decimal strings and times as RFC 3339 UTC (OP-65 rule 4).

use access_authority_core::adapters::KeyAnswer;
use access_authority_core::keys::{self, AsOf, KeyEntry, KeyState, Point};
use access_identity_events::domain::catalog::uuid;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use serde_json::{Map, Value, json};
use suiss_crypto::dcbor::{self, Limits};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::ports::Tenant;

/// Cache lifetime of an answer with a live key, in seconds (OP-149 m.5, PD).
pub const ACTIVE_MAX_AGE: &str = "max-age=60";

/// Cache policy of an answer whose keys have all ended (OP-149 m.5).
pub const ENDED_CACHE: &str = "max-age=31536000, immutable";

/// Most tenants on one page (PD).
pub const TENANT_PAGE: u32 = 100;

/// A request the API refuses; nothing is looked up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("bad request: {0}")]
pub struct BadRequest(pub &'static str);

/// A kid in its JOSE text form: the unpadded base64url of the 32-byte thumbprint (CR-24).
#[must_use]
pub fn kid(text: &str) -> Option<[u8; 32]> {
    let bytes = b64url_decode(text).ok()?;
    let kid = <[u8; 32]>::try_from(bytes).ok()?;
    (b64url_encode(&kid) == text).then_some(kid)
}

/// `as_of`: a ledger position in decimal, or an RFC 3339 time.
///
/// # Errors
/// [`BadRequest`] for anything else.
pub fn as_of(text: Option<&str>) -> Result<AsOf, BadRequest> {
    let Some(text) = text else {
        return Ok(AsOf::Head);
    };
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        return text
            .parse()
            .map(AsOf::Position)
            .map_err(|_| BadRequest("as_of"));
    }
    let t = OffsetDateTime::parse(text, &Rfc3339).map_err(|_| BadRequest("as_of"))?;
    let ms = t.unix_timestamp_nanos() / 1_000_000;
    u64::try_from(ms)
        .map(AsOf::Time)
        .map_err(|_| BadRequest("as_of"))
}

/// A trusted time in milliseconds as RFC 3339 UTC.
#[must_use]
pub fn rfc3339(ms: u64) -> String {
    i128::from(ms)
        .checked_mul(1_000_000)
        .and_then(|n| OffsetDateTime::from_unix_timestamp_nanos(n).ok())
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}

/// A `DomainID` in its text form, `sha-256:` and unpadded base64url (L0-ENC-20).
#[must_use]
pub fn domain_text(d: &Digest) -> String {
    format!("sha-256:{}", b64url_encode(&d.0))
}

/// The batch body `{domain, kids, as_of?}`: 1 to [`keys::MAX_KIDS`] distinct kids.
///
/// # Errors
/// [`BadRequest`].
pub fn batch(body: &[u8]) -> Result<(Digest, Vec<[u8; 32]>, AsOf), BadRequest> {
    let Ok(Value::Object(mut m)) = serde_json::from_slice::<Value>(body) else {
        return Err(BadRequest("json"));
    };
    let domain = m
        .remove("domain")
        .and_then(|d| d.as_str().and_then(crate::adp::adapters::domain_id))
        .ok_or(BadRequest("domain"))?;
    let Some(Value::Array(list)) = m.remove("kids") else {
        return Err(BadRequest("kids"));
    };
    if list.is_empty() || list.len() > keys::MAX_KIDS {
        return Err(BadRequest("kids"));
    }
    let mut kids = Vec::with_capacity(list.len());
    for k in &list {
        let k = k.as_str().and_then(kid).ok_or(BadRequest("kids"))?;
        if kids.contains(&k) {
            return Err(BadRequest("kids"));
        }
        kids.push(k);
    }
    let at = match m.remove("as_of") {
        None => AsOf::Head,
        Some(Value::String(s)) => as_of(Some(&s))?,
        Some(_) => return Err(BadRequest("as_of")),
    };
    if !m.is_empty() {
        return Err(BadRequest("unknown-member"));
    }
    Ok((domain, kids, at))
}

fn point(p: Point) -> Value {
    json!({ "position": p.pos.to_string(), "time": rfc3339(p.at) })
}

/// One key as JSON; `public_key` is the base64url of its `COSE_Key`.
#[must_use]
pub fn key_json(e: &KeyEntry) -> Value {
    let cose = dcbor::encode(&keys::cose_key(&e.key), Limits::CEILING).unwrap_or_default();
    let mut m = Map::new();
    m.insert("kid".into(), b64url_encode(&e.kid).into());
    m.insert("alg".into(), keys::alg(&e.key).into());
    m.insert("public_key".into(), b64url_encode(&cose).into());
    m.insert("party".into(), b64url_encode(&e.party.0).into());
    m.insert("instance".into(), b64url_encode(&e.instance.0).into());
    m.insert("since".into(), point(e.since));
    if let Some(p) = e.ended {
        m.insert("ended".into(), point(p));
    }
    if let Some(s) = e.successor {
        m.insert("successor".into(), b64url_encode(&s.0).into());
    }
    m.insert("key_state".into(), e.state.name().into());
    if let Some(c) = e.compromise {
        m.insert(
            "compromise".into(),
            json!({
                "from": rfc3339(c.from),
                "declared_at": rfc3339(c.declared_at),
                "source": b64url_encode(&c.claim.0),
            }),
        );
    }
    Value::Object(m)
}

/// The JSON form of a lookup: the signed payload's content, unsigned, with the consistency
/// token (OP-149 m.5).
#[must_use]
pub fn lookup_json(a: &KeyAnswer) -> Value {
    let l = &a.lookup;
    json!({
        "domain": domain_text(&l.domain),
        "position": l.pos.to_string(),
        "iat": rfc3339(l.iat),
        "keys": l.keys.iter().map(key_json).collect::<Vec<_>>(),
        "unknown": l.unknown.iter().map(|k| b64url_encode(k)).collect::<Vec<_>>(),
        "consistency_token": a.consistency,
    })
}

/// `Cache-Control` of a lookup: immutable once every key asked for has ended, else short.
#[must_use]
pub fn cache_control(a: &KeyAnswer) -> &'static str {
    let l = &a.lookup;
    if l.unknown.is_empty() && l.keys.iter().all(|k| k.state == KeyState::Ended) {
        ENDED_CACHE
    } else {
        ACTIVE_MAX_AGE
    }
}

/// The snapshot of `tenant` named `id` (OP-149 m.4): its `version` is the digest of the rest,
/// so it changes exactly when the snapshot does. The retention section is empty until OP-147
/// policies are stored. A realm is named by its id as events name it in `accessrealm`, its
/// issuer and its slug.
#[must_use]
pub fn snapshot(id: &str, tenant: &Tenant, region: &str) -> Value {
    let realms: Vec<Value> = tenant
        .realms
        .iter()
        .map(|r| json!({ "id": uuid(&r.id), "issuer": r.issuer, "slug": r.slug }))
        .collect();
    let mut body = json!({
        "tenant": id,
        "organizations": tenant.organizations,
        "realms": realms,
        "region": region,
        "status": tenant.status,
        "retention": {},
    });
    let digest = suiss_crypto::digest::sha256(body.to_string().as_bytes());
    let version = format!("v1.{}", b64url_encode(&digest));
    if let Value::Object(m) = &mut body {
        m.insert("version".into(), version.into());
    }
    body
}

#[cfg(test)]
mod tests;
