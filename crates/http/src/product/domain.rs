//! The product client API's JSON (OP-149 m.4, m.5, m.28 (c), OP-65): requests into terms and
//! answers out. Positions travel as decimal strings and times as RFC 3339 UTC (OP-65 rule 4).

use access_authority_core::adapters::{KeyAnswer, PartyAnswer};
use access_authority_core::keys::{self, AsOf, KeyEntry, KeyState, Point};
use access_authority_core::parties::{self, PartyEntry};
use access_identity_events::domain::catalog::uuid;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::Id;
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
    m.insert("actor_kind".into(), e.actor_kind.name().into());
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

/// A `PartyID` in its ADP text form: the unpadded base64url of its 16 bytes (OP-149 m.16 (f)).
#[must_use]
pub fn party_id(text: &str) -> Option<Id> {
    let bytes = b64url_decode(text).ok()?;
    let id = <[u8; 16]>::try_from(bytes).ok()?;
    (b64url_encode(&id) == text).then_some(Id(id))
}

/// The Party batch body `{domain, parties, as_of?}`: 1 to [`parties::MAX_PARTIES`] distinct
/// Parties (OP-149 m.28 (c)).
///
/// # Errors
/// [`BadRequest`].
pub fn party_batch(body: &[u8]) -> Result<(Digest, Vec<Id>, AsOf), BadRequest> {
    let Ok(Value::Object(mut m)) = serde_json::from_slice::<Value>(body) else {
        return Err(BadRequest("json"));
    };
    let domain = m
        .remove("domain")
        .and_then(|d| d.as_str().and_then(crate::adp::adapters::domain_id))
        .ok_or(BadRequest("domain"))?;
    let Some(Value::Array(list)) = m.remove("parties") else {
        return Err(BadRequest("parties"));
    };
    if list.is_empty() || list.len() > parties::MAX_PARTIES {
        return Err(BadRequest("parties"));
    }
    let mut ids = Vec::with_capacity(list.len());
    for p in &list {
        let p = p.as_str().and_then(party_id).ok_or(BadRequest("parties"))?;
        if ids.contains(&p) {
            return Err(BadRequest("parties"));
        }
        ids.push(p);
    }
    let at = match m.remove("as_of") {
        None => AsOf::Head,
        Some(Value::String(s)) => as_of(Some(&s))?,
        Some(_) => return Err(BadRequest("as_of")),
    };
    if !m.is_empty() {
        return Err(BadRequest("unknown-member"));
    }
    Ok((domain, ids, at))
}

/// One Party as JSON (OP-149 m.28 (c)).
#[must_use]
pub fn party_json(e: &PartyEntry) -> Value {
    let mut m = Map::new();
    m.insert("party".into(), b64url_encode(&e.party.0).into());
    m.insert("actor_kind".into(), e.actor_kind.name().into());
    m.insert("since".into(), point(e.since));
    if let Some(p) = e.ended {
        m.insert("ended".into(), point(p));
    }
    Value::Object(m)
}

/// The JSON form of a Party lookup: the signed payload's content, unsigned, with the
/// consistency token (OP-149 m.28 (c)).
#[must_use]
pub fn party_lookup_json(a: &PartyAnswer) -> Value {
    let l = &a.lookup;
    json!({
        "domain": domain_text(&l.domain),
        "position": l.pos.to_string(),
        "iat": rfc3339(l.iat),
        "parties": l.parties.iter().map(party_json).collect::<Vec<_>>(),
        "unknown": l.unknown.iter().map(|p| b64url_encode(&p.0)).collect::<Vec<_>>(),
        "consistency_token": a.consistency,
    })
}

/// `Cache-Control` of a Party lookup: immutable once every Party asked for has ended, else
/// short (as the key lookup, OP-149 m.5).
#[must_use]
pub fn party_cache_control(a: &PartyAnswer) -> &'static str {
    let l = &a.lookup;
    if l.unknown.is_empty() && l.parties.iter().all(|p| p.ended.is_some()) {
        ENDED_CACHE
    } else {
        ACTIVE_MAX_AGE
    }
}

/// Most entries one subject resolution names (OP-149 A11, PD; as `keys:batchGet`).
pub const MAX_RESOLVE: usize = 100;

/// A canonical lower-case UUID.
#[must_use]
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    if text.len() != 36 {
        return None;
    }
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    let mut out = [0_u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2)?;
        *o = u8::from_str_radix(hex.get(at..at.checked_add(2)?)?, 16).ok()?;
    }
    (uuid(&out) == text).then_some(out)
}

/// A pairwise `sub`: 32 random bytes in unpadded base64url (MD-10).
fn sub_ok(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A resolution request (OP-149 A11): `{realm, client_id, parties | subs}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveRequest {
    /// The realm, as the tenant snapshot names it.
    pub realm: [u8; 16],
    /// The client whose pairwise `sub` is meant: its sector.
    pub client_id: String,
    /// The direction and entries.
    pub lookup: super::ports::SubjectQuery,
}

/// Reads a resolution request: exactly one of `parties` (base64url `PartyID`s) and `subs`,
/// 1 to [`MAX_RESOLVE`] distinct entries.
///
/// # Errors
/// [`BadRequest`].
pub fn resolve_request(body: &[u8]) -> Result<ResolveRequest, BadRequest> {
    use super::ports::SubjectQuery;
    let Ok(Value::Object(mut m)) = serde_json::from_slice::<Value>(body) else {
        return Err(BadRequest("json"));
    };
    let realm = m
        .remove("realm")
        .and_then(|r| r.as_str().and_then(parse_uuid))
        .ok_or(BadRequest("realm"))?;
    let client_id = match m.remove("client_id") {
        Some(Value::String(c)) if !c.is_empty() && c.len() <= 128 => c,
        _ => return Err(BadRequest("client_id")),
    };
    let list = |v: Value, code: &'static str| -> Result<Vec<String>, BadRequest> {
        let Value::Array(items) = v else {
            return Err(BadRequest(code));
        };
        if items.is_empty() || items.len() > MAX_RESOLVE {
            return Err(BadRequest(code));
        }
        let mut out: Vec<String> = Vec::with_capacity(items.len());
        for i in items {
            let s = i.as_str().ok_or(BadRequest(code))?;
            if out.iter().any(|o| o == s) {
                return Err(BadRequest(code));
            }
            out.push(String::from(s));
        }
        Ok(out)
    };
    let lookup = match (m.remove("parties"), m.remove("subs")) {
        (Some(p), None) => {
            let mut parties = Vec::new();
            for text in list(p, "parties")? {
                let id = b64url_decode(&text)
                    .ok()
                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
                    .filter(|id| b64url_encode(id) == text)
                    .ok_or(BadRequest("parties"))?;
                parties.push(id);
            }
            SubjectQuery::Parties(parties)
        }
        (None, Some(s)) => {
            let subs = list(s, "subs")?;
            if !subs.iter().all(|s| sub_ok(s)) {
                return Err(BadRequest("subs"));
            }
            SubjectQuery::Subs(subs)
        }
        _ => return Err(BadRequest("parties-or-subs")),
    };
    if !m.is_empty() {
        return Err(BadRequest("unknown-member"));
    }
    Ok(ResolveRequest {
        realm,
        client_id,
        lookup,
    })
}

/// The answer to a resolution (OP-149 A11): the pairs found and the entries that did not
/// resolve, in the request's direction, with the consistency token.
#[must_use]
pub fn resolution_json(req: &ResolveRequest, found: &super::ports::Resolved) -> Value {
    use super::ports::SubjectQuery;
    let mut pairs: Vec<Value> = found
        .pairs
        .iter()
        .map(|(p, s)| json!({ "party": b64url_encode(p), "sub": s }))
        .collect();
    // OP-149 m.34 (b): a client without a Party resolves to its client_id
    pairs.extend(
        found
            .clients
            .iter()
            .map(|(c, s)| json!({ "client_id": c, "sub": s })),
    );
    let unknown: Vec<Value> = match &req.lookup {
        SubjectQuery::Parties(list) => list
            .iter()
            .filter(|p| !found.pairs.iter().any(|(q, _)| q == *p))
            .map(|p| Value::from(b64url_encode(p)))
            .collect(),
        SubjectQuery::Subs(list) => list
            .iter()
            .filter(|s| {
                !found.pairs.iter().any(|(_, t)| t == *s)
                    && !found.clients.iter().any(|(_, t)| t == *s)
            })
            .map(|s| Value::from(s.as_str()))
            .collect(),
    };
    json!({
        "realm": uuid(&req.realm),
        "client_id": req.client_id,
        "resolved": pairs,
        "unknown": unknown,
        "consistency_token": found.consistency,
    })
}

/// An allowed Exercise as JSON (OP-149 m.9): where its decision is, what it allowed and the
/// receipt the decision point issued, when kept.
#[must_use]
pub fn exercise_json(
    domain: &Digest,
    r: &access_authority_core::adapters::ExerciseRecord,
) -> Value {
    let mut m = Map::new();
    m.insert("exercise".into(), b64url_encode(&r.exercise.0).into());
    m.insert("domain".into(), domain_text(domain).into());
    m.insert("status".into(), "allowed".into());
    m.insert("position".into(), r.position.to_string().into());
    m.insert("intent".into(), b64url_encode(&r.intent.0).into());
    if let Some(i) = r.instance {
        m.insert("instance".into(), b64url_encode(&i.0).into());
    }
    if let Some(receipt) = receipt_json(r) {
        m.insert("receipt".into(), receipt);
    }
    Value::Object(m)
}

/// The kept receipt of an Exercise: its payload and, once signed, its `COSE_Sign1` and key
/// excerpt.
fn receipt_json(r: &access_authority_core::adapters::ExerciseRecord) -> Option<Value> {
    let p = r.receipt.as_ref()?;
    let mut receipt = Map::new();
    receipt.insert("payload".into(), b64url_encode(p).into());
    if let Some((sign1, excerpt)) = &r.signed_receipt {
        receipt.insert("cose_sign1".into(), b64url_encode(sign1).into());
        receipt.insert("key_excerpt".into(), b64url_encode(excerpt).into());
    }
    Some(Value::Object(receipt))
}

/// The agency chain of an allowed Exercise as JSON (OP-149 m.11), from its kept receipt: the
/// declared capacity, the links from the principal to the agent (empty when the actor acted
/// for itself) and the receipt that signs them. `None` when no receipt was kept.
///
/// # Errors
/// The kept receipt does not decode.
pub fn agency_json(
    domain: &Digest,
    r: &access_authority_core::adapters::ExerciseRecord,
) -> Result<Option<Value>, access_kernel::codec::ModelError> {
    use access_kernel::codec::Canonical as _;
    use access_kernel::combinator::Capacity;
    let Some(payload) = &r.receipt else {
        return Ok(None);
    };
    let parsed = access_kernel::receipt::Receipt::from_bytes(payload)?;
    let capacity = match parsed.capacity {
        Capacity::Own => Value::from("own"),
        Capacity::For(p) => json!({ "for": b64url_encode(&p.0) }),
    };
    let agency: Vec<Value> = parsed
        .agency
        .iter()
        .map(|l| {
            json!({
                "mandate": b64url_encode(&l.mandate.0),
                "principal": b64url_encode(&l.principal.0),
                "agent": b64url_encode(&l.agent.0),
            })
        })
        .collect();
    Ok(Some(json!({
        "exercise": b64url_encode(&r.exercise.0),
        "domain": domain_text(domain),
        "capacity": capacity,
        "agency": agency,
        "receipt": receipt_json(r),
    })))
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
