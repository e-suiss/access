//! Authority token requests at the token endpoint (§9.9, §9.13.5, §10.4 (i), OP-150 m.2):
//! the RFC 9396 `authorization_details` that ask for authority, the one RFC 8707 `resource`,
//! and the holder's signed `projection.issue` Exercise (`access_exercise`) the authority plane
//! decides. Free of I/O.
//!
//! `access_exercise` is base64url of the deterministic CBOR `token-exercise` of
//! `conformance/cddl/token-exercise.cddl`. The Exercise's AIS is signed by the holder Instance's
//! key, which is the DPoP key of the request: the token's `cnf` is the actor Instance's
//! key binding (§9.9.4).

use std::collections::BTreeSet;

use access_kernel::codec::Canonical as _;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::meta::{self, ExerciseBasis, Payload};
use access_kernel::model::ActionRef;
use access_kernel::verify::cose::{self, KID};
use access_kernel::verify::projection::digest_text;
use serde_json::Value as Json;
use suiss_crypto::dcbor::{self, Limits, Value};

/// The form parameter that carries the RFC 9396 details.
pub const DETAILS_PARAM: &str = "authorization_details";

/// The form parameter that carries the holder's `projection.issue` Exercise.
pub const EXERCISE_PARAM: &str = "access_exercise";

/// Largest `access_exercise`, in base64url characters.
pub const MAX_EXERCISE: usize = 16 * 1024;

/// Most details in one request.
pub const MAX_DETAILS: usize = 16;

/// The meta-action an authority token is decided as.
pub const PROJECTION_ISSUE: &str = "projection_issue";

/// The intent parameter that names the meta payload's digest (`opaque["payload"]`).
const PAYLOAD: &str = "payload";

/// RAR members common to every type that never bound Access authority (§9.13.5, P25).
pub const IGNORED: [&str; 5] = [
    "locations",
    "actions",
    "datatypes",
    "identifier",
    "privileges",
];

/// RFC 9396 detail `kind` of an Access type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One intent.
    Intent,
    /// A set of actions within bounds.
    Bounds,
}

/// One requested detail: its type, its schema digest in text form, and for `intent` the intent
/// digest in text form.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Detail {
    /// `<namespace>:<name>:<major>`.
    pub r#type: String,
    /// The Action Schema digest, `sha-256:…`.
    pub schema: String,
    /// The intent digest of an `intent` detail.
    pub intent: Option<String>,
}

/// What is wrong with an authority token request, by its OAuth error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// RFC 9396 §5: the details are malformed or not what the Exercise asks.
    #[error("invalid_authorization_details")]
    Details,
    /// RFC 8707: no resource, or not the Exercise's audience; there is no default resource.
    #[error("invalid_target")]
    Target,
    /// The Exercise is malformed or is not a `projection.issue` of this realm's domain.
    #[error("invalid_request")]
    Exercise,
    /// The Exercise is not signed by the request's DPoP key (§9.9.4).
    #[error("invalid_dpop_proof")]
    Holder,
}

impl AuthorityError {
    /// The OAuth `error`.
    #[must_use]
    pub const fn error(self) -> &'static str {
        match self {
            Self::Details => "invalid_authorization_details",
            Self::Target => "invalid_target",
            Self::Exercise => "invalid_request",
            Self::Holder => "invalid_dpop_proof",
        }
    }
}

/// The RAR `type` of an action (§9.13.5).
#[must_use]
pub fn action_type(a: &ActionRef) -> String {
    format!("{}:{}:{}", a.namespace, a.name, a.major)
}

fn text<'a>(o: &'a serde_json::Map<String, Json>, k: &str) -> Result<&'a str, AuthorityError> {
    o.get(k)
        .and_then(Json::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or(AuthorityError::Details)
}

/// Parses `authorization_details` (RFC 9396 §2): 1 to [`MAX_DETAILS`] objects of one `kind`,
/// each with `type`, `kind` and `schema`, an `intent` detail alone and with its `intent`
/// digest. The common members never bound authority (§9.13.5): they are ignored, except
/// `locations`, which must name only `resource` (RFC 8707).
///
/// # Errors
/// [`AuthorityError::Details`].
pub fn parse_details(
    raw: &str,
    resource: &str,
) -> Result<(Kind, BTreeSet<Detail>), AuthorityError> {
    let parsed: Json = serde_json::from_str(raw).map_err(|_| AuthorityError::Details)?;
    let Json::Array(items) = parsed else {
        return Err(AuthorityError::Details);
    };
    if items.is_empty() || items.len() > MAX_DETAILS {
        return Err(AuthorityError::Details);
    }
    let mut kind = None;
    let mut out = BTreeSet::new();
    for item in &items {
        let Json::Object(o) = item else {
            return Err(AuthorityError::Details);
        };
        let k = match text(o, "kind")? {
            "intent" => Kind::Intent,
            "bounds" => Kind::Bounds,
            _ => return Err(AuthorityError::Details),
        };
        if kind.replace(k).is_some_and(|prev| prev != k) {
            return Err(AuthorityError::Details);
        }
        // §9.13.5, P25
        if let Some(l) = o.get("locations") {
            let Json::Array(l) = l else {
                return Err(AuthorityError::Details);
            };
            if l.iter().any(|x| x.as_str() != Some(resource)) {
                return Err(AuthorityError::Details);
            }
        }
        let intent = match k {
            Kind::Intent => Some(String::from(text(o, "intent")?)),
            Kind::Bounds => None,
        };
        out.insert(Detail {
            r#type: String::from(text(o, "type")?),
            schema: String::from(text(o, "schema")?),
            intent,
        });
    }
    let kind = kind.ok_or(AuthorityError::Details)?;
    if kind == Kind::Intent && out.len() != 1 {
        return Err(AuthorityError::Details);
    }
    Ok((kind, out))
}

/// How long a delegation to an app lasts unless the person changes it (OP-153 m.3 (x)): an
/// app is not a human, so it always ends.
pub const CONNECT_DEFAULT_MS: u64 = 30 * 86_400_000;

/// The S1 draft a third-party app's typed bounds open when the person connects it (§8.17.4.3,
/// §2.2.2 #2, X27, OP-153 m.3 (x)): to the app, what its details name and nothing else, no
/// passing on, no capacity chosen for the person, ending after [`CONNECT_DEFAULT_MS`]. It is a
/// draft only: what is committed is the `grant.issue` of the exact preview the person signs.
/// There is no scope list and no "Allow".
///
/// # Errors
/// [`AuthorityError::Details`] for an `intent` request, which asks to run one action, not to be
/// given authority.
pub fn connect_draft(
    app: &str,
    kind: Kind,
    details: &BTreeSet<Detail>,
    now_ms: u64,
) -> Result<Json, AuthorityError> {
    if kind != Kind::Bounds {
        return Err(AuthorityError::Details);
    }
    let can_do: Vec<String> = details
        .iter()
        .map(|d| {
            let mut parts = d.r#type.splitn(3, ':');
            match (parts.next(), parts.next()) {
                (Some(ns), Some(name)) => format!("{ns}.{name}"),
                _ => d.r#type.clone(),
            }
        })
        .collect();
    Ok(serde_json::json!({
        "source": "editor",
        "to": { "name": app, "kind": "agent" },
        "canDo": can_do,
        "actingAs": null,
        "capacity": null,
        "canPassOn": false,
        "limits": [],
        "requires": [],
        "valid": { "kind": "until", "atMs": now_ms.saturating_add(CONNECT_DEFAULT_MS) },
        "interpretations": [],
    }))
}

/// The holder's signed `projection.issue` Exercise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenExercise {
    /// The governing domain.
    pub domain: Digest,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The `projection_issue` intent.
    pub intent: IntentEnvelope,
    /// The payload as sent.
    pub payload_bytes: Vec<u8>,
    /// The payload.
    pub payload: Payload,
    /// Declared basis.
    pub basis: ExerciseBasis,
    /// Declared capacity.
    pub capacity: Capacity,
    /// The AIS (`COSE_Sign1`) by the holder Instance.
    pub ais: Vec<u8>,
    /// The intent of an exact-intent token.
    pub target: Option<IntentEnvelope>,
}

fn field<'a>(m: &'a [(Value, Value)], k: &str) -> Option<&'a Value> {
    m.iter()
        .find(|(key, _)| *key == Value::text(k))
        .map(|(_, v)| v)
}

fn bytes(v: Option<&Value>) -> Result<Vec<u8>, AuthorityError> {
    match v {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(AuthorityError::Exercise),
    }
}

const FIELDS: [&str; 8] = [
    "domain", "nonce", "intent", "payload", "basis", "capacity", "ais", "target",
];

/// Parses `access_exercise`: base64url of a deterministic CBOR `token-exercise` map, nothing
/// beyond its members.
///
/// # Errors
/// [`AuthorityError::Exercise`].
pub fn parse_exercise(raw: &str) -> Result<TokenExercise, AuthorityError> {
    if raw.is_empty() || raw.len() > MAX_EXERCISE {
        return Err(AuthorityError::Exercise);
    }
    let cbor = access_kernel::json::b64url_decode(raw).map_err(|_| AuthorityError::Exercise)?;
    let Ok(Value::Map(m)) = dcbor::decode(&cbor, Limits::CEILING) else {
        return Err(AuthorityError::Exercise);
    };
    if m.iter()
        .any(|(k, _)| !matches!(k, Value::Text(t) if FIELDS.contains(&t.as_str())))
    {
        return Err(AuthorityError::Exercise);
    }
    let get = |k: &str| field(&m, k).ok_or(AuthorityError::Exercise);
    let bad = |_| AuthorityError::Exercise;
    let payload_bytes = bytes(field(&m, "payload"))?;
    let nonce = bytes(field(&m, "nonce"))?;
    if !(16..=64).contains(&nonce.len()) {
        return Err(AuthorityError::Exercise);
    }
    Ok(TokenExercise {
        domain: Digest::from_value(get("domain")?).ok_or(AuthorityError::Exercise)?,
        nonce,
        intent: IntentEnvelope::from_value(get("intent")?).map_err(bad)?,
        payload: Payload::from_bytes(&payload_bytes).map_err(bad)?,
        payload_bytes,
        basis: meta::exercise_basis(get("basis")?).map_err(bad)?,
        capacity: meta::capacity(get("capacity")?).map_err(bad)?,
        ais: bytes(field(&m, "ais"))?,
        target: field(&m, "target")
            .map(IntentEnvelope::from_value)
            .transpose()
            .map_err(bad)?,
    })
}

/// The `token-exercise` CBOR of `e`, base64url: what a holder sends.
///
/// # Errors
/// [`AuthorityError::Exercise`] when it cannot be encoded.
pub fn encode_exercise(e: &TokenExercise) -> Result<String, AuthorityError> {
    let mut m = vec![
        (Value::text("domain"), e.domain.to_value()),
        (Value::text("nonce"), Value::Bytes(e.nonce.clone())),
        (Value::text("intent"), e.intent.to_value()),
        (
            Value::text("payload"),
            Value::Bytes(e.payload_bytes.clone()),
        ),
        (Value::text("basis"), meta::basis_value(&e.basis)),
        (Value::text("capacity"), meta::capacity_value(e.capacity)),
        (Value::text("ais"), Value::Bytes(e.ais.clone())),
    ];
    if let Some(t) = &e.target {
        m.push((Value::text("target"), t.to_value()));
    }
    // RFC 8949 §4.2.1
    m.sort_by(|(a, _), (b, _)| match (a, b) {
        (Value::Text(a), Value::Text(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
        _ => core::cmp::Ordering::Equal,
    });
    let cbor =
        dcbor::encode(&Value::Map(m), Limits::CEILING).map_err(|_| AuthorityError::Exercise)?;
    Ok(access_kernel::json::b64url_encode(&cbor))
}

/// The `kid` of the AIS: the RFC 7638 thumbprint of the key that signed it.
fn ais_kid(ais: &[u8]) -> Option<[u8; 32]> {
    let msg = cose::parse_sign1(ais).ok()?;
    let Ok(Value::Map(header)) = dcbor::decode(&msg.protected, Limits::CEILING) else {
        return None;
    };
    header.iter().find_map(|(k, v)| match (k, v) {
        (Value::Unsigned(l), Value::Bytes(b)) if *l == KID => {
            <[u8; 32]>::try_from(b.as_slice()).ok()
        }
        _ => None,
    })
}

/// What the request asks for once checked: the class and, for an exact-intent token, its
/// intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    /// The class.
    pub kind: Kind,
    /// The intent of an exact-intent token.
    pub target: Option<IntentEnvelope>,
}

/// Checks the Exercise against the request (§9.9, §9.13.5): a `projection_issue` of `domain`
/// whose intent names its payload, whose audience has `resource`, whose bounds are exactly the
/// requested details (and for `intent` the one intent), signed by the DPoP key `jkt`.
///
/// # Errors
/// [`AuthorityError`].
pub fn check(
    e: &TokenExercise,
    kind: Kind,
    details: &BTreeSet<Detail>,
    resource: &str,
    domain: &Digest,
    jkt: &[u8; 32],
) -> Result<Checked, AuthorityError> {
    if e.domain != *domain
        || e.intent.action.namespace != meta::NAMESPACE
        || e.intent.action.name != PROJECTION_ISSUE
    {
        return Err(AuthorityError::Exercise);
    }
    let named = e.payload.digest().map_err(|_| AuthorityError::Exercise)?;
    if e.intent.opaque.get(PAYLOAD) != Some(&named) {
        return Err(AuthorityError::Exercise);
    }
    let Payload::ProjectionIssue {
        bounds, audience, ..
    } = &e.payload
    else {
        return Err(AuthorityError::Exercise);
    };
    // §9.9.3 rule 1
    if !audience.contains(resource) {
        return Err(AuthorityError::Target);
    }
    // §9.9.4
    if ais_kid(&e.ais) != Some(*jkt) {
        return Err(AuthorityError::Holder);
    }
    let of = |a: &ActionRef, intent: Option<String>| Detail {
        r#type: action_type(a),
        schema: digest_text(&a.schema),
        intent,
    };
    let expected: BTreeSet<Detail> = match (kind, &e.target) {
        (Kind::Bounds, None) => bounds
            .authority
            .actions
            .exact
            .iter()
            .map(|a| of(a, None))
            .collect(),
        (Kind::Intent, Some(t)) => {
            let d = intent_digest(t).map_err(|_| AuthorityError::Exercise)?;
            BTreeSet::from([of(&t.action, Some(digest_text(&d)))])
        }
        _ => return Err(AuthorityError::Details),
    };
    if expected != *details || !bounds.authority.actions.prefix.is_empty() {
        return Err(AuthorityError::Details);
    }
    Ok(Checked {
        kind,
        target: e.target.clone(),
    })
}

/// Whether a token request asks for no more than the authorization request did (RFC 9396
/// §6.1): every detail's type and schema were authorized.
#[must_use]
pub fn within(asked: &BTreeSet<Detail>, authorized: &BTreeSet<Detail>) -> bool {
    asked.iter().all(|d| {
        authorized
            .iter()
            .any(|a| a.r#type == d.r#type && a.schema == d.schema)
    })
}

#[cfg(test)]
mod tests;
