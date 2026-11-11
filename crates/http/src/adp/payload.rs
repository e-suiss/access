//! The JSON form of a meta-action payload (L1-ADP-17, OP-152 m.7 (d)): the `meta-payload` of
//! `kernel.cddl` member for member, so a browser that writes no CBOR can name a role version, a
//! Grant change or a policy and the BFF drafts its exact dCBOR. JSON → dCBOR value → the
//! Kernel's own decoder, so nothing the Kernel refuses gets through, and the answer is always
//! the canonical bytes the Kernel re-encodes.
//!
//! Forms (L1-ADP-6): an id, a key or other bytes is base64url text; a digest is base64url text
//! of its 32 bytes; a `time-window` and a holding are objects (`{from, until}`,
//! `{grant, holder, since}`); an equality value is a string, an integer, a boolean or
//! `{"bytes": base64url}`; a set is an array whose order does not matter and which may not repeat
//! an item. Every other CDDL map is an object with the same member names; an unknown member is
//! refused.

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::meta::Payload;
use access_kernel::model::{AuthoritySet, CanonicalAuthority};
use serde_json::{Map, Value as Json};
use suiss_crypto::dcbor::{self, Limits, Value};

/// Why a JSON payload is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("payload member {at} is not its CDDL form")]
pub struct PayloadError {
    /// The JSON Pointer of the member at fault (RFC 6901), `""` for the whole value.
    pub at: String,
}

impl PayloadError {
    /// The stable problem code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "payload"
    }
}

/// One CDDL rule, read in both directions.
enum T {
    Uint,
    Int,
    Text,
    Bool,
    Bytes,
    Digest,
    Eq,
    Lit(&'static [&'static str]),
    Array(&'static T),
    Set(&'static T),
    Struct(&'static [(&'static str, &'static T, bool)]),
    Dict(&'static T),
    Tuple(&'static [(&'static str, &'static T)]),
    Tagged(&'static [(&'static str, &'static T)]),
    Or(&'static [&'static T]),
}

static UINT: T = T::Uint;
static INT: T = T::Int;
static TEXT: T = T::Text;
static BOOL: T = T::Bool;
static BYTES: T = T::Bytes;
static DIGEST: T = T::Digest;
static EQ: T = T::Eq;
static TEXTS: T = T::Array(&TEXT);
static TEXT_SET: T = T::Set(&TEXT);
static ID_SET: T = T::Set(&BYTES);
static WINDOW: T = T::Tuple(&[("from", &UINT), ("until", &UINT)]);
static ACTION_REF: T = T::Struct(&[
    ("namespace", &TEXT, true),
    ("name", &TEXT, true),
    ("major", &UINT, true),
    ("schema", &DIGEST, true),
]);
static ACTION_REFS: T = T::Set(&ACTION_REF);
static RESOURCE_REF: T = T::Struct(&[
    ("namespace", &TEXT, true),
    ("path", &TEXTS, true),
    ("incarnation", &UINT, true),
]);
static PURPOSE: T = T::Tagged(&[
    ("code", &TEXT),
    ("work", &DIGEST),
    ("aim", &DIGEST),
    ("case", &DIGEST),
]);
static PURPOSES: T = T::Set(&PURPOSE);
static WHERE: T = T::Dict(&EQ);
static STRUCTURAL: T = T::Struct(&[
    ("namespace", &TEXT, true),
    ("prefix", &TEXTS, false),
    ("type", &TEXT, false),
    ("where", &WHERE, false),
]);
static EXACT: T = T::Tagged(&[("exact", &RESOURCE_REF)]);
static RESOURCE: T = T::Or(&[&EXACT, &STRUCTURAL]);
static CONJUNCT: T = T::Struct(&[("claim_class", &TEXT, true), ("value", &EQ, false)]);
static CONJUNCTS: T = T::Set(&CONJUNCT);
static PUBLIC: T = T::Lit(&["public"]);
static FOREIGN_SUBJECT: T =
    T::Struct(&[("domain", &DIGEST, true), ("authority_class", &TEXT, true)]);
static SUBJECT_TAGGED: T = T::Tagged(&[
    ("party", &BYTES),
    ("pred", &CONJUNCTS),
    ("foreign", &FOREIGN_SUBJECT),
]);
static SUBJECT: T = T::Or(&[&PUBLIC, &SUBJECT_TAGGED]);
static RANGE: T = T::Struct(&[
    ("min", &INT, false),
    ("max", &INT, false),
    ("unit", &TEXT, true),
]);
static BOUND: T = T::Tagged(&[
    ("enum", &TEXT_SET),
    ("eq", &EQ),
    ("range", &RANGE),
    ("count_max", &UINT),
    ("interval", &WINDOW),
    ("resource", &RESOURCE),
    ("subject", &SUBJECT),
    ("purpose", &PURPOSES),
    ("flag", &BOOL),
]);
static BOUNDS: T = T::Dict(&BOUND);
static PREFIX: T = T::Struct(&[("namespace", &TEXT, true), ("catalog", &DIGEST, true)]);
static PREFIXES: T = T::Set(&PREFIX);
static ACTION_SET: T = T::Struct(&[("exact", &ACTION_REFS, false), ("prefix", &PREFIXES, false)]);
static AUTHORITY_SET: T = T::Struct(&[
    ("actions", &ACTION_SET, true),
    ("resource", &RESOURCE, true),
    ("params", &BOUNDS, false),
    ("recipient", &SUBJECT, false),
    ("purpose", &PURPOSES, false),
]);
static CLAIM_HELD: T = T::Struct(&[
    ("class", &TEXT, true),
    ("subject", &SUBJECT, true),
    ("acceptance", &DIGEST, true),
]);
static WHILE: T = T::Tagged(&[("instance_alive", &BYTES), ("claim_held", &CLAIM_HELD)]);
static WHILES: T = T::Set(&WHILE);
static COUNT: T = T::Lit(&["count"]);
static AMOUNT_DIM: T = T::Tagged(&[("amount", &TEXT)]);
static DIMENSION: T = T::Or(&[&COUNT, &AMOUNT_DIM]);
static TOTAL: T = T::Lit(&["total"]);
static ROLLING: T = T::Tagged(&[("rolling_s", &UINT)]);
static BUDGET_WINDOW: T = T::Or(&[&TOTAL, &ROLLING]);
static BUDGET: T = T::Struct(&[
    ("dimension", &DIMENSION, true),
    ("capacity", &UINT, true),
    ("window", &BUDGET_WINDOW, true),
]);
static BUDGETS: T = T::Set(&BUDGET);
static CONSTRAINTS: T = T::Struct(&[
    ("validity", &WINDOW, true),
    ("while", &WHILES, false),
    ("budget", &BUDGETS, false),
]);
static DELEGATION: T = T::Struct(&[
    ("depth", &UINT, false),
    ("downstream_holder_class", &SUBJECT, false),
]);
static PROOF_KIND: T = T::Lit(&[
    "claim",
    "contribution",
    "authentication",
    "foreign_authority",
]);
static BINDING: T = T::Lit(&["actor_instance", "intent_digest", "resource"]);
static DISTINCT: T = T::Lit(&["party", "instance", "issuer"]);
static INDEPENDENCE: T = T::Tagged(&[("distinct", &DISTINCT)]);
static SINGLE_USE: T = T::Lit(&["single_use"]);
static ASSURANCE: T = T::Dict(&UINT);
static REQUIREMENT: T = T::Struct(&[
    ("proof_kind", &PROOF_KIND, true),
    ("class", &TEXT, true),
    ("count", &UINT, false),
    ("binding", &BINDING, false),
    ("freshness_ms", &UINT, false),
    ("independence", &INDEPENDENCE, false),
    ("consumption", &SINGLE_USE, false),
    ("source", &SUBJECT, false),
    ("assurance", &ASSURANCE, false),
]);
static REQUIREMENTS: T = T::Set(&REQUIREMENT);
static CANONICAL: T = T::Struct(&[
    ("authority", &AUTHORITY_SET, true),
    ("constraints", &CONSTRAINTS, true),
    ("delegation", &DELEGATION, true),
    ("requirements", &REQUIREMENTS, true),
]);
static OWN: T = T::Lit(&["own"]);
static FOR: T = T::Tagged(&[("for", &BYTES)]);
static CAPACITY: T = T::Or(&[&OWN, &FOR]);
static CAPACITIES: T = T::Set(&CAPACITY);
static NAMED: T = T::Struct(&[
    ("name", &TEXT, true),
    ("version", &UINT, true),
    ("digest", &DIGEST, true),
]);
static HOLDING: T = T::Tuple(&[("grant", &BYTES), ("holder", &BYTES), ("since", &UINT)]);
static GRANT_BASIS: T = T::Tagged(&[("anchor", &BYTES), ("holding", &HOLDING)]);
static GRANT_CONTENT: T = T::Struct(&[
    ("basis", &GRANT_BASIS, true),
    ("holder", &SUBJECT, true),
    ("authority", &CANONICAL, true),
    ("agency", &CAPACITIES, false),
    ("named", &NAMED, false),
]);
static JOINT: T = T::Struct(&[("parties", &ID_SET, true), ("k", &UINT, true)]);
static ROOT: T = T::Tagged(&[("sole", &BYTES), ("joint", &JOINT)]);
static DOMAIN_SCOPE: T = T::Lit(&["domain"]);
static SCOPE_TAGGED: T = T::Tagged(&[("resource", &RESOURCE), ("party", &BYTES)]);
static SCOPE: T = T::Or(&[&DOMAIN_SCOPE, &SCOPE_TAGGED]);
static KEEP: T = T::Lit(&["keep", "revoke"]);
static DISPOSITION_ITEM: T = T::Tuple(&[("grant", &BYTES), ("disposition", &KEEP)]);
static DISPOSITION: T = T::Set(&DISPOSITION_ITEM);
static ML_DSA: T = T::Tuple(&[("alg", &INT), ("key", &BYTES)]);
static PUBLIC_KEY: T = T::Tagged(&[("ed25519", &BYTES), ("p256", &BYTES), ("ml_dsa", &ML_DSA)]);
static PUBLIC_KEYS: T = T::Set(&PUBLIC_KEY);
static PROVIDER: T = T::Tagged(&[("provider", &DIGESTS)]);
static DIGESTS: T = T::Set(&DIGEST);
static BINDING_SCOPE: T = T::Or(&[&DOMAIN_SCOPE, &PROVIDER]);
static SUPERSEDED: T = T::Struct(&[("at", &DIGEST, true), ("cited", &DIGEST, true)]);
static BINDING_KEY: T = T::Struct(&[
    ("kid", &BYTES, true),
    ("alg", &INT, true),
    ("key", &PUBLIC_KEY, true),
    ("scope", &BINDING_SCOPE, true),
    ("superseded", &SUPERSEDED, false),
]);
static BINDING_KEYS: T = T::Set(&BINDING_KEY);
static FOREIGN_ISSUER: T =
    T::Struct(&[("domain", &DIGEST, true), ("binding", &BINDING_KEYS, true)]);
static FOREIGN_TAGGED: T = T::Tagged(&[("foreign", &FOREIGN_ISSUER)]);
static ISSUER: T = T::Or(&[&BYTES, &FOREIGN_TAGGED]);
static USE: T = T::Lit(&[
    "actor-binding",
    "predicate-input",
    "subject-selection",
    "foreign-authority",
    "schema-definition",
]);
static QUOTA: T = T::Struct(&[("count", &UINT, true), ("window_s", &UINT, true)]);
static PARAM_TYPE: T = T::Lit(&["amount", "int", "text", "bool", "bytes", "id", "opaque"]);
static PARAM_TYPES: T = T::Dict(&PARAM_TYPE);
static EFFECT_CLASS: T = T::Lit(&["none", "reversible", "irreversible"]);
// E47 (1), OP-156 m.4
static REVERSIBILITY: T = T::Lit(&["reversible", "compensable", "irreversible"]);
static ACTION_SCHEMA: T = T::Struct(&[
    ("name", &TEXT, true),
    ("major", &UINT, true),
    ("effect_class", &EFFECT_CLASS, true),
    ("reserved", &BOOL, false),
    ("consumption_bearing", &BOOL, false),
    ("params", &PARAM_TYPES, false),
    ("resource_types", &TEXT_SET, false),
    ("render", &TEXT, false),
    ("reversibility", &REVERSIBILITY, false),
]);
static ACTION_SCHEMAS: T = T::Set(&ACTION_SCHEMA);
static SPP: T = T::Struct(&[
    ("publisher", &BYTES, true),
    ("namespace", &TEXT, true),
    ("catalog_version", &UINT, true),
    ("actions", &ACTION_SCHEMAS, true),
    ("retirements", &ACTION_REFS, false),
    ("core_spec_min", &UINT, false),
]);
static PINNED: T = T::Struct(&[
    ("iss", &TEXT, true),
    ("aud", &TEXT, true),
    ("keys", &PUBLIC_KEYS, true),
]);
static ACCEPTANCE: T = T::Struct(&[
    ("issuer", &ISSUER, true),
    ("use", &USE, true),
    ("classes", &TEXT_SET, true),
    ("subject", &SUBJECT, true),
    ("anchor", &BYTES, false),
    ("assurance_floor", &ASSURANCE, false),
    ("validity", &WINDOW, true),
    ("ingest_until", &UINT, false),
    ("issued_until", &UINT, false),
    ("quota", &QUOTA, false),
    ("spp", &SPP, false),
    ("pinned", &PINNED, false),
    // OP-157 m.3 (r)
    ("mappings", &DIGESTS, false),
]);
static TARGET_TAGGED: T = T::Tagged(&[("anchor", &BYTES), ("party", &BYTES), ("instance", &BYTES)]);
static TARGET: T = T::Or(&[&DOMAIN_SCOPE, &TARGET_TAGGED]);
static POLICY_REQUIREMENTS: T = T::Dict(&REQUIREMENTS);
static POLICY: T = T::Struct(&[
    ("schema", &TEXT, true),
    ("source", &TEXT, true),
    ("target", &TARGET, true),
    ("requirements", &POLICY_REQUIREMENTS, false),
]);
static MANDATE: T = T::Struct(&[
    ("authority", &AUTHORITY_SET, true),
    ("constraints", &CONSTRAINTS, true),
    ("requirements", &REQUIREMENTS, false),
    ("pin", &HOLDING, false),
]);
static ACTOR_KIND: T = T::Lit(&["human", "agent", "system", "machine", "organization"]);
static PROFILE_CLASS: T = T::Lit(&["online", "intermittent", "offline", "long-running"]);
static PROFILE_VARIANT: T = T::Lit(&[
    "online-strict",
    "bounded-staleness",
    "revalidate-on-reconnect",
    "checkpointed-offline",
    "checkpoint-continuation",
]);
static PROFILE: T = T::Struct(&[
    ("class", &PROFILE_CLASS, true),
    ("variant", &PROFILE_VARIANT, true),
]);
static AMOUNTS: T = T::Dict(&UINT);
static SLICE: T = T::Struct(&[("count", &UINT, false), ("amounts", &AMOUNTS, false)]);
static AUDIENCE: T = T::Set(&TEXT);

static ANCHOR_CREATE: T = T::Struct(&[
    ("scope", &SCOPE, true),
    ("root", &ROOT, true),
    ("root_terms", &REQUIREMENTS, false),
]);
static ANCHOR_TRANSFER: T = T::Struct(&[
    ("anchor", &BYTES, true),
    ("root", &ROOT, true),
    ("disposition", &DISPOSITION, true),
]);
static ANCHOR_AMEND: T = T::Struct(&[
    ("anchor", &BYTES, true),
    ("root", &ROOT, false),
    ("root_terms", &REQUIREMENTS, false),
]);
static ANCHOR_RETIRE: T = T::Struct(&[
    ("anchor", &BYTES, true),
    ("disposition", &DISPOSITION, true),
]);
static PARTY_REGISTER: T = T::Struct(&[
    ("party", &BYTES, true),
    ("root", &ROOT, true),
    ("actor_kind", &ACTOR_KIND, true),
]);
static PARTY_DEPART: T = T::Struct(&[("party", &BYTES, true), ("disposition", &DISPOSITION, true)]);
static INSTANCE_CREATE: T = T::Struct(&[
    ("party", &BYTES, true),
    ("key", &PUBLIC_KEY, true),
    ("mandate", &MANDATE, false),
]);
static INSTANCE_KEYED: T = T::Struct(&[("instance", &BYTES, true), ("key", &PUBLIC_KEY, true)]);
static INSTANCE_ONLY: T = T::Struct(&[("instance", &BYTES, true)]);
static MANDATE_BIND: T = T::Struct(&[("instance", &BYTES, true), ("envelope", &MANDATE, true)]);
static MANDATE_REBIND: T = T::Struct(&[("mandate", &BYTES, true), ("envelope", &MANDATE, true)]);
static MANDATE_ONLY: T = T::Struct(&[("mandate", &BYTES, true)]);
static GRANT_AMEND: T = T::Struct(&[
    ("grant", &BYTES, true),
    ("authority", &CANONICAL, true),
    ("agency", &CAPACITIES, false),
    ("named", &NAMED, false),
]);
static GRANT_ONLY: T = T::Struct(&[("grant", &BYTES, true)]);
static ACCEPTANCE_AMEND: T =
    T::Struct(&[("acceptance", &BYTES, true), ("content", &ACCEPTANCE, true)]);
static ACCEPTANCE_ONLY: T = T::Struct(&[("acceptance", &BYTES, true)]);
static POLICY_SET: T = T::Struct(&[("policy", &BYTES, false), ("content", &POLICY, true)]);
static POLICY_ONLY: T = T::Struct(&[("policy", &BYTES, true)]);
static CLAIM_ISSUE: T = T::Struct(&[
    ("subject", &BYTES, true),
    ("class", &TEXT, true),
    ("value", &EQ, true),
    ("validity", &WINDOW, false),
    ("bound_intent", &DIGEST, false),
    ("supersedes", &BYTES, false),
]);
static CONTRIBUTE: T = T::Struct(&[("target", &DIGEST, true), ("class", &TEXT, true)]);
static RELEASE: T = T::Struct(&[("exercise", &DIGEST, true), ("grounds", &ID_SET, true)]);
static DEFINE: T = T::Struct(&[("name", &TEXT, true), ("authority", &AUTHORITY_SET, true)]);
static PROJECTION: T = T::Struct(&[
    ("bounds", &CANONICAL, true),
    ("audience", &AUDIENCE, true),
    ("profile", &PROFILE, true),
    ("max_staleness_ms", &UINT, false),
    ("offline_slice", &SLICE, false),
]);

static META_PAYLOAD: T = T::Tagged(&[
    ("anchor_create", &ANCHOR_CREATE),
    ("anchor_transfer", &ANCHOR_TRANSFER),
    ("anchor_amend", &ANCHOR_AMEND),
    ("anchor_retire", &ANCHOR_RETIRE),
    ("party_register", &PARTY_REGISTER),
    ("party_depart", &PARTY_DEPART),
    ("instance_create", &INSTANCE_CREATE),
    ("instance_rekey", &INSTANCE_KEYED),
    ("instance_terminate", &INSTANCE_ONLY),
    ("instance_recover", &INSTANCE_KEYED),
    ("mandate_bind", &MANDATE_BIND),
    ("mandate_rebind", &MANDATE_REBIND),
    ("mandate_revoke", &MANDATE_ONLY),
    ("grant_issue", &GRANT_CONTENT),
    ("grant_amend", &GRANT_AMEND),
    ("grant_revoke", &GRANT_ONLY),
    ("grant_renounce", &GRANT_ONLY),
    ("acceptance_establish", &ACCEPTANCE),
    ("acceptance_amend", &ACCEPTANCE_AMEND),
    ("acceptance_revoke", &ACCEPTANCE_ONLY),
    ("policy_set", &POLICY_SET),
    ("policy_retire", &POLICY_ONLY),
    ("claim_issue", &CLAIM_ISSUE),
    ("contribute", &CONTRIBUTE),
    ("consumption_release", &RELEASE),
    ("authority_set_define", &DEFINE),
    ("projection_issue", &PROJECTION),
]);

/// Most nested values one JSON payload may have; deeper is refused before any work.
const MAX_DEPTH: usize = 32;

fn fail(at: &str) -> PayloadError {
    PayloadError { at: at.to_owned() }
}

fn child(at: &str, key: &str) -> String {
    let escaped = key.replace('~', "~0").replace('/', "~1");
    format!("{at}/{escaped}")
}

fn bytes_of(j: &Json, at: &str) -> Result<Vec<u8>, PayloadError> {
    j.as_str()
        .and_then(|s| b64url_decode(s).ok())
        .ok_or_else(|| fail(at))
}

fn encoded(v: &Value, at: &str) -> Result<Vec<u8>, PayloadError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| fail(at))
}

/// JSON → dCBOR value along `t`.
#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "one arm per rule shape of the closed list"
)]
fn to_value(t: &T, j: &Json, at: &str, depth: usize) -> Result<Value, PayloadError> {
    if depth > MAX_DEPTH {
        return Err(fail(at));
    }
    let d = depth.saturating_add(1);
    match t {
        T::Uint => j.as_u64().map(Value::Unsigned).ok_or_else(|| fail(at)),
        T::Int => j.as_i64().map(Value::int).ok_or_else(|| fail(at)),
        T::Text => j.as_str().map(Value::text).ok_or_else(|| fail(at)),
        T::Bool => j.as_bool().map(Value::Bool).ok_or_else(|| fail(at)),
        T::Bytes => Ok(Value::Bytes(bytes_of(j, at)?)),
        T::Digest => {
            let b: [u8; 32] = bytes_of(j, at)?.try_into().map_err(|_| fail(at))?;
            Ok(Digest(b).to_value())
        }
        T::Eq => match j {
            Json::String(s) => Ok(Value::text(s)),
            Json::Bool(b) => Ok(Value::Bool(*b)),
            Json::Number(n) => n.as_i64().map(Value::int).ok_or_else(|| fail(at)),
            Json::Object(m) if m.len() == 1 => {
                let b = m.get("bytes").ok_or_else(|| fail(at))?;
                Ok(Value::Bytes(bytes_of(b, &child(at, "bytes"))?))
            }
            _ => Err(fail(at)),
        },
        T::Lit(words) => match j.as_str() {
            Some(s) if words.contains(&s) => Ok(Value::text(s)),
            _ => Err(fail(at)),
        },
        T::Array(item) => {
            let items = j.as_array().ok_or_else(|| fail(at))?;
            items
                .iter()
                .enumerate()
                .map(|(i, x)| to_value(item, x, &child(at, &i.to_string()), d))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        T::Set(item) => {
            let items = j.as_array().ok_or_else(|| fail(at))?;
            let mut keyed = items
                .iter()
                .enumerate()
                .map(|(i, x)| {
                    let here = child(at, &i.to_string());
                    let v = to_value(item, x, &here, d)?;
                    Ok((encoded(&v, &here)?, v))
                })
                .collect::<Result<Vec<_>, PayloadError>>()?;
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            if keyed
                .windows(2)
                .any(|w| w.first().map(|a| &a.0) == w.get(1).map(|b| &b.0))
            {
                return Err(fail(at));
            }
            Ok(Value::Array(keyed.into_iter().map(|(_, v)| v).collect()))
        }
        T::Struct(fields) => {
            let m = j.as_object().ok_or_else(|| fail(at))?;
            if let Some(k) = m.keys().find(|k| !fields.iter().any(|(n, _, _)| n == k)) {
                return Err(fail(&child(at, k)));
            }
            let mut out = Vec::with_capacity(m.len());
            for (name, ft, required) in *fields {
                match m.get(*name) {
                    Some(x) => {
                        out.push((Value::text(name), to_value(ft, x, &child(at, name), d)?));
                    }
                    None if *required => return Err(fail(&child(at, name))),
                    None => {}
                }
            }
            Ok(Value::Map(out))
        }
        T::Dict(item) => {
            let m = j.as_object().ok_or_else(|| fail(at))?;
            m.iter()
                .map(|(k, x)| Ok((Value::text(k), to_value(item, x, &child(at, k), d)?)))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Map)
        }
        T::Tuple(fields) => {
            let m = j.as_object().ok_or_else(|| fail(at))?;
            if m.len() != fields.len() {
                return Err(fail(at));
            }
            fields
                .iter()
                .map(|(name, ft)| {
                    let x = m.get(*name).ok_or_else(|| fail(&child(at, name)))?;
                    to_value(ft, x, &child(at, name), d)
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array)
        }
        T::Tagged(arms) => {
            let m = j.as_object().ok_or_else(|| fail(at))?;
            let (Some((k, x)), 1) = (m.iter().next(), m.len()) else {
                return Err(fail(at));
            };
            let (_, ft) = arms
                .iter()
                .find(|(n, _)| n == k)
                .ok_or_else(|| fail(&child(at, k)))?;
            Ok(Value::Map(vec![(
                Value::text(k),
                to_value(ft, x, &child(at, k), d)?,
            )]))
        }
        T::Or(arms) => arms
            .iter()
            .find_map(|a| to_value(a, j, at, d).ok())
            .ok_or_else(|| fail(at)),
    }
}

fn digest_bytes(v: &Value) -> Option<[u8; 32]> {
    Digest::from_value(v).map(|d| d.0)
}

/// dCBOR value → JSON along `t`; `None` when `v` is not of the rule.
#[allow(
    clippy::many_single_char_names,
    reason = "one arm per rule shape of the closed list"
)]
fn to_json(t: &T, v: &Value) -> Option<Json> {
    match (t, v) {
        (T::Uint, Value::Unsigned(n)) => Some(Json::from(*n)),
        (T::Int | T::Eq, Value::Unsigned(_) | Value::Negative(_)) => v.as_i64().map(Json::from),
        (T::Text | T::Eq, Value::Text(s)) => Some(Json::from(s.as_str())),
        (T::Bool | T::Eq, Value::Bool(b)) => Some(Json::Bool(*b)),
        (T::Bytes, Value::Bytes(b)) => Some(Json::from(b64url_encode(b))),
        (T::Eq, Value::Bytes(b)) => {
            let mut m = Map::new();
            m.insert(String::from("bytes"), Json::from(b64url_encode(b)));
            Some(Json::Object(m))
        }
        (T::Digest, _) => digest_bytes(v).map(|b| Json::from(b64url_encode(&b))),
        (T::Lit(words), Value::Text(s)) if words.contains(&s.as_str()) => {
            Some(Json::from(s.as_str()))
        }
        (T::Array(item) | T::Set(item), Value::Array(items)) => items
            .iter()
            .map(|x| to_json(item, x))
            .collect::<Option<Vec<_>>>()
            .map(Json::Array),
        (T::Struct(fields), Value::Map(entries)) => {
            let mut m = Map::new();
            for (k, x) in entries {
                let Value::Text(k) = k else { return None };
                let (_, ft, _) = fields.iter().find(|(n, _, _)| n == k)?;
                m.insert(k.clone(), to_json(ft, x)?);
            }
            fields
                .iter()
                .all(|(n, _, req)| !req || m.contains_key(*n))
                .then_some(Json::Object(m))
        }
        (T::Dict(item), Value::Map(entries)) => {
            let mut m = Map::new();
            for (k, x) in entries {
                let Value::Text(k) = k else { return None };
                m.insert(k.clone(), to_json(item, x)?);
            }
            Some(Json::Object(m))
        }
        (T::Tuple(fields), Value::Array(items)) if items.len() == fields.len() => {
            let mut m = Map::new();
            for ((n, ft), x) in fields.iter().zip(items) {
                m.insert((*n).to_owned(), to_json(ft, x)?);
            }
            Some(Json::Object(m))
        }
        (T::Tagged(arms), Value::Map(entries)) => {
            let [(Value::Text(k), x)] = entries.as_slice() else {
                return None;
            };
            let (_, ft) = arms.iter().find(|(n, _)| n == k)?;
            let mut m = Map::new();
            m.insert(k.clone(), to_json(ft, x)?);
            Some(Json::Object(m))
        }
        (T::Or(arms), _) => arms.iter().find_map(|a| to_json(a, v)),
        _ => None,
    }
}

fn canonical_bytes(t: &T, j: &Json) -> Result<Vec<u8>, PayloadError> {
    let v = to_value(t, j, "", 0)?;
    encoded(&v, "")
}

/// The meta payload `j` names, decoded by the Kernel from the bytes its JSON form gives.
///
/// # Errors
/// [`PayloadError`] at the member that is not its CDDL form, or at `""` when the Kernel refuses
/// the value.
pub fn from_json(j: &Json) -> Result<Payload, PayloadError> {
    Payload::from_bytes(&canonical_bytes(&META_PAYLOAD, j)?).map_err(|_| fail(""))
}

/// The JSON form of `p`.
///
/// # Errors
/// [`PayloadError`] when `p` does not encode within the structural limits.
pub fn to_json_value(p: &Payload) -> Result<Json, PayloadError> {
    to_json(&META_PAYLOAD, &p.to_value()).ok_or_else(|| fail(""))
}

/// The `authority-set` `j` names.
///
/// # Errors
/// [`PayloadError`].
pub fn authority_set_from_json(j: &Json) -> Result<AuthoritySet, PayloadError> {
    AuthoritySet::from_bytes(&canonical_bytes(&AUTHORITY_SET, j)?).map_err(|_| fail(""))
}

/// The JSON form of an `authority-set`.
///
/// # Errors
/// [`PayloadError`] when it does not map.
pub fn authority_set_to_json(a: &AuthoritySet) -> Result<Json, PayloadError> {
    to_json(&AUTHORITY_SET, &a.to_value()).ok_or_else(|| fail(""))
}

/// The `canonical-authority` `j` names.
///
/// # Errors
/// [`PayloadError`].
pub fn canonical_authority_from_json(j: &Json) -> Result<CanonicalAuthority, PayloadError> {
    CanonicalAuthority::from_bytes(&canonical_bytes(&CANONICAL, j)?).map_err(|_| fail(""))
}

/// The JSON form of a `canonical-authority`.
///
/// # Errors
/// [`PayloadError`] when it does not map.
pub fn canonical_authority_to_json(a: &CanonicalAuthority) -> Result<Json, PayloadError> {
    to_json(&CANONICAL, &a.to_value()).ok_or_else(|| fail(""))
}

/// The `action-schema` `j` names.
///
/// # Errors
/// [`PayloadError`].
pub fn action_schema_from_json(
    j: &Json,
) -> Result<access_kernel::schema::ActionSchema, PayloadError> {
    access_kernel::schema::ActionSchema::from_bytes(&canonical_bytes(&ACTION_SCHEMA, j)?)
        .map_err(|_| fail(""))
}

/// The `action-ref` `j` names.
///
/// # Errors
/// [`PayloadError`].
pub fn action_ref_from_json(j: &Json) -> Result<access_kernel::model::ActionRef, PayloadError> {
    access_kernel::model::ActionRef::from_bytes(&canonical_bytes(&ACTION_REF, j)?)
        .map_err(|_| fail(""))
}

/// The JSON form of an `action-schema`.
///
/// # Errors
/// [`PayloadError`] when it does not map.
pub fn action_schema_to_json(
    a: &access_kernel::schema::ActionSchema,
) -> Result<Json, PayloadError> {
    to_json(&ACTION_SCHEMA, &a.to_value()).ok_or_else(|| fail(""))
}

/// The rules the contract names, as `OpenAPI` component names.
static RULE_NAMES: [(&T, &str); 17] = [
    (&META_PAYLOAD, "MetaPayload"),
    (&AUTHORITY_SET, "AuthoritySet"),
    (&CANONICAL, "CanonicalAuthority"),
    (&SUBJECT, "KernelSubjectSelector"),
    (&RESOURCE, "KernelResourceSelector"),
    (&ACTION_REF, "KernelActionRef"),
    (&BOUND, "KernelParamBound"),
    (&CONSTRAINTS, "KernelConstraintSet"),
    (&REQUIREMENT, "KernelRequirementTerm"),
    (&WINDOW, "KernelWindow"),
    (&GRANT_CONTENT, "KernelGrantContent"),
    (&ACCEPTANCE, "KernelAcceptanceContent"),
    (&POLICY, "KernelPolicyContent"),
    (&MANDATE, "KernelMandateEnvelope"),
    (&PUBLIC_KEY, "KernelPublicKey"),
    (&SPP, "KernelSpp"),
    (&ACTION_SCHEMA, "KernelActionSchema"),
];

fn name_of(t: &T) -> Option<&'static str> {
    RULE_NAMES
        .iter()
        .find(|(n, _)| std::ptr::eq(*n, t))
        .map(|(_, name)| *name)
}

fn b64_schema(description: &str) -> Json {
    serde_json::json!({ "type": "string", "pattern": "^[A-Za-z0-9_-]*$", "description": description })
}

fn schema(t: &T, defining: bool) -> Json {
    use serde_json::json;
    if !defining && let Some(name) = name_of(t) {
        return json!({ "$ref": format!("#/components/schemas/{name}") });
    }
    match t {
        T::Uint => json!({ "type": "integer", "minimum": 0 }),
        T::Int => json!({ "type": "integer" }),
        T::Text => json!({ "type": "string" }),
        T::Bool => json!({ "type": "boolean" }),
        T::Bytes => b64_schema("Bytes, base64url without padding (an id is 16 bytes)."),
        T::Digest => b64_schema("A SHA-256 digest: its 32 bytes, base64url without padding."),
        T::Eq => json!({ "oneOf": [
            { "type": "string" },
            { "type": "integer" },
            { "type": "boolean" },
            { "type": "object", "additionalProperties": false, "required": ["bytes"],
              "properties": { "bytes": b64_schema("Bytes.") } },
        ] }),
        T::Lit(words) => json!({ "type": "string", "enum": words }),
        T::Array(item) => json!({ "type": "array", "items": schema(item, false) }),
        T::Set(item) => json!({
            "type": "array",
            "uniqueItems": true,
            "items": schema(item, false),
            "description": "A set: any order, no repeats; the canonical form sorts it.",
        }),
        T::Struct(fields) => {
            let props: Map<String, Json> = fields
                .iter()
                .map(|(n, ft, _)| ((*n).to_owned(), schema(ft, false)))
                .collect();
            let required: Vec<&str> = fields
                .iter()
                .filter(|(_, _, r)| *r)
                .map(|(n, _, _)| *n)
                .collect();
            json!({ "type": "object", "additionalProperties": false, "required": required, "properties": props })
        }
        T::Dict(item) => json!({ "type": "object", "additionalProperties": schema(item, false) }),
        T::Tuple(fields) => {
            let props: Map<String, Json> = fields
                .iter()
                .map(|(n, ft)| ((*n).to_owned(), schema(ft, false)))
                .collect();
            let required: Vec<&str> = fields.iter().map(|(n, _)| *n).collect();
            json!({ "type": "object", "additionalProperties": false, "required": required, "properties": props })
        }
        T::Tagged(arms) => {
            let one: Vec<Json> = arms
                .iter()
                .map(|(n, ft)| {
                    json!({
                        "type": "object",
                        "additionalProperties": false,
                        "required": [n],
                        "properties": { *n: schema(ft, false) },
                    })
                })
                .collect();
            json!({ "oneOf": one })
        }
        T::Or(arms) => {
            let one: Vec<Json> = arms.iter().map(|a| schema(a, false)).collect();
            json!({ "oneOf": one })
        }
    }
}

/// The JSON Schemas of the JSON form (L1-ADP-17), by `OpenAPI` component name.
#[must_use]
pub fn schemas() -> Vec<(&'static str, Json)> {
    RULE_NAMES
        .iter()
        .map(|(t, name)| (*name, schema(t, true)))
        .collect()
}

#[cfg(test)]
mod tests;
