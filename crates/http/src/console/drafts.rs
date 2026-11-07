//! The intents the console asks the BFF to draft (OP-151 m.19 (a), PI-7, TN-110): the console
//! never encodes CBOR, so `POST /console/api/intents` turns `{action, resources, params?, mode}`
//! into a canonical intent envelope and its ADP wire JSON. Only a catalogued action of this build
//! is drafted, with its pinned schema digest, on the session's own realm, for the validity the
//! write path takes; anything else is refused (fail closed). Pure: the caller gives the clock.

use std::collections::BTreeMap;

use access_internal_api::idp::{IdpAction, RESOURCE_NAMESPACE};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Mode;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::json::b64url_encode;
use access_kernel::meta::{self, core_action};
use access_kernel::model::{ActionRef, ResourceRef, Window};
use serde_json::{Map, Value, json};

/// The core read action (§9.13.7).
pub const READ: &str = "read";

/// The audit export action (OP-151 m.8 (b), m.19 (d)).
pub const AUDIT_EXPORT: &str = "audit_export";

/// The resource namespace of the audit read and the audit export.
pub const AUDIT_NAMESPACE: &str = "access.audit";

/// The resource namespace of a search (L1-ADP-16).
pub const SEARCH_NAMESPACE: &str = "access.search";

/// The search kinds a draft may name (L1-ADP-16, OP-151 m.13 (d)).
pub const SEARCH_KINDS: [&str; 7] = [
    "subject",
    "resource",
    "action",
    "schema-publications",
    "change-impact",
    "revocation-impact",
    "compromise-impact",
];

/// How far before now a drafted intent is valid, as the write path drafts (OP-151 m.11 (a)).
pub const VALID_BEFORE_MS: u64 = 60_000;

/// How long a drafted intent stays valid (OP-151 m.11 (a), PD 10 minutes).
pub const VALID_FOR_MS: u64 = 10 * 60_000;

/// Longest segment of a resource path.
const MAX_SEGMENT: usize = 128;

/// Most segments of a resource path.
const MAX_SEGMENTS: usize = 8;

/// Why a draft is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DraftError {
    /// The body is not `{action, resources, params?, mode}`.
    #[error("malformed draft request")]
    Malformed,
    /// The action is not a catalogued action this console may draft.
    #[error("action not catalogued")]
    Action,
    /// A resource outside the session's realm or not the action's.
    #[error("resource not allowed")]
    Resource,
    /// A parameter the action does not take, or a value outside its type.
    #[error("parameter not allowed")]
    Params,
    /// The mode is not one the action may be drafted in.
    #[error("mode not allowed")]
    Mode,
}

impl DraftError {
    /// The stable problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "invalid-request",
            Self::Action => "intent-action-not-catalogued",
            Self::Resource => "intent-resource-not-allowed",
            Self::Params => "intent-params-not-allowed",
            Self::Mode => "intent-mode-not-allowed",
        }
    }
}

/// A drafted intent: the envelope and its ADP wire JSON (L1-ADP-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drafted {
    /// The envelope.
    pub envelope: IntentEnvelope,
    /// Its canonical bytes.
    pub bytes: Vec<u8>,
}

impl Drafted {
    /// The answer: `{intent, envelope}`.
    #[must_use]
    pub fn answer(&self) -> Value {
        json!({ "intent": wire(&self.envelope), "envelope": b64url_encode(&self.bytes) })
    }
}

/// What kind of action a draft names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Idp,
    Read,
    Export,
    Meta,
}

fn catalogued(namespace: &str, name: &str, major: u64) -> Option<(ActionRef, Family)> {
    if major != 1 {
        return None;
    }
    if namespace == meta::NAMESPACE {
        let family = match name {
            READ => Family::Read,
            AUDIT_EXPORT => Family::Export,
            _ if meta::is_meta(namespace, name) => Family::Meta,
            _ => return None,
        };
        return Some((core_action(name), family));
    }
    IdpAction::ALL
        .into_iter()
        .find(|a| a.namespace() == namespace && a.name() == name)
        .map(|a| (a.action_ref(), Family::Idp))
}

fn segment(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SEGMENT && s.bytes().all(|b| b.is_ascii_graphic() && b != b'/')
}

fn resources(v: &Value) -> Result<Vec<ResourceRef>, DraftError> {
    let Value::Array(items) = v else {
        return Err(DraftError::Malformed);
    };
    items
        .iter()
        .map(|r| {
            let o = r.as_object().ok_or(DraftError::Malformed)?;
            if o.keys().any(|k| k != "namespace" && k != "path") {
                return Err(DraftError::Malformed);
            }
            let namespace = o
                .get("namespace")
                .and_then(Value::as_str)
                .ok_or(DraftError::Malformed)?;
            let path = o
                .get("path")
                .and_then(Value::as_array)
                .ok_or(DraftError::Malformed)?
                .iter()
                .map(|p| p.as_str().map(String::from).ok_or(DraftError::Malformed))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ResourceRef {
                namespace: String::from(namespace),
                path,
                incarnation: 0,
            })
        })
        .collect()
}

/// Whether `r` is a resource `family` may name in `realm`.
fn allowed(family: Family, r: &[ResourceRef], realm: &str) -> bool {
    let [one] = r else {
        return false;
    };
    if one.path.is_empty() || one.path.len() > MAX_SEGMENTS || !one.path.iter().all(|s| segment(s))
    {
        return false;
    }
    let first = one.path.first().map(String::as_str);
    match family {
        Family::Idp => one.namespace == RESOURCE_NAMESPACE && first == Some(realm),
        Family::Export => one.namespace == AUDIT_NAMESPACE && one.path == [realm],
        Family::Read => {
            (one.namespace == AUDIT_NAMESPACE && one.path == [realm])
                || (one.namespace == SEARCH_NAMESPACE
                    && one.path.len() == 1
                    && first.is_some_and(|k| SEARCH_KINDS.contains(&k)))
        }
        Family::Meta => one.namespace.starts_with("access.") && one.namespace.len() <= MAX_SEGMENT,
    }
}

/// OP-151 m.8 (b): the export's typed range and disclosure; nothing else takes parameters.
fn params(family: Family, v: Option<&Value>) -> Result<BTreeMap<String, ParamValue>, DraftError> {
    let given = match v {
        None | Some(Value::Null) => return Ok(BTreeMap::new()),
        Some(Value::Object(m)) => m,
        Some(_) => return Err(DraftError::Malformed),
    };
    if given.is_empty() {
        return Ok(BTreeMap::new());
    }
    if family != Family::Export {
        return Err(DraftError::Params);
    }
    given
        .iter()
        .map(|(k, v)| {
            let value = match (k.as_str(), v) {
                ("from" | "to", Value::Number(n)) => {
                    ParamValue::Count(n.as_u64().ok_or(DraftError::Params)?)
                }
                ("disclosure", Value::String(s)) if s == "redacted" || s == "full" => {
                    ParamValue::Enum(s.clone())
                }
                _ => return Err(DraftError::Params),
            };
            Ok((k.clone(), value))
        })
        .collect()
}

fn mode(v: Option<&Value>) -> Result<Mode, DraftError> {
    match v.and_then(Value::as_str) {
        Some("check") => Ok(Mode::Check),
        Some("commit") => Ok(Mode::Commit),
        _ => Err(DraftError::Malformed),
    }
}

/// Drafts the intent `body` asks for in the session's realm `realm` at trusted time `now_ms`.
///
/// A core meta-action carries its payload's digest, which a draft has none of, so it is drafted
/// for `check` only; the read is never committed; `idp.*` actions and the export may be either.
///
/// # Errors
/// [`DraftError`].
pub fn draft(body: &[u8], realm: &str, now_ms: u64) -> Result<Drafted, DraftError> {
    let root: Value = serde_json::from_slice(body).map_err(|_| DraftError::Malformed)?;
    let o = root.as_object().ok_or(DraftError::Malformed)?;
    if o.keys()
        .any(|k| !matches!(k.as_str(), "action" | "resources" | "params" | "mode"))
    {
        return Err(DraftError::Malformed);
    }
    let a = o
        .get("action")
        .and_then(Value::as_object)
        .ok_or(DraftError::Malformed)?;
    if a.keys()
        .any(|k| !matches!(k.as_str(), "namespace" | "name" | "major"))
    {
        return Err(DraftError::Malformed);
    }
    let (Some(namespace), Some(name), Some(major)) = (
        a.get("namespace").and_then(Value::as_str),
        a.get("name").and_then(Value::as_str),
        a.get("major").and_then(Value::as_u64),
    ) else {
        return Err(DraftError::Malformed);
    };
    let mode = mode(o.get("mode"))?;
    let (action, family) = catalogued(namespace, name, major).ok_or(DraftError::Action)?;
    let resources = resources(o.get("resources").ok_or(DraftError::Malformed)?)?;
    if !allowed(family, &resources, realm) {
        return Err(DraftError::Resource);
    }
    let params = params(family, o.get("params"))?;
    let committable = matches!(family, Family::Idp | Family::Export);
    if mode == Mode::Commit && !committable {
        return Err(DraftError::Mode);
    }
    let envelope = IntentEnvelope {
        action,
        resources,
        params,
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: now_ms.saturating_sub(VALID_BEFORE_MS),
            until: now_ms.saturating_add(VALID_FOR_MS),
        },
    };
    let bytes = envelope.to_bytes().map_err(|_| DraftError::Malformed)?;
    // PI-7: what is drafted is what the Kernel reads back, or nothing is drafted
    match IntentEnvelope::from_bytes(&bytes) {
        Ok(back) if back == envelope => Ok(Drafted { envelope, bytes }),
        _ => Err(DraftError::Action),
    }
}

fn param_json(v: &ParamValue) -> Value {
    match v {
        ParamValue::Count(n) => json!({ "count": n }),
        ParamValue::Enum(s) => json!({ "enum": s }),
        ParamValue::Flag(b) => json!({ "flag": b }),
        _ => Value::Null,
    }
}

/// The ADP wire JSON of a drafted envelope (L1-ADP-8): the subset a draft produces.
#[must_use]
pub fn wire(e: &IntentEnvelope) -> Value {
    let params: Map<String, Value> = e
        .params
        .iter()
        .map(|(k, v)| (k.clone(), param_json(v)))
        .collect();
    json!({
        "action": {
            "namespace": e.action.namespace,
            "name": e.action.name,
            "major": e.action.major,
            "schema": b64url_encode(&e.action.schema.0),
        },
        "resources": e.resources.iter().map(|r| json!({
            "namespace": r.namespace,
            "path": r.path,
            "incarnation": r.incarnation,
        })).collect::<Vec<_>>(),
        "params": params,
        "validity": { "from": e.validity.from, "until": e.validity.until },
    })
}

#[cfg(test)]
mod tests;
