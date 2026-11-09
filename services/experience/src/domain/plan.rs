//! The search reads a hub needs (L1-ADP-16, OP-141 m.22 (j)): one `check` over `access:read`
//! on `access.search/[kind]` per domain and kind, naming the reader as the query's Party. The
//! reader's device signs the AIS; this service never holds a key that could (XI-18).

use std::collections::BTreeMap;

use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::json::b64url_encode;
use access_kernel::meta::{core_action, meta_anchor};
use access_kernel::model::{Id, ResourceRef, Window};
use serde_json::{Value, json};

use crate::contract::{Kind, PlannedRead};
use crate::domain::Malformed;

/// The resource namespace of a search.
pub const SEARCH_NAMESPACE: &str = "access.search";

/// How far before now a read intent is valid.
pub const VALID_BEFORE_MS: u64 = 60_000;

/// How long a read intent stays valid.
pub const VALID_FOR_MS: u64 = 5 * 60_000;

/// The search intent of `kind`, valid around `now`.
#[must_use]
pub fn intent(kind: Kind, now: u64) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: core_action("read"),
        resources: vec![ResourceRef {
            namespace: String::from(SEARCH_NAMESPACE),
            path: vec![String::from(kind.search())],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: now.saturating_sub(VALID_BEFORE_MS),
            until: now.saturating_add(VALID_FOR_MS),
        },
    }
}

fn b64(bytes: &[u8]) -> Value {
    Value::from(b64url_encode(bytes))
}

/// The search query of `kind`: the hub kinds name the reader; the domain's Changes feed is
/// always the reader's own (IA-2).
fn query(kind: Kind, viewer: Id) -> Value {
    query_text(kind, &b64url_encode(&viewer.0))
}

fn query_text(kind: Kind, viewer: &str) -> Value {
    match kind {
        Kind::Changes => json!({}),
        Kind::Inventory | Kind::Activity => json!({ "party": viewer }),
    }
}

/// The read of `kind` in `domain` for `viewer` with `nonce`.
///
/// # Errors
/// [`Malformed`] when the intent does not encode.
pub fn read(
    domain: Digest,
    kind: Kind,
    viewer: Id,
    nonce: [u8; 16],
    now: u64,
) -> Result<PlannedRead, Malformed> {
    let envelope = intent(kind, now);
    let digest = intent_digest(&envelope).map_err(|_| Malformed("intent"))?;
    let action = &envelope.action;
    let basis = json!({ "anchor": b64(&meta_anchor(&domain).0) });
    let body = json!({
        "context": {
            "domain": b64(&domain.0),
            "mode": "check",
            "nonce": b64(&nonce),
            "intent": {
                "action": {
                    "namespace": action.namespace,
                    "name": action.name,
                    "major": action.major,
                    "schema": b64(&action.schema.0),
                },
                "resources": [{ "namespace": SEARCH_NAMESPACE, "path": [kind.search()] }],
                "validity": { "from": envelope.validity.from, "until": envelope.validity.until },
            },
            "basis": basis,
            "capacity": "own",
            "query": query(kind, viewer),
        }
    });
    Ok(PlannedRead {
        domain: b64url_encode(&domain.0),
        kind,
        nonce: b64url_encode(&nonce),
        intent_digest: b64url_encode(&digest.0),
        basis,
        body,
    })
}

/// Whether a signed body is a read of `kind` for `viewer` in `domain` and nothing else: the
/// service forwards no other request (XI-22, OP-153 m.3 (v)).
#[must_use]
pub fn is_read(body: &Value, domain: &str, kind: Kind, viewer: &str) -> bool {
    let c = &body["context"];
    body.as_object().is_some_and(|o| o.len() == 1)
        && c["domain"] == domain
        && c["mode"] == "check"
        && c.get("query") == Some(&query_text(kind, viewer))
        && c.pointer("/intent/resources")
            == Some(&json!([{ "namespace": SEARCH_NAMESPACE, "path": [kind.search()] }]))
        && c.pointer("/intent/action/name") == Some(&json!("read"))
        && c.pointer("/intent/action/namespace") == Some(&json!("access"))
        && c.get("payload").is_none()
}

/// The domain digest of its base64url text.
///
/// # Errors
/// [`Malformed`] when it is not 32 bytes of unpadded base64url.
pub fn domain_of(text: &str) -> Result<Digest, Malformed> {
    let bytes = access_kernel::json::b64url_decode(text).map_err(|_| Malformed("domain"))?;
    <[u8; 32]>::try_from(bytes)
        .map(Digest)
        .map_err(|_| Malformed("domain"))
}

/// A Party of its base64url text.
///
/// # Errors
/// [`Malformed`] when it is not 16 bytes of unpadded base64url.
pub fn party_of(text: &str) -> Result<Id, Malformed> {
    let bytes = access_kernel::json::b64url_decode(text).map_err(|_| Malformed("party"))?;
    <[u8; 16]>::try_from(bytes)
        .map(Id)
        .map_err(|_| Malformed("party"))
}
