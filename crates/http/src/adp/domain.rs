//! ADP JSON (L1-ADP-5…10, OP-141 m.17): a request into the core's terms and a response out.

use std::collections::BTreeMap;

use access_authority_core::app::MAX_PROOFS;
use access_authority_core::app::Response;
use access_authority_core::domain::{ProofRef, Request};
use access_authority_core::query::{Hit, Query};
use access_kernel::codec::Canonical;
use access_kernel::combinator::codec::decision_value;
use access_kernel::combinator::{Capacity, Mode, Outcome};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::json::{Json, b64url_decode, b64url_encode};
use access_kernel::meta::{ExerciseBasis, HoldingRef, Payload};
use access_kernel::model::{ActionRef, EqValue, Id, PurposeRef, ResourceRef, Window};
use serde_json::{Map, Value as Out};
use suiss_crypto::dcbor::Value;

/// A protocol error: the request is not evaluated (§9.5 k.4, L1-ADP-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("protocol error: {0}")]
pub struct AdpError(pub &'static str);

/// A decoded request with what came with it.
#[derive(Clone, Debug)]
pub struct Decoded {
    /// The request.
    pub request: Request,
    /// The AIS bytes.
    pub ais: Option<Vec<u8>>,
}

type R<T> = Result<T, AdpError>;

/// The members of one object; whatever is left unread is an unknown member (L1-ADP-9).
struct Obj<'a> {
    members: Vec<(&'a str, &'a Json)>,
}

impl<'a> Obj<'a> {
    fn of(v: &'a Json, what: &'static str) -> R<Self> {
        match v {
            Json::Object(m) => Ok(Self {
                members: m.iter().map(|(k, v)| (k.as_str(), v)).collect(),
            }),
            _ => Err(AdpError(what)),
        }
    }

    fn opt(&mut self, name: &str) -> Option<&'a Json> {
        let i = self.members.iter().position(|(k, _)| *k == name)?;
        Some(self.members.swap_remove(i).1)
    }

    fn req(&mut self, name: &str, what: &'static str) -> R<&'a Json> {
        self.opt(name).ok_or(AdpError(what))
    }

    fn done(self) -> R<()> {
        if self.members.is_empty() {
            Ok(())
        } else {
            Err(AdpError("unknown-member"))
        }
    }
}

/// The single member of a tagged object such as `{"anchor": ...}`.
fn single<'a>(v: &'a Json, what: &'static str) -> R<(&'a str, &'a Json)> {
    match v {
        Json::Object(m) if m.len() == 1 => m
            .first()
            .map(|(k, v)| (k.as_str(), v))
            .ok_or(AdpError(what)),
        _ => Err(AdpError(what)),
    }
}

fn text(v: &Json, what: &'static str) -> R<String> {
    v.as_str().map(String::from).ok_or(AdpError(what))
}

fn uint(v: &Json, what: &'static str) -> R<u64> {
    v.as_int()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or(AdpError(what))
}

fn bytes(v: &Json, what: &'static str) -> R<Vec<u8>> {
    v.as_str()
        .and_then(|s| b64url_decode(s).ok())
        .ok_or(AdpError(what))
}

fn fixed<const N: usize>(v: &Json, what: &'static str) -> R<[u8; N]> {
    <[u8; N]>::try_from(bytes(v, what)?.as_slice()).map_err(|_| AdpError(what))
}

fn id(v: &Json) -> R<Id> {
    fixed(v, "id").map(Id)
}

fn digest(v: &Json) -> R<Digest> {
    fixed(v, "digest").map(Digest)
}

fn window(v: &Json) -> R<Window> {
    let mut o = Obj::of(v, "window")?;
    let w = Window {
        from: uint(o.req("from", "window")?, "window")?,
        until: uint(o.req("until", "window")?, "window")?,
    };
    o.done()?;
    Ok(w)
}

fn action(v: &Json) -> R<ActionRef> {
    let mut o = Obj::of(v, "action")?;
    let a = ActionRef {
        namespace: text(o.req("namespace", "action")?, "action")?,
        name: text(o.req("name", "action")?, "action")?,
        major: uint(o.req("major", "action")?, "action")?,
        schema: digest(o.req("schema", "action")?)?,
    };
    o.done()?;
    Ok(a)
}

fn resource(v: &Json) -> R<ResourceRef> {
    let mut o = Obj::of(v, "resource")?;
    let Json::Array(path) = o.req("path", "resource")? else {
        return Err(AdpError("resource"));
    };
    let r = ResourceRef {
        namespace: text(o.req("namespace", "resource")?, "resource")?,
        path: path.iter().map(|p| text(p, "resource")).collect::<R<_>>()?,
        incarnation: o
            .opt("incarnation")
            .map(|v| uint(v, "resource"))
            .transpose()?
            .unwrap_or_default(),
    };
    o.done()?;
    Ok(r)
}

fn purpose(v: &Json) -> R<PurposeRef> {
    match single(v, "purpose")? {
        ("code", c) => Ok(PurposeRef::Code(text(c, "purpose")?)),
        ("work", d) => Ok(PurposeRef::Work(digest(d)?)),
        ("aim", d) => Ok(PurposeRef::Aim(digest(d)?)),
        _ => Err(AdpError("purpose")),
    }
}

fn eq(v: &Json) -> R<EqValue> {
    Ok(match v {
        Json::Str(s) => EqValue::Text(s.clone()),
        Json::Int(i) => EqValue::Int(*i),
        Json::Bool(b) => EqValue::Bool(*b),
        Json::Object(_) => match single(v, "param")? {
            ("bytes", b) => EqValue::Bytes(bytes(b, "param")?),
            _ => return Err(AdpError("param")),
        },
        _ => return Err(AdpError("param")),
    })
}

fn param(v: &Json) -> R<ParamValue> {
    let (tag, inner) = single(v, "param")?;
    Ok(match tag {
        "enum" => ParamValue::Enum(text(inner, "param")?),
        "eq" => ParamValue::Eq(eq(inner)?),
        "amount" => {
            let mut o = Obj::of(inner, "param")?;
            let a = ParamValue::Amount {
                value: o.req("value", "param")?.as_int().ok_or(AdpError("param"))?,
                unit: text(o.req("unit", "param")?, "param")?,
            };
            o.done()?;
            a
        }
        "count" => ParamValue::Count(uint(inner, "param")?),
        "interval" => ParamValue::Interval(window(inner)?),
        "resource" => ParamValue::Resource(resource(inner)?),
        "subject" => ParamValue::Subject(id(inner)?),
        "purpose" => ParamValue::Purpose(purpose(inner)?),
        "flag" => match inner {
            Json::Bool(b) => ParamValue::Flag(*b),
            _ => return Err(AdpError("param")),
        },
        _ => return Err(AdpError("param")),
    })
}

fn named<T>(
    v: Option<&Json>,
    each: impl Fn(&Json) -> R<T>,
    what: &'static str,
) -> R<BTreeMap<String, T>> {
    match v {
        None => Ok(BTreeMap::new()),
        Some(Json::Object(m)) => m.iter().map(|(k, v)| Ok((k.clone(), each(v)?))).collect(),
        Some(_) => Err(AdpError(what)),
    }
}

fn context_refs(v: &Json) -> R<ContextRefs> {
    let mut o = Obj::of(v, "context-refs")?;
    let c = ContextRefs {
        work: o.opt("work").map(digest).transpose()?,
        commitment: o.opt("commitment").map(digest).transpose()?,
        step: o.opt("step").map(digest).transpose()?,
        upstream_exercise: o.opt("upstream_exercise").map(digest).transpose()?,
    };
    o.done()?;
    Ok(c)
}

/// L1-ADP-8.
fn intent(v: &Json) -> R<IntentEnvelope> {
    let mut o = Obj::of(v, "intent")?;
    let Json::Array(resources) = o.req("resources", "intent")? else {
        return Err(AdpError("intent"));
    };
    if resources.is_empty() {
        return Err(AdpError("intent"));
    }
    let e = IntentEnvelope {
        action: action(o.req("action", "intent")?)?,
        resources: resources.iter().map(resource).collect::<R<_>>()?,
        params: named(o.opt("params"), param, "param")?,
        opaque: named(o.opt("opaque"), digest, "digest")?,
        recipient: o.opt("recipient").map(id).transpose()?,
        purpose: o.opt("purpose").map(purpose).transpose()?,
        context: o
            .opt("context")
            .map(context_refs)
            .transpose()?
            .unwrap_or_default(),
        validity: window(o.req("validity", "intent")?)?,
    };
    o.done()?;
    Ok(e)
}

fn basis(v: &Json) -> R<ExerciseBasis> {
    match single(v, "basis")? {
        ("anchor", a) => Ok(ExerciseBasis::Anchor(id(a)?)),
        ("public", g) => Ok(ExerciseBasis::Public(id(g)?)),
        ("holding", h) => {
            let mut o = Obj::of(h, "basis")?;
            let r = HoldingRef {
                grant: id(o.req("grant", "basis")?)?,
                holder: id(o.req("holder", "basis")?)?,
                since: uint(o.req("since", "basis")?, "basis")?,
            };
            o.done()?;
            Ok(ExerciseBasis::Holding(r))
        }
        _ => Err(AdpError("basis")),
    }
}

fn capacity(v: &Json) -> R<Capacity> {
    match v {
        Json::Str(s) if s == "own" => Ok(Capacity::Own),
        Json::Object(_) => match single(v, "capacity")? {
            ("for", p) => Ok(Capacity::For(id(p)?)),
            _ => Err(AdpError("capacity")),
        },
        _ => Err(AdpError("capacity")),
    }
}

fn mode(v: &Json) -> R<Mode> {
    match v.as_str() {
        Some("commit") => Ok(Mode::Commit),
        Some("continue") => Ok(Mode::Continue),
        Some("check") => Ok(Mode::Check),
        _ => Err(AdpError("mode")),
    }
}

/// L1-ADP-5: the `AuthZEN` carriers name the intent's action and first resource.
fn carriers(root: &Json, intent: &IntentEnvelope) -> R<()> {
    let action = root
        .get("action")
        .and_then(|a| a.get("name"))
        .and_then(Json::as_str);
    let resource = root.get("resource");
    let kind = resource.and_then(|r| r.get("type")).and_then(Json::as_str);
    let rid = resource.and_then(|r| r.get("id")).and_then(Json::as_str);
    let first = intent.resources.first().ok_or(AdpError("intent"))?;
    if root.get("subject").is_none()
        || action != Some(intent.action.name.as_str())
        || kind != Some(first.namespace.as_str())
        || rid != Some(first.path.join("/").as_str())
    {
        return Err(AdpError("carrier"));
    }
    Ok(())
}

/// The proof objects of L1-ADP-12: 1 to 16 of them.
fn proofs(v: &Json) -> R<Vec<ProofRef>> {
    let Json::Array(items) = v else {
        return Err(AdpError("proofs"));
    };
    if items.is_empty() || items.len() > MAX_PROOFS {
        return Err(AdpError("proofs"));
    }
    items
        .iter()
        .map(|p| match single(p, "proofs")? {
            ("claim", c) => Ok(ProofRef::Claim(bytes(c, "proofs")?)),
            ("claim_ref", c) => Ok(ProofRef::ClaimRef(id(c)?)),
            ("contribution", c) => Ok(ProofRef::Contribution(digest(c)?)),
            _ => Err(AdpError("unknown-member")),
        })
        .collect()
}

/// Decodes an evaluation request body (L1-ADP-5…9, L1-ADP-12, L1-ADP-13).
///
/// # Errors
/// [`AdpError`] names the protocol error.
pub fn decode(body: &[u8], max_len: usize) -> R<Decoded> {
    let root = access_kernel::json::parse(body, max_len).map_err(|_| AdpError("json"))?;
    decode_value(&root)
}

/// Most items of one batch (OP-141 m.22 (a), PD).
pub const MAX_BATCH: usize = 64;

/// How a batch is evaluated (`AuthZEN` `evaluations_semantic`, OP-141 m.22 (a)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Semantic {
    /// Every item.
    ExecuteAll,
    /// Stop at the first deny; check only.
    DenyOnFirstDeny,
    /// Stop at the first permit; check only.
    PermitOnFirstPermit,
}

/// One batch item: decoded, or the protocol error it got.
pub type Item = R<Decoded>;

/// Decodes a batch body: the items with the top-level carriers they inherit, and the
/// semantic. `context` is never inherited (OP-141 m.22 (a)).
///
/// # Errors
/// [`AdpError`] for a body that is not a batch; an item's own error stays with the item.
pub fn decode_batch(body: &[u8], max_len: usize) -> R<(Vec<Item>, Semantic)> {
    let root = access_kernel::json::parse(body, max_len).map_err(|_| AdpError("json"))?;
    let Some(Json::Array(items)) = root.get("evaluations") else {
        return Err(AdpError("evaluations"));
    };
    if items.is_empty() || items.len() > MAX_BATCH {
        return Err(AdpError("evaluations"));
    }
    let semantic = match root
        .get("options")
        .and_then(|o| o.get("evaluations_semantic"))
        .map(|s| s.as_str())
    {
        None | Some(Some("execute_all")) => Semantic::ExecuteAll,
        Some(Some("deny_on_first_deny")) => Semantic::DenyOnFirstDeny,
        Some(Some("permit_on_first_permit")) => Semantic::PermitOnFirstPermit,
        Some(_) => return Err(AdpError("evaluations_semantic")),
    };
    let decoded: Vec<Item> = items
        .iter()
        .map(|item| {
            let Json::Object(own) = item else {
                return Err(AdpError("evaluations"));
            };
            let mut merged = own.clone();
            for carrier in ["subject", "action", "resource"] {
                if item.get(carrier).is_none()
                    && let Some(v) = root.get(carrier)
                {
                    merged.push((String::from(carrier), v.clone()));
                }
            }
            decode_value(&Json::Object(merged))
        })
        .collect();
    // OP-141 m.22 (a): short-circuiting would leave it open which commit happened
    if semantic != Semantic::ExecuteAll
        && decoded
            .iter()
            .any(|d| d.as_ref().is_ok_and(|d| d.request.mode != Mode::Check))
    {
        return Err(AdpError("evaluations_semantic"));
    }
    Ok((decoded, semantic))
}

fn decode_value(root: &Json) -> R<Decoded> {
    let mut ctx = Obj::of(root.get("context").ok_or(AdpError("context"))?, "context")?;
    let intent = intent(ctx.req("intent", "intent")?)?;
    carriers(root, &intent)?;
    let decoded = context(&mut ctx, intent)?;
    ctx.done()?;
    Ok(decoded)
}

/// Decodes a search body of `kind` (L1-ADP-16): the reader's context, `context.query` and the
/// page token. The `AuthZEN` carriers are the caller's own and are not read.
///
/// # Errors
/// [`AdpError`] names the protocol error.
pub fn decode_search(
    body: &[u8],
    max_len: usize,
    kind: &str,
) -> R<(Decoded, Query, Option<String>)> {
    let root = access_kernel::json::parse(body, max_len).map_err(|_| AdpError("json"))?;
    let mut ctx = Obj::of(root.get("context").ok_or(AdpError("context"))?, "context")?;
    let intent = intent(ctx.req("intent", "intent")?)?;
    let mut q = Obj::of(ctx.req("query", "query")?, "query")?;
    let query = match kind {
        "subject" => Query::Subject {
            action: action(q.req("action", "query")?)?,
            resource: resource(q.req("resource", "query")?)?,
        },
        "resource" => Query::Resource {
            party: id(q.req("party", "query")?)?,
            action: action(q.req("action", "query")?)?,
        },
        "action" => Query::Action {
            party: id(q.req("party", "query")?)?,
            resource: resource(q.req("resource", "query")?)?,
        },
        _ => return Err(AdpError("search")),
    };
    q.done()?;
    let decoded = context(&mut ctx, intent)?;
    ctx.done()?;
    let page = root
        .get("page")
        .and_then(|p| p.get("token"))
        .map(|t| text(t, "page"))
        .transpose()?
        .filter(|t| !t.is_empty());
    Ok((decoded, query, page))
}

/// One search page as `AuthZEN` results (L1-ADP-16).
#[must_use]
pub fn encode_search(hits: &[Hit], next: Option<&str>) -> Out {
    let results: Vec<Out> = hits
        .iter()
        .map(|h| match h {
            Hit::Party(p) => {
                serde_json::json!({ "type": "access_party", "id": b64url_encode(&p.0) })
            }
            Hit::Public => serde_json::json!({ "type": "public" }),
            Hit::Group(classes) => serde_json::json!({ "type": "group", "id": classes.join(",") }),
            Hit::Resource(sel) => json_of(&sel.to_value()),
            Hit::Action(a) => json_of(&a.to_value()),
        })
        .collect();
    serde_json::json!({
        "results": results,
        "page": { "next_token": next.unwrap_or("") },
        "context": { "advisory": true },
    })
}

fn context(ctx: &mut Obj<'_>, intent: IntentEnvelope) -> R<Decoded> {
    let nonce = bytes(ctx.req("nonce", "nonce")?, "nonce")?;
    if !(16..=64).contains(&nonce.len()) {
        return Err(AdpError("nonce"));
    }
    let payload = ctx
        .opt("payload")
        .map(|p| Payload::from_bytes(&bytes(p, "payload")?).map_err(|_| AdpError("payload")))
        .transpose()?;
    let request = Request {
        domain: digest(ctx.req("domain", "domain")?)?,
        mode: mode(ctx.req("mode", "mode")?)?,
        nonce,
        intent,
        payload,
        basis: basis(ctx.req("basis", "basis")?)?,
        capacity: capacity(ctx.req("capacity", "capacity")?)?,
        proofs: ctx
            .opt("proofs")
            .map(proofs)
            .transpose()?
            .unwrap_or_default(),
        exercise: ctx.opt("exercise").map(digest).transpose()?,
        consistency: ctx
            .opt("consistency_token")
            .map(|t| text(t, "consistency_token"))
            .transpose()?,
    };
    let ais = ctx.opt("ais").map(|a| bytes(a, "ais")).transpose()?;
    Ok(Decoded { request, ais })
}

/// A dCBOR value as JSON: binaries base64url, a digest `[-16, h]` as `h` (L1-ADP-6).
fn json_of(v: &Value) -> Out {
    match v {
        Value::Unsigned(n) => Out::from(*n),
        Value::Negative(n) => i64::try_from(*n)
            .ok()
            .and_then(i64::checked_neg)
            .and_then(|n| n.checked_sub(1))
            .map_or(Out::Null, Out::from),
        Value::Bytes(b) => Out::from(b64url_encode(b)),
        Value::Text(t) => Out::from(t.as_str()),
        Value::Bool(b) => Out::from(*b),
        Value::Array(items) => match items.as_slice() {
            [Value::Negative(15), Value::Bytes(h)] if h.len() == 32 => Out::from(b64url_encode(h)),
            _ => Out::Array(items.iter().map(json_of).collect()),
        },
        Value::Map(entries) => Out::Object(
            entries
                .iter()
                .map(|(k, v)| {
                    let key = match k {
                        Value::Text(t) => t.clone(),
                        other => json_of(other).to_string(),
                    };
                    (key, json_of(v))
                })
                .collect::<Map<_, _>>(),
        ),
        Value::Tag(_, inner) => json_of(inner),
    }
}

/// The requester's view of a blocker (§9.6, TI-20, OP-141 m.22 (h)): its class, resolver and
/// remediation, and its position only when it is a lineage hop; never the subcode, which may
/// name an undisclosed restriction.
fn requester_view(blocker: &mut Out) {
    if let Out::Object(b) = blocker {
        b.remove("subcode");
        if b.get("position").is_none_or(|p| p.get("hop").is_none()) {
            b.remove("position");
        }
    }
}

/// Encodes a decision (L1-ADP-10); the disclosure filter is its last stage (TI-20).
#[must_use]
pub fn encode(response: &Response, mode: Mode) -> Out {
    let mut context = match json_of(&decision_value(&response.decision)) {
        Out::Object(m) => m,
        _ => Map::new(),
    };
    if let Some(Out::Array(blockers)) = context.get_mut("blockers") {
        blockers.iter_mut().for_each(requester_view);
    }
    if mode == Mode::Check {
        context.insert(String::from("advisory"), Out::Bool(true));
    }
    if let Some(e) = &response.exercise {
        context.insert(String::from("exercise"), Out::from(b64url_encode(&e.0)));
    }
    if let Some(t) = &response.consistency {
        context.insert(String::from("consistency_token"), Out::from(t.as_str()));
    }
    // OP-141 m.22 (e): the record is named by an opaque reference, never its position
    if let Some(r) = &response.basis_ref {
        context.insert(String::from("basis_ref"), Out::from(r.as_str()));
    }
    if response.replayed {
        context.insert(String::from("replayed"), Out::Bool(true));
    }
    context.insert(
        String::from("versions"),
        serde_json::json!({ "core": 1, "meta_schema": 1 }),
    );
    let mut out = Map::new();
    out.insert(
        String::from("decision"),
        Out::Bool(response.decision.outcome == Outcome::Allow),
    );
    out.insert(String::from("context"), Out::Object(context));
    Out::Object(out)
}

#[cfg(test)]
mod tests;
