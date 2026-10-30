//! ADP JSON (L1-ADP-5…10, OP-141 m.17): a request into the core's terms and a response out.

use std::collections::BTreeMap;

use access_authority_core::app::Response;
use access_authority_core::domain::Request;
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
            .map_or(Ok(0), |v| uint(v, "resource"))?,
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

/// Decodes an evaluation request body (L1-ADP-5…9).
///
/// # Errors
/// [`AdpError`] names the protocol error.
pub fn decode(body: &[u8], max_len: usize) -> R<Decoded> {
    let root = access_kernel::json::parse(body, max_len).map_err(|_| AdpError("json"))?;
    let mut ctx = Obj::of(root.get("context").ok_or(AdpError("context"))?, "context")?;
    let intent = intent(ctx.req("intent", "intent")?)?;
    carriers(&root, &intent)?;
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
    };
    let ais = ctx.opt("ais").map(|a| bytes(a, "ais")).transpose()?;
    ctx.done()?;
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

/// Encodes a decision (L1-ADP-10).
#[must_use]
pub fn encode(response: &Response, mode: Mode) -> Out {
    let mut context = match json_of(&decision_value(&response.decision)) {
        Out::Object(m) => m,
        _ => Map::new(),
    };
    if mode == Mode::Check {
        context.insert(String::from("advisory"), Out::Bool(true));
    }
    if let Some(e) = &response.exercise {
        context.insert(String::from("exercise"), Out::from(b64url_encode(&e.0)));
    }
    if let Some(pos) = response.record {
        context.insert(String::from("record"), Out::from(pos));
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
