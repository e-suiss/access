//! ADP JSON (L1-ADP-5…10, OP-141 m.17): a request into the core's terms and a response out.

use std::collections::BTreeMap;

use access_authority_core::app::MAX_PROOFS;
use access_authority_core::app::audit::{Explained, Named, reason_user};
use access_authority_core::app::impact::{Compromised, Revoked};
use access_authority_core::app::{Response, Scope};
use access_authority_core::domain::{ProofRef, Request};
use access_authority_core::query::{Change, Hit, Query};
use access_internal_api::context::RateContext;
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
    /// The PEP's pseudonymous rate context (§13.7.4, OP-152 m.5 (b)).
    pub context: Option<RateContext>,
}

type R<T> = Result<T, AdpError>;

/// Which body a request came in: an ADP request with its `context`, or an eligibility check
/// with its `set` (OP-149 m.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    /// `evaluation`, `evaluations`, `explain` and `search`.
    Context,
    /// `eligibility:check`.
    Eligibility,
}

/// Where in `body` the part a protocol `code` names is, as a URI fragment JSON Pointer
/// (RFC 6901, RFC 9457 §3); `None` for a code that names no single member.
#[must_use]
pub fn pointer(body: Body, code: &str) -> Option<String> {
    let at = match body {
        Body::Context => "#/context",
        Body::Eligibility => "#/set",
    };
    let member = match (body, code) {
        (Body::Eligibility, "subject" | "set") => return Some(format!("#/{code}")),
        (Body::Eligibility, "consistency_token") => return Some(String::from("#/as_of")),
        (Body::Context, "context") => return Some(String::from("#/context")),
        (
            _,
            "domain" | "nonce" | "payload" | "mode" | "basis" | "capacity" | "proofs" | "exercise"
            | "consistency_token" | "ais" | "intent" | "query" | "record" | "scope"
            | "rate_context",
        ) => code,
        (_, "aas-binding") => "proofs",
        (_, "intent-validity" | "window") => "intent/validity",
        (_, "action") => "intent/action",
        (_, "resource") => "intent/resources",
        (_, "param") => "intent/params",
        _ => return None,
    };
    Some(format!("{at}/{member}"))
}

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

/// An error of a generic part as the member it sits in: `id` or `digest` alone names nothing.
fn within(member: &'static str) -> impl Fn(AdpError) -> AdpError {
    move |e| {
        if matches!(e.0, "id" | "digest") {
            AdpError(member)
        } else {
            e
        }
    }
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

/// The proof objects of L1-ADP-12: 1 to 64 of them.
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
            ("aas", c) => Ok(ProofRef::Aas(bytes(c, "proofs")?)),
            ("foreign_pap", c) => foreign_pap(c),
            _ => Err(AdpError("unknown-member")),
        })
        .collect()
}

/// A foreign PAP with its domain's metadata, its key excerpt and the holder's presentation
/// (OP-143 m.13 (c)), and the home domain's status list with its key excerpt when the PAP
/// names a status entry (§9.15A.3).
fn foreign_pap(v: &Json) -> R<ProofRef> {
    let mut o = Obj::of(v, "proofs")?;
    let status = match o.opt("status") {
        None => None,
        Some(s) => {
            let mut s = Obj::of(s, "proofs")?;
            let list = bytes(s.req("list", "proofs")?, "proofs")?;
            let excerpt = bytes(s.req("excerpt", "proofs")?, "proofs")?;
            s.done()?;
            Some((list, excerpt))
        }
    };
    let p = ProofRef::ForeignPap {
        metadata: bytes(o.req("metadata", "proofs")?, "proofs")?,
        pap: bytes(o.req("pap", "proofs")?, "proofs")?,
        excerpt: bytes(o.req("excerpt", "proofs")?, "proofs")?,
        presentation: bytes(o.req("presentation", "proofs")?, "proofs")?,
        status,
    };
    o.done()?;
    Ok(p)
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
    // OP-141 m.22 (a)
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

/// Decodes the `context` member of a body that has no `AuthZEN` carriers, such as a
/// publication request (L1-ADP-18).
///
/// # Errors
/// [`AdpError`] names the protocol error.
pub fn decode_context(body: &[u8], max_len: usize) -> R<Decoded> {
    let root = access_kernel::json::parse(body, max_len).map_err(|_| AdpError("json"))?;
    let mut ctx = Obj::of(root.get("context").ok_or(AdpError("context"))?, "context")?;
    let intent = intent(ctx.req("intent", "intent")?)?;
    let decoded = context(&mut ctx, intent)?;
    ctx.done()?;
    Ok(decoded)
}

/// What an eligibility body's `set` may not carry: it is always an anonymous `check`.
const NOT_IN_SET: [&str; 7] = [
    "mode",
    "nonce",
    "payload",
    "exercise",
    "consistency_token",
    "ais",
    "rate_context",
];

/// Decodes an eligibility body `{subject, set, as_of?}` (OP-149 m.10): `set` is the context
/// of an ADP `check` (`domain`, `intent`, `basis`, `capacity`, `proofs`) and `as_of` a
/// consistency token. The nonce is derived from the body, since nothing is recorded.
///
/// # Errors
/// [`AdpError`] names the protocol error.
pub fn decode_eligibility(body: &[u8], max_len: usize) -> R<(Decoded, Id)> {
    let root = access_kernel::json::parse(body, max_len).map_err(|_| AdpError("json"))?;
    let mut top = Obj::of(&root, "eligibility")?;
    let subject = id(top.req("subject", "subject")?).map_err(within("subject"))?;
    let set = top.req("set", "set")?;
    let as_of = top.opt("as_of").cloned();
    top.done()?;
    let mut ctx = Obj::of(set, "set")?;
    if NOT_IN_SET.iter().any(|m| ctx.opt(m).is_some()) {
        return Err(AdpError("set"));
    }
    let mode = Json::Str(String::from("check"));
    let nonce = Json::Str(b64url_encode(&suiss_crypto::digest::sha256(body)));
    ctx.members.push(("mode", &mode));
    ctx.members.push(("nonce", &nonce));
    if let Some(t) = &as_of {
        ctx.members.push(("consistency_token", t));
    }
    let intent = intent(ctx.req("intent", "intent")?).map_err(within("intent"))?;
    let decoded = context(&mut ctx, intent)?;
    ctx.done()?;
    Ok((decoded, subject))
}

/// Decodes an explain body: the request and, for a recorded decision, `context.record`
/// (L1-ADP-15, OP-141 m.36 (b)).
///
/// # Errors
/// [`AdpError`] names the protocol error.
pub fn decode_explain(body: &[u8], max_len: usize) -> R<(Decoded, Option<(u64, Scope)>)> {
    let root = access_kernel::json::parse(body, max_len).map_err(|_| AdpError("json"))?;
    let mut ctx = Obj::of(root.get("context").ok_or(AdpError("context"))?, "context")?;
    let intent = intent(ctx.req("intent", "intent")?)?;
    carriers(&root, &intent)?;
    let record = ctx.opt("record").map(|r| uint(r, "record")).transpose()?;
    // OP-141 m.38 (a)
    let scope = match ctx
        .opt("scope")
        .map(|s| text(s, "scope"))
        .transpose()?
        .as_deref()
    {
        None | Some("requester") => Scope::Requester,
        Some("viewer") => Scope::Viewer,
        Some("audit") => Scope::Audit,
        Some(_) => return Err(AdpError("scope")),
    };
    let decoded = context(&mut ctx, intent)?;
    ctx.done()?;
    if record.is_none() && scope != Scope::Requester {
        return Err(AdpError("scope"));
    }
    Ok((decoded, record.map(|r| (r, scope))))
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
        "schema-publications" => Query::SchemaPublications {
            namespace: text(q.req("namespace", "query")?, "query")?,
        },
        "change-impact" => change(&mut q)?,
        "roles" => Query::Roles,
        "role" => Query::Role {
            name: text(q.req("name", "query")?, "query")?,
            version: q.opt("version").map(|v| uint(v, "query")).transpose()?,
        },
        "admin-grant" => Query::AdminGrant {
            grant: id(q.req("grant", "query")?).map_err(within("query"))?,
        },
        "holdings" => Query::Holdings,
        "changes" => Query::Changes {
            before: q.opt("before").map(|v| uint(v, "query")).transpose()?,
        },
        "bulk-impact" => {
            let Json::Array(items) = q.req("revoke", "query")? else {
                return Err(AdpError("query"));
            };
            if items.is_empty() || items.len() > access_authority_core::app::management::MAX_BULK {
                return Err(AdpError("query"));
            }
            let revoke = items
                .iter()
                .map(|g| id(g).map_err(within("query")))
                .collect::<R<Vec<_>>>()?;
            let unique: std::collections::BTreeSet<_> = revoke.iter().collect();
            if unique.len() != revoke.len() {
                return Err(AdpError("query"));
            }
            Query::BulkImpact { revoke }
        }
        "revocation-impact" => {
            let revoked = match (q.opt("grant"), q.opt("instance")) {
                (Some(g), None) => Revoked::Grant(id(g).map_err(within("query"))?),
                (None, Some(i)) => Revoked::Instance(id(i).map_err(within("query"))?),
                _ => return Err(AdpError("query")),
            };
            Query::RevocationImpact {
                revoked,
                at: q.opt("at").map(|a| uint(a, "query")).transpose()?,
            }
        }
        "compromise-impact" => {
            let compromised = match (q.opt("instance"), q.opt("issuer"), q.opt("key")) {
                (Some(i), None, None) => Compromised::Instance(id(i).map_err(within("query"))?),
                (None, Some(p), None) => Compromised::Issuer(id(p).map_err(within("query"))?),
                (None, None, Some(k)) => Compromised::Key(fixed(k, "query")?),
                _ => return Err(AdpError("query")),
            };
            Query::CompromiseImpact {
                compromised,
                window: window(q.req("window", "query")?).map_err(within("query"))?,
            }
        }
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

/// The change of a `change-impact` search: a role move or a `policy.set` candidate.
fn change(q: &mut Obj<'_>) -> R<Query> {
    if let Some(name) = q.opt("role") {
        return Ok(Query::ChangeImpact(Change::Role {
            name: text(name, "query")?,
            from: uint(q.req("from", "query")?, "query")?,
            to: uint(q.req("to", "query")?, "query")?,
        }));
    }
    let candidate = bytes(q.req("candidate", "query")?, "query")?;
    Ok(Query::ChangeImpact(Change::Policy {
        policy: q
            .opt("policy")
            .map(|p| id(p).map_err(within("query")))
            .transpose()?,
        candidate,
    }))
}

/// The `page` member of a search answer (§9.7.1): `total` only when this first page is the
/// whole visible result, so it counts nothing outside the reader's disclosure scope and its
/// presence never depends on records the reader cannot see; otherwise `has_more`.
#[must_use]
pub fn page(visible: usize, next: Option<&str>, first: bool) -> Out {
    match next {
        None if first => serde_json::json!({ "next_token": "", "total": visible }),
        None => serde_json::json!({ "next_token": "", "has_more": false }),
        Some(t) => serde_json::json!({ "next_token": t, "has_more": true }),
    }
}

/// One search page as `AuthZEN` results (L1-ADP-16); `first` when no page token was given.
#[must_use]
pub fn encode_search(hits: &[Hit], next: Option<&str>, first: bool) -> Out {
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
            Hit::Report(r) => crate::adp::report::encode(r),
        })
        .collect();
    serde_json::json!({
        "results": results,
        "page": page(results.len(), next, first),
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
        domain: digest(ctx.req("domain", "domain")?).map_err(within("domain"))?,
        mode: mode(ctx.req("mode", "mode")?)?,
        nonce,
        intent,
        payload,
        basis: basis(ctx.req("basis", "basis")?).map_err(within("basis"))?,
        capacity: capacity(ctx.req("capacity", "capacity")?).map_err(within("capacity"))?,
        proofs: ctx
            .opt("proofs")
            .map(proofs)
            .transpose()?
            .unwrap_or_default(),
        exercise: ctx
            .opt("exercise")
            .map(digest)
            .transpose()
            .map_err(within("exercise"))?,
        consistency: ctx
            .opt("consistency_token")
            .map(|t| text(t, "consistency_token"))
            .transpose()?,
    };
    let ais = ctx.opt("ais").map(|a| bytes(a, "ais")).transpose()?;
    // OP-152 m.5 (b)
    let context = ctx
        .opt("rate_context")
        .map(|c| {
            c.as_str()
                .and_then(RateContext::parse)
                .ok_or(AdpError("rate_context"))
        })
        .transpose()?;
    Ok(Decoded {
        request,
        ais,
        context,
    })
}

/// A dCBOR value as JSON: binaries base64url, a digest `[-16, h]` as `h` (L1-ADP-6).
pub(crate) fn json_of(v: &Value) -> Out {
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

/// The viewer's view of a blocker (OP-141 m.38 (c)): everything but the subcode of a
/// `restricted` blocker.
fn viewer_view(blocker: &mut Out) {
    if let Out::Object(b) = blocker
        && b.get("class").and_then(Out::as_str) == Some("restricted")
    {
        b.remove("subcode");
    }
}

fn identity(n: &Named) -> Out {
    match n {
        Named::Clear(id) => serde_json::json!({ "id": b64url_encode(&id.0) }),
        Named::Pseudonym(p) => serde_json::json!({ "pseudonym": b64url_encode(p) }),
    }
}

/// The lineage for a viewer or auditor (§13.7.5) and, at audit scope only, `reason_admin`
/// (§9.6.1, §17.1.1): `basis_ref` expanded, the `StateBasis`, the P41 rows, the cited proofs and
/// the consumption. Below audit scope the member does not exist; its presence is a disclosure.
fn explained(context: &mut Map<String, Out>, e: &Explained, scope: Scope) {
    if scope == Scope::Requester {
        return;
    }
    let lineage: Vec<Out> = e
        .lineage
        .iter()
        .map(|h| {
            let mut m = Map::new();
            m.insert(String::from("hop"), Out::from(h.hop));
            m.insert(String::from("grant"), identity(&h.grant));
            if let Some(holder) = &h.holder {
                m.insert(String::from("holder"), identity(holder));
            }
            Out::Object(m)
        })
        .collect();
    context.insert(String::from("lineage"), Out::Array(lineage));
    let (Scope::Audit, Some(a)) = (scope, &e.audit) else {
        return;
    };
    let reads: Vec<Out> = a
        .reads
        .iter()
        .map(|(k, v)| serde_json::json!({ "key": b64url_encode(k), "version": v }))
        .collect();
    let reasons: Vec<Out> = a
        .reason_admin
        .iter()
        .map(|r| {
            let mut m = Map::new();
            m.insert(String::from("category"), Out::from(r.category));
            m.insert(String::from("code"), Out::from(r.user));
            if let Some(s) = &r.subcode {
                m.insert(String::from("subcode"), Out::from(s.as_str()));
            }
            Out::Object(m)
        })
        .collect();
    let mut admin = Map::new();
    admin.insert(
        String::from("basis_ref"),
        serde_json::json!({
            "domain": b64url_encode(&a.basis.domain.0),
            "position_q_minus_1": a.basis.position_q_minus_1,
            "version_vector_digest": b64url_encode(&a.basis.version_vector_digest.0),
        }),
    );
    admin.insert(
        String::from("state_basis"),
        serde_json::json!({ "evaluated_at": a.evaluated_at, "reads": reads }),
    );
    admin.insert(String::from("reasons"), Out::Array(reasons));
    admin.insert(
        String::from("cited"),
        Out::Array(
            a.cited
                .iter()
                .map(|c| Out::from(b64url_encode(&c.0)))
                .collect(),
        ),
    );
    if let Some(c) = &a.consumption {
        admin.insert(String::from("consumption"), json_of(c));
    }
    context.insert(String::from("reason_admin"), Out::Object(admin));
}

/// Encodes a decision for the requester (L1-ADP-10); the disclosure filter is its last stage
/// (TI-20).
#[must_use]
pub fn encode(response: &Response, mode: Mode) -> Out {
    encode_for(response, mode, Scope::Requester)
}

/// Encodes a decision with the disclosure filter of `scope` (OP-141 m.38).
#[must_use]
pub fn encode_for(response: &Response, mode: Mode, scope: Scope) -> Out {
    let mut context = match json_of(&decision_value(&response.decision)) {
        Out::Object(m) => m,
        _ => Map::new(),
    };
    if let Some(Out::Array(blockers)) = context.get_mut("blockers") {
        match scope {
            Scope::Requester => blockers.iter_mut().for_each(requester_view),
            Scope::Viewer => blockers.iter_mut().for_each(viewer_view),
            Scope::Audit => {}
        }
    }
    // P41, §9.6.1
    let user = reason_user(&response.decision);
    if !user.is_empty() {
        context.insert(String::from("reason_user"), Out::from(user));
    }
    if let Some(e) = &response.explained {
        explained(&mut context, e, scope);
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
    // OP-141 m.22 (e)
    if let Some(r) = &response.basis_ref {
        context.insert(String::from("basis_ref"), Out::from(r.as_str()));
    }
    if response.replayed {
        context.insert(String::from("replayed"), Out::Bool(true));
    }
    // §9.8, L2-RCP-2
    if let Some((sign1, excerpt)) = &response.signed_receipt {
        context.insert(
            String::from("receipt"),
            serde_json::json!({ "sign1": b64url_encode(sign1), "excerpt": b64url_encode(excerpt) }),
        );
    }
    // L2-PAP-2
    if let Some((sign1, excerpt)) = &response.signed_pap {
        context.insert(
            String::from("pap"),
            serde_json::json!({ "sign1": b64url_encode(sign1), "excerpt": b64url_encode(excerpt) }),
        );
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
