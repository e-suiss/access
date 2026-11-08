//! One evaluation call from body to reply (L1-ADP-2, L1-ADP-3).

use access_authority_core::CoreError;
use access_authority_core::app::{Incoming, Scope};
use access_kernel::combinator::{Mode, Outcome};
use access_kernel::json::b64url_encode;
use serde_json::Value;

use crate::adp::domain::{
    AdpError, Body, Decoded, Semantic, decode, decode_batch, decode_eligibility, decode_explain,
    decode_search, encode, encode_for, encode_search, pointer,
};
use crate::adp::ports::Pdp;
use crate::problem::FieldError;

/// What the transport sends back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// 200 with a decision.
    Decision(Value),
    /// 400: a protocol error with the parts of the body it is about; nothing is recorded.
    Protocol(&'static str, Vec<FieldError>),
    /// 401: no authenticated PEP.
    Unauthenticated,
    /// 422: the nonce belongs to another intent or actor.
    Conflict,
    /// 503: the domain cannot decide now, with a stable reason when there is one.
    Unavailable(Option<&'static str>),
    /// 429: over a rate limit (§13.7.4, OP-35).
    Limited,
}

/// The ADP service of one deployment.
pub struct Service<P: Pdp> {
    pdp: P,
    max_body: usize,
}

impl<P: Pdp> Service<P> {
    /// A service over `pdp` that accepts bodies up to `max_body` bytes.
    pub const fn new(pdp: P, max_body: usize) -> Self {
        Self { pdp, max_body }
    }

    /// The decision point.
    pub(crate) const fn pdp(&self) -> &P {
        &self.pdp
    }

    /// The largest body accepted, in bytes.
    pub(crate) const fn max_body(&self) -> usize {
        self.max_body
    }

    /// The binding-signed Domain Metadata of `domain`, if the signer has it (§9.15.1).
    pub async fn metadata(&self, domain: access_kernel::digest::Digest) -> Option<Vec<u8>> {
        self.pdp.metadata(domain).await
    }

    /// `POST /access/v1/evaluation`.
    pub async fn evaluation(
        &self,
        body: &[u8],
        pep: Option<String>,
        requester: Option<String>,
    ) -> Reply {
        let Some(pep) = pep else {
            return Reply::Unauthenticated;
        };
        match decode(body, self.max_body) {
            Ok(d) => self.decide(d, (pep, requester), false, Body::Context).await,
            Err(e) => bad(e, Body::Context),
        }
    }

    /// `POST /access/v1/evaluations`: independent items, each answered like a single
    /// evaluation; a short-circuit leaves the rest `{"evaluated": false}` (OP-141 m.22 (a)).
    pub async fn evaluations(
        &self,
        body: &[u8],
        pep: Option<String>,
        requester: Option<String>,
    ) -> Reply {
        let Some(pep) = pep else {
            return Reply::Unauthenticated;
        };
        let (items, semantic) = match decode_batch(body, self.max_body) {
            Ok(b) => b,
            Err(e) => return bad(e, Body::Context),
        };
        let mut out = Vec::with_capacity(items.len());
        let mut stopped = false;
        for item in items {
            if stopped {
                out.push(serde_json::json!({ "evaluated": false }));
                continue;
            }
            let reply = match item {
                Ok(d) => {
                    self.decide(d, (pep.clone(), requester.clone()), false, Body::Context)
                        .await
                }
                Err(e) => bad(e, Body::Context),
            };
            // OP-141 m.25
            if reply == Reply::Limited {
                return Reply::Limited;
            }
            let value = match reply {
                Reply::Decision(v) => v,
                Reply::Protocol(code, _) => serde_json::json!({ "error": code }),
                Reply::Conflict => serde_json::json!({ "error": "nonce-conflict" }),
                Reply::Unavailable(_) | Reply::Limited => {
                    serde_json::json!({ "error": "unavailable" })
                }
                Reply::Unauthenticated => serde_json::json!({ "error": "pep-unauthenticated" }),
            };
            let decision = value.get("decision").and_then(serde_json::Value::as_bool);
            stopped = match semantic {
                Semantic::ExecuteAll => false,
                Semantic::DenyOnFirstDeny => decision == Some(false),
                Semantic::PermitOnFirstPermit => decision == Some(true),
            };
            out.push(value);
        }
        Reply::Decision(serde_json::json!({ "evaluations": out }))
    }

    /// `POST /access/v1/explain`: for a hypothetical intent a `check` evaluation labelled
    /// `kind: "hypothetical"`, never recorded (OP-141 m.22 (h)); with `context.record` the
    /// recorded decision at that position, rebuilt and labelled `kind: "recorded"` (OP-141 m.36).
    pub async fn explain(
        &self,
        body: &[u8],
        pep: Option<String>,
        requester: Option<String>,
    ) -> Reply {
        let Some(pep) = pep else {
            return Reply::Unauthenticated;
        };
        let (decoded, record) = match decode_explain(body, self.max_body) {
            Ok(d) => d,
            Err(e) => return bad(e, Body::Context),
        };
        if let Some((record, scope)) = record {
            let mode = decoded.request.mode;
            let inc = Incoming {
                request: decoded.request,
                ais: decoded.ais,
                pep,
                requester: requester.clone(),
                explain: true,
                status: None,
                context: decoded.context,
            };
            return match self.pdp.explain_recorded(inc.clone(), record, scope).await {
                Ok(r) => {
                    let mut v = encode_for(&r, mode, scope);
                    let extra = self.depth(&inc, record, scope).await;
                    if let Some(ctx) = v.get_mut("context").and_then(Value::as_object_mut) {
                        ctx.insert(String::from("kind"), Value::from("recorded"));
                        ctx.insert(String::from("record"), Value::from(record));
                        causal(ctx, &inc.request.intent, r.causal);
                        ctx.extend(extra);
                    }
                    Reply::Decision(v)
                }
                Err(e) => failed(e, Body::Context),
            };
        }
        if decoded.request.mode != Mode::Check {
            return bad(AdpError("explain-mode"), Body::Context);
        }
        match self
            .decide(decoded, (pep, requester), true, Body::Context)
            .await
        {
            Reply::Decision(mut v) => {
                if let Some(ctx) = v.get_mut("context").and_then(Value::as_object_mut) {
                    ctx.insert(String::from("kind"), Value::from("hypothetical"));
                }
                Reply::Decision(v)
            }
            other => other,
        }
    }

    /// `POST /access/v1/eligibility:check`: whether `subject` may act on the `check` its `set`
    /// describes, with the head it was answered at; a thin wrapper over `check` that records
    /// nothing (OP-149 m.10, §9.5.2 rule 1, P36).
    pub async fn eligibility(
        &self,
        body: &[u8],
        pep: Option<String>,
        requester: Option<String>,
    ) -> Reply {
        let Some(pep) = pep else {
            return Reply::Unauthenticated;
        };
        let (decoded, subject) = match decode_eligibility(body, self.max_body) {
            Ok(d) => d,
            Err(e) => return bad(e, Body::Eligibility),
        };
        let inc = Incoming {
            request: decoded.request,
            ais: None,
            pep,
            requester,
            explain: false,
            status: None,
            context: None,
        };
        match self.pdp.eligible(inc, subject).await {
            Ok(r) => Reply::Decision(serde_json::json!({
                "eligible": r.decision.outcome == Outcome::Allow,
                "consistency_token": r.consistency,
            })),
            Err(e) => failed(e, Body::Eligibility),
        }
    }

    /// `POST /access/v1/search/{kind}`: one page, advisory, as far as the reader may see
    /// (L1-ADP-16, OP-141 m.22 (j)).
    pub async fn search(
        &self,
        kind: &str,
        body: &[u8],
        pep: Option<String>,
        requester: Option<String>,
    ) -> Reply {
        let Some(pep) = pep else {
            return Reply::Unauthenticated;
        };
        let (decoded, query, page) = match decode_search(body, self.max_body, kind) {
            Ok(d) => d,
            Err(e) => return bad(e, Body::Context),
        };
        let inc = Incoming {
            request: decoded.request,
            ais: decoded.ais,
            pep,
            requester,
            explain: false,
            status: None,
            context: None,
        };
        let first = page.is_none();
        match self.pdp.search(inc, query, page).await {
            Ok((hits, next)) => Reply::Decision(encode_search(&hits, next.as_deref(), first)),
            Err(e) => failed(e, Body::Context),
        }
    }

    async fn decide(
        &self,
        decoded: Decoded,
        (pep, requester): (String, Option<String>),
        explain: bool,
        body: Body,
    ) -> Reply {
        let mode = decoded.request.mode;
        let upstream = decoded.request.intent.context.upstream_exercise.is_some();
        let inc = Incoming {
            request: decoded.request,
            ais: decoded.ais,
            pep,
            requester,
            explain,
            status: None,
            context: decoded.context,
        };
        match self.pdp.evaluate(inc).await {
            Ok(r) => {
                let mut v = encode(&r, mode);
                if upstream && let Some(ctx) = v.get_mut("context").and_then(Value::as_object_mut) {
                    ctx.insert(String::from(CAUSAL_BINDING), Value::from(binding(r.causal)));
                }
                Reply::Decision(v)
            }
            Err(e) => failed(e, body),
        }
    }

    /// What a recorded explanation adds at its depth: at audit scope, the selection part of a
    /// two-part reason (E-5) and the decision evaluated again (INV-27). Either is left out when
    /// the decision point does not give it; neither is ever guessed.
    async fn depth(
        &self,
        inc: &Incoming,
        record: u64,
        scope: Scope,
    ) -> serde_json::Map<String, Value> {
        let mut out = serde_json::Map::new();
        if scope != Scope::Audit {
            return out;
        }
        // E-5
        let mut probe = inc.clone();
        probe.request.mode = Mode::Check;
        probe.ais = None;
        probe.request.nonce =
            suiss_crypto::digest::context_digest(SELECTION_NONCE, &inc.request.nonce).0[..16]
                .to_vec();
        if let Ok(e) = self.pdp.lab_explain(probe).await
            && let Some(s) = e.selection
        {
            out.insert(
                String::from("selection"),
                serde_json::json!({
                    "grant": b64url_encode(&s.grant.0),
                    "classes": s.classes,
                    "since": s.since,
                }),
            );
        }
        if let Ok(r) = self.pdp.lab_replay(inc.clone(), record).await {
            out.insert(
                String::from("replay"),
                serde_json::json!({ "match": r.matches, "differing": r.differing }),
            );
        }
        out
    }
}

/// The digest context of the nonce a selection probe runs under.
const SELECTION_NONCE: &str = "access/explain-selection/v1";

/// The Decision Response member that tells whether an upstream causal ref was enforced (§9.9.2).
pub const CAUSAL_BINDING: &str = "causal_binding";

/// §9.9.2, E17: the upstream link was not enforced, only recorded for audit and detection.
pub const AUDIT_ONLY: &str = "audit-only";

/// §9.9.2, E17: the domain declares causal-bound allowances and this one was evaluated.
pub const ENFORCED: &str = "enforced";

/// `enforced` only when the decision point evaluated the declared causal-bound allowance
/// (OP-152 m.7 (d) E11); anything else is `audit-only`.
const fn binding(causal: Option<bool>) -> &'static str {
    if matches!(causal, Some(true)) {
        ENFORCED
    } else {
        AUDIT_ONLY
    }
}

/// §9.9.2: a request naming an upstream Exercise says whether that link was enforced.
fn causal(
    ctx: &mut serde_json::Map<String, Value>,
    intent: &access_kernel::intent::IntentEnvelope,
    enforced: Option<bool>,
) {
    if intent.context.upstream_exercise.is_some() {
        ctx.insert(String::from(CAUSAL_BINDING), Value::from(binding(enforced)));
    }
}

/// A body the decoder refused, with where in `body` the refused part is when known.
pub(crate) fn bad(e: AdpError, body: Body) -> Reply {
    Reply::Protocol(
        e.0,
        vec![FieldError {
            pointer: pointer(body, e.0),
            code: e.0,
        }],
    )
}

/// The stable, non-secret reason of a 503: what the domain could not reach or do.
#[must_use]
pub const fn unavailable_reason(e: &CoreError) -> Option<&'static str> {
    match e {
        CoreError::Unavailable(reason) => Some(reason),
        CoreError::Store(_) => Some("store"),
        CoreError::Sequencer(_) => Some("sequencer"),
        _ => None,
    }
}

pub(crate) fn failed(e: CoreError, body: Body) -> Reply {
    match e {
        CoreError::Nonce => Reply::Conflict,
        CoreError::Limited => Reply::Limited,
        CoreError::Sequencer(_) | CoreError::Store(_) | CoreError::Unavailable(_) => {
            Reply::Unavailable(unavailable_reason(&e))
        }
        // OP-149 m.12, m.30 (b)
        CoreError::Protocol(_) | CoreError::AasBinding(_) => {
            let reason = e.reason().unwrap_or_default();
            let errors = std::iter::once(reason)
                .chain(e.expected())
                .map(|code| FieldError {
                    pointer: pointer(body, reason),
                    code,
                })
                .collect();
            Reply::Protocol(e.code(), errors)
        }
        e => Reply::Protocol(e.code(), Vec::new()),
    }
}
