//! One evaluation call from body to reply (L1-ADP-2, L1-ADP-3).

use access_authority_core::CoreError;
use access_authority_core::app::Incoming;
use access_kernel::combinator::{Mode, Outcome};
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
    pub async fn evaluation(&self, body: &[u8], pep: Option<String>) -> Reply {
        let Some(pep) = pep else {
            return Reply::Unauthenticated;
        };
        match decode(body, self.max_body) {
            Ok(d) => self.decide(d, pep, false, Body::Context).await,
            Err(e) => bad(e, Body::Context),
        }
    }

    /// `POST /access/v1/evaluations`: independent items, each answered like a single
    /// evaluation; a short-circuit leaves the rest `{"evaluated": false}` (OP-141 m.22 (a)).
    pub async fn evaluations(&self, body: &[u8], pep: Option<String>) -> Reply {
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
                Ok(d) => self.decide(d, pep.clone(), false, Body::Context).await,
                Err(e) => bad(e, Body::Context),
            };
            // OP-141 m.25: a limit is the batch's answer, never an item inside a 200; items
            // already committed are answered again on retry with the same nonce (L2-REC-5)
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
    pub async fn explain(&self, body: &[u8], pep: Option<String>) -> Reply {
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
                explain: true,
                status: None,
            };
            return match self.pdp.explain_recorded(inc, record, scope).await {
                Ok(r) => {
                    let mut v = encode_for(&r, mode, scope);
                    if let Some(ctx) = v.get_mut("context").and_then(Value::as_object_mut) {
                        ctx.insert(String::from("kind"), Value::from("recorded"));
                        ctx.insert(String::from("record"), Value::from(record));
                    }
                    Reply::Decision(v)
                }
                Err(e) => failed(e, Body::Context),
            };
        }
        if decoded.request.mode != Mode::Check {
            return bad(AdpError("explain-mode"), Body::Context);
        }
        match self.decide(decoded, pep, true, Body::Context).await {
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
    pub async fn eligibility(&self, body: &[u8], pep: Option<String>) -> Reply {
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
            explain: false,
            status: None,
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
    pub async fn search(&self, kind: &str, body: &[u8], pep: Option<String>) -> Reply {
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
            explain: false,
            status: None,
        };
        let first = page.is_none();
        match self.pdp.search(inc, query, page).await {
            Ok((hits, next)) => Reply::Decision(encode_search(&hits, next.as_deref(), first)),
            Err(e) => failed(e, Body::Context),
        }
    }

    async fn decide(&self, decoded: Decoded, pep: String, explain: bool, body: Body) -> Reply {
        let mode = decoded.request.mode;
        let inc = Incoming {
            request: decoded.request,
            ais: decoded.ais,
            pep,
            explain,
            status: None,
        };
        match self.pdp.evaluate(inc).await {
            Ok(r) => Reply::Decision(encode(&r, mode)),
            Err(e) => failed(e, body),
        }
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
        // OP-149 m.12, m.30 (b): the reason first, then what the rejection expected
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
