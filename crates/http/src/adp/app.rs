//! One evaluation call from body to reply (L1-ADP-2, L1-ADP-3).

use access_authority_core::CoreError;
use access_authority_core::app::Incoming;
use access_kernel::combinator::Mode;
use serde_json::Value;

use crate::adp::domain::{Decoded, Semantic, decode, decode_batch, encode};
use crate::adp::ports::Pdp;

/// What the transport sends back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// 200 with a decision.
    Decision(Value),
    /// 400: a protocol error; nothing is recorded.
    Protocol(&'static str),
    /// 401: no authenticated PEP.
    Unauthenticated,
    /// 422: the nonce belongs to another intent or actor.
    Conflict,
    /// 503: the domain cannot decide now.
    Unavailable,
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

    /// `POST /access/v1/evaluation`.
    pub async fn evaluation(&self, body: &[u8], pep: Option<String>) -> Reply {
        let Some(pep) = pep else {
            return Reply::Unauthenticated;
        };
        match decode(body, self.max_body) {
            Ok(d) => self.decide(d, pep).await,
            Err(e) => Reply::Protocol(e.0),
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
            Err(e) => return Reply::Protocol(e.0),
        };
        let mut out = Vec::with_capacity(items.len());
        let mut stopped = false;
        for item in items {
            if stopped {
                out.push(serde_json::json!({ "evaluated": false }));
                continue;
            }
            let reply = match item {
                Ok(d) => self.decide(d, pep.clone()).await,
                Err(e) => Reply::Protocol(e.0),
            };
            let value = match reply {
                Reply::Decision(v) => v,
                Reply::Protocol(code) => serde_json::json!({ "error": code }),
                Reply::Conflict => serde_json::json!({ "error": "nonce-conflict" }),
                Reply::Unavailable => serde_json::json!({ "error": "unavailable" }),
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

    /// `POST /access/v1/explain` for a hypothetical intent: a `check` evaluation labelled
    /// `kind: "hypothetical"`, never recorded (OP-141 m.22 (h)). Explaining a recorded decision
    /// is not offered yet; such a request is the protocol error `explain-mode`.
    pub async fn explain(&self, body: &[u8], pep: Option<String>) -> Reply {
        let Some(pep) = pep else {
            return Reply::Unauthenticated;
        };
        let decoded = match decode(body, self.max_body) {
            Ok(d) => d,
            Err(e) => return Reply::Protocol(e.0),
        };
        if decoded.request.mode != Mode::Check {
            return Reply::Protocol("explain-mode");
        }
        match self.decide(decoded, pep).await {
            Reply::Decision(mut v) => {
                if let Some(ctx) = v.get_mut("context").and_then(Value::as_object_mut) {
                    ctx.insert(String::from("kind"), Value::from("hypothetical"));
                }
                Reply::Decision(v)
            }
            other => other,
        }
    }

    async fn decide(&self, decoded: Decoded, pep: String) -> Reply {
        let mode = decoded.request.mode;
        let inc = Incoming {
            request: decoded.request,
            ais: decoded.ais,
            pep,
        };
        match self.pdp.evaluate(inc).await {
            Ok(r) => Reply::Decision(encode(&r, mode)),
            Err(CoreError::Nonce) => Reply::Conflict,
            Err(CoreError::Sequencer(_) | CoreError::Store(_) | CoreError::Unavailable(_)) => {
                Reply::Unavailable
            }
            Err(e) => Reply::Protocol(e.code()),
        }
    }
}
