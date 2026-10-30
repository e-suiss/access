//! One evaluation call from body to reply (L1-ADP-2, L1-ADP-3).

use access_authority_core::CoreError;
use access_authority_core::app::Incoming;
use serde_json::Value;

use crate::adp::domain::{decode, encode};
use crate::adp::ports::{Clock, Pdp};

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
pub struct Service<P: Pdp, C: Clock> {
    pdp: P,
    clock: C,
    max_body: usize,
}

impl<P: Pdp, C: Clock> Service<P, C> {
    /// A service over `pdp` that accepts bodies up to `max_body` bytes.
    pub const fn new(pdp: P, clock: C, max_body: usize) -> Self {
        Self {
            pdp,
            clock,
            max_body,
        }
    }

    /// `POST /access/v1/evaluation`.
    pub async fn evaluation(&self, body: &[u8], pep: Option<String>) -> Reply {
        let Some(pep) = pep else {
            return Reply::Unauthenticated;
        };
        let decoded = match decode(body, self.max_body) {
            Ok(d) => d,
            Err(e) => return Reply::Protocol(e.0),
        };
        let mode = decoded.request.mode;
        let inc = Incoming {
            request: decoded.request,
            ais: decoded.ais,
            pep,
        };
        match self.pdp.evaluate(inc, self.clock.now()).await {
            Ok(r) => Reply::Decision(encode(&r, mode)),
            Err(CoreError::Nonce) => Reply::Conflict,
            Err(CoreError::Sequencer(_) | CoreError::Store(_)) => Reply::Unavailable,
            Err(e) => Reply::Protocol(e.code()),
        }
    }
}
