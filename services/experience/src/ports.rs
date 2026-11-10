//! What the experience needs from outside (OP-63): Access's public search route, a clock, a
//! source of nonces and the signal feed. Each is a port; none can write authority.

use std::future::Future;

use access_sdk::transport::Answer;
use tokio::sync::watch;

use crate::contract::Kind;

/// Access's public ADP search route of a domain, called as this service's authenticated PEP
/// (XI-18, IA-7): the body goes as the reader signed it.
pub trait Upstream: Send + Sync {
    /// `POST /access/v1/search/{kind}` at the Access serving `domain`; an unknown domain or a
    /// transport failure is [`Answer::Unanswered`].
    fn search(
        &self,
        domain: &str,
        kind: Kind,
        body: Vec<u8>,
    ) -> impl Future<Output = Answer> + Send;

    /// `GET /.well-known/suiss-configuration/realms/{realm}` at Access (OP-149 m.3); none by
    /// default.
    fn discovery(&self, realm: &str) -> impl Future<Output = Answer> + Send {
        let _ = realm;
        async { Answer::Unanswered(access_sdk::transport::Fault::Unreachable) }
    }

    /// `GET /access/v1/relay-status` at Access (OP-156 m.11 (e)); none by default.
    fn relay_status(&self) -> impl Future<Output = Answer> + Send {
        async { Answer::Unanswered(access_sdk::transport::Fault::Unreachable) }
    }

    /// `GET {url}?party={party}`: the coordinator's public Needs Attention count for the reader
    /// (OP-156 m.3 (t)); none by default.
    fn attention(&self, url: &str, party: &str) -> impl Future<Output = Answer> + Send {
        let _ = (url, party);
        async { Answer::Unanswered(access_sdk::transport::Fault::Unreachable) }
    }
}

/// Wall-clock time for "as of" (XI-16), Unix ms. Not a trusted time: no decision rests on it.
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> u64;
}

/// Fresh nonces for the reads to sign; `None` plans nothing.
pub trait Random: Send + Sync {
    /// Sixteen random bytes.
    fn nonce(&self) -> Option<[u8; 16]>;
}

/// The signal feed of the stream (OP-153 m.3 (v)): the highest position known to have moved.
pub trait Signals: Send + Sync {
    /// A receiver of the latest position.
    fn watch(&self) -> watch::Receiver<u64>;
}
