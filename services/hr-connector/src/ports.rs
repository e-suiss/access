//! What a connector needs from outside (OP-63): the HR system's pages, Access's realm-admin
//! surface, the Instance key that signs its Actor Intent Statements, time and randomness.

use serde_json::Value;

/// Why a call had no usable answer: the run stops and nothing is assumed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Fault {
    /// Not reached, or no answer in time.
    #[error("unreachable")]
    Unreachable,
    /// An answer that is not what the call expects.
    #[error("malformed answer")]
    Malformed,
    /// Refused with this status and problem code.
    #[error("refused {0}: {1}")]
    Refused(u16, String),
    /// A key, token or credential file could not be read.
    #[error("credential")]
    Credential,
}

/// The HR system: its employee listing, page by page.
pub trait Pull: Send + Sync {
    /// Every page of the listing as JSON.
    fn pages(&self) -> impl Future<Output = Result<Vec<Value>, Fault>> + Send;
}

/// Access's realm-admin surface (`admin-v1.json`), the public contract any administrator's tool
/// uses (OP-62): a write is drafted, then committed with the actor's AIS.
pub trait Access: Send + Sync {
    /// `POST /admin/v1/realms/{slug}/intents`: the draft of `ask`.
    fn draft(&self, slug: &str, ask: Value) -> impl Future<Output = Result<Value, Fault>> + Send;

    /// `POST {path}` with `body`, the AIS and an `Idempotency-Key`: the answer's status and
    /// body.
    fn commit(
        &self,
        path: &str,
        body: Value,
        ais_and_key: (&str, &str),
    ) -> impl Future<Output = Result<(u16, Value), Fault>> + Send;
}

/// The connector Instance's key: it signs the Actor Intent Statement of each write.
pub trait Sign: Send + Sync {
    /// The base64url `COSE_Sign1` of the AIS committing `intent` in `domain` at `pep`, or
    /// `None` when the key did not sign.
    fn ais(
        &self,
        domain: [u8; 32],
        nonce: &[u8; 16],
        intent: [u8; 32],
        pep: &str,
    ) -> Option<String>;
}

/// Wall-clock time.
pub trait Clock: Send + Sync {
    /// Unix milliseconds, `None` when the clock is unusable.
    fn now(&self) -> Option<u64>;
}

/// Randomness.
pub trait Random: Send + Sync {
    /// 16 random bytes, `None` when the source failed.
    fn bytes(&self) -> Option<[u8; 16]>;
}
