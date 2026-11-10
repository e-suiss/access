//! What the issuer needs from the identity plane (OP-63): the person's verified facts, the
//! realm's status list entries, time and randomness. A port answers what it holds; it never
//! decides whether a credential is issued.

use crate::domain::types::PersonAttribute;

/// Trusted time.
pub trait Clock {
    /// Unix milliseconds; `None` without trusted time, and then nothing is issued.
    fn now(&self) -> Option<u64>;
}

/// Randomness.
pub trait Random {
    /// 16 fresh bytes; `None` when there are none.
    fn bytes(&self) -> Option<[u8; 16]>;
}

/// The person's verified facts, as the identity plane holds them.
pub trait Facts {
    /// The attribute's value for `subject`: `Some(true)`-like JSON for a fact that holds, the
    /// verified name for `verified_name`, `None` when it is not verified or does not hold.
    fn value(&self, subject: &[u8; 16], attribute: PersonAttribute) -> Option<serde_json::Value>;
}

/// The realm's credential status list.
pub trait StatusList {
    /// A fresh entry for a new credential: its index and the list's URI; `None` when the list is
    /// full or unavailable.
    fn allocate(&self) -> Option<(u64, String)>;
}
