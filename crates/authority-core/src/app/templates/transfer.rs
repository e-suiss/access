//! A change of legal ownership (CI-13, §7.9.9.2, OP-157 m.3 (i)).
//!
//! Money or Pay says the legal owner of an Anchor's resource changed with an
//! `ownership_changed` Claim (CDDL `product-seam.cddl`). Access never asserts ownership and the
//! Claim moves nothing: the root stays until an `anchor.transfer` Exercise of the current root
//! moves it. The Claim is only the condition a pre-written transfer waits for.

use access_kernel::digest::Digest;
use access_kernel::model::{EqValue, Id, SubjectSelector, WhileCondition};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

/// The Claim class of an ownership change.
pub const OWNERSHIP_CHANGED: &str = "ownership_changed";

/// What an `ownership_changed` Claim says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnershipChanged {
    /// The Anchor whose resource changed owner.
    pub anchor: Id,
    /// The previous owner Party.
    pub from: Id,
    /// The new owner Party.
    pub to: Id,
    /// When the change took effect, Unix ms.
    pub effective_at: u64,
}

impl OwnershipChanged {
    /// The `ownership-changed` body.
    #[must_use]
    pub fn body(&self) -> Value {
        Value::Map(vec![
            (Value::text("to"), Value::Bytes(self.to.0.to_vec())),
            (Value::text("from"), Value::Bytes(self.from.0.to_vec())),
            (Value::text("anchor"), Value::Bytes(self.anchor.0.to_vec())),
            (
                Value::text("effective_at"),
                Value::Unsigned(self.effective_at),
            ),
        ])
    }

    /// The `value` of the Claim with this body (L2-CLB-1).
    #[must_use]
    pub fn value_digest(&self) -> [u8; 32] {
        let bytes = dcbor::encode(
            &Value::Array(vec![Value::text(OWNERSHIP_CHANGED), self.body()]),
            Limits::CEILING,
        )
        .unwrap_or_default();
        context_digest(access_kernel::claim::body::BODY_CONTEXT, &bytes).0
    }

    /// The change a disclosed `body` says, when it is one and matches `value`.
    #[must_use]
    pub fn decode(value: Option<&EqValue>, body: &[u8]) -> Option<Self> {
        let v = dcbor::decode(body, Limits::CEILING).ok()?;
        let Value::Map(entries) = &v else {
            return None;
        };
        if entries.len() != 4 {
            return None;
        }
        let id = |name: &str| match v.get(name) {
            Some(Value::Bytes(b)) => <[u8; 16]>::try_from(b.as_slice()).ok().map(Id),
            _ => None,
        };
        let effective_at = match v.get("effective_at") {
            Some(Value::Unsigned(t)) => *t,
            _ => return None,
        };
        let c = Self {
            anchor: id("anchor")?,
            from: id("from")?,
            to: id("to")?,
            effective_at,
        };
        match value {
            Some(EqValue::Bytes(d)) if d.as_slice() == c.value_digest() => Some(c),
            _ => None,
        }
    }
}

/// The condition a pre-written transfer waits for: `subject` holds a current
/// `ownership_changed` Claim that the Acceptance with digest `acceptance` admits.
#[must_use]
pub fn condition(subject: Id, acceptance: Digest) -> WhileCondition {
    WhileCondition::ClaimHeld {
        class: String::from(OWNERSHIP_CHANGED),
        subject: SubjectSelector::Party(subject),
        acceptance,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // CI-13, §7.9.9.2, OP-157 m.3 (i), Ek B 5669
    #[test]
    fn an_ownership_change_is_read_only_from_a_matching_body() {
        let c = OwnershipChanged {
            anchor: Id([2; 16]),
            from: Id([3; 16]),
            to: Id([4; 16]),
            effective_at: 7,
        };
        let body = dcbor::encode(&c.body(), Limits::CEILING).unwrap();
        let value = EqValue::Bytes(c.value_digest().to_vec());
        assert_eq!(OwnershipChanged::decode(Some(&value), &body), Some(c));
        assert_eq!(OwnershipChanged::decode(None, &body), None);
        let other = OwnershipChanged {
            to: Id([5; 16]),
            ..c
        };
        assert_eq!(
            OwnershipChanged::decode(Some(&EqValue::Bytes(other.value_digest().to_vec())), &body),
            None
        );
    }
}
