//! A review product twin (IDP-39 (3), OP-157 m.3 (w)): an IGA that reads Access's searches and
//! sends its review decisions as Exercise requests. It keeps its own campaign UX; Access answers
//! who holds what, why, and what a removal would end, and every decision is the reviewer's own:
//! a keep is the reviewer's signed keep digest, a removal the reviewer's `grant.revoke`.

use access_kernel::digest::Digest;
use serde_json::Value;
use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
use suiss_crypto::digest::context_digest;

/// The context of a keep digest (OP-157 m.6 (a)).
pub const KEEP_CONTEXT: &str = "access/review-keep/v1";

/// The digest a reviewer's AIS signs to keep `grant` (base64url) in campaign `review`:
/// `context_digest("access/review-keep/v1", dCBOR([review, grant]))`; `None` when it does not
/// encode.
#[must_use]
pub fn keep_digest(review: &str, grant: &str) -> Option<Digest> {
    let v = Cbor::Array(vec![Cbor::text(review), Cbor::text(grant)]);
    let bytes = dcbor::encode(&v, Limits::CEILING).ok()?;
    Some(context_digest(KEEP_CONTEXT, &bytes))
}

/// One delegation's hygiene marks from an inventory answer (§8.17.12, XI-19).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Marks {
    /// The Grant, base64url.
    pub grant: String,
    /// Not used for 90 days.
    pub unused: bool,
    /// Ends within 7 days.
    pub expiring: bool,
    /// Any resource of a namespace, an action prefix, or onward delegation.
    pub broad: bool,
}

/// The hygiene marks of an inventory search's `results`.
#[must_use]
pub fn hygiene(results: &[Value]) -> Vec<Marks> {
    results
        .iter()
        .filter(|v| v["type"] == "hygiene")
        .filter_map(|v| {
            Some(Marks {
                grant: v["grant"].as_str()?.to_owned(),
                unused: v["unused"] == true,
                expiring: v["expiring"] == true,
                broad: v["broad"] == true,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    // OP-157 m.6 (a), XI-19
    #[test]
    fn a_keep_digest_names_its_campaign_and_grant_and_marks_are_read_as_stated() {
        assert_ne!(keep_digest("q4", "a"), keep_digest("q4", "b"));
        let m = hygiene(&[
            json!({ "type": "holding", "grant": "g0" }),
            json!({ "type": "hygiene", "grant": "g1", "unused": false, "expiring": true, "broad": false }),
        ]);
        assert_eq!(m.len(), 1);
        assert!(m[0].expiring && !m[0].broad && !m[0].unused);
    }
}
