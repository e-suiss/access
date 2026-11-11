//! What offboarding a Party would touch, from the authority plane's read into the identity
//! plane's port (OP-157 m.3 (v), §8.17.9.6).

use access_authority_core::app::offboarding::Channels;
use access_identity_admin::ports::{Departing, EndedByRule, HeldByRule, Selects};
use access_kernel::json::b64url_encode;
use access_kernel::model::{Conjunct, EqValue};

fn selects<'a>(c: impl IntoIterator<Item = &'a Conjunct>) -> Vec<Selects> {
    c.into_iter()
        .map(|c| Selects {
            class: c.claim_class.clone(),
            value: c.value.as_ref().map(|v| match v {
                EqValue::Text(t) => t.clone(),
                EqValue::Int(i) => i.to_string(),
                EqValue::Bool(b) => b.to_string(),
                EqValue::Bytes(b) => b64url_encode(b),
            }),
        })
        .collect()
}

/// `c` as the identity plane's port carries it.
pub(crate) fn departing(c: Channels) -> Departing {
    Departing {
        anchor: c.anchor,
        departed: c.departed,
        direct: c.direct,
        instances: c.instances,
        holdings: c
            .holdings
            .iter()
            .map(|h| HeldByRule {
                grant: h.grant,
                selects: selects(&h.conjuncts),
                since: h.since,
                stale: h.stale,
            })
            .collect(),
        given: c.given,
        derived: c.derived,
        ended: c
            .ended
            .iter()
            .map(|e| EndedByRule {
                grant: e.grant,
                selects: selects(&e.conjuncts),
                at: e.at,
                issuer: e.issuer,
            })
            .collect(),
    }
}
