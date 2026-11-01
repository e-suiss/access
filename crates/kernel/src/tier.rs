//! Consequence tiers (§13.7.1, OP-141 m.34): how much an Exercise risks, from its meta-action
//! class and its amounts.

use crate::intent::{IntentEnvelope, ParamValue};
use crate::meta::Payload;
use crate::schema::{ActionSchema, EffectClass};

/// Consequence tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// No effect.
    Ct0,
    /// Reversible or low value.
    Ct1,
    /// Irreversible, external or above the CT1 threshold.
    Ct2,
    /// Expansion meta-actions and amounts above the CT3 threshold.
    Ct3,
}

/// The unit the default thresholds are in.
pub const THRESHOLD_UNIT: &str = "eur";
/// Above this many cents an amount is CT2 (1,000 EUR, PD).
pub const CT1_MAX: i64 = 100_000;
/// Above this many cents an amount is CT3 (100,000 EUR, PD).
pub const CT2_MAX: i64 = 10_000_000;

/// The longest intent validity a tier allows, in milliseconds (§13.7.3).
#[must_use]
pub const fn validity_ceiling(tier: Tier) -> u64 {
    match tier {
        Tier::Ct3 => 72 * 3_600 * 1_000,
        _ => 24 * 3_600 * 1_000,
    }
}

/// The tier of an Exercise: a meta-action by its class and whether it widens authority, a
/// domain action by its amounts and its Action Schema (OP-141 m.34 (a), m.35 (g)).
#[must_use]
pub fn of(
    intent: &IntentEnvelope,
    payload: Option<&Payload>,
    expansion: bool,
    schema: Option<&ActionSchema>,
) -> Tier {
    match payload {
        Some(p) if !expansion || matches!(p, Payload::Contribute { .. }) => Tier::Ct1,
        Some(
            Payload::AnchorCreate { .. }
            | Payload::AnchorTransfer { .. }
            | Payload::AnchorAmend { .. }
            | Payload::AnchorRetire { .. }
            | Payload::PartyDepart { .. }
            | Payload::InstanceRecover { .. }
            | Payload::GrantAmend { .. }
            | Payload::AcceptanceEstablish(_)
            | Payload::AcceptanceAmend { .. }
            | Payload::PolicySet { .. }
            | Payload::PolicyRetire { .. },
        ) => Tier::Ct3,
        Some(_) => Tier::Ct2,
        None => {
            let amounts = intent
                .params
                .values()
                .filter_map(|v| match v {
                    ParamValue::Amount { value, unit } => Some(amount_tier(*value, unit)),
                    _ => None,
                })
                .max();
            match schema {
                Some(s) if s.reserved => Tier::Ct3,
                Some(s) if s.effect == EffectClass::Irreversible => {
                    amounts.unwrap_or(Tier::Ct2).max(Tier::Ct2)
                }
                Some(s) if s.effect == EffectClass::None => amounts.unwrap_or(Tier::Ct0),
                _ => amounts.unwrap_or(Tier::Ct1),
            }
        }
    }
}

fn amount_tier(value: i64, unit: &str) -> Tier {
    if unit != THRESHOLD_UNIT {
        return Tier::Ct2;
    }
    if value > CT2_MAX {
        Tier::Ct3
    } else if value > CT1_MAX {
        Tier::Ct2
    } else {
        Tier::Ct1
    }
}

#[cfg(test)]
mod tests;
