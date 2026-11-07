//! The Claims SL2 asks the realm issuer for (TN-46, OP-150 m.12): the subject's `risk_level`,
//! one line per subject so each level supersedes the last, and one `risk_signal` per fired
//! signal. Both classes only narrow (CI-2): they carry no assurance level and bind no intent, and
//! Claim Ingest refuses a `risk_*` Claim that does.

use std::collections::BTreeMap;

use access_identity_account::domain::claims::{
    Bind, ClaimOrder, Content, RISK_SIGNAL, SIGNAL_TTL_MS, line,
};
use access_kernel::model::EqValue;

use crate::domain::score::Level;
use crate::domain::signal::RiskSignal;

/// The class of the SL2 level.
pub const LEVEL_CLASS: &str = "risk_level";

/// The namespace of SL2 classes.
pub const NAMESPACE: &str = "risk_";

/// The `risk_level` order of `subject` at `at`.
#[must_use]
pub fn level(subject: [u8; 16], level: Level, at: u64) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: String::from(LEVEL_CLASS),
        at,
        ttl_ms: SIGNAL_TTL_MS,
        content: Content::Scalar(EqValue::Text(String::from(level.name()))),
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(line(&[LEVEL_CLASS.as_bytes(), &subject])),
        retract: false,
    }
}

/// The `risk_signal` order of `signal`.
#[must_use]
pub fn signal(subject: [u8; 16], signal: RiskSignal, at: u64) -> ClaimOrder {
    ClaimOrder {
        subject,
        class: String::from(RISK_SIGNAL),
        at,
        ttl_ms: SIGNAL_TTL_MS,
        content: Content::Scalar(EqValue::Text(String::from(signal.name()))),
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: None,
        retract: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CI-2, TN-46: a risk order carries no assurance and binds nothing it could qualify
    #[test]
    fn risk_orders_only_narrow() {
        for o in [
            level([1; 16], Level::High, 5),
            signal([1; 16], RiskSignal::ImpossibleTravel, 5),
        ] {
            assert!(o.assurance.is_empty());
            assert_eq!(o.bind, Bind::None);
            assert!(o.class.starts_with(NAMESPACE) || o.class == RISK_SIGNAL);
        }
        assert_eq!(
            level([1; 16], Level::Low, 1).line,
            level([1; 16], Level::High, 2).line
        );
        // CMP-22b: the realm's identity signer signs both classes
        assert!(access_identity_signer::issuer::issues(LEVEL_CLASS));
        assert!(access_identity_signer::issuer::issues(RISK_SIGNAL));
        assert_ne!(
            level([1; 16], Level::Low, 1).line,
            level([2; 16], Level::Low, 1).line
        );
    }
}
