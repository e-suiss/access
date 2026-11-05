//! Judging one case from what the PEP said and what the protected resource saw.

use serde::Serialize;

use crate::case::Expect;
use crate::protocol::Outcome;

/// The judgement of one case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum Verdict {
    /// The PEP behaved as expected.
    Pass,
    /// The PEP produced an effect, or claimed to allow, where none is allowed (X21, TI-9).
    Leak {
        /// Why.
        reason: String,
    },
    /// The PEP did not behave as expected, without producing a forbidden effect.
    Fail {
        /// Why.
        reason: String,
    },
}

impl Verdict {
    /// Whether the case passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Judges a case: `outcome` is the adapter's answer (`None` when it gave none before the
/// runner's deadline) and `effects` the number of effect calls the resource received.
#[must_use]
pub fn judge(expect: Expect, outcome: Option<Outcome>, effects: u32) -> Verdict {
    let said = outcome.map_or("no answer", |o| match o {
        Outcome::Allow => "allow",
        Outcome::Deny => "deny",
        Outcome::Error => "error",
    });
    match expect {
        Expect::Effect => match (outcome, effects) {
            (Some(Outcome::Allow), 1) => Verdict::Pass,
            _ => Verdict::Fail {
                reason: format!(
                    "healthy upstreams: expected allow with one effect, got {said} with {effects}"
                ),
            },
        },
        Expect::Deny | Expect::NoEffect if effects > 0 => Verdict::Leak {
            reason: format!("{effects} effect(s) performed; PEP said {said}"),
        },
        Expect::Deny | Expect::NoEffect if outcome == Some(Outcome::Allow) => Verdict::Leak {
            reason: String::from("PEP said allow"),
        },
        Expect::Deny if outcome == Some(Outcome::Deny) => Verdict::Pass,
        Expect::NoEffect if outcome.is_some() => Verdict::Pass,
        Expect::Deny | Expect::NoEffect => Verdict::Fail {
            reason: format!("expected {}, got {said}", expect_name(expect)),
        },
    }
}

const fn expect_name(expect: Expect) -> &'static str {
    match expect {
        Expect::Effect => "effect",
        Expect::Deny => "deny",
        Expect::NoEffect => "no-effect",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // X21, TI-9, CMP-17
    #[test]
    fn any_effect_or_allow_on_a_fault_is_a_leak() {
        for expect in [Expect::Deny, Expect::NoEffect] {
            for outcome in [
                None,
                Some(Outcome::Allow),
                Some(Outcome::Deny),
                Some(Outcome::Error),
            ] {
                assert!(
                    matches!(judge(expect, outcome, 1), Verdict::Leak { .. }),
                    "{expect:?} {outcome:?}"
                );
            }
            assert!(matches!(
                judge(expect, Some(Outcome::Allow), 0),
                Verdict::Leak { .. }
            ));
        }
    }

    // X21, TI-9
    #[test]
    fn deny_needs_an_explicit_deny_and_no_effect_accepts_an_error() {
        assert_eq!(judge(Expect::Deny, Some(Outcome::Deny), 0), Verdict::Pass);
        assert!(matches!(
            judge(Expect::Deny, Some(Outcome::Error), 0),
            Verdict::Fail { .. }
        ));
        assert_eq!(
            judge(Expect::NoEffect, Some(Outcome::Error), 0),
            Verdict::Pass
        );
        assert_eq!(
            judge(Expect::NoEffect, Some(Outcome::Deny), 0),
            Verdict::Pass
        );
        assert!(matches!(
            judge(Expect::NoEffect, None, 0),
            Verdict::Fail { .. }
        ));
    }

    // CMP-17
    #[test]
    fn the_control_needs_exactly_one_effect() {
        assert_eq!(
            judge(Expect::Effect, Some(Outcome::Allow), 1),
            Verdict::Pass
        );
        for (outcome, effects) in [
            (Some(Outcome::Allow), 0),
            (Some(Outcome::Allow), 2),
            (Some(Outcome::Deny), 0),
            (None, 1),
        ] {
            assert!(matches!(
                judge(Expect::Effect, outcome, effects),
                Verdict::Fail { .. }
            ));
        }
    }
}
