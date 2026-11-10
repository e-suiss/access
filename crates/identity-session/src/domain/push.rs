//! Push verification rules (OP-156 m.3 (d), §10.2.3, §12): a second factor of AAL2 at best that
//! meets no Consequence Tier, a 120 s single-use challenge, and the fatigue limits: at most three
//! challenges in ten minutes, none for fifteen minutes after a refusal, none for an hour after
//! three unanswered in a row.

use crate::domain::assurance::{BindingStrength, Factor, FactorKind, MethodClass};

/// How long a challenge lives.
pub const CHALLENGE_TTL_MS: u64 = 120_000;

/// The window the pending limit counts in.
pub const PENDING_WINDOW_MS: u64 = 10 * 60_000;

/// Most challenges in [`PENDING_WINDOW_MS`].
pub const MAX_PENDING: usize = 3;

/// No push after a refusal for this long.
pub const REFUSAL_HOLD_MS: u64 = 15 * 60_000;

/// Unanswered challenges in a row that hold push.
pub const UNANSWERED_IN_A_ROW: usize = 3;

/// No push after [`UNANSWERED_IN_A_ROW`] unanswered challenges for this long.
pub const UNANSWERED_HOLD_MS: u64 = 60 * 60_000;

/// How far back the limits look.
pub const HISTORY_MS: u64 = 2 * 60 * 60_000;

/// How a past challenge ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// Approved.
    Approved,
    /// Refused: denied, "This wasn't me" or the wrong number.
    Refused,
}

impl Ended {
    /// The stored decision as an ending; unknown names count as a refusal.
    #[must_use]
    pub fn of(decision: &str) -> Self {
        if decision == "approve" {
            Self::Approved
        } else {
            Self::Refused
        }
    }
}

/// One past challenge of the account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Past {
    /// Unix ms.
    pub created_ms: u64,
    /// Unix ms.
    pub expires_ms: u64,
    /// How it ended and when, once answered.
    pub answered: Option<(Ended, u64)>,
}

/// Why push is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    /// Three challenges in ten minutes.
    Pending,
    /// A recent refusal.
    Refused,
    /// Three unanswered in a row.
    Unanswered,
}

impl Hold {
    /// The telemetry reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Refused => "refused",
            Self::Unanswered => "unanswered",
        }
    }
}

/// Whether a new challenge may go out at `now_ms` given `history`, newest first; when not, why
/// and until when.
#[must_use]
pub fn held(history: &[Past], now_ms: u64) -> Option<(Hold, u64)> {
    let mut holds = Vec::new();
    // OP-156 m.3 (d)
    if let Some(until) = history
        .iter()
        .filter_map(|p| match p.answered {
            Some((Ended::Refused, at)) => Some(at.saturating_add(REFUSAL_HOLD_MS)),
            _ => None,
        })
        .max()
        .filter(|u| *u > now_ms)
    {
        holds.push((Hold::Refused, until));
    }
    let recent: Vec<&Past> = history.iter().take(UNANSWERED_IN_A_ROW).collect();
    if recent.len() == UNANSWERED_IN_A_ROW
        && recent
            .iter()
            .all(|p| p.answered.is_none() && p.expires_ms <= now_ms)
        && let Some(newest) = recent.first()
    {
        let until = newest.expires_ms.saturating_add(UNANSWERED_HOLD_MS);
        if until > now_ms {
            holds.push((Hold::Unanswered, until));
        }
    }
    let window: Vec<&Past> = history
        .iter()
        .filter(|p| p.created_ms.saturating_add(PENDING_WINDOW_MS) > now_ms)
        .collect();
    if window.len() >= MAX_PENDING
        && let Some(oldest) = window.get(MAX_PENDING.saturating_sub(1))
    {
        holds.push((
            Hold::Pending,
            oldest.created_ms.saturating_add(PENDING_WINDOW_MS),
        ));
    }
    holds.into_iter().max_by_key(|(_, until)| *until)
}

/// The step an approved push proves (§10.2.3, IDP-8): possession of the approver key, replay
/// resistant through the single-use challenge, never phishing resistant and never a CT, so it
/// is marked as satisfying none.
#[must_use]
pub fn factor(approver: [u8; 16], at_ms: u64) -> Factor {
    let mut f = Factor::email(MethodClass::Push, at_ms);
    f.kinds = vec![FactorKind::Possession];
    f.binding = BindingStrength::None;
    f.replay_resistant = true;
    f.session_login_only = true;
    f.credential = Some(approver);
    f
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;
    use crate::domain::assurance::{Aal, CtCeiling, ct_ceiling, vector};

    fn open(at: u64) -> Past {
        Past {
            created_ms: at,
            expires_ms: at + CHALLENGE_TTL_MS,
            answered: None,
        }
    }

    // OP-156 m.3 (d), §10.2.3, IDP-8
    #[test]
    fn push_is_aal2_with_a_password_and_meets_no_ct() {
        let steps = [Factor::password(1), factor([1; 16], 2)];
        assert_eq!(vector(&steps).aal, Aal::Aal2);
        assert!(!vector(&steps).phishing_resistant);
        assert_eq!(ct_ceiling(&steps), CtCeiling::None);
        assert_eq!(vector(&[factor([1; 16], 2)]).aal, Aal::Aal1);
    }

    // OP-156 m.3 (d)
    #[test]
    fn the_fourth_challenge_in_ten_minutes_is_held() {
        let mut h = [open(3_000), open(2_000), open(1_000)];
        assert_eq!(held(&h[1..], 3_000), None);
        assert_eq!(
            held(&h, 3_500),
            Some((Hold::Pending, 1_000 + PENDING_WINDOW_MS))
        );
        for p in &mut h {
            p.answered = Some((Ended::Approved, p.created_ms + 1));
        }
        assert_eq!(held(&h, 1_000 + PENDING_WINDOW_MS), None);
    }

    // OP-156 m.3 (d)
    #[test]
    fn a_refusal_holds_push_for_fifteen_minutes() {
        let mut p = open(1_000);
        p.answered = Some((Ended::Refused, 5_000));
        assert_eq!(
            held(&[p], 6_000),
            Some((Hold::Refused, 5_000 + REFUSAL_HOLD_MS))
        );
        assert_eq!(held(&[p], 5_000 + REFUSAL_HOLD_MS), None);
        p.answered = Some((Ended::Approved, 5_000));
        assert_eq!(held(&[p], 6_000), None);
    }

    // OP-156 m.3 (d)
    #[test]
    fn three_unanswered_in_a_row_hold_push_for_an_hour() {
        let t = 20 * 60_000;
        let h = [open(t), open(t / 2), open(1)];
        let after = t + CHALLENGE_TTL_MS;
        assert_eq!(
            held(&h, after),
            Some((Hold::Unanswered, after + UNANSWERED_HOLD_MS))
        );
        let mut answered = h;
        answered[1].answered = Some((Ended::Approved, t / 2 + 5));
        assert_eq!(held(&answered, after), None);
        assert_eq!(held(&h, after + UNANSWERED_HOLD_MS), None);
    }
}
