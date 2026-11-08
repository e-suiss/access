//! What a surface shows after it sends an authority-changing request (§8.13, §13.8, G39, X26,
//! HL-5, TI-8, XI-3). Nothing is shown as done before Access answers with a position; a missing
//! answer is "Not confirmed — checking", followed by a retry with the same nonce while the
//! signed intent is valid and then only by reading the outcome; "Not recorded — try again" only
//! when the nonce is not in the lineage; "Couldn't … not recorded" only when no attempt was ever
//! sent on a direct path. There is no queued or pending authority change.

use crate::domain::texts;

/// How far a request got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// No byte left the device: the transport never connected.
    Never,
    /// It was handed to the transport; Access may have recorded it.
    Sent,
}

/// The path the request takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// Straight to the domain's Access.
    Direct,
    /// Through an intermediary that may have forwarded it (§8.17.7.2 note).
    Mediated,
}

/// What came back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Nothing yet, or nothing at all.
    Nothing,
    /// A recorded decision.
    Recorded {
        /// Whether it was allowed.
        allowed: bool,
        /// Whether the checkpoint covering it still awaits a witness.
        witness_pending: bool,
    },
    /// A rate refusal before anything was recorded (429).
    Busy,
    /// The decision point has no trusted time (§16.7): nothing was recorded.
    NoTrustedTime,
    /// The outcome read says the nonce is not in the lineage.
    Absent,
}

/// One authority-changing request as the surface tracks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// How far it got.
    pub sent: Sent,
    /// Its path.
    pub path: Path,
    /// What came back.
    pub answer: Answer,
    /// Whether the transport gave up waiting.
    pub timed_out: bool,
    /// When the signed intent stops being valid, Unix ms.
    pub valid_until: u64,
}

/// What the surface shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shown {
    /// "Submitted": sent, waiting for the answer (XI-3).
    Submitted,
    /// Recorded and allowed: "Revoked 14:03:12".
    Confirmed,
    /// Recorded and allowed; the covering checkpoint awaits a witness.
    WitnessPending,
    /// Recorded and refused.
    NotAllowed,
    /// "Not confirmed — checking".
    Checking,
    /// "Not recorded — try again".
    NotRecorded,
    /// "Couldn't … unreachable. Your request was not recorded."
    CouldntReach,
    /// "Busy — retry".
    Busy,
    /// "Unavailable — time check".
    NoTrustedTime,
}

impl Shown {
    /// The text key.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Submitted => texts::OUTCOME_SUBMITTED,
            Self::Confirmed => texts::OUTCOME_CONFIRMED,
            Self::WitnessPending => texts::OUTCOME_WITNESS_PENDING,
            Self::NotAllowed => texts::OUTCOME_NOT_ALLOWED,
            Self::Checking => texts::OUTCOME_CHECKING,
            Self::NotRecorded => texts::OUTCOME_NOT_RECORDED,
            Self::CouldntReach => texts::OUTCOME_COULDNT_REACH,
            Self::Busy => texts::OUTCOME_BUSY,
            Self::NoTrustedTime => texts::OUTCOME_TIME,
        }
    }

    /// Whether the change is shown as done.
    #[must_use]
    pub const fn done(self) -> bool {
        matches!(self, Self::Confirmed | Self::WitnessPending)
    }
}

/// What the surface does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Wait for the answer.
    Wait,
    /// Send the same signed request again, same nonce: Access answers a recorded nonce with its
    /// recorded decision and records it at most once (HL-5, TI-8).
    RetrySameNonce,
    /// The intent's validity has passed: only read the outcome.
    QueryOutcome,
    /// Nothing more: the outcome is known.
    Done,
    /// A new request with a new nonce may be made.
    MayRetryNew,
}

/// What `a` shows (G39, X26).
#[must_use]
pub const fn shown(a: &Attempt) -> Shown {
    match a.answer {
        Answer::Recorded {
            allowed: true,
            witness_pending: true,
        } => Shown::WitnessPending,
        Answer::Recorded { allowed: true, .. } => Shown::Confirmed,
        Answer::Recorded { .. } => Shown::NotAllowed,
        Answer::Busy => Shown::Busy,
        Answer::NoTrustedTime => Shown::NoTrustedTime,
        Answer::Absent => Shown::NotRecorded,
        Answer::Nothing => match (a.sent, a.path, a.timed_out) {
            (Sent::Never, Path::Direct, true) => Shown::CouldntReach,
            (Sent::Never, Path::Mediated, true) | (Sent::Sent, _, true) => Shown::Checking,
            (_, _, false) => Shown::Submitted,
        },
    }
}

/// What comes after `a` at `now` (§8.13 timeout rule).
#[must_use]
pub const fn next(a: &Attempt, now: u64) -> Next {
    match shown(a) {
        Shown::Confirmed | Shown::WitnessPending | Shown::NotAllowed => Next::Done,
        Shown::Submitted => Next::Wait,
        Shown::NotRecorded | Shown::CouldntReach | Shown::Busy | Shown::NoTrustedTime => {
            Next::MayRetryNew
        }
        Shown::Checking => {
            if now < a.valid_until {
                Next::RetrySameNonce
            } else {
                Next::QueryOutcome
            }
        }
    }
}

/// What an ADP evaluation answer of `status` with `body` tells about a commit (L1-ADP-10):
/// a decision with its `ExerciseID` was recorded; a rate refusal and a missing trusted time
/// recorded nothing; anything else, a protocol problem included, is not known either way.
#[must_use]
pub fn answer_of(status: u16, body: &[u8]) -> Answer {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    match status {
        200 => match (
            v.get("decision").and_then(serde_json::Value::as_bool),
            v.pointer("/context/exercise"),
        ) {
            (Some(allowed), Some(_)) => Answer::Recorded {
                allowed,
                witness_pending: false,
            },
            _ => Answer::Nothing,
        },
        429 => Answer::Busy,
        503 if v.get("reason").and_then(serde_json::Value::as_str) == Some("time") => {
            Answer::NoTrustedTime
        }
        _ => Answer::Nothing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempt(sent: Sent, path: Path, answer: Answer, timed_out: bool) -> Attempt {
        Attempt {
            sent,
            path,
            answer,
            timed_out,
            valid_until: 1_000,
        }
    }

    // XI-3, §8.5
    #[test]
    fn nothing_is_done_before_the_recorded_position() {
        let a = attempt(Sent::Sent, Path::Direct, Answer::Nothing, false);
        assert_eq!(shown(&a), Shown::Submitted);
        assert!(!shown(&a).done());
        assert_eq!(next(&a, 0), Next::Wait);
        let recorded = Attempt {
            answer: Answer::Recorded {
                allowed: true,
                witness_pending: false,
            },
            ..a
        };
        assert_eq!(shown(&recorded), Shown::Confirmed);
        assert!(shown(&recorded).done());
    }

    // G39, X26, HL-5, TI-8
    #[test]
    fn an_unknown_outcome_is_never_confirmed_or_not_recorded() {
        for path in [Path::Direct, Path::Mediated] {
            let a = attempt(Sent::Sent, path, Answer::Nothing, true);
            assert_eq!(shown(&a), Shown::Checking);
            assert!(!shown(&a).done());
            assert_eq!(next(&a, 999), Next::RetrySameNonce);
            assert_eq!(next(&a, 1_000), Next::QueryOutcome);
        }
        let mediated = attempt(Sent::Never, Path::Mediated, Answer::Nothing, true);
        assert_eq!(shown(&mediated), Shown::Checking);
    }

    // §8.17.7.2, X26
    #[test]
    fn not_recorded_only_without_any_attempt_or_with_an_absent_nonce() {
        let never = attempt(Sent::Never, Path::Direct, Answer::Nothing, true);
        assert_eq!(shown(&never), Shown::CouldntReach);
        assert_eq!(next(&never, 0), Next::MayRetryNew);
        let absent = attempt(Sent::Sent, Path::Direct, Answer::Absent, true);
        assert_eq!(shown(&absent), Shown::NotRecorded);
        let sent = attempt(Sent::Sent, Path::Direct, Answer::Nothing, true);
        assert_ne!(shown(&sent), Shown::NotRecorded);
        assert_ne!(shown(&sent), Shown::CouldntReach);
    }

    // G39, L1-ADP-10
    #[test]
    fn only_a_decision_with_its_exercise_is_recorded() {
        let ok = br#"{"decision": true, "context": {"exercise": "ZQ"}}"#;
        assert_eq!(
            answer_of(200, ok),
            Answer::Recorded {
                allowed: true,
                witness_pending: false
            }
        );
        assert_eq!(
            answer_of(200, br#"{"decision": true, "context": {}}"#),
            Answer::Nothing
        );
        assert_eq!(answer_of(429, b"{}"), Answer::Busy);
        assert_eq!(
            answer_of(503, br#"{"reason": "time"}"#),
            Answer::NoTrustedTime
        );
        assert_eq!(
            answer_of(503, br#"{"reason": "sequencer"}"#),
            Answer::Nothing
        );
        assert_eq!(answer_of(400, b"{}"), Answer::Nothing);
    }

    // §13.8, CL-1, CL-2
    #[test]
    fn busy_and_time_are_their_own_texts() {
        let busy = attempt(Sent::Sent, Path::Direct, Answer::Busy, false);
        assert_eq!(shown(&busy).text(), texts::OUTCOME_BUSY);
        let time = attempt(Sent::Sent, Path::Direct, Answer::NoTrustedTime, false);
        assert_eq!(shown(&time).text(), texts::OUTCOME_TIME);
        let witness = attempt(
            Sent::Sent,
            Path::Direct,
            Answer::Recorded {
                allowed: true,
                witness_pending: true,
            },
            false,
        );
        assert_eq!(shown(&witness).text(), texts::OUTCOME_WITNESS_PENDING);
        let refused = attempt(
            Sent::Sent,
            Path::Direct,
            Answer::Recorded {
                allowed: false,
                witness_pending: false,
            },
            false,
        );
        assert_eq!(shown(&refused), Shown::NotAllowed);
    }
}
