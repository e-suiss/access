//! The honest status ladder (§6.4 XI-2, §8.7, X14, B3, R6): Requested → Approval recorded →
//! Gate satisfied → Allowed / Not allowed → Started → Reported done / not done / unknown /
//! differs. Every rung names its owner and is shown on its own: none is inferred from another,
//! so revoked is not stopped, delivered is not applied, and unknown is neither failed nor
//! succeeded.

use crate::contract::Owner;

/// A rung's owner (XI-1): the ladder adds the coordinator to the row owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RungOwner {
    /// A row owner.
    Row(Owner),
    /// The coordinator whose Gate it is (Work or a third party).
    Coordinator,
    /// Whoever asked.
    Requester,
}

/// What is known about one rung.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Its owner reported it.
    Reached,
    /// Its owner reported it did not happen.
    NotReached,
    /// Its owner has not reported.
    Unknown,
    /// Not part of this flow.
    NotApplicable,
}

/// The rungs, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Requested.
    Requested,
    /// Approval recorded.
    ApprovalRecorded,
    /// Gate satisfied.
    GateSatisfied,
    /// Allowed / not allowed.
    Decision,
    /// Started.
    Started,
    /// Reported done / not done / unknown / differs.
    Reported,
}

/// How a runtime reported the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    /// Done.
    Done,
    /// Not done.
    NotDone,
    /// What it reports differs from what was allowed.
    Differs,
}

/// What each owner reported; `None` is "has not reported".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Whether the flow needs an approval.
    pub needs_approval: bool,
    /// Whether the flow has a Gate.
    pub has_gate: bool,
    /// Access recorded the approval (contribution).
    pub approval: Option<bool>,
    /// The coordinator reported the Gate.
    pub gate: Option<bool>,
    /// Access recorded the decision.
    pub allowed: Option<bool>,
    /// The runtime reported a start.
    pub started: Option<bool>,
    /// The runtime reported the outcome.
    pub reported: Option<Report>,
}

/// One rung as shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rung {
    /// Which.
    pub step: Step,
    /// Who reports it.
    pub owner: RungOwner,
    /// What is known.
    pub state: State,
    /// Its text key.
    pub text: &'static str,
}

fn of(v: Option<bool>) -> State {
    match v {
        Some(true) => State::Reached,
        Some(false) => State::NotReached,
        None => State::Unknown,
    }
}

/// The ladder for `f`: six rungs, always, each from its own owner.
#[must_use]
pub fn ladder(f: &Facts) -> [Rung; 6] {
    let reported = match f.reported {
        Some(Report::Done) => (State::Reached, "ladder.reported_done"),
        Some(Report::NotDone) => (State::NotReached, "ladder.reported_not_done"),
        Some(Report::Differs) => (State::Reached, "ladder.reported_differs"),
        None => (State::Unknown, "ladder.reported_unknown"),
    };
    let decision = match f.allowed {
        Some(true) => (State::Reached, "ladder.allowed"),
        Some(false) => (State::NotReached, "ladder.not_allowed"),
        None => (State::Unknown, "ladder.decision_unknown"),
    };
    [
        Rung {
            step: Step::Requested,
            owner: RungOwner::Requester,
            state: State::Reached,
            text: "ladder.requested",
        },
        Rung {
            step: Step::ApprovalRecorded,
            owner: RungOwner::Row(Owner::Access),
            state: if f.needs_approval {
                of(f.approval)
            } else {
                State::NotApplicable
            },
            text: "ladder.approval_recorded",
        },
        Rung {
            step: Step::GateSatisfied,
            owner: RungOwner::Coordinator,
            state: if f.has_gate {
                of(f.gate)
            } else {
                State::NotApplicable
            },
            text: "ladder.gate_satisfied",
        },
        Rung {
            step: Step::Decision,
            owner: RungOwner::Row(Owner::Access),
            state: decision.0,
            text: decision.1,
        },
        Rung {
            step: Step::Started,
            owner: RungOwner::Row(Owner::Executor),
            state: of(f.started),
            text: "ladder.started",
        },
        Rung {
            step: Step::Reported,
            owner: RungOwner::Row(Owner::Executor),
            state: reported.0,
            text: reported.1,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // XI-2, X14, B3, R6
    #[test]
    fn the_ladder_never_collapses() {
        let allowed_only = ladder(&Facts {
            allowed: Some(true),
            ..Facts::default()
        });
        assert_eq!(allowed_only.len(), 6);
        assert_eq!(allowed_only[3].state, State::Reached);
        assert_eq!(
            allowed_only[4].state,
            State::Unknown,
            "allowed is not started"
        );
        assert_eq!(
            allowed_only[5].state,
            State::Unknown,
            "unknown is not failed"
        );
        assert_eq!(allowed_only[5].text, "ladder.reported_unknown");
        let refused = ladder(&Facts {
            allowed: Some(false),
            started: Some(true),
            ..Facts::default()
        });
        assert_eq!(refused[3].state, State::NotReached);
        assert_eq!(
            refused[4].state,
            State::Reached,
            "a refusal does not stop what the runtime reports started"
        );
        let owners: Vec<RungOwner> = refused.iter().map(|r| r.owner).collect();
        assert_eq!(
            owners,
            [
                RungOwner::Requester,
                RungOwner::Row(Owner::Access),
                RungOwner::Coordinator,
                RungOwner::Row(Owner::Access),
                RungOwner::Row(Owner::Executor),
                RungOwner::Row(Owner::Executor),
            ]
        );
    }

    // XI-2, XI-1, EI-10, EI-11
    #[test]
    fn no_two_rungs_share_a_label_and_each_rung_reads_only_its_owner() {
        let bools = [None, Some(false), Some(true)];
        let reports = [
            None,
            Some(Report::Done),
            Some(Report::NotDone),
            Some(Report::Differs),
        ];
        for needs_approval in [false, true] {
            for has_gate in [false, true] {
                for approval in bools {
                    for gate in bools {
                        for allowed in bools {
                            for started in bools {
                                for reported in reports {
                                    let f = Facts {
                                        needs_approval,
                                        has_gate,
                                        approval,
                                        gate,
                                        allowed,
                                        started,
                                        reported,
                                    };
                                    let l = ladder(&f);
                                    for (i, a) in l.iter().enumerate() {
                                        for b in l.iter().skip(i + 1) {
                                            assert_ne!(a.text, b.text, "{f:?}");
                                        }
                                    }
                                    let only_runtime = ladder(&Facts {
                                        started,
                                        reported,
                                        ..Facts::default()
                                    });
                                    assert_eq!(l[4], only_runtime[4], "{f:?}");
                                    assert_eq!(l[5], only_runtime[5], "{f:?}");
                                    let only_decision = ladder(&Facts {
                                        allowed,
                                        ..Facts::default()
                                    });
                                    assert_eq!(l[3], only_decision[3], "{f:?}");
                                }
                            }
                        }
                    }
                }
            }
        }
        let unknown = ladder(&Facts::default())[5];
        let failed = ladder(&Facts {
            reported: Some(Report::NotDone),
            ..Facts::default()
        })[5];
        let done = ladder(&Facts {
            reported: Some(Report::Done),
            ..Facts::default()
        })[5];
        assert_ne!(unknown.state, failed.state);
        assert_ne!(unknown.text, failed.text);
        assert_ne!(unknown.text, done.text);
        assert_ne!(failed.text, done.text);
    }
}
