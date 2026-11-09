//! What a job does next (E62, E63, §7.9.7.2, U5): one command from its folded history, the
//! time and whether this process holds the released token. The executor decides nothing about
//! authority; every effect waits for Access's answer, and every re-check point asks again.

use super::history::{Evidence, Job, Outcome, Reading};
use super::step::{Reversibility, within};

/// What follows an outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Follow {
    /// A person takes over (E51).
    Handoff,
    /// A semantic event: ask again before the next step.
    Semantic,
    /// Pause: an unknown outcome waits for a person (E62 (3)).
    Pause(&'static str),
    /// Stop, for the reason given.
    Stop(&'static str),
}

/// One command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Next {
    /// Nothing more: completed, or stopped and confirmed.
    Done,
    /// Nothing before this time.
    Wait(u64),
    /// Paused and confirmed; a person resumes it.
    Idle,
    /// Confirm the stop with an `executor_control` Claim (U5).
    ConfirmStop,
    /// Confirm the pause with an `executor_control` Claim (U5).
    ConfirmPause,
    /// Record a stop, for the reason given.
    Stop(&'static str),
    /// Record a pause, for the reason given.
    Pause(&'static str),
    /// Ask Access with the next `continue` statement (§7.9.7.2).
    Recheck,
    /// Access asked for an approval: wait for the person, at most [`super::HANDOFF_WAIT_MS`].
    AwaitApproval(u32),
    /// Open the step's delayed-commit window.
    OpenWindow(u32, u64),
    /// Ask the vault for the Exercise's token.
    Release(u32),
    /// Commit the outbox entry, then send the request (TI-6).
    Outbox(u32),
    /// Send again, once and with the same key, a request whose answer was lost (TI-6).
    Resend(u32),
    /// Record the step's outcome and what follows it.
    Settle(u32, Outcome, Vec<Evidence>, Option<Follow>),
    /// Report the step's outcome to Access.
    Attest(u32),
}

/// The outcome of a driver's reading (E64).
#[must_use]
pub fn settle(reading: Reading) -> (Outcome, Vec<Evidence>, Option<Follow>) {
    match reading {
        Reading::Confirmed => (Outcome::Done, vec![Evidence::UpstreamConfirmation], None),
        Reading::Refused => (Outcome::NotDone, Vec::new(), None),
        Reading::Blocked => (Outcome::NotDone, Vec::new(), Some(Follow::Handoff)),
        Reading::Conflict => (Outcome::NotDone, Vec::new(), Some(Follow::Semantic)),
        Reading::Unclear => (Outcome::Unknown, Vec::new(), Some(Follow::Pause("unknown"))),
    }
}

fn index(i: usize) -> u32 {
    u32::try_from(i).unwrap_or(u32::MAX)
}

fn unknown() -> (Outcome, Vec<Evidence>, Option<Follow>) {
    (Outcome::Unknown, Vec::new(), Some(Follow::Pause("unknown")))
}

/// The next command of `job` at `now`; `token` is whether this process holds the released
/// token.
#[must_use]
pub fn next(job: &Job, now: u64, token: bool) -> Next {
    if job.confirmed == Some(super::history::Confirmed::Stopped) {
        return Next::Done;
    }
    let current = job.current();
    if let Some(i) = current
        && let Some(s) = job.steps.get(i)
    {
        // E64
        if s.outcome.is_some() {
            return Next::Attest(index(i));
        }
        if let Some((_, _, reading)) = s.answered {
            let (outcome, evidence, then) = settle(reading);
            return Next::Settle(index(i), outcome, evidence, then);
        }
        if s.faulted {
            let (outcome, evidence, then) = unknown();
            return Next::Settle(index(i), outcome, evidence, then);
        }
    }
    // U5
    if job.stop_requested.is_some() {
        if let Some(i) = current
            && let Some(s) = job.steps.get(i)
            && s.outbox.is_some()
        {
            // TI-6
            return Next::Settle(index(i), Outcome::Unknown, Vec::new(), None);
        }
        return Next::ConfirmStop;
    }
    if job.completed() {
        return Next::Done;
    }
    if let Some(code) = &job.refused {
        return if code == "require_action" {
            match &job.handoff {
                None => Next::AwaitApproval(current.map_or(0, index)),
                Some((_, _, until)) if now >= *until => Next::Stop("silence"),
                Some((_, _, until)) => Next::Wait(*until),
            }
        } else {
            Next::Stop("decision")
        };
    }
    // E47 (4), E51
    if let Some((_, _, until)) = &job.handoff {
        return if now >= *until {
            Next::Stop("silence")
        } else {
            Next::Wait(*until)
        };
    }
    if job.pause_requested {
        return if job.confirmed == Some(super::history::Confirmed::Paused) {
            Next::Idle
        } else {
            Next::ConfirmPause
        };
    }
    let Some(pos) = current else {
        return Next::Done;
    };
    step(job, pos, now, token)
}

fn not_done(at: u32, reason: &'static str) -> Next {
    Next::Settle(at, Outcome::NotDone, Vec::new(), Some(Follow::Stop(reason)))
}

/// The next command of the job's current step `pos`, once no control state holds it.
fn step(job: &Job, pos: usize, now: u64, token: bool) -> Next {
    let Some(s) = job.steps.get(pos) else {
        return Next::Done;
    };
    let at = index(pos);
    // §7.9.7.2, Ek B 4277, 4498
    if job.recheck_due {
        return if job.continuations.is_empty() {
            Next::Pause("continuation")
        } else {
            Next::Recheck
        };
    }
    // TI-6, E62 (3)
    if s.outbox.is_some() {
        if s.spec.idempotent && !s.resent && token {
            return Next::Resend(at);
        }
        let (outcome, evidence, then) = unknown();
        return Next::Settle(at, outcome, evidence, then);
    }
    if s.cancelled {
        return not_done(at, "cancel");
    }
    if now > job.envelope.validity.until {
        return not_done(at, "horizon");
    }
    // INV-19, Ek B 4280
    if !within(&s.spec, &job.envelope) {
        return not_done(at, "envelope");
    }
    // E47 (2), (3)
    if s.spec.reversibility == Reversibility::Irreversible && job.started.commit_window_ms > 0 {
        match s.window_until {
            None => {
                return Next::OpenWindow(at, now.saturating_add(job.started.commit_window_ms));
            }
            Some(until) if now < until => return Next::Wait(until),
            Some(_) => {}
        }
    }
    match (token, job.released_until) {
        (false, None) => Next::Release(at),
        (true, Some(until)) if now < until => Next::Outbox(at),
        _ => not_done(at, "release"),
    }
}
