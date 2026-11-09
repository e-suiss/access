//! `subscriptions/listen` as a long-running exercise (§11.5.7, A-8, AG-15, E31, U64, OP-154
//! m.3 (v)). The stream opens on one decision and closes at `min(token exp, horizon)`, never
//! later: the token is not refreshed on the stream, the client reconnects with a new token and
//! a new decision. Halfway to the horizon the PEP asks `continue`; a DENY, an unknown answer or
//! a missing statement closes the stream at once. A signal (SSF/CAEP or an Access event) asks
//! again now; it hurries the check, the horizon is the guarantee.
//!
//! [`Listen::deliver`] is the only way an event leaves: after the close or while a checkpoint is
//! open it hands nothing back.

use access_kernel::digest::Digest;
use access_kernel::model::TrustedTime;

/// The response headers of the stream (§11.5.6 #26). `Mcp-Session-Id` is not among them.
pub const SSE_HEADERS: [(&str, &str); 3] = [
    ("content-type", "text/event-stream"),
    ("cache-control", "no-store"),
    ("x-accel-buffering", "no"),
];

/// Why the stream closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// The decision's horizon was reached.
    Horizon,
    /// The token expired first.
    TokenExpired,
    /// `continue` was not allowed, not answered, or had no statement.
    Denied,
}

/// What the host does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Events may be delivered.
    Open,
    /// Ask `continue` for this Exercise before delivering anything else.
    Checkpoint(Digest),
    /// Close the stream; deliver nothing more.
    Closed(Closed),
}

/// The stream could not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ListenError {
    /// The horizon or the token's expiry is not after now.
    #[error("listen-horizon")]
    Horizon,
    /// A new token was presented on an open stream: refreshing in place is not allowed.
    #[error("listen-refresh")]
    Refresh,
}

/// One open stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listen {
    exercise: Digest,
    close_at: TrustedTime,
    reason: Closed,
    checkpoint: Option<TrustedTime>,
    asking: bool,
    closed: Option<Closed>,
}

impl Listen {
    /// The stream of the allowed Exercise `exercise`, opened at `now` under a token expiring
    /// at `token_exp` and a decision whose horizon is `horizon`; the checkpoint is halfway.
    ///
    /// # Errors
    /// [`ListenError::Horizon`].
    pub fn open(
        exercise: Digest,
        now: TrustedTime,
        token_exp: TrustedTime,
        horizon: TrustedTime,
    ) -> Result<Self, ListenError> {
        let (close_at, reason) = if token_exp < horizon {
            (token_exp, Closed::TokenExpired)
        } else {
            (horizon, Closed::Horizon)
        };
        if close_at <= now {
            return Err(ListenError::Horizon);
        }
        let half = close_at.saturating_sub(now) / 2;
        Ok(Self {
            exercise,
            close_at,
            reason,
            checkpoint: Some(now.saturating_add(half)),
            asking: false,
            closed: None,
        })
    }

    /// When the stream closes at the latest.
    #[must_use]
    pub const fn close_at(&self) -> TrustedTime {
        self.close_at
    }

    /// The Exercise the stream runs under.
    #[must_use]
    pub const fn exercise(&self) -> &Digest {
        &self.exercise
    }

    /// What to do at `now`.
    pub fn next(&mut self, now: TrustedTime) -> Next {
        if let Some(c) = self.closed {
            return Next::Closed(c);
        }
        if now >= self.close_at {
            self.closed = Some(self.reason);
            return Next::Closed(self.reason);
        }
        if self.asking || self.checkpoint.is_some_and(|c| now >= c) {
            self.asking = true;
            return Next::Checkpoint(self.exercise);
        }
        Next::Open
    }

    /// An SSF/CAEP or Access event about this authority arrived: ask `continue` now.
    pub fn signal(&mut self) {
        if self.closed.is_none() {
            self.asking = true;
        }
    }

    /// The answer to the checkpoint: `allowed` keeps the stream open until the same close time
    /// (a `continue` never moves it); anything else closes it.
    pub fn continued(&mut self, allowed: bool) {
        if self.closed.is_some() {
            return;
        }
        if allowed && self.asking {
            self.asking = false;
            self.checkpoint = None;
        } else {
            self.asking = false;
            self.closed = Some(Closed::Denied);
        }
    }

    /// Hands `event` back for sending only while the stream is open at `now` and no
    /// checkpoint is pending.
    pub fn deliver<E>(&mut self, now: TrustedTime, event: E) -> Option<E> {
        match self.next(now) {
            Next::Open => Some(event),
            Next::Checkpoint(_) | Next::Closed(_) => None,
        }
    }

    /// A token presented on the open stream (AG-15): always refused; the stream keeps its
    /// close time and the client reconnects with the new token.
    ///
    /// # Errors
    /// [`ListenError::Refresh`].
    pub const fn present_token(&self, _token: &str) -> Result<(), ListenError> {
        Err(ListenError::Refresh)
    }
}
