//! What the daemon keeps between restarts (OP-156 m.3 (p), MD-8, SI-22): the last NSS
//! snapshot, each user's last online console sign-in with the security keys Access listed for
//! them, and the latest time the daemon saw. Every offline answer is bounded by the snapshot's
//! age limit, the 8-hour console limit and the host's horizon; a clock that went back refuses
//! every offline answer; `sudo` is never answered offline.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::fido::Credential;
use super::snapshot::Snapshot;

/// How far the clock may step back before offline answers stop, ms.
pub const CLOCK_SLACK_MS: u64 = 60_000;

/// A user's last online console sign-in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsoleSignIn {
    /// When Access allowed it, ms.
    pub at_ms: u64,
    /// The security keys Access listed for the user, the only way to sign in offline.
    pub credentials: Vec<Credential>,
}

/// The daemon's kept state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The last NSS snapshot.
    pub snapshot: Option<Snapshot>,
    /// Last online console sign-in by user.
    pub console: BTreeMap<String, ConsoleSignIn>,
    /// The latest time the daemon read, ms.
    pub last_ms: u64,
}

/// Why nothing offline answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Offline {
    /// No snapshot, or it is past its age limit or the horizon.
    #[error("linux-offline-expired")]
    Expired,
    /// The clock went back.
    #[error("linux-offline-clock")]
    Clock,
    /// The user has no console sign-in to reuse, or it is past 8 hours or the horizon.
    #[error("linux-offline-no-sign-in")]
    NoSignIn,
}

impl State {
    /// Records a reading of the clock; `false` when it went back past the slack, and then no
    /// offline answer is given until it catches up.
    pub fn tick(&mut self, now: u64) -> bool {
        if now.saturating_add(CLOCK_SLACK_MS) < self.last_ms {
            return false;
        }
        self.last_ms = self.last_ms.max(now);
        true
    }

    /// The snapshot that may answer at `now`.
    ///
    /// # Errors
    /// [`Offline`].
    pub fn snapshot_at(&mut self, now: u64) -> Result<&Snapshot, Offline> {
        if !self.tick(now) {
            return Err(Offline::Clock);
        }
        match &self.snapshot {
            Some(s) if now < s.nss_until() => Ok(s),
            _ => Err(Offline::Expired),
        }
    }

    /// The credentials an offline console sign-in of `user` at `now` may use: within 8 hours
    /// (or the host's shorter limit) of the last online sign-in, while the snapshot and the
    /// user's Grant answer, never past the horizon.
    ///
    /// # Errors
    /// [`Offline`].
    pub fn offline_console(&mut self, user: &str, now: u64) -> Result<Vec<Credential>, Offline> {
        let s = self.snapshot_at(now)?;
        let ttl = s.console_ttl_ms();
        let horizon = s.horizon_ms;
        let console_user = s.user(user, now).is_some_and(|u| u.console);
        if !console_user {
            return Err(Offline::NoSignIn);
        }
        let Some(c) = self.console.get(user) else {
            return Err(Offline::NoSignIn);
        };
        let until = c.at_ms.saturating_add(ttl).min(horizon);
        if now >= until || now < c.at_ms.saturating_sub(CLOCK_SLACK_MS) || c.credentials.is_empty()
        {
            return Err(Offline::NoSignIn);
        }
        Ok(c.credentials.clone())
    }

    /// Records the counter a security key reached, so a replayed or cloned key is refused.
    pub fn counted(&mut self, user: &str, credential: &[u8], count: u32) {
        if let Some(c) = self.console.get_mut(user)
            && let Some(k) = c.credentials.iter_mut().find(|k| k.id == credential)
        {
            k.sign_count = k.sign_count.max(count);
        }
    }

    /// Drops every user the snapshot no longer names from the console cache.
    pub fn prune(&mut self) {
        if let Some(s) = &self.snapshot {
            self.console
                .retain(|name, _| s.users.iter().any(|u| u.name == *name && u.console));
        } else {
            self.console.clear();
        }
    }
}
