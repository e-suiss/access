//! The executor's pure core (OP-63): the job history and its fold, the next step a job takes,
//! the Claims it reports and the Web Bot Auth signature base. No I/O, clock or randomness: those
//! are ports, and every value read from them is in the history (E62 (1)).

pub mod attest;
pub mod b64;
pub mod bridge;
pub mod browser;
pub mod history;
pub mod isolation;
pub mod machine;
pub mod profile;
pub mod step;
pub mod webbot;

use serde::{Deserialize, Serialize};

/// A registered executor's kind; every kind follows the same rules (E57 (1), Ek B 4490).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Run by the operator of Access.
    Cloud,
    /// Run by a customer.
    Customer,
    /// On the person's own device.
    Local,
}

impl Kind {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cloud => "cloud",
            Self::Customer => "customer",
            Self::Local => "local",
        }
    }

    /// The kind of a wire name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Cloud, Self::Customer, Self::Local]
            .into_iter()
            .find(|k| k.name() == name)
    }
}

/// The default delayed-commit window of an irreversible step (E47 (2), OP-154 m.3 (u)).
pub const COMMIT_WINDOW_MS: u64 = 15_000;

/// How long a job waits for a person at a handoff or an approval before it stops; silence is
/// not approval (E47 (4), E51).
pub const HANDOFF_WAIT_MS: u64 = 600_000;

/// Most steps in one job.
pub const MAX_STEPS: usize = 32;

/// Most continuation statements a job holds.
pub const MAX_CONTINUATIONS: usize = 64;
