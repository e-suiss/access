//! The release rule (G59, U65, U66, EI-26, AG-32, AG-40, OP-154 m.3 (t)): an upstream token
//! leaves the vault only for an Exercise the authority plane allowed, only to the registered
//! executor that is that Exercise's PEP, once, for the Party the connection belongs to, and
//! never past the decision's horizon. Holding a `TokenSet` is never a reason (AGI-2). Every
//! release path, the executor's, path (b) and a release that refreshes first, asks [`admit`].
//! Free of I/O.

use access_kernel::intent::IntentEnvelope;
use access_kernel::tier::Tier;

use crate::domain::resource::Resource;

/// Path (b)'s lifetime ceiling for a token without an upstream revocation endpoint: one hour
/// (AG-40 (4), PD).
pub const PATH_B_MAX_LIFETIME_MS: u64 = 3_600_000;

/// A token this close to its expiry is refreshed before release, under the refresh lease
/// (OP-154 m.3 (t)).
pub const REFRESH_AHEAD_MS: u64 = 300_000;

/// What the authority plane kept of an allowed Exercise: its receipt and what follows from it
/// at the head. `None` in [`admit`] means no allowed Exercise: unknown, denied or waiting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allowed {
    /// The PEP the decision was addressed to (the receipt's `audience`).
    pub pep: String,
    /// The Party acted for: the principal of `for(P)`, else the actor Instance's Party.
    pub principal: Option<[u8; 16]>,
    /// The actor Instance's Party.
    pub actor: Option<[u8; 16]>,
    /// The Exercise's consequence tier from its accepted Action Schema; `None` when the
    /// action has no accepted schema.
    pub tier: Option<Tier>,
    /// Whether its basis still stands at the head (a revoked Grant does not).
    pub basis_live: bool,
    /// Position of the decision record.
    pub position: u64,
}

/// The connection a release asks for, as the vault holds it.
#[derive(Clone, Copy, Debug)]
pub struct Held<'a> {
    /// `active`, `pending`, `needs_reconnect` or `disconnected`.
    pub status: &'a str,
    /// The person's Party.
    pub party: [u8; 16],
    /// Its Resource; `None` once the Resource is disabled.
    pub resource: Option<&'a Resource>,
}

/// What the vault knows of the token it would release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenFacts {
    /// When it expires, Unix milliseconds, when known.
    pub expires_at: Option<u64>,
    /// Whether the upstream publishes a revocation endpoint.
    pub revocable: bool,
}

/// Where a released token goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    /// (a) broker-as-PEP: only the registered executor holds it and makes the call.
    Executor,
    /// (b) a short-lived token the executor may hand to the agent's code (CT0–CT1 only).
    Agent,
}

impl Path {
    /// Its wire and stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Executor => "executor",
            Self::Agent => "agent",
        }
    }
}

/// A release [`admit`] allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// Where the token goes.
    pub path: Path,
    /// The tier the decision was taken at; an unclassified action is CT2.
    pub tier: Tier,
    /// Unix milliseconds the token may be used until: never past the horizon.
    pub use_until: u64,
}

/// Why a release is refused; each is fail-closed and none falls back to another route.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// No PEP authenticated the call: an agent has no route to the vault (§11.13).
    #[error("release-unauthenticated")]
    Unauthenticated,
    /// No allowed Exercise, or not the intent it was allowed for (G59, EI-26).
    #[error("release-without-exercise")]
    NoExercise,
    /// The Exercise was decided for another PEP (EI-26).
    #[error("release-foreign-exercise")]
    ForeignExercise,
    /// The caller is not a registered executor of the Resource (AG-40 (3)).
    #[error("release-not-executor")]
    NotExecutor,
    /// The Exercise's basis no longer stands: its Grant ended (INV-5).
    #[error("release-basis-ended")]
    BasisEnded,
    /// Outside the intent's validity.
    #[error("release-outside-validity")]
    OutsideValidity,
    /// The connection is not active, or its Resource is disabled.
    #[error("release-not-connected")]
    NotConnected,
    /// The connection lapsed and waits on the person (OP-154 m.3 (t)).
    #[error("release-needs-reconnect")]
    NeedsReconnect,
    /// The Exercise was not for the Party the connection belongs to (AGI-2).
    #[error("release-not-the-holder")]
    NotTheHolder,
    /// The Resource does not map the Exercise's action.
    #[error("release-action-not-mapped")]
    ActionNotMapped,
    /// The Exercise was released already: one release per Exercise (one step).
    #[error("release-already-used")]
    AlreadyUsed,
}

impl Refusal {
    /// Its stable code.
    #[must_use]
    pub fn code(self) -> String {
        self.to_string()
    }

    /// Its HTTP status.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::Unauthenticated => 401,
            Self::NotConnected | Self::NeedsReconnect | Self::AlreadyUsed => 409,
            _ => 403,
        }
    }
}

/// What one release is asked as: by the PEP `caller`, for `intent`, path (b) wanted or not.
#[derive(Clone, Copy, Debug)]
pub struct Asked<'a> {
    /// The PEP the transport authenticated; `None` for anyone else.
    pub caller: Option<&'a str>,
    /// The intent presented with the Exercise.
    pub intent: &'a IntentEnvelope,
    /// Whether path (b) is asked for.
    pub agent: bool,
}

/// Decides one release at `now`: `asked` against `allowed` and `held`, with the realm's mode
/// and the token's facts. Path (b) is given only when every one of its conditions holds and is
/// otherwise path (a) (AG-40 (4), MD-8).
///
/// # Errors
/// [`Refusal`].
pub fn admit(
    asked: &Asked<'_>,
    allowed: Option<&Allowed>,
    held: &Held<'_>,
    (release_open, token): (bool, TokenFacts),
    now: u64,
) -> Result<Admitted, Refusal> {
    // §11.13, Ek B 4627
    let caller = asked.caller.ok_or(Refusal::Unauthenticated)?;
    // G59, EI-26
    let a = allowed.ok_or(Refusal::NoExercise)?;
    if a.pep != caller {
        return Err(Refusal::ForeignExercise);
    }
    let resource = match held.status {
        "active" => held.resource.ok_or(Refusal::NotConnected)?,
        "needs_reconnect" => return Err(Refusal::NeedsReconnect),
        _ => return Err(Refusal::NotConnected),
    };
    // AG-40 (3)
    if !resource.executors.contains(caller) {
        return Err(Refusal::NotExecutor);
    }
    // INV-5
    if !a.basis_live {
        return Err(Refusal::BasisEnded);
    }
    let intent = asked.intent;
    let horizon = intent.validity.until;
    if now < intent.validity.from || now >= horizon {
        return Err(Refusal::OutsideValidity);
    }
    // AGI-2
    if a.principal != Some(held.party) {
        return Err(Refusal::NotTheHolder);
    }
    if resource.mapped(&intent.action).is_none() {
        return Err(Refusal::ActionNotMapped);
    }
    // AG-40 (6)
    let tier = a.tier.unwrap_or(Tier::Ct2);
    // U65, AG-40 (4)
    let short = token.expires_at.is_some_and(|e| {
        e > now
            && e <= horizon
            && (e.saturating_sub(now) <= PATH_B_MAX_LIFETIME_MS || token.revocable)
    });
    let path = if asked.agent && release_open && tier <= Tier::Ct1 && short {
        Path::Agent
    } else {
        Path::Executor
    };
    let use_until = token.expires_at.map_or(horizon, |e| e.min(horizon));
    Ok(Admitted {
        path,
        tier,
        use_until,
    })
}

/// Whether a token expiring at `expires_at` is refreshed before a release at `now`.
#[must_use]
pub fn refresh_first(expires_at: Option<u64>, now: u64) -> bool {
    expires_at.is_some_and(|e| e <= now.saturating_add(REFRESH_AHEAD_MS))
}

#[cfg(test)]
mod tests;
