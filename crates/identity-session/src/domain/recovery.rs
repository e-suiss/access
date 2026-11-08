//! Account recovery as a typed state machine (§12.3.2, TN-52–TN-63, OP-153 m.3 (c)–(f)): the
//! recovery classes and their assurance labels, the AAL a set of evidence reaches, the cooling
//! table, the realm's recovery policy and its tightening rule, the restricted actions of the
//! grace period and the codes people read. Pure: time and randomness come from the caller.

use crate::domain::assurance::Aal;
pub use access_identity_account::domain::claim_classes::RecoveryPath;
pub use access_identity_account::domain::recovery_policy::{
    CoolingTable, INTENT_TTL_MAX_MS, INTENT_TTL_MS, PolicyRefusal, RecoveryPolicy, TAP_LENGTH,
    TAP_LENGTH_MAX, TAP_LENGTH_MIN, TAP_TTL_MAX_MS, TAP_TTL_MIN_MS, TAP_TTL_MS, tap_code,
};

const MINUTE_MS: u64 = 60_000;
const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;

/// SEC18, OP-153 m.3 (e): the grace period after a recovery, aligned with the 24 hours in which
/// a new authenticator binding satisfies no CT2+ term.
pub const GRACE_MS: u64 = DAY_MS;

/// OP-153 m.3 (d): a sent e-mail code lives 15 minutes.
pub const SENT_CODE_TTL_MS: u64 = 15 * MINUTE_MS;

/// TN-52: a recovery contact's code lives 24 hours; the extension the contact may give adds 24
/// more.
pub const CONTACT_CODE_TTL_MS: u64 = DAY_MS;

/// OP-153 m.3 (d): five tries per sent code.
pub const SENT_CODE_TRIES: i16 = 5;

/// OP-153 m.3 (d): ten failed proofs lock the attempt, never the account.
pub const ATTEMPT_FAILURES: usize = 10;

/// OP-153 m.3 (d): at most three recovery contacts.
pub const MAX_CONTACTS: usize = 3;

/// OP-153 m.3 (d): the waits between failed proofs grow from 30 seconds to one hour.
#[must_use]
pub fn backoff_ms(failures: usize) -> u64 {
    let shift = u32::try_from(failures.saturating_sub(1))
        .unwrap_or(u32::MAX)
        .min(16);
    30_000_u64
        .checked_shl(shift)
        .unwrap_or(HOUR_MS)
        .min(HOUR_MS)
}

/// TN-59: a cross-device link code lives at most 10 minutes.
pub const LINK_CODE_TTL_MS: u64 = 10 * MINUTE_MS;

/// The rebind window an attempt opens: its credential-only token lives this long.
pub const REBIND_TTL_MS: u64 = HOUR_MS;

/// Every recovery class, in wire order.
pub const PATHS: [RecoveryPath; 7] = [
    RecoveryPath::RegisteredCode,
    RecoveryPath::SentCode,
    RecoveryPath::RecoveryContact,
    RecoveryPath::SecondAuthenticator,
    RecoveryPath::IdentityReproofing,
    RecoveryPath::ResetIntent,
    RecoveryPath::TemporaryAccessPass,
];

/// The class of a wire name.
#[must_use]
pub fn path(name: &str) -> Option<RecoveryPath> {
    PATHS.into_iter().find(|p| p.name() == name)
}

/// The name of an AAL as the schema orders it (TN-53 rule 1).
#[must_use]
pub const fn aal_name(a: Aal) -> &'static str {
    match a {
        Aal::Aal1 => "aal1",
        Aal::Aal2 => "aal2",
        Aal::Aal3 => "aal3",
    }
}

/// The AAL of a schema name.
#[must_use]
pub fn aal_of(name: &str) -> Option<Aal> {
    match name {
        "aal1" => Some(Aal::Aal1),
        "aal2" => Some(Aal::Aal2),
        "aal3" => Some(Aal::Aal3),
        _ => None,
    }
}

/// The AAL of a Claim level (§10.1.6).
#[must_use]
pub const fn aal_from_level(level: u8) -> Option<Aal> {
    match level {
        1 => Some(Aal::Aal1),
        2 => Some(Aal::Aal2),
        3 => Some(Aal::Aal3),
        _ => None,
    }
}

/// The AAL as a Claim level (§10.1.6).
#[must_use]
pub const fn aal_level(a: Aal) -> u8 {
    match a {
        Aal::Aal1 => 1,
        Aal::Aal2 => 2,
        Aal::Aal3 => 3,
    }
}

/// The assurance label a recovery method carries on its own (TN-53 rule 1, NIST SP 800-63B-4
/// §4.2): one code of any class is AAL1; identity re-proofing is AAL2. A reset intent and a
/// temporary access pass are issued by an attributable Exercise after the issuer's own check
/// (TN-61, TN-62) and carry AAL2.
#[must_use]
pub const fn label(p: RecoveryPath) -> Aal {
    match p {
        RecoveryPath::RegisteredCode
        | RecoveryPath::SentCode
        | RecoveryPath::RecoveryContact
        | RecoveryPath::SecondAuthenticator => Aal::Aal1,
        RecoveryPath::IdentityReproofing
        | RecoveryPath::ResetIntent
        | RecoveryPath::TemporaryAccessPass => Aal::Aal2,
    }
}

/// The AAL a set of spent evidence reaches (§12.3.2 AAL matrix): AAL2 takes two different
/// classes, or a code and a single-factor authenticator bound to the account, or identity
/// re-proofing; one class alone is AAL1. Recovery never reaches AAL3 (in-person biometric
/// comparison only). `None` for no evidence.
#[must_use]
pub fn achieved(evidence: &[RecoveryPath]) -> Option<Aal> {
    let mut distinct: Vec<RecoveryPath> = Vec::new();
    for e in evidence {
        if !distinct.contains(e) {
            distinct.push(*e);
        }
    }
    let top = distinct.iter().map(|p| label(*p)).max()?;
    if distinct.len() >= 2 {
        Some(top.max(Aal::Aal2))
    } else {
        Some(top)
    }
}

/// The strongest AAL a recovery configuration can reach: what [`achieved`] gives when every
/// configured class is spent.
#[must_use]
pub fn reachable(configured: &[RecoveryPath]) -> Option<Aal> {
    achieved(configured)
}

/// TN-53 rule 1, TN-52, INV-40 (i): a configuration that cannot reach the account's AAL is
/// refused when it is made, never at run time. An AAL2 account with only an e-mail code is the
/// textbook case.
#[must_use]
pub fn too_weak(required: Aal, configured: &[RecoveryPath]) -> bool {
    reachable(configured).is_none_or(|r| r < required)
}

/// The states (TN-54).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// Started; evidence pending.
    Requested,
    /// A proof failed; the next waits.
    Throttled,
    /// Too many failed proofs: the attempt, never the account, is locked.
    Locked,
    /// Cancelled: by the owner's own sign-in or refusal.
    Denied,
    /// The evidence reaches the required AAL.
    EvidenceMet,
    /// The objection window runs.
    CoolingDown,
    /// The browser may bind one authenticator, nothing else.
    RebindOpen,
    /// An authenticator is bound; restricted actions wait.
    GracePeriod,
    /// Over.
    Closed,
}

impl State {
    /// Every state.
    pub const ALL: [Self; 9] = [
        Self::Requested,
        Self::Throttled,
        Self::Locked,
        Self::Denied,
        Self::EvidenceMet,
        Self::CoolingDown,
        Self::RebindOpen,
        Self::GracePeriod,
        Self::Closed,
    ];

    /// The schema name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Throttled => "throttled",
            Self::Locked => "locked",
            Self::Denied => "denied",
            Self::EvidenceMet => "evidence_met",
            Self::CoolingDown => "cooling_down",
            Self::RebindOpen => "rebind_open",
            Self::GracePeriod => "grace_period",
            Self::Closed => "closed",
        }
    }

    /// The state of a schema name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Whether nothing more happens to the attempt.
    #[must_use]
    pub const fn terminal(self) -> bool {
        matches!(self, Self::Locked | Self::Denied | Self::Closed)
    }

    /// Whether the owner's own sign-in still cancels it (TN-54): every state before an
    /// authenticator is bound.
    #[must_use]
    pub const fn cancellable(self) -> bool {
        matches!(
            self,
            Self::Requested
                | Self::Throttled
                | Self::EvidenceMet
                | Self::CoolingDown
                | Self::RebindOpen
        )
    }

    /// TN-54: the typed transitions; no step can be skipped by removing it (Keycloak 40744).
    #[must_use]
    pub const fn may(self, to: Self) -> bool {
        match self {
            Self::Requested | Self::Throttled => matches!(
                to,
                Self::Requested | Self::Throttled | Self::Locked | Self::EvidenceMet | Self::Denied
            ),
            Self::EvidenceMet => matches!(to, Self::CoolingDown | Self::RebindOpen | Self::Denied),
            Self::CoolingDown => matches!(to, Self::RebindOpen | Self::Denied),
            Self::RebindOpen => matches!(to, Self::GracePeriod | Self::Denied),
            Self::GracePeriod => matches!(to, Self::Closed),
            Self::Locked | Self::Denied | Self::Closed => false,
        }
    }
}

/// TN-56, OP-153 m.3 (e): what the grace period after a recovery refuses or steps up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Restricted {
    /// E-mail or phone change.
    ContactChange,
    /// A new recovery address or contact.
    RecoveryAddress,
    /// New recovery codes.
    RecoveryCodes,
    /// Removing a passkey or second factor.
    RemoveAuthenticator,
    /// A second new authenticator (the first is the rebind itself).
    SecondAuthenticator,
    /// Linking or unlinking an identity provider.
    IdpLink,
    /// A role raise, an invitation or an ownership transfer.
    RoleRaise,
    /// A bulk export or portability request.
    Export,
    /// A payment instrument, a withdrawal or a billing address.
    Payment,
    /// A new API key.
    ApiKey,
    /// A long-lived token.
    LongLivedToken,
    /// Deleting the account.
    Deletion,
    /// A cross-device link code.
    LinkCode,
}

impl Restricted {
    /// Every restricted action.
    pub const ALL: [Self; 13] = [
        Self::ContactChange,
        Self::RecoveryAddress,
        Self::RecoveryCodes,
        Self::RemoveAuthenticator,
        Self::SecondAuthenticator,
        Self::IdpLink,
        Self::RoleRaise,
        Self::Export,
        Self::Payment,
        Self::ApiKey,
        Self::LongLivedToken,
        Self::Deletion,
        Self::LinkCode,
    ];
}

/// Whether the grace period refuses `action` at `now_ms`: every listed action until it ends
/// (TN-56). A grace period that has ended refuses nothing.
#[must_use]
pub fn grace_refuses(grace_until_ms: Option<u64>, now_ms: u64, _action: Restricted) -> bool {
    grace_until_ms.is_some_and(|u| now_ms < u)
}

/// TN-59: a cross-device link code's entropy: 40 bits when the identifier is typed too,
/// 112 bits otherwise.
#[must_use]
pub const fn link_code_bits(with_identifier: bool) -> u16 {
    if with_identifier { 40 } else { 112 }
}

/// A cross-device link code from `random`: base32 of 5 bytes (40 bits) or 14 bytes (112 bits),
/// in groups of four.
#[must_use]
pub fn link_code(random: &[u8; 14], with_identifier: bool) -> String {
    let n = if with_identifier { 5 } else { 14 };
    group(&super::codes::base32(random.get(..n).unwrap_or_default()))
}

fn group(raw: &str) -> String {
    let mut out = String::new();
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && i.is_multiple_of(4) {
            out.push('-');
        }
        out.push(c);
    }
    out
}

/// The stored digest of a code sent for `attempt` (TN-59: never stored in the clear).
#[must_use]
pub fn code_digest(attempt: &[u8; 16], code: &str) -> [u8; 32] {
    let mut m = attempt.to_vec();
    m.extend_from_slice(code.trim().as_bytes());
    suiss_crypto::digest::context_digest("access/recovery-code/v1", &m).0
}

/// A typed code in canonical form: the recovery code rules (separators dropped, upper case).
#[must_use]
pub fn canonical(typed: &str) -> String {
    super::codes::canonical_recovery_code(typed)
}

/// What a person reads after a recovery (X38, X29, TN-55, §8.13): the dates, never "full access
/// restored".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aftermath {
    /// When high-impact actions open: the end of the grace period and of SEC18.
    pub sensitive_after_ms: u64,
}

#[cfg(test)]
mod tests;
