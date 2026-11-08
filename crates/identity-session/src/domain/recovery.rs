//! Account recovery as a typed state machine (§12.3.2, TN-52–TN-63, OP-153 m.3 (c)–(f)): the
//! recovery classes and their assurance labels, the AAL a set of evidence reaches, the cooling
//! table, the realm's recovery policy and its tightening rule, the restricted actions of the
//! grace period and the codes people read. Pure: time and randomness come from the caller.

use serde::{Deserialize, Serialize};

use crate::domain::assurance::Aal;
pub use access_identity_account::domain::claim_classes::RecoveryPath;

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

/// OP-153 m.3 (f), TN-61: a reset intent lives one hour by default and never past 24.
pub const INTENT_TTL_MS: u64 = HOUR_MS;

/// TN-61: the longest reset intent.
pub const INTENT_TTL_MAX_MS: u64 = DAY_MS;

/// TN-62: a temporary access pass lives one hour by default, between 10 minutes and 30 days.
pub const TAP_TTL_MS: u64 = HOUR_MS;

/// TN-62: the shortest pass.
pub const TAP_TTL_MIN_MS: u64 = 10 * MINUTE_MS;

/// TN-62: the longest pass.
pub const TAP_TTL_MAX_MS: u64 = 30 * DAY_MS;

/// TN-62: a pass is 16 characters by default, between 8 and 48.
pub const TAP_LENGTH: usize = 16;

/// TN-62: the shortest pass.
pub const TAP_LENGTH_MIN: usize = 8;

/// TN-62: the longest pass.
pub const TAP_LENGTH_MAX: usize = 48;

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

/// TN-55, OP-153 m.3 (e): the identity plane's cooling table, inversely proportional to the
/// strength of the evidence and sensitive to risk. It is never shortened for one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoolingTable {
    /// A registered recovery code.
    pub registered_code_ms: u64,
    /// An e-mail code alone, or a recovery contact alone.
    pub sent_code_ms: u64,
    /// Two channels.
    pub two_channels_ms: u64,
    /// Two channels at medium or high risk.
    pub two_channels_risky_ms: u64,
    /// Identity re-proofing.
    pub reproofing_ms: u64,
    /// A temporary access pass or a reset intent: approved out of band.
    pub out_of_band_ms: u64,
    /// A high-value account, whatever the method (at least).
    pub high_value_ms: u64,
}

impl CoolingTable {
    /// OP-153 m.3 (e).
    pub const DEFAULT: Self = Self {
        registered_code_ms: 0,
        sent_code_ms: DAY_MS,
        two_channels_ms: 4 * HOUR_MS,
        two_channels_risky_ms: DAY_MS,
        reproofing_ms: HOUR_MS,
        out_of_band_ms: 0,
        high_value_ms: DAY_MS,
    };

    fn entries(&self) -> [u64; 7] {
        [
            self.registered_code_ms,
            self.sent_code_ms,
            self.two_channels_ms,
            self.two_channels_risky_ms,
            self.reproofing_ms,
            self.out_of_band_ms,
            self.high_value_ms,
        ]
    }

    /// Whether every entry is at least `other`'s.
    #[must_use]
    pub fn at_least(&self, other: &Self) -> bool {
        self.entries()
            .iter()
            .zip(other.entries())
            .all(|(a, b)| *a >= b)
    }

    /// The cooling of an attempt that spent `evidence`: risky two channels wait longer; a
    /// high-value account waits at least its entry (OP-153 m.3 (e)).
    #[must_use]
    pub fn cooling(&self, evidence: &[RecoveryPath], risky: bool, high_value: bool) -> u64 {
        let mut distinct: Vec<RecoveryPath> = Vec::new();
        for e in evidence {
            if !distinct.contains(e) {
                distinct.push(*e);
            }
        }
        let channels: Vec<RecoveryPath> = distinct
            .iter()
            .copied()
            .filter(|p| *p != RecoveryPath::SecondAuthenticator)
            .collect();
        let base = if distinct.iter().any(|p| {
            matches!(
                p,
                RecoveryPath::ResetIntent | RecoveryPath::TemporaryAccessPass
            )
        }) {
            self.out_of_band_ms
        } else if distinct.contains(&RecoveryPath::IdentityReproofing) {
            self.reproofing_ms
        } else if channels.len() >= 2 {
            if risky {
                self.two_channels_risky_ms
            } else {
                self.two_channels_ms
            }
        } else if channels == [RecoveryPath::RegisteredCode] {
            self.registered_code_ms
        } else {
            self.sent_code_ms
        };
        if high_value {
            base.max(self.high_value_ms)
        } else {
            base
        }
    }
}

/// The realm's recovery policy (`idp.account.recovery_policy`, OP-153 m.3 (a), (e), (f)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    /// The cooling table.
    pub cooling: CoolingTable,
    /// Whether temporary access passes exist (TN-62: only if the realm opts in).
    pub tap: bool,
    /// A pass's default lifetime.
    pub tap_ttl_ms: u64,
    /// A pass's default length.
    pub tap_length: usize,
    /// A reset intent's default lifetime.
    pub intent_ttl_ms: u64,
    /// The extra AAL a rebind needs beyond the account's own, if the domain asks for one
    /// (§10.1.3: tighten only).
    pub rebind_aal: Option<Aal>,
}

/// Why a recovery policy is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyRefusal {
    /// A value is outside its range, or below the floor of OP-153 m.3 (e).
    #[error("recovery policy out of range")]
    OutOfRange,
    /// The change loosens recovery: `idp.account.recovery_policy_loosen` (CT3, TN-55).
    #[error("recovery policy loosens")]
    Loosens,
}

impl RecoveryPolicy {
    /// OP-153 m.3 (e), (f): the default table, no passes, one-hour intents.
    pub const DEFAULT: Self = Self {
        cooling: CoolingTable::DEFAULT,
        tap: false,
        tap_ttl_ms: TAP_TTL_MS,
        tap_length: TAP_LENGTH,
        intent_ttl_ms: INTENT_TTL_MS,
        rebind_aal: None,
    };

    /// Checks the ranges: no entry below the m.3 (e) floor (a domain never loosens below it,
    /// §10.1.3), pass and intent values inside TN-61/TN-62.
    ///
    /// # Errors
    /// [`PolicyRefusal::OutOfRange`].
    pub fn validate(&self) -> Result<(), PolicyRefusal> {
        let ok = self.cooling.at_least(&CoolingTable::DEFAULT)
            && (TAP_TTL_MIN_MS..=TAP_TTL_MAX_MS).contains(&self.tap_ttl_ms)
            && (TAP_LENGTH_MIN..=TAP_LENGTH_MAX).contains(&self.tap_length)
            && (1..=INTENT_TTL_MAX_MS).contains(&self.intent_ttl_ms)
            && self.cooling.entries().iter().all(|e| *e <= 30 * DAY_MS);
        if ok {
            Ok(())
        } else {
            Err(PolicyRefusal::OutOfRange)
        }
    }

    /// Whether moving from `current` to `self` loosens recovery anywhere: a shorter cooling,
    /// passes turned on or longer, longer intents, or a lower rebind term (TN-55).
    #[must_use]
    pub fn loosens(&self, current: &Self) -> bool {
        !self.cooling.at_least(&current.cooling)
            || (self.tap && !current.tap)
            || self.tap_ttl_ms > current.tap_ttl_ms
            || self.tap_length < current.tap_length
            || self.intent_ttl_ms > current.intent_ttl_ms
            || self.rebind_aal < current.rebind_aal
    }

    /// The change under the action it needs: `Ok(false)` tightens (CT1), `Ok(true)` loosens
    /// (CT3).
    ///
    /// # Errors
    /// [`PolicyRefusal::OutOfRange`].
    pub fn change(&self, current: &Self) -> Result<bool, PolicyRefusal> {
        self.validate()?;
        Ok(self.loosens(current))
    }

    /// The stored bytes.
    ///
    /// # Errors
    /// [`PolicyRefusal::OutOfRange`] when it cannot be encoded.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PolicyRefusal> {
        serde_json::to_vec(self).map_err(|_| PolicyRefusal::OutOfRange)
    }

    /// The policy of stored bytes.
    ///
    /// # Errors
    /// [`PolicyRefusal::OutOfRange`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PolicyRefusal> {
        let p: Self = serde_json::from_slice(bytes).map_err(|_| PolicyRefusal::OutOfRange)?;
        p.validate()?;
        Ok(p)
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

/// A temporary access pass of `length` characters from `random` (5 bits a character).
#[must_use]
pub fn tap_code(random: &[u8; 30], length: usize) -> String {
    super::codes::base32(random).chars().take(length).collect()
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
