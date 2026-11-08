//! Security signals of the identity plane (TN-41, TN-43, §9.16.2 k.3 (a)): what happened to an
//! account, its sessions or its credentials, queued in the business transaction. The SSF
//! transmitter turns each into one CAEP or RISC SET per receiver, naming the subject by that
//! receiver's own pairwise `sub`. A signal is never authority and its loss widens nothing
//! (PI-9, L18). The payload holds ids and closed codes only, no personal data (OP-73).

use access_kernel::json::b64url_encode;
use serde_json::{Map, Value};

/// Prefix of the identity outbox kinds of signals.
pub const OUTBOX_PREFIX: &str = "signal.";

/// The family a signal is published in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// OpenID CAEP 1.0.
    Caep,
    /// OpenID RISC 1.0.
    Risc,
}

/// What happened (TN-41: the eight CAEP events; TN-43: the RISC events).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignalKind {
    /// CAEP `session-revoked`: sessions ended, by sign-out or a `session_epoch` step (MD-7).
    SessionRevoked,
    /// CAEP `credential-change`: a password, passkey or TOTP was added, replaced or removed.
    CredentialChange,
    /// CAEP `assurance-level-change`: a step-up reached a level.
    AssuranceLevelChange,
    /// CAEP `token-claims-change`: a claim mapper changed what tokens say.
    TokenClaimsChange,
    /// CAEP `device-compliance-change`: a device Instance ended or its posture changed.
    DeviceComplianceChange,
    /// CAEP `risk-level-change`: the SL2 risk level moved (§12.2.4).
    RiskLevelChange,
    /// CAEP `session-established`: a login session started.
    SessionEstablished,
    /// CAEP `session-presented`: a live session was presented to a client.
    SessionPresented,
    /// RISC `account-disabled`.
    AccountDisabled,
    /// RISC `account-purged`: the crypto-shred finished (OP-73).
    AccountPurged,
    /// RISC `identifier-recycled`: an identifier of the subject now belongs to another.
    IdentifierRecycled,
    /// RISC `credential-compromise`.
    CredentialCompromise,
}

impl SignalKind {
    /// Every kind, CAEP first.
    pub const ALL: [Self; 12] = [
        Self::SessionRevoked,
        Self::CredentialChange,
        Self::AssuranceLevelChange,
        Self::TokenClaimsChange,
        Self::DeviceComplianceChange,
        Self::RiskLevelChange,
        Self::SessionEstablished,
        Self::SessionPresented,
        Self::AccountDisabled,
        Self::AccountPurged,
        Self::IdentifierRecycled,
        Self::CredentialCompromise,
    ];

    /// The standard event name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SessionRevoked => "session-revoked",
            Self::CredentialChange => "credential-change",
            Self::AssuranceLevelChange => "assurance-level-change",
            Self::TokenClaimsChange => "token-claims-change",
            Self::DeviceComplianceChange => "device-compliance-change",
            Self::RiskLevelChange => "risk-level-change",
            Self::SessionEstablished => "session-established",
            Self::SessionPresented => "session-presented",
            Self::AccountDisabled => "account-disabled",
            Self::AccountPurged => "account-purged",
            Self::IdentifierRecycled => "identifier-recycled",
            Self::CredentialCompromise => "credential-compromise",
        }
    }

    /// CAEP or RISC.
    #[must_use]
    pub const fn family(self) -> Family {
        match self {
            Self::AccountDisabled
            | Self::AccountPurged
            | Self::IdentifierRecycled
            | Self::CredentialCompromise => Family::Risc,
            _ => Family::Caep,
        }
    }

    /// The kind of a standard event name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    /// The identity outbox kind: the name with `_` for `-`, as outbox kinds are spelled.
    #[must_use]
    pub fn outbox_kind(self) -> String {
        format!("{OUTBOX_PREFIX}{}", self.name().replace('-', "_"))
    }

    /// The kind of an identity outbox kind.
    #[must_use]
    pub fn from_outbox(kind: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.outbox_kind() == kind)
    }
}

/// Who started a session revocation (CAEP 1.0 §3 `initiating_entity`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Initiator {
    /// An administrator.
    Admin,
    /// The account holder.
    User,
    /// A policy of the realm or the authority plane.
    Policy,
    /// The system itself.
    System,
}

impl Initiator {
    /// The CAEP value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
            Self::Policy => "policy",
            Self::System => "system",
        }
    }
}

/// A credential's CAEP `credential_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialType {
    /// A password.
    Password,
    /// A TOTP authenticator app.
    App,
    /// A passkey; CAEP has no synced-passkey value, a passkey is reported as roaming.
    Fido2,
    /// An asymmetric signing key, as the realm's JOSE key (CR-27).
    Key,
}

impl CredentialType {
    /// The CAEP value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::App => "app",
            Self::Fido2 => "fido2-roaming",
            Self::Key => "x509",
        }
    }
}

/// A credential change's CAEP `change_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeType {
    /// Added.
    Create,
    /// Revoked.
    Revoke,
    /// Replaced.
    Update,
}

impl ChangeType {
    /// The CAEP value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Revoke => "revoke",
            Self::Update => "update",
        }
    }
}

/// A CAEP risk level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// `LOW`.
    Low,
    /// `MEDIUM`.
    Medium,
    /// `HIGH`.
    High,
}

impl RiskLevel {
    /// The CAEP value.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }

    /// The level of a CAEP value.
    #[must_use]
    pub fn from_name(s: &str) -> Option<Self> {
        [Self::Low, Self::Medium, Self::High]
            .into_iter()
            .find(|l| l.name().eq_ignore_ascii_case(s))
    }
}

/// A queued signal.
#[derive(Clone, Debug, PartialEq)]
pub struct Signal {
    /// What happened.
    pub kind: SignalKind,
    /// 32 random bytes, the dedup key; never derived from the subject (TI-RT10).
    pub id: [u8; 32],
    /// The identity subject; `None` for a realm-wide signal (CR-27).
    pub subject: Option<[u8; 16]>,
    /// When it happened, Unix ms.
    pub at: u64,
    /// The event members beside `event_timestamp`, as the standard names them.
    pub detail: Map<String, Value>,
}

/// An outbox entry that is not a [`Signal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed signal")]
pub struct Malformed;

fn decode<const N: usize>(v: Option<&Value>) -> Option<[u8; N]> {
    let raw = access_kernel::json::b64url_decode(v?.as_str()?).ok()?;
    <[u8; N]>::try_from(raw.as_slice()).ok()
}

impl Signal {
    fn new(kind: SignalKind, id: [u8; 32], subject: Option<[u8; 16]>, at: u64) -> Self {
        Self {
            kind,
            id,
            subject,
            at,
            detail: Map::new(),
        }
    }

    fn with(mut self, k: &str, v: impl Into<Value>) -> Self {
        self.detail.insert(String::from(k), v.into());
        self
    }

    /// `session-revoked` (MD-7).
    #[must_use]
    pub fn session_revoked(id: [u8; 32], subject: [u8; 16], by: Initiator, at: u64) -> Self {
        Self::new(SignalKind::SessionRevoked, id, Some(subject), at)
            .with("initiating_entity", by.name())
    }

    /// `credential-change`.
    #[must_use]
    pub fn credential_change(
        id: [u8; 32],
        subject: [u8; 16],
        credential: CredentialType,
        change: ChangeType,
        at: u64,
    ) -> Self {
        Self::new(SignalKind::CredentialChange, id, Some(subject), at)
            .with("credential_type", credential.name())
            .with("change_type", change.name())
    }

    /// `assurance-level-change` in the NIST AAL namespace: a step-up reached `current`.
    #[must_use]
    pub fn assurance_level(
        id: [u8; 32],
        subject: [u8; 16],
        current: &str,
        previous: Option<&str>,
        at: u64,
    ) -> Self {
        let mut s = Self::new(SignalKind::AssuranceLevelChange, id, Some(subject), at)
            .with("namespace", "NIST-AAL")
            .with("current_level", current);
        if let Some(p) = previous {
            let direction = if p < current { "increase" } else { "decrease" };
            s = s
                .with("previous_level", p)
                .with("change_direction", direction);
        }
        s
    }

    /// `token-claims-change`: the names of the claims that changed, never their values.
    #[must_use]
    pub fn token_claims_change(id: [u8; 32], subject: [u8; 16], claims: &[&str], at: u64) -> Self {
        let mut names = Map::new();
        for c in claims {
            names.insert(String::from(*c), Value::Null);
        }
        Self::new(SignalKind::TokenClaimsChange, id, Some(subject), at)
            .with("claims", Value::Object(names))
    }

    /// `device-compliance-change`.
    #[must_use]
    pub fn device_compliance(id: [u8; 32], subject: [u8; 16], compliant: bool, at: u64) -> Self {
        let (previous, current) = if compliant {
            ("not-compliant", "compliant")
        } else {
            ("compliant", "not-compliant")
        };
        Self::new(SignalKind::DeviceComplianceChange, id, Some(subject), at)
            .with("previous_status", previous)
            .with("current_status", current)
    }

    /// `risk-level-change` of the account (§12.2.4: risk only narrows).
    #[must_use]
    pub fn risk_level(
        id: [u8; 32],
        subject: [u8; 16],
        current: RiskLevel,
        previous: Option<RiskLevel>,
        at: u64,
    ) -> Self {
        let mut s = Self::new(SignalKind::RiskLevelChange, id, Some(subject), at)
            .with("principal", "USER")
            .with("current_level", current.name());
        if let Some(p) = previous {
            s = s.with("previous_level", p.name());
        }
        s
    }

    /// `session-established`.
    #[must_use]
    pub fn session_established(id: [u8; 32], subject: [u8; 16], at: u64) -> Self {
        Self::new(SignalKind::SessionEstablished, id, Some(subject), at)
    }

    /// `session-presented`.
    #[must_use]
    pub fn session_presented(id: [u8; 32], subject: [u8; 16], at: u64) -> Self {
        Self::new(SignalKind::SessionPresented, id, Some(subject), at)
    }

    /// `account-disabled`.
    #[must_use]
    pub fn account_disabled(id: [u8; 32], subject: [u8; 16], at: u64) -> Self {
        Self::new(SignalKind::AccountDisabled, id, Some(subject), at)
    }

    /// `account-purged`.
    #[must_use]
    pub fn account_purged(id: [u8; 32], subject: [u8; 16], at: u64) -> Self {
        Self::new(SignalKind::AccountPurged, id, Some(subject), at)
    }

    /// `identifier-recycled`, about the identifier's previous holder: the receiver learns it
    /// through the `sub` it already has, never the identifier itself.
    #[must_use]
    pub fn identifier_recycled(id: [u8; 32], previous: [u8; 16], at: u64) -> Self {
        Self::new(SignalKind::IdentifierRecycled, id, Some(previous), at)
    }

    /// `credential-compromise`; `subject` `None` is the realm's own key (CR-27).
    #[must_use]
    pub fn credential_compromise(
        id: [u8; 32],
        subject: Option<[u8; 16]>,
        credential: CredentialType,
        at: u64,
    ) -> Self {
        Self::new(SignalKind::CredentialCompromise, id, subject, at)
            .with("credential_type", credential.name())
    }

    /// The outbox bytes: `{"id", "subject"?, "at", "detail"}` as JSON.
    ///
    /// # Errors
    /// [`Malformed`] when encoding fails.
    pub fn to_outbox(&self) -> Result<Vec<u8>, Malformed> {
        let mut m = Map::new();
        m.insert("id".into(), b64url_encode(&self.id).into());
        if let Some(s) = &self.subject {
            m.insert("subject".into(), b64url_encode(s).into());
        }
        m.insert("at".into(), self.at.into());
        m.insert("detail".into(), Value::Object(self.detail.clone()));
        serde_json::to_vec(&Value::Object(m)).map_err(|_| Malformed)
    }

    /// Reads an outbox entry of `kind`.
    ///
    /// # Errors
    /// [`Malformed`].
    pub fn from_outbox(kind: &str, bytes: &[u8]) -> Result<Self, Malformed> {
        let kind = SignalKind::from_outbox(kind).ok_or(Malformed)?;
        let v: Value = serde_json::from_slice(bytes).map_err(|_| Malformed)?;
        let id = decode::<32>(v.get("id")).ok_or(Malformed)?;
        let subject = match v.get("subject") {
            None => None,
            Some(s) => Some(decode::<16>(Some(s)).ok_or(Malformed)?),
        };
        let at = v.get("at").and_then(Value::as_u64).ok_or(Malformed)?;
        let detail = match v.get("detail") {
            Some(Value::Object(d)) => d.clone(),
            _ => return Err(Malformed),
        };
        Ok(Self {
            kind,
            id,
            subject,
            at,
            detail,
        })
    }

    /// The CAEP/RISC event body: the detail with `event_timestamp` in seconds.
    #[must_use]
    pub fn event_body(&self) -> Value {
        let mut m = self.detail.clone();
        m.insert("event_timestamp".into(), (self.at / 1000).into());
        Value::Object(m)
    }
}

/// `{"credential_type"}` of a compromise of the realm's signing key (CR-27).
#[must_use]
pub fn realm_key_compromise(id: [u8; 32], at: u64) -> Signal {
    Signal::credential_compromise(id, None, CredentialType::Key, at)
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-41, TN-43
    #[test]
    fn eight_caep_and_four_risc_kinds() {
        let caep = SignalKind::ALL
            .iter()
            .filter(|k| k.family() == Family::Caep)
            .count();
        assert_eq!((caep, SignalKind::ALL.len() - caep), (8, 4));
        for k in SignalKind::ALL {
            assert_eq!(SignalKind::from_name(k.name()), Some(k));
        }
    }

    // TI-RT10, OP-73
    #[test]
    fn signals_round_trip_through_the_outbox() {
        let s = Signal::credential_change(
            [7; 32],
            [1; 16],
            CredentialType::Password,
            ChangeType::Update,
            5_000,
        );
        let back = Signal::from_outbox(&s.kind.outbox_kind(), &s.to_outbox().unwrap()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.event_body()["event_timestamp"], 5);
        let realm = realm_key_compromise([8; 32], 1);
        let back = Signal::from_outbox("signal.credential_compromise", &realm.to_outbox().unwrap())
            .unwrap();
        assert_eq!(back.subject, None);
        assert!(Signal::from_outbox("signal.other", b"{}").is_err());
    }

    // §12.2.4
    #[test]
    fn assurance_levels_name_the_direction() {
        let s = Signal::assurance_level([0; 32], [0; 16], "aal2", Some("aal1"), 0);
        assert_eq!(s.detail["change_direction"], "increase");
        assert_eq!(RiskLevel::from_name("high"), Some(RiskLevel::High));
    }
}
