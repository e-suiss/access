//! The Relay message contract, version 1 (E42 m.1, OP-146 m.4 (b)): what Access asks Relay to
//! deliver to a person. Access owns the content and "to whom, why"; channel, timing, retry and
//! fallback are Relay's (§7.9.8).
//!
//! Redaction rules (OP-64):
//! - a recipient address is personal data and prints as `[redacted]`;
//! - the one-time code and the magic link are the only secrets a message carries; they are
//!   [`Secret`]s and have no `Debug` of their own;
//! - nothing else is carried: no password, no token, no IP address, no device fingerprint.

use core::convert::Infallible;
use core::fmt;

use access_crypto::Secret;
use serde_json::{Map, Value, json};

use crate::domain::status::AccountStatus;

/// Prefix of every outbox kind and `CloudEvents` `type` of the contract.
pub const KIND_PREFIX: &str = "relay.message.";

/// Contract version, the last segment of every kind.
pub const VERSION: &str = "v1";

/// A message the contract cannot carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid relay message: {0}")]
pub struct Invalid(pub &'static str);

/// Where Relay delivers. Relay picks the channel for it (E42 m.1).
#[derive(Clone, PartialEq, Eq)]
pub enum Address {
    /// An e-mail address, at most 320 characters.
    Email(String),
    /// An E.164 phone number.
    Phone(String),
    /// An approver device, by the RFC 7638 thumbprint of its device key in base64url; Relay
    /// reaches it through the push registration the approver made (OP-156 m.3 (d)).
    Device(String),
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Email(_) => f.write_str("Email([redacted])"),
            Self::Phone(_) => f.write_str("Phone([redacted])"),
            Self::Device(_) => f.write_str("Device([redacted])"),
        }
    }
}

impl Address {
    fn validate(&self) -> Result<(), Invalid> {
        match self {
            Self::Email(a) => {
                let ok = (3..=320).contains(&a.chars().count())
                    && a.split_once('@')
                        .is_some_and(|(l, d)| !l.is_empty() && !d.is_empty() && !d.contains('@'))
                    && !a.chars().any(|c| c.is_control() || c.is_whitespace());
                if ok {
                    Ok(())
                } else {
                    Err(Invalid("email address"))
                }
            }
            Self::Phone(p) => {
                let digits = p.strip_prefix('+').unwrap_or("");
                let ok = (7..=15).contains(&digits.len())
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && !digits.starts_with('0');
                if ok {
                    Ok(())
                } else {
                    Err(Invalid("phone number"))
                }
            }
            Self::Device(d) => {
                if d.len() == 43
                    && d.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    Ok(())
                } else {
                    Err(Invalid("device"))
                }
            }
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Self::Email(a) => json!({ "email": a }),
            Self::Phone(p) => json!({ "phone": p }),
            Self::Device(d) => json!({ "device": d }),
        }
    }

    fn from_json(v: &Value) -> Result<Self, Invalid> {
        let a = match (v.get("email"), v.get("phone"), v.get("device")) {
            (Some(Value::String(e)), None, None) => Self::Email(e.clone()),
            (None, Some(Value::String(p)), None) => Self::Phone(p.clone()),
            (None, None, Some(Value::String(d))) => Self::Device(d.clone()),
            _ => return Err(Invalid("recipient")),
        };
        a.validate()?;
        Ok(a)
    }
}

/// Why a one-time code was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpPurpose {
    /// Sign-in factor.
    SignIn,
    /// Proving control of an address.
    VerifyAddress,
    /// Account recovery.
    Recovery,
    /// A new account's sign-up code (OP-153 m.3 (g)).
    SignUp,
}

impl OtpPurpose {
    const ALL: [Self; 4] = [
        Self::SignIn,
        Self::VerifyAddress,
        Self::Recovery,
        Self::SignUp,
    ];

    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::VerifyAddress => "verify_address",
            Self::Recovery => "recovery",
            Self::SignUp => "sign_up",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == s)
    }
}

/// How a new sign-in authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInMethod {
    /// Password.
    Password,
    /// Passkey or security key.
    Passkey,
    /// One-time code.
    Otp,
    /// Magic link.
    MagicLink,
    /// Federated identity provider.
    Federated,
}

impl SignInMethod {
    const ALL: [Self; 5] = [
        Self::Password,
        Self::Passkey,
        Self::Otp,
        Self::MagicLink,
        Self::Federated,
    ];

    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Passkey => "passkey",
            Self::Otp => "otp",
            Self::MagicLink => "magic_link",
            Self::Federated => "federated",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == s)
    }
}

/// A notice about the account, sent to its registered address (§8.15.2, OP-153 m.2 N0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// A recovery was started (OP-153 m.3 (d)).
    RecoveryRequested,
    /// A recovery waits out its cooling period; `until` is when it can finish (OP-153 m.3 (e)).
    RecoveryCooling,
    /// A recovery finished.
    RecoveryCompleted,
    /// New recovery codes were made; the old ones no longer work.
    RecoveryCodesRegenerated,
    /// A second step was turned on.
    SecondFactorEnabled,
    /// A new sign-in method was added.
    NewMethod,
    /// The e-mail address was changed; sent to the old address (OP-153 m.3 (i)).
    EmailChanged,
    /// The account is scheduled for deletion; `until` is the date (OP-153 m.3 (bb)).
    DeletionScheduled,
    /// The account is deleted; `until` is how long some records are kept (OP-153 m.3 (bb)).
    DeletionCompleted,
    /// The account will be turned off for inactivity; `until` is when (OP-153 m.3 (dd)).
    InactivityNotice,
    /// N1: someone asked to create an account with this address, which already has one; sent to
    /// the account's own address instead of saying so on the page (§10.2.1 m.6, CR-40, TN-80).
    SignUpExisting,
    /// N3: an ownership transfer of an organization the person owns or receives was proposed;
    /// `until` is the earliest it can complete (TN-91).
    OwnershipHandover,
    /// N3: the person joined an organization by its domain rule, and what the membership gives
    /// that is reserved or CT3 waits until `until` (TN-109, SI-21).
    MembershipCooling,
    /// N3: a ward asked for the guardian's consent; it lapses at `until`, and silence is not
    /// consent (E53, E47).
    GuardianConsent,
}

impl Notice {
    /// Every notice.
    pub const ALL: [Self; 14] = [
        Self::RecoveryRequested,
        Self::RecoveryCooling,
        Self::RecoveryCompleted,
        Self::RecoveryCodesRegenerated,
        Self::SecondFactorEnabled,
        Self::NewMethod,
        Self::EmailChanged,
        Self::DeletionScheduled,
        Self::DeletionCompleted,
        Self::InactivityNotice,
        Self::SignUpExisting,
        Self::OwnershipHandover,
        Self::MembershipCooling,
        Self::GuardianConsent,
    ];

    /// Its outbox kind and `CloudEvents` `type`.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::RecoveryRequested => "relay.message.recovery_requested.v1",
            Self::RecoveryCooling => "relay.message.recovery_cooling.v1",
            Self::RecoveryCompleted => "relay.message.recovery_completed.v1",
            Self::RecoveryCodesRegenerated => "relay.message.recovery_codes_regenerated.v1",
            Self::SecondFactorEnabled => "relay.message.second_factor_enabled.v1",
            Self::NewMethod => "relay.message.new_method.v1",
            Self::EmailChanged => "relay.message.email_changed.v1",
            Self::DeletionScheduled => "relay.message.deletion_scheduled.v1",
            Self::DeletionCompleted => "relay.message.deletion_completed.v1",
            Self::InactivityNotice => "relay.message.inactivity_notice.v1",
            Self::SignUpExisting => "relay.message.signup_existing.v1",
            Self::OwnershipHandover => "relay.message.ownership_handover.v1",
            Self::MembershipCooling => "relay.message.membership_cooling.v1",
            Self::GuardianConsent => "relay.message.guardian_consent.v1",
        }
    }

    /// Whether the notice carries `until`, and must.
    #[must_use]
    pub const fn has_until(self) -> bool {
        matches!(
            self,
            Self::RecoveryCooling
                | Self::DeletionScheduled
                | Self::DeletionCompleted
                | Self::InactivityNotice
                | Self::OwnershipHandover
                | Self::MembershipCooling
                | Self::GuardianConsent
        )
    }

    fn of_kind(kind: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.kind() == kind)
    }
}

/// What a link a person opens is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkPurpose {
    /// A support agent's reset-intent token, sent to another registered address (TN-61).
    ResetIntent,
    /// The person's data export download (TN-79, OP-153 m.3 (cc)).
    ExportReady,
}

impl LinkPurpose {
    const ALL: [Self; 2] = [Self::ResetIntent, Self::ExportReady];

    /// Its outbox kind and `CloudEvents` `type`.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::ResetIntent => "relay.message.reset_intent.v1",
            Self::ExportReady => "relay.message.export_ready.v1",
        }
    }

    fn of_kind(kind: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.kind() == kind)
    }
}

/// A notice about an agent the person sponsors or operates (OP-154 m.2 L0, m.3 (e)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentNotice {
    /// The agent was suspended: its last sponsor left, or an administrator suspended it.
    Suspended,
    /// The agent has no active human sponsor and waits for one (AG-41).
    SponsorNeeded,
}

impl AgentNotice {
    const ALL: [Self; 2] = [Self::Suspended, Self::SponsorNeeded];

    /// Its outbox kind and `CloudEvents` `type`.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Suspended => "relay.message.agent_suspended.v1",
            Self::SponsorNeeded => "relay.message.agent_sponsor_needed.v1",
        }
    }

    fn of_kind(kind: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.kind() == kind)
    }
}

/// A prompt that asks the person to act on a trusted surface through a link (OP-154 m.2 L0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prompt {
    /// An agent's connected account must be connected again; nothing falls back
    /// (OP-154 m.3 (t)). The name is the connection's.
    AgentConnectionNeedsReconnect,
    /// A device asks for approval of its device code (RFC 8628, OP-154 m.3 (p)). The name is the
    /// client's.
    DeviceCodeApproval,
    /// An approval waits on the person's Approval Surface; a CIBA request uses
    /// [`Body::CibaInvite`] instead (OP-154 m.3 (ff), OP-155 m.3 (l), E42). The name is the
    /// requester's.
    ApprovalRequested,
    /// An organization's one-use SSO setup link, valid 72 hours (OP-155 m.3 (i)). The name is
    /// the organization's.
    SsoSetupLink,
}

impl Prompt {
    /// Every prompt.
    pub const ALL: [Self; 4] = [
        Self::AgentConnectionNeedsReconnect,
        Self::DeviceCodeApproval,
        Self::ApprovalRequested,
        Self::SsoSetupLink,
    ];

    /// Its outbox kind and `CloudEvents` `type`.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::AgentConnectionNeedsReconnect => {
                "relay.message.agent_connection_needs_reconnect.v1"
            }
            Self::DeviceCodeApproval => "relay.message.device_code_approval.v1",
            Self::ApprovalRequested => "relay.message.approval_requested.v1",
            Self::SsoSetupLink => "relay.message.sso_setup_link.v1",
        }
    }

    /// The member its name travels in.
    #[must_use]
    pub const fn name_member(self) -> &'static str {
        match self {
            Self::AgentConnectionNeedsReconnect => "connection",
            Self::DeviceCodeApproval => "client",
            Self::ApprovalRequested => "requester",
            Self::SsoSetupLink => "organization",
        }
    }

    fn of_kind(kind: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|n| n.kind() == kind)
    }
}

/// What happened to a directory app password (OP-155 m.3 (n)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppPasswordChange {
    /// One was created for an application.
    Created,
    /// One was revoked.
    Revoked,
    /// One was replaced over LDAP (RFC 3062).
    Changed,
}

impl AppPasswordChange {
    const ALL: [Self; 3] = [Self::Created, Self::Revoked, Self::Changed];

    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Revoked => "revoked",
            Self::Changed => "changed",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == s)
    }
}

/// Why a semantic notice is sent (OP-156 m.3 (c)); authority never waits on its delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoticeReason {
    /// A step-up is needed to go on.
    StepUp,
    /// An approver's answer is needed.
    ApproverNeeded,
    /// A security intervention concerns the person.
    SecurityIntervention,
    /// Authority the person held or relied on was revoked.
    AuthorityRevoked,
    /// Authority the person held or relied on was narrowed.
    AuthorityNarrowed,
}

impl NoticeReason {
    const ALL: [Self; 5] = [
        Self::StepUp,
        Self::ApproverNeeded,
        Self::SecurityIntervention,
        Self::AuthorityRevoked,
        Self::AuthorityNarrowed,
    ];

    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StepUp => "step_up",
            Self::ApproverNeeded => "approver_needed",
            Self::SecurityIntervention => "security_intervention",
            Self::AuthorityRevoked => "authority_revoked",
            Self::AuthorityNarrowed => "authority_narrowed",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == s)
    }
}

/// A security-relevant authority event sent at once (OP-156 m.3 (c)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityEvent {
    /// A new sub-delegation in the person's name.
    SubDelegation,
    /// A new domain accepted the person's authority.
    DomainAcceptance,
    /// One of the person's Instances was ended.
    InstanceEnded,
}

impl SecurityEvent {
    const ALL: [Self; 3] = [
        Self::SubDelegation,
        Self::DomainAcceptance,
        Self::InstanceEnded,
    ];

    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SubDelegation => "sub_delegation",
            Self::DomainAcceptance => "domain_acceptance",
            Self::InstanceEnded => "instance_ended",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == s)
    }
}

/// Length of an SMS one-time code, in digits (OP-156 m.3 (f)).
pub const SMS_CODE_DIGITS: usize = 6;

/// Longest CIBA `binding_message`, in characters (OP-155 m.3 (l)).
pub const BINDING_MESSAGE_MAX: usize = 32;

/// What a support access notice says (OP-157 m.3 (f), SI-21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupportEvent {
    /// The person gave support access.
    Granted,
    /// The operator started acting with it.
    Started,
    /// It ended at its time or with its case.
    Ended,
    /// The person revoked it.
    Revoked,
}

impl SupportEvent {
    /// Every event.
    pub const ALL: [Self; 4] = [Self::Granted, Self::Started, Self::Ended, Self::Revoked];

    /// Its name on the wire.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Started => "started",
            Self::Ended => "ended",
            Self::Revoked => "revoked",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.name() == s)
    }
}

/// What a break-glass alarm reports to the on-call Parties (OP-157 m.3 (h)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakglassAlarm {
    /// A break-glass account signed in.
    Signin,
    /// A break-glass Grant was used.
    Used,
    /// A use was not reviewed within the review window.
    ReviewOverdue,
    /// No drill ran within the drill window.
    DrillOverdue,
    /// A break-glass Grant holder left; the Grant must be rotated.
    RotationRequired,
}

impl BreakglassAlarm {
    /// Every alarm.
    pub const ALL: [Self; 5] = [
        Self::Signin,
        Self::Used,
        Self::ReviewOverdue,
        Self::DrillOverdue,
        Self::RotationRequired,
    ];

    /// Its name on the wire.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Signin => "signin",
            Self::Used => "used",
            Self::ReviewOverdue => "review_overdue",
            Self::DrillOverdue => "drill_overdue",
            Self::RotationRequired => "rotation_required",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.name() == s)
    }
}

/// Longest canonical render an in-notification approval carries, base64url (OP-157 m.3 (m)).
pub const INLINE_RENDER_MAX: usize = 16 * 1024;

/// What the message says.
pub enum Body {
    /// A one-time code (`relay.message.otp.v1`).
    Otp {
        /// The code: 4–12 ASCII letters or digits.
        code: Secret<String>,
        /// Why.
        purpose: OtpPurpose,
        /// Unix ms after which it is worthless; Relay is not asked to send it later.
        expires_at_ms: u64,
    },
    /// A sign-in link (`relay.message.magic_link.v1`).
    MagicLink {
        /// The `https` link, at most 2048 bytes.
        link: Secret<String>,
        /// Unix ms after which it is worthless.
        expires_at_ms: u64,
    },
    /// The password was set or reset (`relay.message.password_changed.v1`).
    PasswordChanged {
        /// When, Unix ms.
        at_ms: u64,
    },
    /// A new sign-in (`relay.message.new_sign_in.v1`, SEC18).
    NewSignIn {
        /// When, Unix ms.
        at_ms: u64,
        /// How.
        method: SignInMethod,
    },
    /// The account's status changed (`relay.message.account_status.v1`, TN-49).
    AccountStatus {
        /// The new status.
        status: AccountStatus,
        /// When, Unix ms.
        at_ms: u64,
    },
    /// A notice about the account (each [`Notice`] its own kind).
    Notice {
        /// Which.
        notice: Notice,
        /// When, Unix ms.
        at_ms: u64,
        /// The date the notice names, Unix ms, exactly when [`Notice::has_until`].
        until_ms: Option<u64>,
    },
    /// A link the person opens (each [`LinkPurpose`] its own kind).
    Link {
        /// What for.
        purpose: LinkPurpose,
        /// The `https` link, at most 2048 bytes.
        link: Secret<String>,
        /// Unix ms after which it is worthless.
        expires_at_ms: u64,
    },
    /// An organization's invitation (`relay.message.invitation.v1`, OP-153 m.3 (o)). The names
    /// are attacker input: Relay renders them as text, never as a link.
    Invitation {
        /// The `https` accept link, at most 2048 bytes.
        link: Secret<String>,
        /// The organization's name, at most 200 characters.
        organization: String,
        /// The inviter's display name, at most 200 characters.
        inviter: String,
        /// Unix ms after which it is worthless.
        expires_at_ms: u64,
    },
    /// A notice about an agent (each [`AgentNotice`] its own kind). The name is attacker input:
    /// Relay renders it as text.
    Agent {
        /// Which.
        notice: AgentNotice,
        /// The agent's display name, at most 200 characters.
        agent: String,
        /// When, Unix ms.
        at_ms: u64,
    },
    /// A prompt to act through a link (each [`Prompt`] its own kind). The name is attacker
    /// input: Relay renders it as text, never as a link.
    Prompt {
        /// Which.
        prompt: Prompt,
        /// The `https` link, at most 2048 bytes.
        link: Secret<String>,
        /// The connection's, client's or requester's name, at most 200 characters.
        name: String,
        /// Unix ms after which it is worthless.
        expires_at_ms: u64,
    },
    /// A CIBA request waits for the person on the Approval Surface
    /// (`relay.message.ciba_invite.v1`, OP-155 m.3 (l)). It names the client and the binding
    /// message, never the intent. Both are attacker input: Relay renders them as text.
    CibaInvite {
        /// The `https` link to the Approval Surface, at most 2048 bytes.
        link: Secret<String>,
        /// The client's name, at most 200 characters.
        client: String,
        /// The client's binding message, at most 32 characters.
        binding_message: Option<String>,
        /// Unix ms after which it is worthless: the request's `expires_in`.
        expires_at_ms: u64,
    },
    /// An upstream identity provider answered with another subject for the person's link; no
    /// re-link happened (`relay.message.upstream_subject_conflict.v1`, OP-155 m.3 (h)). The
    /// name is the upstream's, attacker input rendered as text.
    UpstreamSubjectConflict {
        /// The upstream's display name, at most 200 characters.
        upstream: String,
        /// When, Unix ms.
        at_ms: u64,
    },
    /// A directory app password was created or revoked
    /// (`relay.message.ldap_credential_changed.v1`, OP-155 m.3 (n)). The application's name is
    /// attacker input rendered as text; the password is never carried.
    LdapCredentialChanged {
        /// What happened.
        change: AppPasswordChange,
        /// The application's name, at most 200 characters.
        application: String,
        /// When, Unix ms.
        at_ms: u64,
    },
    /// A push verification to an approver device (`relay.message.push_approval.v1`, OP-156
    /// m.3 (d)). It never carries the number to match. The names are attacker input rendered
    /// as text.
    PushApproval {
        /// The challenge id the approver answers, base64url.
        challenge: Secret<String>,
        /// The application or client's name, at most 200 characters.
        application: String,
        /// What is being approved, at most 200 characters.
        action: String,
        /// The coarse location from `GeoLookup`, at most 200 characters; absent when unknown.
        location: Option<String>,
        /// Unix ms after which it is worthless: 120 s after it was made.
        expires_at_ms: u64,
    },
    /// Something needs the person's attention (`relay.message.semantic_notice.v1`, OP-156 m.3
    /// (c)): to whom, why, which intent, until when.
    SemanticNotice {
        /// Why.
        reason: NoticeReason,
        /// The intent digest it concerns, 64 lower-case hex digits.
        intent: String,
        /// The `https` link where the person acts, at most 2048 bytes.
        link: Secret<String>,
        /// Unix ms until which it matters; absent when it does not lapse.
        until_ms: Option<u64>,
    },
    /// A security-relevant authority event, sent at once (`relay.message.security_authority_notice.v1`,
    /// OP-156 m.3 (c)): "If you didn't expect this: Revoke / Review". The name is attacker input
    /// rendered as text.
    SecurityAuthorityNotice {
        /// What happened.
        event: SecurityEvent,
        /// The other Party's or the domain's name, at most 200 characters.
        name: String,
        /// The `https` Review link, at most 2048 bytes.
        review_link: Secret<String>,
        /// The `https` Revoke link, at most 2048 bytes; absent when nothing is left to revoke.
        revoke_link: Option<Secret<String>>,
        /// When, Unix ms.
        at_ms: u64,
    },
    /// A one-use passkey setup invitation on an HR start date (`relay.message.passkey_setup_invite.v1`,
    /// OP-156 m.3 (q)), valid 7 days. The name is attacker input rendered as text.
    PasskeySetupInvite {
        /// The `https` link, at most 2048 bytes.
        link: Secret<String>,
        /// The organization's name, at most 200 characters.
        organization: String,
        /// Unix ms after which it is worthless.
        expires_at_ms: u64,
    },
    /// A personal agent interrupts the person at the critical level (`relay.message.critical_interrupt.v1`,
    /// E48, Ek B 4494). Relay checks the Grant live at delivery. The names are attacker input
    /// rendered as text.
    CriticalInterrupt {
        /// The agent's display name, at most 200 characters.
        agent: String,
        /// The Grant that allows it, 32 lower-case hex digits.
        grant: String,
        /// What the agent says, at most 200 characters.
        summary: String,
        /// When, Unix ms.
        at_ms: u64,
    },
    /// A restricted SMS one-time code (`relay.message.sms_otp.v1`, OP-156 m.3 (f)): 6 digits,
    /// 5 minutes, to a phone number only.
    SmsOtp {
        /// The code: exactly 6 ASCII digits.
        code: Secret<String>,
        /// Why.
        purpose: OtpPurpose,
        /// Unix ms after which it is worthless.
        expires_at_ms: u64,
    },
    /// Stage 11 Q9: one İYS consent record for Relay to register (`relay.message.iys_consent.v1`,
    /// IDP-37 (4), B23, OP-156 m.3 (c)). It is never delivered to the person; the recipient is
    /// the address the consent is about: the e-mail for `email`, the phone for `sms` and `call`.
    IysConsent {
        /// The commercial message channel.
        channel: IysChannel,
        /// `individual` or `merchant`.
        recipient_type: IysRecipient,
        /// Approved or rejected.
        approved: bool,
        /// How it was given: `self_service`, `admin`, `import` or `app`.
        source: String,
        /// When it was given, Unix ms.
        consent_at_ms: u64,
    },
    /// A support operator asks for support access (`relay.message.support_access_request.v1`,
    /// OP-157 m.3 (f)). It is an invitation only: the link opens the person's own grant page,
    /// which the operator cannot open. The names are attacker input rendered as text.
    SupportAccessRequest {
        /// The support organization's name, at most 200 characters.
        organization: String,
        /// The case as the case system shows it, at most 200 characters.
        case: String,
        /// What the access would allow, at most 200 characters.
        scope: String,
        /// For how many minutes, 1 to 1440.
        minutes: u32,
        /// The `https` link to the person's own grant page, at most 2048 bytes.
        link: Secret<String>,
        /// Unix ms after which it is worthless.
        expires_at_ms: u64,
    },
    /// Support access was given, started, ended or revoked (`relay.message.support_access_notice.v1`,
    /// OP-157 m.3 (f), SI-21). The names are attacker input rendered as text.
    SupportAccessNotice {
        /// What happened.
        event: SupportEvent,
        /// The operator's display name, at most 200 characters.
        operator: String,
        /// The support organization's name, at most 200 characters.
        organization: String,
        /// The case, at most 200 characters.
        case: String,
        /// When, Unix ms.
        at_ms: u64,
        /// Unix ms when it ends; absent once it has ended.
        until_ms: Option<u64>,
    },
    /// Emergency access was used on the person's account (`relay.message.breakglass_used.v1`,
    /// OP-157 m.3 (h)), written in the same outbox transaction as the Exercise. The names are
    /// attacker input rendered as text.
    BreakglassUsed {
        /// The acting organization's name, at most 200 characters.
        organization: String,
        /// The incident reference, at most 200 characters.
        incident: String,
        /// How many approvals the use carried.
        approvals: u32,
        /// When, Unix ms.
        at_ms: u64,
        /// Unix ms when the emergency access ends.
        until_ms: u64,
    },
    /// A critical break-glass alarm to an on-call Party (`relay.message.breakglass_alarm.v1`,
    /// OP-157 m.3 (h)). The name is attacker input rendered as text.
    BreakglassAlarm {
        /// What happened.
        alarm: BreakglassAlarm,
        /// The account's or Grant holder's display name, at most 200 characters.
        account: String,
        /// The `https` console link, at most 2048 bytes.
        link: Secret<String>,
        /// When, Unix ms.
        at_ms: u64,
    },
    /// A CT1 approval inside the approver notification (`relay.message.approval_inline.v1`,
    /// OP-157 m.3 (m)), to a registered approver device only: the whole canonical render, which
    /// the approver SDK rebuilds with the Kernel before it signs H(AAS).
    ApprovalInline {
        /// The intent digest, 64 lower-case hex digits.
        intent: String,
        /// The canonical render, base64url of its dCBOR, at most [`INLINE_RENDER_MAX`] bytes.
        render: String,
        /// The render digest, 64 lower-case hex digits.
        render_digest: String,
        /// Unix ms after which it is worthless.
        expires_at_ms: u64,
    },
    /// An access review campaign is open for a manager (`relay.message.review_campaign.v1`,
    /// OP-157 m.3 (w)): a link to the view, never a queue. The name is attacker input rendered
    /// as text.
    ReviewCampaign {
        /// The campaign's name, at most 200 characters.
        campaign: String,
        /// How many Grants it shows.
        items: u32,
        /// The `https` link, at most 2048 bytes.
        link: Secret<String>,
        /// Unix ms when the campaign's period ends.
        due_ms: u64,
    },
}

/// An İYS message channel (IDP-37 (4)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IysChannel {
    /// SMS.
    Sms,
    /// E-mail.
    Email,
    /// Voice call.
    Call,
}

impl IysChannel {
    /// Its wire name, as preferences name the channel.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sms => "sms",
            Self::Email => "email",
            Self::Call => "call",
        }
    }

    /// The channel of a preference channel; `push` is no İYS channel.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sms" => Some(Self::Sms),
            "email" => Some(Self::Email),
            "call" => Some(Self::Call),
            _ => None,
        }
    }
}

/// An İYS recipient type (IDP-37 (4)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IysRecipient {
    /// A person (bireysel).
    Individual,
    /// A merchant (tacir).
    Merchant,
}

impl IysRecipient {
    /// Its wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::Merchant => "merchant",
        }
    }

    /// The type of a wire name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "individual" => Some(Self::Individual),
            "merchant" => Some(Self::Merchant),
            _ => None,
        }
    }
}

impl fmt::Debug for Body {
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per body, each its redactions"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Otp {
                purpose,
                expires_at_ms,
                ..
            } => f
                .debug_struct("Otp")
                .field("code", &"[redacted]")
                .field("purpose", purpose)
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::MagicLink { expires_at_ms, .. } => f
                .debug_struct("MagicLink")
                .field("link", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::PasswordChanged { at_ms } => f
                .debug_struct("PasswordChanged")
                .field("at_ms", at_ms)
                .finish(),
            Self::NewSignIn { at_ms, method } => f
                .debug_struct("NewSignIn")
                .field("at_ms", at_ms)
                .field("method", method)
                .finish(),
            Self::AccountStatus { status, at_ms } => f
                .debug_struct("AccountStatus")
                .field("status", status)
                .field("at_ms", at_ms)
                .finish(),
            Self::Notice {
                notice,
                at_ms,
                until_ms,
            } => f
                .debug_struct("Notice")
                .field("notice", notice)
                .field("at_ms", at_ms)
                .field("until_ms", until_ms)
                .finish(),
            Self::Link {
                purpose,
                expires_at_ms,
                ..
            } => f
                .debug_struct("Link")
                .field("purpose", purpose)
                .field("link", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::Invitation { expires_at_ms, .. } => f
                .debug_struct("Invitation")
                .field("link", &"[redacted]")
                .field("organization", &"[redacted]")
                .field("inviter", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::Agent { notice, at_ms, .. } => f
                .debug_struct("Agent")
                .field("notice", notice)
                .field("agent", &"[redacted]")
                .field("at_ms", at_ms)
                .finish(),
            Self::Prompt {
                prompt,
                expires_at_ms,
                ..
            } => f
                .debug_struct("Prompt")
                .field("prompt", prompt)
                .field("link", &"[redacted]")
                .field("name", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::CibaInvite { expires_at_ms, .. } => f
                .debug_struct("CibaInvite")
                .field("link", &"[redacted]")
                .field("client", &"[redacted]")
                .field("binding_message", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::UpstreamSubjectConflict { at_ms, .. } => f
                .debug_struct("UpstreamSubjectConflict")
                .field("upstream", &"[redacted]")
                .field("at_ms", at_ms)
                .finish(),
            Self::LdapCredentialChanged { change, at_ms, .. } => f
                .debug_struct("LdapCredentialChanged")
                .field("change", change)
                .field("application", &"[redacted]")
                .field("at_ms", at_ms)
                .finish(),
            Self::PushApproval { expires_at_ms, .. } => f
                .debug_struct("PushApproval")
                .field("challenge", &"[redacted]")
                .field("application", &"[redacted]")
                .field("action", &"[redacted]")
                .field("location", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::SemanticNotice {
                reason, until_ms, ..
            } => f
                .debug_struct("SemanticNotice")
                .field("reason", reason)
                .field("intent", &"[redacted]")
                .field("link", &"[redacted]")
                .field("until_ms", until_ms)
                .finish(),
            Self::SecurityAuthorityNotice { event, at_ms, .. } => f
                .debug_struct("SecurityAuthorityNotice")
                .field("event", event)
                .field("name", &"[redacted]")
                .field("review_link", &"[redacted]")
                .field("revoke_link", &"[redacted]")
                .field("at_ms", at_ms)
                .finish(),
            Self::PasskeySetupInvite { expires_at_ms, .. } => f
                .debug_struct("PasskeySetupInvite")
                .field("link", &"[redacted]")
                .field("organization", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::CriticalInterrupt { at_ms, .. } => f
                .debug_struct("CriticalInterrupt")
                .field("agent", &"[redacted]")
                .field("grant", &"[redacted]")
                .field("summary", &"[redacted]")
                .field("at_ms", at_ms)
                .finish(),
            Self::SmsOtp {
                purpose,
                expires_at_ms,
                ..
            } => f
                .debug_struct("SmsOtp")
                .field("code", &"[redacted]")
                .field("purpose", purpose)
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::IysConsent {
                channel,
                recipient_type,
                approved,
                source,
                consent_at_ms,
            } => f
                .debug_struct("IysConsent")
                .field("channel", channel)
                .field("recipient_type", recipient_type)
                .field("approved", approved)
                .field("source", source)
                .field("consent_at_ms", consent_at_ms)
                .finish(),
            Self::SupportAccessRequest {
                minutes,
                expires_at_ms,
                ..
            } => f
                .debug_struct("SupportAccessRequest")
                .field("organization", &"[redacted]")
                .field("case", &"[redacted]")
                .field("scope", &"[redacted]")
                .field("minutes", minutes)
                .field("link", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::SupportAccessNotice {
                event,
                at_ms,
                until_ms,
                ..
            } => f
                .debug_struct("SupportAccessNotice")
                .field("event", event)
                .field("operator", &"[redacted]")
                .field("organization", &"[redacted]")
                .field("case", &"[redacted]")
                .field("at_ms", at_ms)
                .field("until_ms", until_ms)
                .finish(),
            Self::BreakglassUsed {
                approvals,
                at_ms,
                until_ms,
                ..
            } => f
                .debug_struct("BreakglassUsed")
                .field("organization", &"[redacted]")
                .field("incident", &"[redacted]")
                .field("approvals", approvals)
                .field("at_ms", at_ms)
                .field("until_ms", until_ms)
                .finish(),
            Self::BreakglassAlarm { alarm, at_ms, .. } => f
                .debug_struct("BreakglassAlarm")
                .field("alarm", alarm)
                .field("account", &"[redacted]")
                .field("link", &"[redacted]")
                .field("at_ms", at_ms)
                .finish(),
            Self::ApprovalInline { expires_at_ms, .. } => f
                .debug_struct("ApprovalInline")
                .field("intent", &"[redacted]")
                .field("render", &"[redacted]")
                .field("render_digest", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::ReviewCampaign { items, due_ms, .. } => f
                .debug_struct("ReviewCampaign")
                .field("campaign", &"[redacted]")
                .field("items", items)
                .field("link", &"[redacted]")
                .field("due_ms", due_ms)
                .finish(),
        }
    }
}

/// Every kind of the contract, as outbox kind and `CloudEvents` `type`.
pub const KINDS: [&str; 44] = [
    "relay.message.otp.v1",
    "relay.message.magic_link.v1",
    "relay.message.password_changed.v1",
    "relay.message.new_sign_in.v1",
    "relay.message.account_status.v1",
    "relay.message.recovery_requested.v1",
    "relay.message.recovery_cooling.v1",
    "relay.message.recovery_completed.v1",
    "relay.message.recovery_codes_regenerated.v1",
    "relay.message.second_factor_enabled.v1",
    "relay.message.new_method.v1",
    "relay.message.email_changed.v1",
    "relay.message.deletion_scheduled.v1",
    "relay.message.deletion_completed.v1",
    "relay.message.inactivity_notice.v1",
    "relay.message.signup_existing.v1",
    "relay.message.ownership_handover.v1",
    "relay.message.membership_cooling.v1",
    "relay.message.guardian_consent.v1",
    "relay.message.reset_intent.v1",
    "relay.message.export_ready.v1",
    "relay.message.invitation.v1",
    "relay.message.agent_suspended.v1",
    "relay.message.agent_sponsor_needed.v1",
    "relay.message.agent_connection_needs_reconnect.v1",
    "relay.message.device_code_approval.v1",
    "relay.message.approval_requested.v1",
    "relay.message.sso_setup_link.v1",
    "relay.message.ciba_invite.v1",
    "relay.message.upstream_subject_conflict.v1",
    "relay.message.ldap_credential_changed.v1",
    "relay.message.push_approval.v1",
    "relay.message.semantic_notice.v1",
    "relay.message.security_authority_notice.v1",
    "relay.message.passkey_setup_invite.v1",
    "relay.message.critical_interrupt.v1",
    "relay.message.sms_otp.v1",
    "relay.message.iys_consent.v1",
    "relay.message.support_access_request.v1",
    "relay.message.support_access_notice.v1",
    "relay.message.breakglass_used.v1",
    "relay.message.breakglass_alarm.v1",
    "relay.message.approval_inline.v1",
    "relay.message.review_campaign.v1",
];

impl Body {
    /// The outbox kind and `CloudEvents` `type`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Otp { .. } => KINDS[0],
            Self::MagicLink { .. } => KINDS[1],
            Self::PasswordChanged { .. } => KINDS[2],
            Self::NewSignIn { .. } => KINDS[3],
            Self::AccountStatus { .. } => KINDS[4],
            Self::Notice { notice, .. } => notice.kind(),
            Self::Link { purpose, .. } => purpose.kind(),
            Self::Invitation { .. } => KINDS[21],
            Self::Agent { notice, .. } => notice.kind(),
            Self::Prompt { prompt, .. } => prompt.kind(),
            Self::CibaInvite { .. } => KINDS[28],
            Self::UpstreamSubjectConflict { .. } => KINDS[29],
            Self::LdapCredentialChanged { .. } => KINDS[30],
            Self::PushApproval { .. } => KINDS[31],
            Self::SemanticNotice { .. } => KINDS[32],
            Self::SecurityAuthorityNotice { .. } => KINDS[33],
            Self::PasskeySetupInvite { .. } => KINDS[34],
            Self::CriticalInterrupt { .. } => KINDS[35],
            Self::SmsOtp { .. } => KINDS[36],
            Self::IysConsent { .. } => KINDS[37],
            Self::SupportAccessRequest { .. } => KINDS[38],
            Self::SupportAccessNotice { .. } => KINDS[39],
            Self::BreakglassUsed { .. } => KINDS[40],
            Self::BreakglassAlarm { .. } => KINDS[41],
            Self::ApprovalInline { .. } => KINDS[42],
            Self::ReviewCampaign { .. } => KINDS[43],
        }
    }

    /// When the message stops being worth sending.
    #[must_use]
    pub const fn expires_at_ms(&self) -> Option<u64> {
        match self {
            Self::Otp { expires_at_ms, .. }
            | Self::MagicLink { expires_at_ms, .. }
            | Self::Link { expires_at_ms, .. }
            | Self::Invitation { expires_at_ms, .. }
            | Self::Prompt { expires_at_ms, .. }
            | Self::CibaInvite { expires_at_ms, .. }
            | Self::PushApproval { expires_at_ms, .. }
            | Self::PasskeySetupInvite { expires_at_ms, .. }
            | Self::SmsOtp { expires_at_ms, .. }
            | Self::SupportAccessRequest { expires_at_ms, .. }
            | Self::ApprovalInline { expires_at_ms, .. } => Some(*expires_at_ms),
            Self::SemanticNotice { until_ms, .. } => *until_ms,
            _ => None,
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per body, each its field rules"
    )]
    fn validate(&self) -> Result<(), Invalid> {
        match self {
            Self::Otp { code, .. } => {
                let c = code.expose();
                if (4..=12).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    Ok(())
                } else {
                    Err(Invalid("code"))
                }
            }
            Self::MagicLink { link, .. } | Self::Link { link, .. } => https_link(link.expose()),
            Self::Invitation {
                link,
                organization,
                inviter,
                ..
            } => {
                https_link(link.expose())?;
                name(organization, "organization")?;
                name(inviter, "inviter")
            }
            Self::Agent { agent, .. } => name(agent, "agent"),
            Self::CibaInvite {
                link,
                client,
                binding_message,
                ..
            } => {
                https_link(link.expose())?;
                name(client, "client")?;
                binding_message.as_deref().map_or(Ok(()), binding)
            }
            Self::UpstreamSubjectConflict { upstream, .. } => name(upstream, "upstream"),
            Self::LdapCredentialChanged { application, .. } => name(application, "application"),
            Self::Prompt {
                prompt,
                link,
                name: n,
                ..
            } => {
                https_link(link.expose())?;
                name(n, prompt.name_member())
            }
            Self::Notice {
                notice, until_ms, ..
            } => {
                if notice.has_until() == until_ms.is_some() {
                    Ok(())
                } else {
                    Err(Invalid("until"))
                }
            }
            Self::PushApproval {
                challenge,
                application,
                action,
                location,
                ..
            } => {
                let c = challenge.expose();
                if !(22..=86).contains(&c.len())
                    || !c
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(Invalid("challenge"));
                }
                name(application, "application")?;
                name(action, "action")?;
                location.as_deref().map_or(Ok(()), |l| name(l, "location"))
            }
            Self::SemanticNotice { intent, link, .. } => {
                hex_id(intent, 64, "intent")?;
                https_link(link.expose())
            }
            Self::SecurityAuthorityNotice {
                name: n,
                review_link,
                revoke_link,
                ..
            } => {
                name(n, "name")?;
                https_link(review_link.expose())?;
                revoke_link
                    .as_ref()
                    .map_or(Ok(()), |l| https_link(l.expose()))
            }
            Self::PasskeySetupInvite {
                link, organization, ..
            } => {
                https_link(link.expose())?;
                name(organization, "organization")
            }
            Self::CriticalInterrupt {
                agent,
                grant,
                summary,
                ..
            } => {
                name(agent, "agent")?;
                hex_id(grant, 32, "grant")?;
                name(summary, "summary")
            }
            Self::SmsOtp { code, .. } => {
                let c = code.expose();
                if c.len() == SMS_CODE_DIGITS && c.bytes().all(|b| b.is_ascii_digit()) {
                    Ok(())
                } else {
                    Err(Invalid("code"))
                }
            }
            Self::IysConsent { source, .. } => {
                if ["self_service", "admin", "import", "app"].contains(&source.as_str()) {
                    Ok(())
                } else {
                    Err(Invalid("source"))
                }
            }
            // OP-157 m.3 (z)
            Self::SupportAccessRequest {
                organization,
                case,
                scope,
                minutes,
                link,
                ..
            } => {
                name(organization, "organization")?;
                name(case, "case")?;
                name(scope, "scope")?;
                if !(1..=1440).contains(minutes) {
                    return Err(Invalid("minutes"));
                }
                https_link(link.expose())
            }
            Self::SupportAccessNotice {
                event,
                operator,
                organization,
                case,
                until_ms,
                ..
            } => {
                name(operator, "operator")?;
                name(organization, "organization")?;
                name(case, "case")?;
                let ended = matches!(event, SupportEvent::Ended | SupportEvent::Revoked);
                if ended == until_ms.is_some() {
                    return Err(Invalid("until"));
                }
                Ok(())
            }
            Self::BreakglassUsed {
                organization,
                incident,
                approvals,
                ..
            } => {
                name(organization, "organization")?;
                name(incident, "incident")?;
                if *approvals < 2 {
                    return Err(Invalid("approvals"));
                }
                Ok(())
            }
            Self::BreakglassAlarm { account, link, .. } => {
                name(account, "account")?;
                https_link(link.expose())
            }
            Self::ApprovalInline {
                intent,
                render,
                render_digest,
                ..
            } => {
                hex_id(intent, 64, "intent")?;
                hex_id(render_digest, 64, "render_digest")?;
                if render.is_empty()
                    || render.len() > INLINE_RENDER_MAX
                    || !render
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(Invalid("render"));
                }
                Ok(())
            }
            Self::ReviewCampaign { campaign, link, .. } => {
                name(campaign, "campaign")?;
                https_link(link.expose())
            }
            _ => Ok(()),
        }
    }
}

fn https_link(l: &str) -> Result<(), Invalid> {
    if l.len() <= 2048
        && l.strip_prefix("https://").is_some_and(|r| !r.is_empty())
        && !l.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        Ok(())
    } else {
        Err(Invalid("link"))
    }
}

// OP-155 m.3 (l)
fn binding(m: &str) -> Result<(), Invalid> {
    if (1..=BINDING_MESSAGE_MAX).contains(&m.chars().count()) && !m.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(Invalid("binding_message"))
    }
}

fn hex_id(h: &str, len: usize, field: &'static str) -> Result<(), Invalid> {
    if h.len() == len && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(Invalid(field))
    }
}

fn name(n: &str, field: &'static str) -> Result<(), Invalid> {
    if (1..=200).contains(&n.chars().count()) && !n.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(Invalid(field))
    }
}

/// One message to one person.
#[derive(Debug)]
pub struct Message {
    /// The identity subject it concerns (internal id).
    pub subject: [u8; 16],
    /// Where to deliver.
    pub to: Address,
    /// BCP 47 language tag for Relay's template, when the person has one.
    pub locale: Option<String>,
    /// Since when the recipient has owned the mailbox (`mailbox_owner_since`), Unix ms: Relay
    /// sends it as RFC 7293 `Require-Recipient-Valid-Since` (OP-153 m.3 (i)). Required on every
    /// e-mail and absent on every other channel (OP-153 m.9 (d)).
    pub valid_since_ms: Option<u64>,
    /// What it says.
    pub body: Body,
}

fn valid_locale(l: &str) -> bool {
    (2..=35).contains(&l.len())
        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !l.starts_with('-')
        && !l.ends_with('-')
}

impl Message {
    /// Checks every field against the contract.
    ///
    /// # Errors
    /// [`Invalid`] naming the field.
    pub fn validate(&self) -> Result<(), Invalid> {
        self.to.validate()?;
        if self.locale.as_deref().is_some_and(|l| !valid_locale(l)) {
            return Err(Invalid("locale"));
        }
        // OP-153 m.3 (i), m.9 (d)
        if self.valid_since_ms.is_some() != matches!(self.to, Address::Email(_)) {
            return Err(Invalid("valid_since"));
        }
        // OP-156 m.3 (d), (f)
        let channel = match (&self.body, &self.to) {
            (Body::PushApproval { .. } | Body::ApprovalInline { .. }, to) => {
                matches!(to, Address::Device(_))
            }
            (Body::SmsOtp { .. }, to) => matches!(to, Address::Phone(_)),
            (Body::CriticalInterrupt { .. } | Body::SupportAccessRequest { .. }, _) => true,
            // IDP-37 (4)
            (Body::IysConsent { channel, .. }, to) => match channel {
                IysChannel::Email => matches!(to, Address::Email(_)),
                IysChannel::Sms | IysChannel::Call => matches!(to, Address::Phone(_)),
            },
            (_, to) => !matches!(to, Address::Device(_)),
        };
        if !channel {
            return Err(Invalid("recipient"));
        }
        self.body.validate()
    }

    /// The sealed form stored in the outbox: integer times, no wire formatting.
    #[expect(clippy::too_many_lines, reason = "one arm per body, each its members")]
    pub(crate) fn to_sealed_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("recipient".into(), self.to.to_json());
        if let Some(l) = &self.locale {
            m.insert("locale".into(), Value::String(l.clone()));
        }
        if let Some(v) = self.valid_since_ms {
            m.insert("valid_since_ms".into(), v.into());
        }
        match &self.body {
            Body::Otp {
                code,
                purpose,
                expires_at_ms,
            } => {
                m.insert("code".into(), Value::String(code.expose().clone()));
                m.insert("purpose".into(), purpose.name().into());
                m.insert("expires_at_ms".into(), (*expires_at_ms).into());
            }
            Body::Notice {
                at_ms, until_ms, ..
            } => {
                m.insert("at_ms".into(), (*at_ms).into());
                if let Some(u) = until_ms {
                    m.insert("until_ms".into(), (*u).into());
                }
            }
            Body::Invitation {
                link,
                organization,
                inviter,
                expires_at_ms,
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert("organization".into(), Value::String(organization.clone()));
                m.insert("inviter".into(), Value::String(inviter.clone()));
                m.insert("expires_at_ms".into(), (*expires_at_ms).into());
            }
            Body::MagicLink {
                link,
                expires_at_ms,
            }
            | Body::Link {
                link,
                expires_at_ms,
                ..
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert("expires_at_ms".into(), (*expires_at_ms).into());
            }
            Body::Agent { agent, at_ms, .. } => {
                m.insert("agent".into(), Value::String(agent.clone()));
                m.insert("at_ms".into(), (*at_ms).into());
            }
            Body::Prompt {
                prompt,
                link,
                name,
                expires_at_ms,
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert(prompt.name_member().into(), Value::String(name.clone()));
                m.insert("expires_at_ms".into(), (*expires_at_ms).into());
            }
            Body::CibaInvite {
                link,
                client,
                binding_message,
                expires_at_ms,
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert("client".into(), Value::String(client.clone()));
                if let Some(b) = binding_message {
                    m.insert("binding_message".into(), Value::String(b.clone()));
                }
                m.insert("expires_at_ms".into(), (*expires_at_ms).into());
            }
            Body::UpstreamSubjectConflict { upstream, at_ms } => {
                m.insert("upstream".into(), Value::String(upstream.clone()));
                m.insert("at_ms".into(), (*at_ms).into());
            }
            Body::LdapCredentialChanged {
                change,
                application,
                at_ms,
            } => {
                m.insert("change".into(), change.name().into());
                m.insert("application".into(), Value::String(application.clone()));
                m.insert("at_ms".into(), (*at_ms).into());
            }
            Body::PasswordChanged { at_ms } => {
                m.insert("at_ms".into(), (*at_ms).into());
            }
            Body::NewSignIn { at_ms, method } => {
                m.insert("at_ms".into(), (*at_ms).into());
                m.insert("method".into(), method.name().into());
            }
            Body::PushApproval { .. }
            | Body::SemanticNotice { .. }
            | Body::SecurityAuthorityNotice { .. }
            | Body::PasskeySetupInvite { .. }
            | Body::CriticalInterrupt { .. }
            | Body::SmsOtp { .. }
            | Body::IysConsent { .. }
            | Body::SupportAccessRequest { .. }
            | Body::SupportAccessNotice { .. }
            | Body::BreakglassUsed { .. }
            | Body::BreakglassAlarm { .. }
            | Body::ApprovalInline { .. }
            | Body::ReviewCampaign { .. } => match self
                .body
                .stage11_members(&mut m, "_ms", |ms| Ok::<_, Infallible>(ms.into()))
            {
                Ok(()) => {}
                Err(never) => match never {},
            },
            Body::AccountStatus { status, at_ms } => {
                m.insert("status".into(), status.name().into());
                m.insert("at_ms".into(), (*at_ms).into());
            }
        }
        Value::Object(m)
    }

    /// Reads the sealed form back and validates it.
    #[expect(clippy::too_many_lines, reason = "one arm per kind, each its members")]
    pub(crate) fn from_sealed_json(
        kind: &str,
        subject: [u8; 16],
        v: &Value,
    ) -> Result<Self, Invalid> {
        let int = |k: &'static str| v.get(k).and_then(Value::as_u64).ok_or(Invalid(k));
        let text = |k: &'static str| v.get(k).and_then(Value::as_str).ok_or(Invalid(k));
        let body = match kind {
            "relay.message.push_approval.v1" => Body::PushApproval {
                challenge: Secret::new(text("challenge")?.to_owned()),
                application: text("application")?.to_owned(),
                action: text("action")?.to_owned(),
                location: opt_text(v, "location")?,
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.semantic_notice.v1" => Body::SemanticNotice {
                reason: NoticeReason::parse(text("reason")?).ok_or(Invalid("reason"))?,
                intent: text("intent")?.to_owned(),
                link: Secret::new(text("link")?.to_owned()),
                until_ms: opt_int(v, "until_ms")?,
            },
            "relay.message.security_authority_notice.v1" => Body::SecurityAuthorityNotice {
                event: SecurityEvent::parse(text("event")?).ok_or(Invalid("event"))?,
                name: text("name")?.to_owned(),
                review_link: Secret::new(text("review_link")?.to_owned()),
                revoke_link: opt_text(v, "revoke_link")?.map(Secret::new),
                at_ms: int("at_ms")?,
            },
            "relay.message.passkey_setup_invite.v1" => Body::PasskeySetupInvite {
                link: Secret::new(text("link")?.to_owned()),
                organization: text("organization")?.to_owned(),
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.critical_interrupt.v1" => Body::CriticalInterrupt {
                agent: text("agent")?.to_owned(),
                grant: text("grant")?.to_owned(),
                summary: text("summary")?.to_owned(),
                at_ms: int("at_ms")?,
            },
            "relay.message.sms_otp.v1" => Body::SmsOtp {
                code: Secret::new(text("code")?.to_owned()),
                purpose: OtpPurpose::parse(text("purpose")?).ok_or(Invalid("purpose"))?,
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.iys_consent.v1" => Body::IysConsent {
                channel: IysChannel::parse(text("channel")?).ok_or(Invalid("channel"))?,
                recipient_type: IysRecipient::parse(text("recipient_type")?)
                    .ok_or(Invalid("recipient_type"))?,
                approved: match text("consent")? {
                    "approved" => true,
                    "rejected" => false,
                    _ => return Err(Invalid("consent")),
                },
                source: text("source")?.to_owned(),
                consent_at_ms: int("consent_at_ms")?,
            },
            "relay.message.support_access_request.v1" => Body::SupportAccessRequest {
                organization: text("organization")?.to_owned(),
                case: text("case")?.to_owned(),
                scope: text("scope")?.to_owned(),
                minutes: u32::try_from(int("minutes")?).map_err(|_| Invalid("minutes"))?,
                link: Secret::new(text("link")?.to_owned()),
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.support_access_notice.v1" => Body::SupportAccessNotice {
                event: SupportEvent::parse(text("event")?).ok_or(Invalid("event"))?,
                operator: text("operator")?.to_owned(),
                organization: text("organization")?.to_owned(),
                case: text("case")?.to_owned(),
                at_ms: int("at_ms")?,
                until_ms: opt_int(v, "until_ms")?,
            },
            "relay.message.breakglass_used.v1" => Body::BreakglassUsed {
                organization: text("organization")?.to_owned(),
                incident: text("incident")?.to_owned(),
                approvals: u32::try_from(int("approvals")?).map_err(|_| Invalid("approvals"))?,
                at_ms: int("at_ms")?,
                until_ms: int("until_ms")?,
            },
            "relay.message.breakglass_alarm.v1" => Body::BreakglassAlarm {
                alarm: BreakglassAlarm::parse(text("alarm")?).ok_or(Invalid("alarm"))?,
                account: text("account")?.to_owned(),
                link: Secret::new(text("link")?.to_owned()),
                at_ms: int("at_ms")?,
            },
            "relay.message.approval_inline.v1" => Body::ApprovalInline {
                intent: text("intent")?.to_owned(),
                render: text("render")?.to_owned(),
                render_digest: text("render_digest")?.to_owned(),
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.review_campaign.v1" => Body::ReviewCampaign {
                campaign: text("campaign")?.to_owned(),
                items: u32::try_from(int("items")?).map_err(|_| Invalid("items"))?,
                link: Secret::new(text("link")?.to_owned()),
                due_ms: int("due_ms")?,
            },
            "relay.message.otp.v1" => Body::Otp {
                code: Secret::new(text("code")?.to_owned()),
                purpose: OtpPurpose::parse(text("purpose")?).ok_or(Invalid("purpose"))?,
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.magic_link.v1" => Body::MagicLink {
                link: Secret::new(text("link")?.to_owned()),
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.password_changed.v1" => Body::PasswordChanged {
                at_ms: int("at_ms")?,
            },
            "relay.message.new_sign_in.v1" => Body::NewSignIn {
                at_ms: int("at_ms")?,
                method: SignInMethod::parse(text("method")?).ok_or(Invalid("method"))?,
            },
            "relay.message.account_status.v1" => Body::AccountStatus {
                status: AccountStatus::parse(text("status")?).ok_or(Invalid("status"))?,
                at_ms: int("at_ms")?,
            },
            "relay.message.ciba_invite.v1" => Body::CibaInvite {
                link: Secret::new(text("link")?.to_owned()),
                client: text("client")?.to_owned(),
                binding_message: match v.get("binding_message") {
                    None => None,
                    Some(Value::String(b)) => Some(b.clone()),
                    Some(_) => return Err(Invalid("binding_message")),
                },
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.upstream_subject_conflict.v1" => Body::UpstreamSubjectConflict {
                upstream: text("upstream")?.to_owned(),
                at_ms: int("at_ms")?,
            },
            "relay.message.ldap_credential_changed.v1" => Body::LdapCredentialChanged {
                change: AppPasswordChange::parse(text("change")?).ok_or(Invalid("change"))?,
                application: text("application")?.to_owned(),
                at_ms: int("at_ms")?,
            },
            "relay.message.invitation.v1" => Body::Invitation {
                link: Secret::new(text("link")?.to_owned()),
                organization: text("organization")?.to_owned(),
                inviter: text("inviter")?.to_owned(),
                expires_at_ms: int("expires_at_ms")?,
            },
            k => {
                if let Some(notice) = Notice::of_kind(k) {
                    Body::Notice {
                        notice,
                        at_ms: int("at_ms")?,
                        until_ms: match v.get("until_ms") {
                            None => None,
                            Some(u) => Some(u.as_u64().ok_or(Invalid("until_ms"))?),
                        },
                    }
                } else if let Some(purpose) = LinkPurpose::of_kind(k) {
                    Body::Link {
                        purpose,
                        link: Secret::new(text("link")?.to_owned()),
                        expires_at_ms: int("expires_at_ms")?,
                    }
                } else if let Some(notice) = AgentNotice::of_kind(k) {
                    Body::Agent {
                        notice,
                        agent: text("agent")?.to_owned(),
                        at_ms: int("at_ms")?,
                    }
                } else if let Some(prompt) = Prompt::of_kind(k) {
                    Body::Prompt {
                        prompt,
                        link: Secret::new(text("link")?.to_owned()),
                        name: text(prompt.name_member())?.to_owned(),
                        expires_at_ms: int("expires_at_ms")?,
                    }
                } else {
                    return Err(Invalid("kind"));
                }
            }
        };
        let locale = match v.get("locale") {
            None => None,
            Some(Value::String(l)) => Some(l.clone()),
            Some(_) => return Err(Invalid("locale")),
        };
        let valid_since_ms = match v.get("valid_since_ms") {
            None => None,
            Some(t) => Some(t.as_u64().ok_or(Invalid("valid_since_ms"))?),
        };
        let m = Self {
            subject,
            to: Address::from_json(v.get("recipient").ok_or(Invalid("recipient"))?)?,
            locale,
            valid_since_ms,
            body,
        };
        m.validate()?;
        Ok(m)
    }

    /// The `CloudEvents` `data` member: RFC 3339 times, the secret in clear for Relay only.
    #[expect(clippy::too_many_lines, reason = "one arm per body, each its members")]
    pub(crate) fn to_wire_data(&self) -> Result<Value, Invalid> {
        let mut m = Map::new();
        m.insert("recipient".into(), self.to.to_json());
        if let Some(l) = &self.locale {
            m.insert("locale".into(), Value::String(l.clone()));
        }
        // OP-153 m.3 (i), RFC 7293
        if let Some(v) = self.valid_since_ms {
            m.insert("recipient_valid_since".into(), rfc3339(v)?.into());
        }
        match &self.body {
            Body::Otp {
                code,
                purpose,
                expires_at_ms,
            } => {
                m.insert("code".into(), Value::String(code.expose().clone()));
                m.insert("purpose".into(), purpose.name().into());
                m.insert("expires_at".into(), rfc3339(*expires_at_ms)?.into());
            }
            Body::Notice {
                at_ms, until_ms, ..
            } => {
                m.insert("at".into(), rfc3339(*at_ms)?.into());
                if let Some(u) = until_ms {
                    m.insert("until".into(), rfc3339(*u)?.into());
                }
            }
            Body::Invitation {
                link,
                organization,
                inviter,
                expires_at_ms,
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert("organization".into(), Value::String(organization.clone()));
                m.insert("inviter".into(), Value::String(inviter.clone()));
                m.insert("expires_at".into(), rfc3339(*expires_at_ms)?.into());
            }
            Body::MagicLink {
                link,
                expires_at_ms,
            }
            | Body::Link {
                link,
                expires_at_ms,
                ..
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert("expires_at".into(), rfc3339(*expires_at_ms)?.into());
            }
            Body::Agent { agent, at_ms, .. } => {
                m.insert("agent".into(), Value::String(agent.clone()));
                m.insert("at".into(), rfc3339(*at_ms)?.into());
            }
            Body::Prompt {
                prompt,
                link,
                name,
                expires_at_ms,
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert(prompt.name_member().into(), Value::String(name.clone()));
                m.insert("expires_at".into(), rfc3339(*expires_at_ms)?.into());
            }
            Body::CibaInvite {
                link,
                client,
                binding_message,
                expires_at_ms,
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert("client".into(), Value::String(client.clone()));
                if let Some(b) = binding_message {
                    m.insert("binding_message".into(), Value::String(b.clone()));
                }
                m.insert("expires_at".into(), rfc3339(*expires_at_ms)?.into());
            }
            Body::UpstreamSubjectConflict { upstream, at_ms } => {
                m.insert("upstream".into(), Value::String(upstream.clone()));
                m.insert("at".into(), rfc3339(*at_ms)?.into());
            }
            Body::LdapCredentialChanged {
                change,
                application,
                at_ms,
            } => {
                m.insert("change".into(), change.name().into());
                m.insert("application".into(), Value::String(application.clone()));
                m.insert("at".into(), rfc3339(*at_ms)?.into());
            }
            Body::PasswordChanged { at_ms } => {
                m.insert("at".into(), rfc3339(*at_ms)?.into());
            }
            Body::NewSignIn { at_ms, method } => {
                m.insert("at".into(), rfc3339(*at_ms)?.into());
                m.insert("method".into(), method.name().into());
            }
            Body::PushApproval { .. }
            | Body::SemanticNotice { .. }
            | Body::SecurityAuthorityNotice { .. }
            | Body::PasskeySetupInvite { .. }
            | Body::CriticalInterrupt { .. }
            | Body::SmsOtp { .. }
            | Body::IysConsent { .. }
            | Body::SupportAccessRequest { .. }
            | Body::SupportAccessNotice { .. }
            | Body::BreakglassUsed { .. }
            | Body::BreakglassAlarm { .. }
            | Body::ApprovalInline { .. }
            | Body::ReviewCampaign { .. } => {
                self.body
                    .stage11_members(&mut m, "", |ms| rfc3339(ms).map(Value::from))?;
            }
            Body::AccountStatus { status, at_ms } => {
                m.insert("status".into(), status.name().into());
                m.insert("at".into(), rfc3339(*at_ms)?.into());
            }
        }
        Ok(Value::Object(m))
    }
}

fn opt_text(v: &Value, k: &'static str) -> Result<Option<String>, Invalid> {
    match v.get(k) {
        None => Ok(None),
        Some(Value::String(t)) => Ok(Some(t.clone())),
        Some(_) => Err(Invalid(k)),
    }
}

fn opt_int(v: &Value, k: &'static str) -> Result<Option<u64>, Invalid> {
    match v.get(k) {
        None => Ok(None),
        Some(n) => n.as_u64().map(Some).ok_or(Invalid(k)),
    }
}

impl Body {
    /// The members of the Stage 11 bodies, with times as `time` encodes them under their name
    /// plus `suffix` (`_ms` sealed, none on the wire).
    #[expect(
        clippy::too_many_lines,
        reason = "one arm per Stage 11 and Stage 12 body, each its members"
    )]
    fn stage11_members<E>(
        &self,
        m: &mut Map<String, Value>,
        suffix: &str,
        time: impl Fn(u64) -> Result<Value, E>,
    ) -> Result<(), E> {
        let put_time = |m: &mut Map<String, Value>, base: &str, ms: u64| -> Result<(), E> {
            m.insert(format!("{base}{suffix}"), time(ms)?);
            Ok(())
        };
        let text = |t: &str| Value::String(t.to_owned());
        match self {
            Self::PushApproval {
                challenge,
                application,
                action,
                location,
                expires_at_ms,
            } => {
                m.insert("challenge".into(), text(challenge.expose()));
                m.insert("application".into(), text(application));
                m.insert("action".into(), text(action));
                if let Some(l) = location {
                    m.insert("location".into(), text(l));
                }
                put_time(m, "expires_at", *expires_at_ms)?;
            }
            Self::SemanticNotice {
                reason,
                intent,
                link,
                until_ms,
            } => {
                m.insert("reason".into(), reason.name().into());
                m.insert("intent".into(), text(intent));
                m.insert("link".into(), text(link.expose()));
                if let Some(u) = until_ms {
                    put_time(m, "until", *u)?;
                }
            }
            Self::SecurityAuthorityNotice {
                event,
                name,
                review_link,
                revoke_link,
                at_ms,
            } => {
                m.insert("event".into(), event.name().into());
                m.insert("name".into(), text(name));
                m.insert("review_link".into(), text(review_link.expose()));
                if let Some(l) = revoke_link {
                    m.insert("revoke_link".into(), text(l.expose()));
                }
                put_time(m, "at", *at_ms)?;
            }
            Self::PasskeySetupInvite {
                link,
                organization,
                expires_at_ms,
            } => {
                m.insert("link".into(), text(link.expose()));
                m.insert("organization".into(), text(organization));
                put_time(m, "expires_at", *expires_at_ms)?;
            }
            Self::CriticalInterrupt {
                agent,
                grant,
                summary,
                at_ms,
            } => {
                m.insert("agent".into(), text(agent));
                m.insert("grant".into(), text(grant));
                m.insert("summary".into(), text(summary));
                put_time(m, "at", *at_ms)?;
            }
            Self::SmsOtp {
                code,
                purpose,
                expires_at_ms,
            } => {
                m.insert("code".into(), text(code.expose()));
                m.insert("purpose".into(), purpose.name().into());
                put_time(m, "expires_at", *expires_at_ms)?;
            }
            Self::IysConsent {
                channel,
                recipient_type,
                approved,
                source,
                consent_at_ms,
            } => {
                m.insert("channel".into(), channel.name().into());
                m.insert("recipient_type".into(), recipient_type.name().into());
                m.insert(
                    "consent".into(),
                    if *approved { "approved" } else { "rejected" }.into(),
                );
                m.insert("source".into(), text(source));
                put_time(m, "consent_at", *consent_at_ms)?;
            }
            // OP-157 m.3 (z)
            Self::SupportAccessRequest {
                organization,
                case,
                scope,
                minutes,
                link,
                expires_at_ms,
            } => {
                m.insert("organization".into(), text(organization));
                m.insert("case".into(), text(case));
                m.insert("scope".into(), text(scope));
                m.insert("minutes".into(), (*minutes).into());
                m.insert("link".into(), text(link.expose()));
                put_time(m, "expires_at", *expires_at_ms)?;
            }
            Self::SupportAccessNotice {
                event,
                operator,
                organization,
                case,
                at_ms,
                until_ms,
            } => {
                m.insert("event".into(), event.name().into());
                m.insert("operator".into(), text(operator));
                m.insert("organization".into(), text(organization));
                m.insert("case".into(), text(case));
                put_time(m, "at", *at_ms)?;
                if let Some(u) = until_ms {
                    put_time(m, "until", *u)?;
                }
            }
            Self::BreakglassUsed {
                organization,
                incident,
                approvals,
                at_ms,
                until_ms,
            } => {
                m.insert("organization".into(), text(organization));
                m.insert("incident".into(), text(incident));
                m.insert("approvals".into(), (*approvals).into());
                put_time(m, "at", *at_ms)?;
                put_time(m, "until", *until_ms)?;
            }
            Self::BreakglassAlarm {
                alarm,
                account,
                link,
                at_ms,
            } => {
                m.insert("alarm".into(), alarm.name().into());
                m.insert("account".into(), text(account));
                m.insert("link".into(), text(link.expose()));
                put_time(m, "at", *at_ms)?;
            }
            Self::ApprovalInline {
                intent,
                render,
                render_digest,
                expires_at_ms,
            } => {
                m.insert("intent".into(), text(intent));
                m.insert("render".into(), text(render));
                m.insert("render_digest".into(), text(render_digest));
                put_time(m, "expires_at", *expires_at_ms)?;
            }
            Self::ReviewCampaign {
                campaign,
                items,
                link,
                due_ms,
            } => {
                m.insert("campaign".into(), text(campaign));
                m.insert("items".into(), (*items).into());
                m.insert("link".into(), text(link.expose()));
                put_time(m, "due", *due_ms)?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Unix ms as RFC 3339 UTC with milliseconds.
///
/// # Errors
/// [`Invalid`] past year 9999.
pub fn rfc3339(ms: u64) -> Result<String, Invalid> {
    let nanos = i128::from(ms)
        .checked_mul(1_000_000)
        .ok_or(Invalid("time"))?;
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| Invalid("time"))?;
    let f = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    t.format(&f).map_err(|_| Invalid("time"))
}
