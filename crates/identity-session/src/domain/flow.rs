//! The authentication flow as a typed state machine (TN-132, LFP-23, TN-102): no step can be
//! deleted or reordered into a bypass, because completion is decided by the requirement list
//! alone. The state lives on the server; the client holds an opaque handle and the starting
//! browser a device secret. The state holds digests and internal ids only (OP-146 m.5 (f)).

use serde::{Deserialize, Serialize};
use suiss_crypto::digest::sha256;

use crate::domain::assurance::{Aal, Factor, MethodClass};
use crate::domain::requirement::{is_first_factor, is_second_factor};

/// Absolute lifetime of a flow (PD).
pub const FLOW_TTL_MS: u64 = 30 * 60 * 1000;

/// Absolute lifetime of a suspension: an e-mail code or link (§10.2.2: at most 15 minutes).
pub const SUSPENSION_TTL_MS: u64 = 15 * 60 * 1000;

/// Wrong e-mail codes before the code is void (PD).
pub const EMAIL_CODE_ATTEMPTS: u8 = 5;

/// One day in milliseconds; flows are partitioned by the day they start.
pub const DAY_MS: u64 = 86_400_000;

const HANDLE_CONTEXT: &[u8] = b"access/auth-flow/v1\0";
const DEVICE_CONTEXT: &[u8] = b"access/auth-device/v1\0";
const RESUME_CONTEXT: &[u8] = b"access/auth-resume/v1\0";
const IDENTIFIER_CONTEXT: &[u8] = b"access/auth-identifier/v1\0";
const CODE_CONTEXT: &[u8] = b"access/auth-email-code/v1\0";

fn tagged(context: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = context.to_vec();
    for p in parts {
        m.extend_from_slice(&u32::try_from(p.len()).unwrap_or(u32::MAX).to_be_bytes());
        m.extend_from_slice(p);
    }
    sha256(&m)
}

/// The stored digest of a flow handle (CR-38: opaque values are stored hashed).
#[must_use]
pub fn handle_digest(handle: &[u8; 32]) -> [u8; 32] {
    tagged(HANDLE_CONTEXT, &[handle])
}

/// The stored digest of a device secret.
#[must_use]
pub fn device_digest(secret: &[u8; 32]) -> [u8; 32] {
    tagged(DEVICE_CONTEXT, &[secret])
}

/// The stored digest of a resume token (magic link).
#[must_use]
pub fn resume_digest(token: &[u8; 32]) -> [u8; 32] {
    tagged(RESUME_CONTEXT, &[token])
}

/// The digest that ties a flow to the identifier it was started with, without storing it.
#[must_use]
pub fn identifier_digest(tenant: &[u8; 16], realm: &[u8; 16], folded: &str) -> [u8; 32] {
    tagged(IDENTIFIER_CONTEXT, &[tenant, realm, folded.as_bytes()])
}

/// The digest of an e-mail code, bound to its flow.
#[must_use]
pub fn code_digest(flow: &[u8; 32], code: &str) -> [u8; 32] {
    tagged(CODE_CONTEXT, &[flow, code.as_bytes()])
}

/// The partition day of a moment.
#[must_use]
pub const fn day_of(ms: u64) -> u64 {
    ms / DAY_MS
}

/// What the flow is for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// A new sign-in.
    Login,
    /// A fresher or stronger authentication for a live session (TN-44): `max_age` is
    /// mandatory.
    StepUp {
        /// The session.
        session: [u8; 16],
        /// The freshness the caller asked for.
        max_age_ms: u64,
        /// The AAL the step-up must reach.
        min_aal: Aal,
    },
    /// TOTP enrollment from a live session.
    EnrollTotp {
        /// The session.
        session: [u8; 16],
    },
    /// Passkey registration from a live session.
    RegisterPasskey {
        /// The session.
        session: [u8; 16],
    },
    /// A single-use challenge a device Instance key answers (OP-149 m.6).
    InstanceKey {
        /// The session.
        session: [u8; 16],
    },
}

/// The WebAuthn authentication state the flow keeps, single use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ceremony {
    /// The issued challenge.
    pub challenge: [u8; 32],
    /// The account's `user.id`, when one was identified.
    pub user: Option<Vec<u8>>,
    /// The `allowCredentials` sent.
    pub allowed: Vec<Vec<u8>>,
    /// UV demanded.
    pub require_uv: bool,
    /// Unix seconds.
    pub expires_at_s: u64,
}

/// The WebAuthn registration state the flow keeps, single use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// The issued challenge.
    pub challenge: [u8; 32],
    /// The account's `user.id`.
    pub user: Vec<u8>,
    /// Conditional create.
    pub conditional: bool,
    /// Unix seconds.
    pub expires_at_s: u64,
    /// The PRF salt offered.
    pub prf_salt: Option<[u8; 32]>,
}

/// A suspended step (TN-102): what was declared when suspending, the only thing resuming may
/// complete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pending {
    /// An e-mail code is out.
    EmailCode {
        /// [`code_digest`] of the code; `None` when the identifier has no account, so no
        /// code can ever match.
        digest: Option<[u8; 32]>,
        /// Absolute end.
        expires_ms: u64,
        /// Wrong codes still allowed.
        attempts_left: u8,
    },
    /// A magic link is out; its token digest is the row's resume hash.
    MagicLink {
        /// Absolute end.
        expires_ms: u64,
        /// A link was really sent (the identifier has an account).
        live: bool,
    },
    /// A push verification is out to the account's approvers (OP-156 m.3 (d)): a second step
    /// only, resumed by the approver's signed answer.
    Push {
        /// The stored digest of the challenge id.
        challenge: [u8; 32],
        /// Absolute end: 120 s after it was sent.
        expires_ms: u64,
    },
}

impl Pending {
    /// The method the suspension completes.
    #[must_use]
    pub const fn method(&self) -> MethodClass {
        match self {
            Self::EmailCode { .. } => MethodClass::EmailOtp,
            Self::MagicLink { .. } => MethodClass::MagicLink,
            Self::Push { .. } => MethodClass::Push,
        }
    }

    /// Absolute end.
    #[must_use]
    pub const fn expires_ms(&self) -> u64 {
        match self {
            Self::EmailCode { expires_ms, .. }
            | Self::MagicLink { expires_ms, .. }
            | Self::Push { expires_ms, .. } => *expires_ms,
        }
    }
}

/// The flow state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowState {
    /// Purpose.
    pub purpose: Purpose,
    /// [`identifier_digest`] of the identifier; `None` on the discoverable passkey path.
    pub identifier: Option<[u8; 32]>,
    /// The account, when the identifier names one or a step proved it. Never sent out before
    /// authentication.
    pub subject: Option<[u8; 16]>,
    /// Completed steps.
    pub factors: Vec<Factor>,
    /// The open WebAuthn ceremony.
    pub ceremony: Option<Ceremony>,
    /// The open WebAuthn registration.
    pub registration: Option<Registration>,
    /// The suspended step.
    pub pending: Option<Pending>,
    /// "Keep me signed in on this device".
    pub keep_signed_in: bool,
    /// "Don't ask for a second step on this device for 30 days" was chosen (X33).
    pub remember_device: bool,
    /// The digest of a device marker the browser presented.
    pub marker: Option<[u8; 32]>,
    /// A sealed secret waiting for confirmation (TOTP enrollment), as the credential store
    /// seals it.
    pub sealed: Option<SealedBlob>,
    /// Start, Unix milliseconds.
    pub started_ms: u64,
    /// Absolute end.
    pub expires_ms: u64,
    /// What SL2 noted and decided for this sign-in (TN-46).
    #[serde(default)]
    pub risk: Option<RiskNote>,
}

/// What SL2 notes in a sign-in flow (§12.2.4, TN-46): the password step's breach check and
/// prior failure count, then the level and whether a step-up was asked. Closed codes and counts
/// only; no address and no place.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskNote {
    /// The breached-password check of the password step (`clean`, `listed`, `unavailable`).
    pub breach: Option<String>,
    /// Failed attempts the account's counter held before the password step.
    pub prior_failures: Option<u32>,
    /// The SL2 level, once assessed.
    pub level: Option<String>,
    /// A step-up was asked of the user (SL1 path).
    pub step_up: bool,
}

/// A sealed secret in transit (ciphertext under the subject's DEK; never plaintext).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBlob {
    /// Wrapping key id.
    pub kek_id: String,
    /// Wrapped DEK.
    pub wrapped_dek: Vec<u8>,
    /// Nonce.
    pub nonce: [u8; 12],
    /// Ciphertext.
    pub ciphertext: Vec<u8>,
}

/// Why a flow step is refused. Before authentication every one of these answers alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FlowRejection {
    /// No such open flow for this browser.
    #[error("no such flow")]
    Unknown,
    /// Past its absolute end.
    #[error("flow expired")]
    Expired,
    /// The step does not fit the flow (TN-102 rule 5: no skipping).
    #[error("step not allowed")]
    NotAllowed,
    /// The step proved a different account.
    #[error("subject mismatch")]
    SubjectMismatch,
    /// Nothing is suspended, or something else is.
    #[error("nothing to resume")]
    NoPending,
}

impl FlowState {
    /// A new flow.
    #[must_use]
    pub fn new(purpose: Purpose, now_ms: u64) -> Self {
        Self {
            purpose,
            identifier: None,
            subject: None,
            factors: Vec::new(),
            ceremony: None,
            registration: None,
            pending: None,
            keep_signed_in: false,
            remember_device: false,
            marker: None,
            sealed: None,
            started_ms: now_ms,
            expires_ms: now_ms.saturating_add(FLOW_TTL_MS),
            risk: None,
        }
    }

    /// Whether the flow is past its end.
    #[must_use]
    pub const fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_ms
    }

    /// Whether a first step is done.
    #[must_use]
    pub fn first_done(&self) -> bool {
        self.factors.iter().any(|f| is_first_factor(f.method))
    }

    /// Records a completed step that proved `subject`.
    ///
    /// # Errors
    /// [`FlowRejection::NotAllowed`] for a second-factor-only method before a first step or a
    /// method already used; [`FlowRejection::SubjectMismatch`].
    pub fn record(&mut self, subject: [u8; 16], factor: Factor) -> Result<(), FlowRejection> {
        if let Some(known) = self.subject
            && known != subject
        {
            return Err(FlowRejection::SubjectMismatch);
        }
        let first_only = is_first_factor(factor.method) && !is_second_factor(factor.method);
        if !is_first_factor(factor.method) && !self.first_done() {
            return Err(FlowRejection::NotAllowed);
        }
        if first_only && self.first_done() && matches!(self.purpose, Purpose::Login) {
            return Err(FlowRejection::NotAllowed);
        }
        if self.factors.iter().any(|f| f.method == factor.method) {
            return Err(FlowRejection::NotAllowed);
        }
        self.subject = Some(subject);
        self.factors.push(factor);
        Ok(())
    }

    /// Suspends the flow on an e-mail step (TN-102 rule 1). Only a first step can be
    /// suspended: e-mail is never a second factor.
    ///
    /// # Errors
    /// [`FlowRejection::NotAllowed`].
    pub fn suspend(&mut self, pending: Pending) -> Result<(), FlowRejection> {
        if matches!(pending, Pending::Push { .. })
            || self.first_done()
            || !matches!(self.purpose, Purpose::Login)
            || self.identifier.is_none()
        {
            return Err(FlowRejection::NotAllowed);
        }
        self.pending = Some(pending);
        Ok(())
    }

    /// Suspends the flow on a push verification (TN-102, OP-156 m.3 (d)). Push is a second step
    /// only: a first step must be done, it must not be push already, and the subject is known.
    ///
    /// # Errors
    /// [`FlowRejection::NotAllowed`].
    pub fn suspend_second(&mut self, pending: Pending) -> Result<(), FlowRejection> {
        let pushed = self.factors.iter().any(|f| f.method == MethodClass::Push);
        if !matches!(pending, Pending::Push { .. })
            || !self.first_done()
            || pushed
            || self.subject.is_none()
            || matches!(
                self.purpose,
                Purpose::EnrollTotp { .. }
                    | Purpose::RegisterPasskey { .. }
                    | Purpose::InstanceKey { .. }
            )
        {
            return Err(FlowRejection::NotAllowed);
        }
        self.pending = Some(pending);
        Ok(())
    }

    /// Takes the suspended step of `method` for resumption (TN-102 rules 2-4): it completes
    /// only the step declared when suspending, and never anything stronger.
    ///
    /// # Errors
    /// [`FlowRejection::NoPending`], [`FlowRejection::Expired`].
    pub fn take_pending(
        &mut self,
        method: MethodClass,
        now_ms: u64,
    ) -> Result<Pending, FlowRejection> {
        let Some(p) = self.pending.as_ref() else {
            return Err(FlowRejection::NoPending);
        };
        if p.method() != method {
            return Err(FlowRejection::NoPending);
        }
        if now_ms >= p.expires_ms() {
            self.pending = None;
            return Err(FlowRejection::Expired);
        }
        self.pending.take().ok_or(FlowRejection::NoPending)
    }

    /// Encodes the state for storage.
    ///
    /// # Errors
    /// Never in practice; an encoding failure is reported as corrupt state.
    pub fn encode(&self) -> Result<Vec<u8>, FlowRejection> {
        serde_json::to_vec(self).map_err(|_| FlowRejection::Unknown)
    }

    /// Decodes stored state.
    ///
    /// # Errors
    /// [`FlowRejection::Unknown`].
    pub fn decode(bytes: &[u8]) -> Result<Self, FlowRejection> {
        serde_json::from_slice(bytes).map_err(|_| FlowRejection::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: [u8; 16] = [5; 16];

    fn login() -> FlowState {
        let mut f = FlowState::new(Purpose::Login, 1_000);
        f.identifier = Some([1; 32]);
        f
    }

    // TN-132, §10.2
    #[test]
    fn second_factors_need_a_first_step() {
        let mut f = login();
        assert_eq!(
            f.record(S, Factor::totp([1; 16], 1)),
            Err(FlowRejection::NotAllowed)
        );
        assert_eq!(
            f.record(S, Factor::recovery_code([1; 16], 1)),
            Err(FlowRejection::NotAllowed)
        );
        f.record(S, Factor::password(1)).unwrap_or_default();
        assert!(f.record(S, Factor::totp([1; 16], 2)).is_ok());
        assert_eq!(
            f.record(S, Factor::totp([1; 16], 3)),
            Err(FlowRejection::NotAllowed)
        );
    }

    // TN-102, TNI-9
    #[test]
    fn a_step_cannot_prove_another_account() {
        let mut f = login();
        f.record(S, Factor::password(1)).unwrap_or_default();
        assert_eq!(
            f.record([6; 16], Factor::totp([1; 16], 2)),
            Err(FlowRejection::SubjectMismatch)
        );
    }

    // TN-102, TNI-9
    #[test]
    fn resuming_completes_only_the_declared_step() {
        let mut f = login();
        f.suspend(Pending::MagicLink {
            expires_ms: 5_000,
            live: true,
        })
        .unwrap_or_default();
        assert_eq!(
            f.take_pending(MethodClass::EmailOtp, 2_000),
            Err(FlowRejection::NoPending)
        );
        assert!(f.take_pending(MethodClass::MagicLink, 2_000).is_ok());
        assert_eq!(
            f.take_pending(MethodClass::MagicLink, 2_000),
            Err(FlowRejection::NoPending)
        );
        f.suspend(Pending::MagicLink {
            expires_ms: 5_000,
            live: true,
        })
        .unwrap_or_default();
        assert_eq!(
            f.take_pending(MethodClass::MagicLink, 5_000),
            Err(FlowRejection::Expired)
        );
        assert_eq!(f.pending, None);
    }

    // §10.2.2
    #[test]
    fn email_cannot_be_suspended_after_a_first_step() {
        let mut f = login();
        f.record(S, Factor::password(1)).unwrap_or_default();
        assert_eq!(
            f.suspend(Pending::EmailCode {
                digest: None,
                expires_ms: 9,
                attempts_left: 1
            }),
            Err(FlowRejection::NotAllowed)
        );
    }

    // OP-156 m.3 (d), TN-102
    #[test]
    fn push_suspends_only_a_second_step() {
        let mut f = login();
        let push = Pending::Push {
            challenge: [3; 32],
            expires_ms: 9_000,
        };
        assert_eq!(f.suspend(push.clone()), Err(FlowRejection::NotAllowed));
        assert_eq!(
            f.suspend_second(push.clone()),
            Err(FlowRejection::NotAllowed)
        );
        f.record(S, Factor::password(1)).unwrap_or_default();
        assert_eq!(f.suspend_second(push.clone()), Ok(()));
        assert_eq!(
            f.take_pending(MethodClass::EmailOtp, 2_000),
            Err(FlowRejection::NoPending)
        );
        assert_eq!(
            f.take_pending(MethodClass::Push, 9_000),
            Err(FlowRejection::Expired)
        );
        assert_eq!(
            f.suspend_second(Pending::MagicLink {
                expires_ms: 9,
                live: true
            }),
            Err(FlowRejection::NotAllowed)
        );
    }

    // OP-146 m.5 (f)
    #[test]
    fn state_round_trips() {
        let mut f = login();
        f.record(S, Factor::password(1)).unwrap_or_default();
        let bytes = f.encode().unwrap_or_default();
        assert_eq!(FlowState::decode(&bytes), Ok(f));
        assert_ne!(handle_digest(&[1; 32]), device_digest(&[1; 32]));
        assert_ne!(handle_digest(&[1; 32]), resume_digest(&[1; 32]));
    }
}
