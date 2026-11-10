//! Use cases over the domain and its ports (OP-63): sign-in steps, sessions, second factors
//! and the epoch cache. Before authentication every refusal that could tell whether an
//! account exists has one answer (CR-40, X34, TN-82); after it, the answer is honest.

pub mod claims;
pub mod dbsc;
pub mod devices;
pub mod epochs;
pub mod mfa;
pub mod portability;
pub mod push;
pub mod recovery;
pub mod registered;
pub mod sessions;
pub mod settings;
pub mod signin;
mod webauthn;

use access_identity_account::app::Realm;
use access_identity_account::app::hasher::Hasher;
use access_identity_account::app::login::LoginGate;
use access_identity_account::domain::login::{Problem, REJECTED};
use access_identity_account::domain::status::AccountStatus;
use access_identity_webauthn::domain::policy::RealmPolicy as WebAuthnPolicy;
use access_identity_webauthn::domain::rp::RelyingParty;
use access_identity_webauthn::ports::{CredentialRegistry, DecoySource, SignalSink};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::audit::AuditEvent;
use access_store::sessions::{FlowRow, FlowUpdate};

use crate::SessionError;
use crate::domain::assurance::{AuthenticationResult, MethodClass};
use crate::domain::flow::{DAY_MS, FlowRejection, FlowState, day_of, device_digest, handle_digest};
use crate::domain::requirement::{AuthPolicy, Enrolled, Requirement};
use crate::domain::session::SessionPolicy;
pub use access_identity_account::notify::ports::Notifier;

use crate::ports::{Clock, Random, SessionDb, SessionTx};
use access_identity_hooks::ports::HookCaller;
pub use access_identity_risk::app::sl2::{Services as RiskServices, Sl2};

/// The credential kinds of second factors.
pub const TOTP: &str = "totp";
/// Recovery codes.
pub const RECOVERY_CODE: &str = "recovery_code";

/// The passkey side of the service.
pub struct Passkeys<'a, P, S> {
    /// The registry.
    pub registry: &'a P,
    /// Where risk signals go (TN-63).
    pub signals: &'a S,
    /// The realm's decoy key (TN-97).
    pub decoys: &'a (dyn DecoySource + Sync),
    /// The relying party.
    pub rp: &'a RelyingParty,
    /// The realm's WebAuthn policy.
    pub policy: &'a WebAuthnPolicy,
}

/// The authentication service of one realm.
pub struct Auth<'a, D, C, R, N, P, S> {
    /// Account, flow and session tables.
    pub db: &'a D,
    /// The realm and its keys.
    pub realm: Realm<'a>,
    /// Sign-in requirements.
    pub policy: AuthPolicy,
    /// Session lifetimes.
    pub lifetimes: SessionPolicy,
    /// Trusted time.
    pub clock: &'a C,
    /// Randomness.
    pub random: &'a R,
    /// The Relay seam (I6).
    pub notifier: &'a N,
    /// The `https` prefix a magic link token is appended to: the realm's confirmation page.
    pub link_base: &'a str,
    /// The password step's process state.
    pub gate: &'a LoginGate,
    /// The Argon2id service.
    pub hasher: &'a Hasher,
    /// Passkeys.
    pub passkeys: Passkeys<'a, P, S>,
    /// The realm's inline hooks (TN-135): `post_login` may refuse a sign-in.
    pub hooks: &'a (dyn HookCaller + Sync),
    /// SL2 risk for this request (TN-46): its sources and the client's address.
    pub risk: Sl2<'a>,
}

/// A flow as the browser names it: the handle from the page, the device secret from the
/// flow cookie.
#[derive(Clone, Copy, Debug)]
pub struct FlowRef<'a> {
    /// The flow handle.
    pub handle: &'a str,
    /// The flow cookie's value.
    pub device: &'a str,
}

/// A refusal on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// The RFC 9457 problem.
    pub problem: Problem,
    /// Wait this long before answering (adaptive delay; never on the wire).
    pub pad_ms: u64,
}

/// A signed-in browser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedIn {
    /// The session.
    pub session: [u8; 16],
    /// The session cookie's `Set-Cookie` value; `None` on step-up, where the cookie stays.
    pub set_cookie: Option<String>,
    /// The device marker's `Set-Cookie` value (X33).
    pub marker_cookie: Option<String>,
    /// The typed result (TN-103).
    pub result: AuthenticationResult,
}

/// The outcome of a flow step. A decision, not an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// More is needed. Before authentication `needs` is `[FirstFactor]` and `enrolled` is
    /// `None`, whatever the account (TN-96).
    Continue {
        /// Still missing.
        needs: Vec<Requirement>,
        /// The account's second factors, after authentication only.
        enrolled: Option<Enrolled>,
    },
    /// Waiting for an e-mail step; the same answer whether or not anything was sent.
    Suspended {
        /// The suspended method.
        method: MethodClass,
    },
    /// Refused.
    Rejected(Refusal),
    /// Too many attempts.
    Throttled {
        /// `Retry-After`, whole seconds.
        retry_after_s: u64,
    },
    /// Complete.
    SignedIn(Box<SignedIn>),
}

/// The flow is gone or never was: independent of any account.
pub const FLOW_GONE: Problem = Problem {
    status: 410,
    code: "sign-in-expired",
    title: "This sign-in has expired; start again",
    retry_after_s: None,
};

/// The realm's `post_login` hook refused the sign-in or did not answer (TN-135, MD-8).
pub const HOOK_REFUSED: Problem = Problem {
    status: 403,
    code: "sign-in-refused",
    title: "This sign-in isn't allowed",
    retry_after_s: None,
};

/// The subject's organization enforces SSO: only its identity provider signs the subject in
/// (TN-94, OP-155 m.3 (i)).
pub const SSO_REQUIRED: Problem = Problem {
    status: 403,
    code: "sso-required",
    title: "Your organization signs you in with its identity provider",
    retry_after_s: None,
};

/// A code was not accepted (after authentication, X34).
pub const CODE_NOT_ACCEPTED: Problem = Problem {
    status: 401,
    code: "code-not-accepted",
    title: "That code isn't valid",
    retry_after_s: None,
};

/// The step does not fit the flow (after authentication, X34).
pub const STEP_NOT_ALLOWED: Problem = Problem {
    status: 409,
    code: "step-not-allowed",
    title: "That step isn't available here",
    retry_after_s: None,
};

/// A second factor is locked after too many failures (TN-59).
pub const FACTOR_LOCKED: Problem = Problem {
    status: 423,
    code: "factor-locked",
    title: "This method is locked; use account recovery",
    retry_after_s: None,
};

pub(crate) fn refuse(problem: Problem) -> Step {
    Step::Rejected(Refusal { problem, pad_ms: 0 })
}

pub(crate) fn neutral(pad_ms: u64) -> Step {
    Step::Rejected(Refusal {
        problem: REJECTED,
        pad_ms,
    })
}

pub(crate) fn gone(_: FlowRejection) -> Step {
    refuse(FLOW_GONE)
}

pub(crate) fn decode32(text: &str) -> Option<[u8; 32]> {
    let bytes = b64url_decode(text).ok()?;
    <[u8; 32]>::try_from(bytes).ok()
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    b64url_encode(bytes)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub(crate) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let b = text.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).ok()?, 16).ok())
        .collect()
}

pub(crate) fn i64_of(v: u64) -> Result<i64, SessionError> {
    i64::try_from(v).map_err(|_| SessionError::Corrupt)
}

pub(crate) fn u64_of(v: i64) -> Result<u64, SessionError> {
    u64::try_from(v).map_err(|_| SessionError::Corrupt)
}

pub(crate) fn active(status: &str) -> bool {
    AccountStatus::parse(status).is_some_and(AccountStatus::can_authenticate)
}

/// A flow read under its row lock.
pub(crate) struct Loaded {
    pub(crate) row: FlowRow,
    pub(crate) state: FlowState,
}

/// What happens to the row's resume digest on save.
pub(crate) enum Resume {
    Keep,
    Set([u8; 32]),
    Clear,
}

pub(crate) fn from_day(now_ms: u64) -> i32 {
    i32::try_from(day_of(now_ms).saturating_sub(1)).unwrap_or(i32::MAX)
}

pub(crate) fn partition(now_ms: u64) -> Result<i32, SessionError> {
    i32::try_from(now_ms / DAY_MS).map_err(|_| SessionError::Corrupt)
}

/// Reads an open flow for this browser.
pub(crate) async fn load<T: SessionTx>(
    tx: &mut T,
    flow: &FlowRef<'_>,
    now_ms: u64,
) -> Result<Result<Loaded, FlowRejection>, SessionError> {
    let (Some(handle), Some(device)) = (decode32(flow.handle), decode32(flow.device)) else {
        return Ok(Err(FlowRejection::Unknown));
    };
    let Some(row) = tx.flow(from_day(now_ms), &handle_digest(&handle)).await? else {
        return Ok(Err(FlowRejection::Unknown));
    };
    if row.status != "open" || row.device_hash != device_digest(&device) {
        return Ok(Err(FlowRejection::Unknown));
    }
    let state = FlowState::decode(&row.state).map_err(|_| SessionError::Corrupt)?;
    if state.expired(now_ms) {
        return Ok(Err(FlowRejection::Expired));
    }
    Ok(Ok(Loaded { row, state }))
}

/// Writes a flow over the version that was read.
pub(crate) async fn save<T: SessionTx>(
    tx: &mut T,
    l: &Loaded,
    status: &str,
    resume: Resume,
) -> Result<(), SessionError> {
    let state = l.state.encode().map_err(|_| SessionError::Corrupt)?;
    let resume_hash = match resume {
        Resume::Keep => l.row.resume_hash,
        Resume::Set(h) => Some(h),
        Resume::Clear => None,
    };
    let done = tx
        .update_flow(&FlowUpdate {
            day: l.row.day,
            flow_hash: &l.row.flow_hash,
            version: l.row.version,
            status,
            state: &state,
            resume_hash: resume_hash.as_ref(),
        })
        .await?;
    if done {
        Ok(())
    } else {
        Err(SessionError::Conflict)
    }
}

pub(crate) async fn audit<T: SessionTx>(
    tx: &mut T,
    event_type: &str,
    actor: &str,
    target: &str,
    correlation: &str,
) -> Result<(), SessionError> {
    Ok(tx
        .audit(&AuditEvent {
            event_type,
            actor,
            target,
            correlation,
        })
        .await?)
}

impl<D, C, R, N, P, S> Auth<'_, D, C, R, N, P, S>
where
    D: SessionDb,
    C: Clock,
    R: Random,
    N: Notifier + Sync,
    P: CredentialRegistry + Sync,
    S: SignalSink + Sync,
{
    pub(crate) fn now(&self) -> u64 {
        self.clock.now_ms()
    }

    pub(crate) fn random32(&self) -> Result<[u8; 32], SessionError> {
        let mut out = [0; 32];
        self.random.fill(&mut out)?;
        Ok(out)
    }

    pub(crate) async fn begin(&self) -> Result<D::Tx, SessionError> {
        Ok(self.db.begin(self.realm.tenant, self.realm.realm).await?)
    }

    pub(crate) fn external(&self, subject: [u8; 16]) -> Result<String, SessionError> {
        Ok(self.realm.external(subject)?)
    }
}
