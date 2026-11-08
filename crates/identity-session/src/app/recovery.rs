//! Account recovery use cases (§12.3.2, TN-52–TN-64, OP-153 m.3 (c)–(f)): starting an attempt
//! with one neutral answer, proving it, the objection window, the credential-only rebind and the
//! grace period, the owner's own sign-in cancelling it, reset intents and temporary access
//! passes, the account's recovery addresses and cross-device link codes.
//!
//! Every transition is a new row of the attempt's record; the one that opens authority checks
//! the state, checks the evidence, spends it and creates the authority in one transaction
//! (TN-54). An identifier that names no account opens an attempt that answers exactly like a
//! real one and can never be proved (CR-40, X34).

use access_crypto::Secret;
use access_identity_account::app::Actor;
use access_identity_account::app::accounts::{PASSWORD, store_password};
use access_identity_account::app::claims::emit;
use access_identity_account::app::events;
use access_identity_account::app::sealing::{open, seal, subject_key};
use access_identity_account::app::signal::{emit as signal, fresh_id};
use access_identity_account::domain::claim_classes::RecoveryResult;
use access_identity_account::domain::claims::{authentication_ended, recovery_result};
use access_identity_account::domain::gcra::Gcra;
use access_identity_account::domain::login::{Problem, counter_key};
use access_identity_account::domain::password::{ALGORITHM, Password};
use access_identity_account::domain::recovery_token::{
    self as tokens, LINK_CODE, REBIND, RESET_INTENT, TEMPORARY_ACCESS_PASS,
};
use access_identity_account::domain::signal::{Initiator, Signal};
use access_identity_account::domain::throttle::{
    DAY_MS as THROTTLE_DAY_MS, Gate, KeyKind, KeyPolicy, Penalty,
};
use access_identity_account::notify::message::{Address, Body, Message, Notice, OtpPurpose};
use access_identity_account::ports::AccountTx;
use access_identity_risk::domain::assess::Breach;
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::accounts::{NewCredential, Revoke};
use access_store::sessions::NewSession;
use access_telemetry::signals::{RECOVERY_RETRIGGERS, RECOVERY_TRANSITIONS, RECOVERY_WEAKEST_PATH};

use super::signin::{ANONYMOUS, address, key_state, throttle_row};
use super::{Auth, CODE_NOT_ACCEPTED, Notifier, RECOVERY_CODE, audit, decode32, encode, i64_of};
use crate::SessionError;
use crate::domain::assurance::{Aal, Factor, vector};
use crate::domain::codes::{
    RECOVERY_CODE_BYTES, canonical_recovery_code, email_code, recovery_code,
};
use crate::domain::recovery::{
    ATTEMPT_FAILURES, CONTACT_CODE_TTL_MS, CoolingTable, GRACE_MS, INTENT_TTL_MAX_MS,
    LINK_CODE_TTL_MS, MAX_CONTACTS, REBIND_TTL_MS, RecoveryPath, RecoveryPolicy, Restricted,
    SENT_CODE_TTL_MS, State, TAP_LENGTH_MAX, TAP_LENGTH_MIN, TAP_TTL_MAX_MS, TAP_TTL_MIN_MS,
    aal_from_level, aal_name, aal_of, achieved, backoff_ms, code_digest, label, link_code,
    link_code_bits, path, too_weak,
};
use crate::domain::session::{SESSION_COOKIE, clear_cookie, cookie_digest, set_cookie};
use crate::ports::{
    AttemptRow, Clock, NewAttempt, NewToken, NewTransition, NoticeAddress, Random, RecoveryTx,
    SessionDb, SessionTx, TransitionRow,
};

/// No live session (G57).
pub const SESSION_REQUIRED: Problem = Problem {
    status: 401,
    code: "session-required",
    title: "Sign in first",
    retry_after_s: None,
};

/// The cookie that holds an attempt's handle in the browser that started it.
pub const RECOVERY_COOKIE: &str = "__Host-access-recovery";

/// The cookie that holds the credential-only rebind token (TN-53 rule 2).
pub const REBIND_COOKIE: &str = "__Host-access-rebind";

/// How long the attempt cookie lives.
const ATTEMPT_COOKIE_S: u64 = 86_400 * 3;

/// OP-153 m.3 (d): ten starts an hour from one network prefix.
const START_PER_PREFIX: KeyPolicy = KeyPolicy {
    rate: Gcra {
        interval_ms: 360_000,
        burst: 10,
    },
    penalty: Penalty::Doubling {
        first_ms: 1_000,
        cap_ms: 30_000,
        lock_at: None,
    },
};

/// OP-153 m.3 (d): three starts a day per account; never a lock, only fewer messages.
const START_PER_ACCOUNT: KeyPolicy = KeyPolicy {
    rate: Gcra {
        interval_ms: 28_800_000,
        burst: 3,
    },
    penalty: Penalty::Doubling {
        first_ms: 1_000,
        cap_ms: 30_000,
        lock_at: None,
    },
};

/// How far back the attempts that can still move are read.
const LIVE_WINDOW_MS: u64 = 31 * 86_400_000;

/// The window of the re-trigger rate (TN-63).
const RETRIGGER_WINDOW_MS: u64 = 30 * 86_400_000;

/// An attempt handle that names nothing, or no longer anything (neutral).
pub const RECOVERY_GONE: Problem = Problem {
    status: 410,
    code: "recovery-expired",
    title: "This recovery has expired; start again",
    retry_after_s: None,
};

/// Ten failed proofs locked the attempt; the account is untouched (OP-153 m.3 (d)).
pub const RECOVERY_LOCKED: Problem = Problem {
    status: 423,
    code: "recovery-locked",
    title: "This recovery is locked; start a new one later",
    retry_after_s: None,
};

/// The step does not fit the attempt's state (TN-54: no step is skipped).
pub const RECOVERY_STEP: Problem = Problem {
    status: 409,
    code: "recovery-step",
    title: "That step isn't available in this recovery",
    retry_after_s: None,
};

/// TN-53 rule 1, INV-40 (i): the recovery configuration cannot reach the account's assurance.
pub const RECOVERY_TOO_WEAK: Problem = Problem {
    status: 409,
    code: "recovery-too-weak",
    title: "This recovery setup is weaker than the account it protects",
    retry_after_s: None,
};

/// TN-56: the grace period after a recovery refuses this action; `Retry-After` is the time
/// left, from which the page says the date (TN-55, Ek B 3656).
pub const RECOVERY_GRACE: Problem = Problem {
    status: 403,
    code: "recovery-grace",
    title: "This action opens after your recovery's waiting period",
    retry_after_s: None,
};

/// TN-59: the request does not fit the recovery rules.
pub const RECOVERY_INVALID: Problem = Problem {
    status: 400,
    code: "invalid-request",
    title: "The request is not valid",
    retry_after_s: None,
};

/// OP-153 m.3 (c): the account has no Party, so no Instance to recover; the rebind alone
/// restores sign-in.
pub const NO_PARTY: Problem = Problem {
    status: 409,
    code: "recovery-no-instance",
    title: "This account has no device to recover; set a new password",
    retry_after_s: None,
};

/// A new password the policy or the breach corpus refuses.
pub const PASSWORD_REFUSED: Problem = Problem {
    status: 400,
    code: "password-rejected",
    title: "Choose another password",
    retry_after_s: None,
};

/// Where an attempt stands, as the browser that started it sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptView {
    /// The attempt's public reference.
    pub attempt: String,
    /// Its state.
    pub state: State,
    /// The path it started on.
    pub path: RecoveryPath,
    /// The AAL the account needs.
    pub required: Aal,
    /// What the evidence reached.
    pub achieved: Option<Aal>,
    /// The evidence classes spent.
    pub evidence: Vec<RecoveryPath>,
    /// The end of a throttle, cooling or grace period, Unix ms.
    pub until_ms: Option<u64>,
}

/// A recovery answer.
#[derive(Default)]
pub struct Recovered {
    /// The attempt, when there is one.
    pub view: Option<AttemptView>,
    /// `Set-Cookie` values.
    pub cookies: Vec<String>,
    /// The one new recovery code that replaces a spent one, shown once (OP-153 m.3 (d)).
    pub replacement: Option<Secret<String>>,
    /// Federated links shown and cut by the password reset (TN-64).
    pub links_cut: u64,
    /// After a rebind: when high-impact actions open (X38, TN-55).
    pub sensitive_after_ms: Option<u64>,
    /// After a successor is named: the Party and the predecessor Instance its self-signed
    /// `instance_recover` names (OP-153 m.3 (c)).
    pub successor: Option<([u8; 16], [u8; 16])>,
}

/// A successor a `recovery_result` names, ready for its `instance_recover` (OP-153 m.3 (c)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Successor {
    /// The session's subject.
    pub subject: [u8; 16],
    /// The attempt in its grace period.
    pub attempt: [u8; 16],
    /// The subject's Party.
    pub party: [u8; 16],
    /// The Instance it recovers.
    pub predecessor: [u8; 16],
    /// The `recovery_result` Claim.
    pub claim: [u8; 16],
}

/// OP-153 m.3 (c): the `recovery_result` Claim is not yet in the governing domain; the
/// `instance_recover` would be denied, so it is not forwarded.
pub const RESULT_PENDING: Problem = Problem {
    status: 409,
    code: "recovery-result-pending",
    title: "Your recovery is still being recorded; try again in a moment",
    retry_after_s: Some(2),
};

/// A recovery decision: done, refused with a problem, or throttled.
pub enum Answer {
    /// Done.
    Done(Box<Recovered>),
    /// Refused.
    Refused(Problem),
    /// Too many: wait.
    Throttled {
        /// `Retry-After`, whole seconds.
        retry_after_s: u64,
    },
}

/// One step of a recovery.
#[derive(Clone, Copy)]
pub enum Proof<'a> {
    /// A code: a sent code (digits) or a registered recovery code.
    Code(&'a str),
    /// The account's current password: a single-factor authenticator bound to it (TN-52).
    Password(&'a str),
    /// Sends a code of another class, for a second proof.
    Send(RecoveryPath),
    /// Opens the rebind window once the objection window is over.
    Continue,
    /// Binds a new password in the rebind window (TN-53 rule 2).
    Bind {
        /// The new password.
        password: &'a str,
        /// The rebind cookie.
        rebind: Option<&'a str>,
    },
    /// Names the device key that becomes the successor Instance in the rebind window: the
    /// realm issuer's `recovery_result` Claim names it (OP-153 m.3 (c), INV-40).
    Successor {
        /// The key's RFC 7638 thumbprint, `x5t#S256`.
        kid: [u8; 32],
        /// The rebind cookie.
        rebind: Option<&'a str>,
    },
}

/// The account's recovery addresses (S11 "Recovery").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverySetup {
    /// Recovery contacts' addresses.
    pub contacts: Vec<String>,
    /// The address recovery codes go to, if any.
    pub recovery_email: Option<String>,
    /// How many addresses get notices.
    pub notice_addresses: usize,
    /// The classes a recovery can prove with.
    pub classes: Vec<RecoveryPath>,
    /// The weakest path's AAL: the account's effective security over recovery (TN-53 rule 3).
    pub weakest: Option<Aal>,
    /// The account's own AAL.
    pub required: Aal,
    /// Whether assisted recovery is on (TN-60).
    pub assisted: bool,
}

/// A change of the account's recovery addresses.
#[derive(Clone, Debug)]
pub struct SetupChange {
    /// Recovery contacts' e-mail addresses, at most three.
    pub contacts: Vec<String>,
    /// Another e-mail address recovery codes go to.
    pub recovery_email: Option<String>,
    /// Turns assisted recovery off; then `permanent_loss_acknowledged` must be set (TN-60).
    pub assisted: bool,
    /// The person acknowledged that they may lose the account for good.
    pub permanent_loss_acknowledged: bool,
}

/// A cross-device link code, shown once and never sent by e-mail (TN-59).
pub struct LinkCode {
    /// The code.
    pub code: Secret<String>,
    /// Its entropy.
    pub bits: u16,
    /// Its end, Unix ms.
    pub expires_ms: u64,
}

fn throttle_day(now: u64) -> Result<i32, SessionError> {
    i32::try_from(now / THROTTLE_DAY_MS).map_err(|_| SessionError::Corrupt)
}

fn last(ts: &[TransitionRow]) -> Result<(&TransitionRow, State), SessionError> {
    let t = ts.last().ok_or(SessionError::Corrupt)?;
    Ok((t, State::parse(&t.state).ok_or(SessionError::Corrupt)?))
}

fn evidence_of(t: &TransitionRow) -> Result<Vec<RecoveryPath>, SessionError> {
    t.evidence
        .iter()
        .map(|e| path(e).ok_or(SessionError::Corrupt))
        .collect()
}

fn names(e: &[RecoveryPath]) -> Vec<String> {
    e.iter().map(|p| String::from(p.name())).collect()
}

fn ms(v: i64) -> Result<u64, SessionError> {
    u64::try_from(v).map_err(|_| SessionError::Corrupt)
}

fn view(a: &AttemptRow, ts: &[TransitionRow]) -> Result<AttemptView, SessionError> {
    let (t, state) = last(ts)?;
    Ok(AttemptView {
        attempt: encode(&a.id),
        state,
        path: path(&a.path).ok_or(SessionError::Corrupt)?,
        required: aal_of(&a.required_aal).ok_or(SessionError::Corrupt)?,
        achieved: t.achieved_aal.as_deref().and_then(aal_of),
        evidence: evidence_of(t)?,
        until_ms: t.until_ms.map(ms).transpose()?,
    })
}

fn email(text: &str) -> Option<Address> {
    let t = text.trim();
    let ok = (3..=320).contains(&t.chars().count())
        && t.split_once('@')
            .is_some_and(|(l, d)| !l.is_empty() && d.contains('.') && !d.contains('@'))
        && !t.chars().any(|c| c.is_control() || c.is_whitespace());
    ok.then(|| Address::Email(t.to_lowercase()))
}

fn shown(a: &Address) -> String {
    match a {
        Address::Email(v) | Address::Phone(v) => v.clone(),
    }
}

fn kinds(list: &[&str]) -> Vec<String> {
    list.iter().map(|k| String::from(*k)).collect()
}

/// Cancels the subject's running recoveries: the owner's own sign-in denies them (TN-54); the
/// rebind tokens die with them. DENIED never ends sessions by itself. How many were denied.
///
/// # Errors
/// [`SessionError`].
pub async fn cancel<T: RecoveryTx>(
    tx: &mut T,
    subject: [u8; 16],
    now: u64,
) -> Result<u64, SessionError> {
    let since = i64_of(now.saturating_sub(LIVE_WINDOW_MS))?;
    let mut n = 0_u64;
    for a in tx.attempts_since(subject, since).await? {
        let ts = tx.transitions(a.id).await?;
        let Ok((t, state)) = last(&ts) else { continue };
        if !state.cancellable() {
            continue;
        }
        let evidence = t.evidence.clone();
        let next = NewTransition {
            seq: t.seq.checked_add(1).ok_or(SessionError::Corrupt)?,
            state: State::Denied.name(),
            required_aal: t.required_aal.as_deref(),
            achieved_aal: t.achieved_aal.as_deref(),
            evidence: &evidence,
            reason: "signed_in",
            until_ms: None,
            at_ms: i64_of(now)?,
        };
        if tx.transition(a.id, &next).await? {
            n = n.saturating_add(1);
            RECOVERY_TRANSITIONS.incr([path_word(&a.path), State::Denied.name()]);
        }
    }
    if n > 0 {
        tx.revoke_tokens(subject, &kinds(&[REBIND])).await?;
    }
    Ok(n)
}

fn path_word(name: &str) -> &'static str {
    path(name).map_or("unknown", RecoveryPath::name)
}

/// The end of the subject's grace period, if one runs at `now` (TN-56). A grace period that
/// has run out is closed on the way (CLOSED is a row like every other state).
///
/// # Errors
/// [`SessionError`].
pub async fn grace_until<T: RecoveryTx>(
    tx: &mut T,
    subject: [u8; 16],
    now: u64,
) -> Result<Option<u64>, SessionError> {
    let since = i64_of(now.saturating_sub(LIVE_WINDOW_MS))?;
    let mut out: Option<u64> = None;
    for a in tx.attempts_since(subject, since).await? {
        let ts = tx.transitions(a.id).await?;
        let Ok((t, State::GracePeriod)) = last(&ts) else {
            continue;
        };
        let until = t.until_ms.map(ms).transpose()?.unwrap_or(0);
        if until > now {
            out = Some(out.map_or(until, |o| o.max(until)));
        } else {
            let evidence = t.evidence.clone();
            let closed = NewTransition {
                seq: t.seq.checked_add(1).ok_or(SessionError::Corrupt)?,
                state: State::Closed.name(),
                required_aal: t.required_aal.as_deref(),
                achieved_aal: t.achieved_aal.as_deref(),
                evidence: &evidence,
                reason: "grace_elapsed",
                until_ms: None,
                at_ms: i64_of(now)?,
            };
            if tx.transition(a.id, &closed).await? {
                RECOVERY_TRANSITIONS.incr([path_word(&a.path), State::Closed.name()]);
            }
        }
    }
    Ok(out)
}

/// The RFC 7293 `Require-Recipient-Valid-Since` time of a message to `to`: e-mail only, never
/// before the epoch's first millisecond (OP-153 m.3 (i)).
fn valid_since(to: &Address, proved_ms: u64) -> Option<u64> {
    matches!(to, Address::Email(_)).then_some(proved_ms.max(1))
}

/// TN-56: `Ok(())` when the grace period lets `action` through at `now`, else the refusal
/// with the time left.
///
/// # Errors
/// [`SessionError`].
pub async fn grace_check<T: RecoveryTx>(
    tx: &mut T,
    subject: [u8; 16],
    now: u64,
    action: Restricted,
) -> Result<Result<(), Problem>, SessionError> {
    let until = grace_until(tx, subject, now).await?;
    if crate::domain::recovery::grace_refuses(until, now, action) {
        let left = until.unwrap_or(now).saturating_sub(now);
        return Ok(Err(Problem {
            retry_after_s: Some(left.div_ceil(1000)),
            ..RECOVERY_GRACE
        }));
    }
    Ok(Ok(()))
}

impl<D, C, R, N, P, S> Auth<'_, D, C, R, N, P, S>
where
    D: SessionDb,
    D::Tx: RecoveryTx,
    C: Clock,
    R: Random,
    N: Notifier + Sync,
    P: CredentialRegistry + Sync,
    S: SignalSink + Sync,
{
    async fn gate(
        &self,
        tx: &mut D::Tx,
        key: &[u8; 32],
        policy: &KeyPolicy,
        now: u64,
    ) -> Result<Result<(), u64>, SessionError> {
        let day = throttle_day(now)?;
        let s = key_state(&tx.throttle(key, day, 2).await?)?;
        match policy.admit(&s, now) {
            Gate::Open(opened) => {
                tx.put_throttle(key, day, &throttle_row(&opened)).await?;
                Ok(Ok(()))
            }
            Gate::Wait { retry_after_ms } => Ok(Err(retry_after_ms.div_ceil(1000).max(1))),
            Gate::Locked => Ok(Err(3600)),
        }
    }

    async fn realm_policy(&self, tx: &mut D::Tx) -> Result<RecoveryPolicy, SessionError> {
        match tx.recovery_realm_policy().await? {
            Some(b) => RecoveryPolicy::from_bytes(&b).map_err(|_| SessionError::Corrupt),
            None => Ok(RecoveryPolicy::DEFAULT),
        }
    }

    /// The AAL the account needs (TN-53 rule 1): the realm's sign-in floor, AAL2 once any
    /// second factor is enrolled, and the domain's extra rebind term (§10.1.3).
    async fn required(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        policy: &RecoveryPolicy,
    ) -> Result<Aal, SessionError> {
        let enrolled = self.enrolled(tx, subject).await?;
        let mut need = self.policy.min_aal;
        if self.policy.mfa == crate::domain::requirement::MfaPolicy::Required
            || enrolled.second_factor()
            || enrolled.recovery_codes
        {
            need = need.max(Aal::Aal2);
        }
        Ok(policy
            .rebind_aal
            .and_then(aal_from_level)
            .map_or(need, |r| need.max(r)))
    }

    async fn high_value(&self, tx: &mut D::Tx, subject: [u8; 16]) -> Result<bool, SessionError> {
        Ok(tx
            .account_recovery_policy(subject)
            .await?
            .is_some_and(|p| p.high_value || !p.assisted_recovery))
    }

    async fn assisted(&self, tx: &mut D::Tx, subject: [u8; 16]) -> Result<bool, SessionError> {
        Ok(tx
            .account_recovery_policy(subject)
            .await?
            .is_none_or(|p| p.assisted_recovery))
    }

    /// Where the account's notices go, never a recovery channel (TN-57): its notice addresses,
    /// or its sign-in contact when it has set none.
    async fn notice_targets(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
    ) -> Result<Vec<(Address, Option<u64>)>, SessionError> {
        let rows = tx.notice_addresses(subject).await?;
        let notices: Vec<(Address, Option<u64>)> = rows
            .into_iter()
            .filter(|a| !a.recovery_target)
            .map(|a| {
                let since = valid_since(&a.to, a.since_ms);
                (a.to, since)
            })
            .collect();
        if !notices.is_empty() {
            return Ok(notices);
        }
        let Some(to) = address(tx.contact(subject).await?) else {
            return Ok(Vec::new());
        };
        let since = valid_since(&to, tx.mailbox_since(subject).await?.unwrap_or(1));
        Ok(vec![(to, since)])
    }

    async fn notice(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        notice: Notice,
        until_ms: Option<u64>,
        now: u64,
    ) -> Result<(), SessionError> {
        for (to, valid_since_ms) in self.notice_targets(tx, subject).await? {
            tx.notify(
                self.notifier,
                &Message {
                    subject,
                    to,
                    locale: None,
                    valid_since_ms,
                    body: Body::Notice {
                        notice,
                        at_ms: now,
                        until_ms,
                    },
                },
            )
            .await?;
        }
        Ok(())
    }

    /// Sends one code of `class` for the attempt to each of its addresses: the recovery address
    /// for a sent code, every recovery contact for a contact code (TN-52). Nothing is sent for
    /// an attempt without an account.
    async fn send_codes(
        &self,
        tx: &mut D::Tx,
        attempt: [u8; 16],
        subject: Option<[u8; 16]>,
        class: RecoveryPath,
        now: u64,
    ) -> Result<(), SessionError> {
        let Some(subject) = subject else {
            return Ok(());
        };
        let (contact, ttl) = match class {
            RecoveryPath::SentCode => (false, SENT_CODE_TTL_MS),
            RecoveryPath::RecoveryContact => (true, CONTACT_CODE_TTL_MS),
            _ => return Ok(()),
        };
        let targets: Vec<NoticeAddress> = tx
            .notice_addresses(subject)
            .await?
            .into_iter()
            .filter(|a| a.recovery_target && a.recovery_contact == contact)
            .collect();
        for t in targets {
            let mut raw = [0; 8];
            self.random.fill(&mut raw)?;
            let code = email_code(&raw);
            let expires = now.saturating_add(ttl);
            tx.insert_evidence(
                attempt,
                class.name(),
                &code_digest(&attempt, &code),
                Some(t.id),
                i64_of(expires)?,
            )
            .await?;
            let valid_since_ms = valid_since(&t.to, t.since_ms);
            tx.notify(
                self.notifier,
                &Message {
                    subject,
                    to: t.to,
                    locale: None,
                    valid_since_ms,
                    body: Body::Otp {
                        code: Secret::new(code),
                        purpose: OtpPurpose::Recovery,
                        expires_at_ms: expires,
                    },
                },
            )
            .await?;
        }
        Ok(())
    }

    /// `POST /v1/recovery` (TN-54, OP-153 m.3 (d)): opens an attempt. The answer is the same
    /// whether or not the identifier names an account, whether or not anything was sent, and
    /// whether or not the account's own start limit was reached; only the network prefix's limit
    /// answers `429`, for every identifier alike. The account's notice addresses hear of it,
    /// never its recovery channel (TN-57).
    ///
    /// # Errors
    /// [`SessionError`].
    #[expect(
        clippy::too_many_lines,
        reason = "one neutral start, read top to bottom"
    )]
    pub async fn start_recovery(
        &self,
        identifier: &str,
        start: RecoveryPath,
        network: &[u8],
        correlation: &str,
    ) -> Result<Answer, SessionError> {
        if !matches!(
            start,
            RecoveryPath::RegisteredCode
                | RecoveryPath::SentCode
                | RecoveryPath::RecoveryContact
                | RecoveryPath::SecondAuthenticator
        ) {
            return Ok(Answer::Refused(RECOVERY_INVALID));
        }
        let folded = Self::folded(identifier)?;
        let now = self.now();
        let (tenant, realm) = (self.realm.tenant.as_bytes(), self.realm.realm.as_bytes());
        let mut tx = self.begin().await?;
        let ip = counter_key(
            KeyKind::Ip,
            tenant,
            realm,
            None,
            Some(&[b"recovery-start:".as_slice(), network].concat()),
        );
        if let Err(retry_after_s) = self.gate(&mut tx, &ip, &START_PER_PREFIX, now).await? {
            tx.commit().await?;
            return Ok(Answer::Throttled { retry_after_s });
        }
        let account = counter_key(
            KeyKind::Account,
            tenant,
            realm,
            Some(&folded),
            Some(b"recovery-start"),
        );
        let limited = self
            .gate(&mut tx, &account, &START_PER_ACCOUNT, now)
            .await?
            .is_err();
        let mut subject = None;
        if let Some(s) = tx.subject_by_identifier(&folded).await?
            && tx
                .subject(s, false)
                .await?
                .is_some_and(|r| super::active(&r.status))
        {
            subject = Some(s);
        }
        let policy = self.realm_policy(&mut tx).await?;
        let mut live = subject.filter(|_| !limited);
        // TN-60
        if let Some(s) = live
            && start != RecoveryPath::RegisteredCode
            && !self.assisted(&mut tx, s).await?
        {
            live = None;
        }
        // RR-45, TN-17
        let rp_id_changed = access_identity_account::domain::recovery_policy::rp_id_change_tightens(
            tx.last_rp_id_change().await?,
            now,
        );
        let (required, high_value) = match live {
            Some(s) => (
                self.required(&mut tx, s, &policy).await?,
                self.high_value(&mut tx, s).await? || rp_id_changed,
            ),
            None => (Aal::Aal1, false),
        };
        let handle = encode(&self.random32()?);
        let cooling = serde_json::to_vec(&policy.cooling).map_err(|_| SessionError::Corrupt)?;
        let id = tx
            .insert_attempt(&NewAttempt {
                subject: live,
                handle_hash: &tokens::digest(&handle),
                path: start.name(),
                required_aal: aal_name(required),
                cooling: &cooling,
                high_value,
                at_ms: i64_of(now)?,
            })
            .await?;
        tx.transition(
            id,
            &NewTransition {
                seq: 0,
                state: State::Requested.name(),
                required_aal: Some(aal_name(required)),
                achieved_aal: None,
                evidence: &[],
                reason: "started",
                until_ms: None,
                at_ms: i64_of(now)?,
            },
        )
        .await?;
        self.send_codes(&mut tx, id, live, start, now).await?;
        let target = match subject {
            Some(s) => self.external(s)?,
            None => String::from(super::signin::UNKNOWN),
        };
        if let Some(s) = live {
            // TN-63
            if self.recently_recovered(&mut tx, s, id, now).await? {
                RECOVERY_RETRIGGERS.incr([start.name()]);
            }
            self.notice(&mut tx, s, Notice::RecoveryRequested, None, now)
                .await?;
        }
        if subject.is_some() && live.is_none() {
            audit(
                &mut tx,
                "recovery.start_limited",
                ANONYMOUS,
                &target,
                correlation,
            )
            .await?;
        } else {
            audit(
                &mut tx,
                "recovery.requested",
                ANONYMOUS,
                &target,
                correlation,
            )
            .await?;
        }
        tx.commit().await?;
        RECOVERY_TRANSITIONS.incr([start.name(), State::Requested.name()]);
        let attempt = AttemptView {
            attempt: encode(&id),
            state: State::Requested,
            path: start,
            required: Aal::Aal1,
            achieved: None,
            evidence: Vec::new(),
            until_ms: None,
        };
        Ok(Answer::Done(Box::new(Recovered {
            view: Some(attempt),
            cookies: vec![set_cookie(RECOVERY_COOKIE, &handle, Some(ATTEMPT_COOKIE_S))],
            ..Recovered::default()
        })))
    }

    async fn recently_recovered(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        current: [u8; 16],
        now: u64,
    ) -> Result<bool, SessionError> {
        let since = i64_of(now.saturating_sub(RETRIGGER_WINDOW_MS))?;
        for a in tx.attempts_since(subject, since).await? {
            if a.id == current {
                continue;
            }
            let ts = tx.transitions(a.id).await?;
            if ts.iter().any(|t| t.state == State::GracePeriod.name()) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn attempt_of(
        &self,
        tx: &mut D::Tx,
        handle: Option<&str>,
        reference: &str,
    ) -> Result<Option<AttemptRow>, SessionError> {
        let Some(handle) = handle else {
            return Ok(None);
        };
        let Some(a) = tx.attempt(&tokens::digest(handle)).await? else {
            return Ok(None);
        };
        if encode(&a.id) != reference {
            return Ok(None);
        }
        tx.recovery_lock(&a.id).await?;
        Ok(Some(a))
    }

    /// `GET /v1/recovery/{attempt}`: the attempt's state for the browser holding its cookie.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn recovery(
        &self,
        handle: Option<&str>,
        reference: &str,
    ) -> Result<Answer, SessionError> {
        let mut tx = self.begin().await?;
        let Some(a) = self.attempt_of(&mut tx, handle, reference).await? else {
            return Ok(Answer::Refused(RECOVERY_GONE));
        };
        let ts = tx.transitions(a.id).await?;
        let v = Self::public_view(&a, &ts)?;
        tx.commit().await?;
        Ok(Answer::Done(Box::new(Recovered {
            view: Some(v),
            ..Recovered::default()
        })))
    }

    /// `POST /v1/recovery/{attempt}/extension` (OP-153 m.3 (d), TN-52): extends the attempt's
    /// recovery contact codes once by 24 hours, before they run out. The answer is the attempt's
    /// view whether or not anything was extended (CR-40).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn extend_recovery(
        &self,
        handle: Option<&str>,
        reference: &str,
        correlation: &str,
    ) -> Result<Answer, SessionError> {
        let mut tx = self.begin().await?;
        let Some(a) = self.attempt_of(&mut tx, handle, reference).await? else {
            return Ok(Answer::Refused(RECOVERY_GONE));
        };
        let ts = tx.transitions(a.id).await?;
        let v = Self::public_view(&a, &ts)?;
        if !v.state.terminal() && tx.extend_contact_codes(a.id).await? > 0 {
            let target = match a.subject {
                Some(s) => self.external(s)?,
                None => String::from(super::signin::UNKNOWN),
            };
            audit(
                &mut tx,
                "recovery.contact_extended",
                ANONYMOUS,
                &target,
                correlation,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Answer::Done(Box::new(Recovered {
            view: Some(v),
            ..Recovered::default()
        })))
    }

    /// The view an attempt shows its browser: before the evidence is met the required AAL is
    /// not told, so a missing account looks like a present one (CR-40).
    fn public_view(a: &AttemptRow, ts: &[TransitionRow]) -> Result<AttemptView, SessionError> {
        let mut v = view(a, ts)?;
        if matches!(v.state, State::Requested | State::Throttled | State::Locked) {
            v.required = Aal::Aal1;
        }
        Ok(v)
    }

    /// `POST /v1/recovery/{attempt}`: one step (TN-54). A proof is checked, spent and recorded
    /// in one transaction; ten failures lock the attempt, waits grow from 30 s to an hour.
    ///
    /// # Errors
    /// [`SessionError`].
    #[expect(clippy::too_many_lines, reason = "one typed transition per proof kind")]
    pub async fn prove_recovery(
        &self,
        handle: Option<&str>,
        reference: &str,
        proof: Proof<'_>,
        correlation: &str,
    ) -> Result<Answer, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(a) = self.attempt_of(&mut tx, handle, reference).await? else {
            return Ok(Answer::Refused(RECOVERY_GONE));
        };
        let ts = tx.transitions(a.id).await?;
        let (t, state) = last(&ts)?;
        let t = t.clone();
        let mut out = Recovered::default();
        match (proof, state) {
            (Proof::Code(_) | Proof::Password(_) | Proof::Send(_), State::Throttled)
                if t.until_ms.map(ms).transpose()?.unwrap_or(0) > now =>
            {
                let left = t
                    .until_ms
                    .map(ms)
                    .transpose()?
                    .unwrap_or(now)
                    .saturating_sub(now);
                return Ok(Answer::Throttled {
                    retry_after_s: left.div_ceil(1000).max(1),
                });
            }
            (Proof::Send(class), State::Requested | State::Throttled) => {
                if !matches!(
                    class,
                    RecoveryPath::SentCode | RecoveryPath::RecoveryContact
                ) {
                    return Ok(Answer::Refused(RECOVERY_INVALID));
                }
                self.send_codes(&mut tx, a.id, a.subject, class, now)
                    .await?;
            }
            (Proof::Code(code), State::Requested | State::Throttled) => {
                let spent = self.spend_code(&mut tx, &a, code, now, &mut out).await?;
                self.proved(&mut tx, &a, &t, spent, now, &mut out, correlation)
                    .await?;
                if spent.is_none() {
                    tx.commit().await?;
                    return Ok(Answer::Refused(CODE_NOT_ACCEPTED));
                }
            }
            (Proof::Password(pw), State::Requested | State::Throttled) => {
                let spent = self.spend_password(&mut tx, &a, pw, now).await?;
                self.proved(&mut tx, &a, &t, spent, now, &mut out, correlation)
                    .await?;
                if spent.is_none() {
                    tx.commit().await?;
                    return Ok(Answer::Refused(CODE_NOT_ACCEPTED));
                }
            }
            (Proof::Continue, State::CoolingDown)
                if t.until_ms.map(ms).transpose()?.unwrap_or(u64::MAX) <= now =>
            {
                self.open_rebind(&mut tx, &a, &t, now, &mut out).await?;
            }
            (Proof::Continue, State::CoolingDown) => {
                let left = t
                    .until_ms
                    .map(ms)
                    .transpose()?
                    .unwrap_or(now)
                    .saturating_sub(now);
                tx.commit().await?;
                return Ok(Answer::Refused(Problem {
                    retry_after_s: Some(left.div_ceil(1000)),
                    ..RECOVERY_STEP
                }));
            }
            (Proof::Successor { kid, rebind }, State::RebindOpen) => {
                if let Err(p) = self
                    .successor(&mut tx, &a, &t, kid, rebind, now, &mut out, correlation)
                    .await?
                {
                    return Ok(Answer::Refused(p));
                }
            }
            (Proof::Bind { password, rebind }, State::RebindOpen) => {
                match self
                    .bind(
                        &mut tx,
                        &a,
                        &t,
                        password,
                        rebind,
                        now,
                        &mut out,
                        correlation,
                    )
                    .await?
                {
                    Ok(()) => {}
                    Err(p) => return Ok(Answer::Refused(p)),
                }
            }
            (_, State::Locked) => return Ok(Answer::Refused(RECOVERY_LOCKED)),
            (_, State::Denied | State::Closed) => return Ok(Answer::Refused(RECOVERY_GONE)),
            _ => return Ok(Answer::Refused(RECOVERY_STEP)),
        }
        let ts = tx.transitions(a.id).await?;
        let (_, after) = last(&ts)?;
        let v = Self::public_view(&a, &ts)?;
        tx.commit().await?;
        if after == State::Locked {
            return Ok(Answer::Refused(RECOVERY_LOCKED));
        }
        out.view = Some(v);
        Ok(Answer::Done(Box::new(out)))
    }

    /// Spends a code against the attempt: a sent code of one of its addresses, or one of the
    /// account's registered recovery codes, which is replaced by exactly one new code shown once
    /// (OP-153 m.3 (d)). `None` when nothing matched; every live sent code loses a try.
    async fn spend_code(
        &self,
        tx: &mut D::Tx,
        a: &AttemptRow,
        code: &str,
        now: u64,
        out: &mut Recovered,
    ) -> Result<Option<RecoveryPath>, SessionError> {
        let typed = code.trim();
        if typed.len() > 64 {
            return Ok(None);
        }
        let digits = !typed.is_empty() && typed.bytes().all(|b| b.is_ascii_digit());
        if digits {
            let presented = code_digest(&a.id, typed);
            let live = tx.evidence(a.id).await?;
            for e in &live {
                if ms(e.expires_ms)? > now
                    && Secret::new(e.code_hash).ct_eq_bytes(&presented)
                    && tx.consume_evidence(e.id, i64_of(now)?).await?
                {
                    return Ok(path(&e.class));
                }
            }
            for e in &live {
                tx.spend_try(e.id).await?;
            }
            return Ok(None);
        }
        let Some(subject) = a.subject else {
            return Ok(None);
        };
        let key = self.factor_key(subject, RECOVERY_CODE);
        let Ok(opened) = self.factor_gate(tx, &key, now).await? else {
            return Ok(None);
        };
        let row = tx
            .subject(subject, true)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let dek = subject_key(&self.realm, &row)?;
        let mut matched = None;
        for c in tx.credentials(subject, RECOVERY_CODE).await? {
            let secret = open(&self.realm, &dek, &subject, RECOVERY_CODE, &c.sealed)?;
            let Some(presented) = Password::presented(&canonical_recovery_code(typed)) else {
                continue;
            };
            if self.hasher.verify(&presented, secret).await?.matched {
                matched = Some(c.id);
                break;
            }
        }
        self.factor_counted(tx, &key, &opened, matched.is_some(), now)
            .await?;
        let Some(used) = matched else {
            return Ok(None);
        };
        let mut raw = [0; RECOVERY_CODE_BYTES];
        self.random.fill(&mut raw)?;
        let fresh = recovery_code(&raw);
        let typed_fresh =
            Password::presented(&canonical_recovery_code(&fresh)).ok_or(SessionError::Corrupt)?;
        let phc = self.hasher.hash(&typed_fresh, self.random.salt()?).await?;
        let sealed = seal(
            &self.realm,
            &dek,
            &subject,
            RECOVERY_CODE,
            phc.expose().as_bytes(),
        )?;
        tx.insert_credential(&NewCredential {
            subject,
            kind: RECOVERY_CODE,
            algorithm: ALGORITHM,
            sealed: &sealed,
        })
        .await?;
        if tx.revoke(subject, used).await? != Revoke::Done {
            return Err(SessionError::Corrupt);
        }
        out.replacement = Some(Secret::new(fresh));
        Ok(Some(RecoveryPath::RegisteredCode))
    }

    /// Checks the account's current password as a single-factor authenticator bound to it
    /// (§12.3.2 AAL matrix), under the per-authenticator failure limit (TN-59).
    async fn spend_password(
        &self,
        tx: &mut D::Tx,
        a: &AttemptRow,
        typed: &str,
        now: u64,
    ) -> Result<Option<RecoveryPath>, SessionError> {
        let Some(subject) = a.subject else {
            return Ok(None);
        };
        let Some(presented) = Password::presented(typed) else {
            return Ok(None);
        };
        let key = self.factor_key(subject, PASSWORD);
        let Ok(opened) = self.factor_gate(tx, &key, now).await? else {
            return Ok(None);
        };
        let row = tx
            .subject(subject, false)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let dek = subject_key(&self.realm, &row)?;
        let mut ok = false;
        for c in tx.credentials(subject, PASSWORD).await? {
            let (secret, _) = access_identity_account::app::sealing::open_password(
                &self.realm,
                &dek,
                &subject,
                &c.sealed,
            )?;
            if self.hasher.verify(&presented, secret).await?.matched {
                ok = true;
                break;
            }
        }
        self.factor_counted(tx, &key, &opened, ok, now).await?;
        Ok(ok.then_some(RecoveryPath::SecondAuthenticator))
    }

    /// Records a proof's outcome: a failure throttles or locks the attempt; a success adds its
    /// class, and once the evidence reaches the required AAL the attempt meets it and starts its
    /// objection window, or opens the rebind at once when the cooling is zero.
    #[expect(
        clippy::too_many_arguments,
        reason = "one proof's outcome and its context"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "the typed transitions after one proof"
    )]
    async fn proved(
        &self,
        tx: &mut D::Tx,
        a: &AttemptRow,
        t: &TransitionRow,
        spent: Option<RecoveryPath>,
        now: u64,
        out: &mut Recovered,
        correlation: &str,
    ) -> Result<(), SessionError> {
        let seq = t.seq.checked_add(1).ok_or(SessionError::Corrupt)?;
        let at = i64_of(now)?;
        let Some(class) = spent else {
            let failures = tx
                .transitions(a.id)
                .await?
                .iter()
                .filter(|r| r.state == State::Throttled.name())
                .count()
                .saturating_add(1);
            let (state, until) = if failures >= ATTEMPT_FAILURES {
                (State::Locked, None)
            } else {
                (
                    State::Throttled,
                    Some(i64_of(now.saturating_add(backoff_ms(failures)))?),
                )
            };
            tx.transition(
                a.id,
                &NewTransition {
                    seq,
                    state: state.name(),
                    required_aal: t.required_aal.as_deref(),
                    achieved_aal: t.achieved_aal.as_deref(),
                    evidence: &t.evidence,
                    reason: "evidence_failed",
                    until_ms: until,
                    at_ms: at,
                },
            )
            .await?;
            RECOVERY_TRANSITIONS.incr([path_word(&a.path), state.name()]);
            return Ok(());
        };
        let mut evidence = evidence_of(t)?;
        evidence.push(class);
        let reached = achieved(&evidence);
        let required = aal_of(&a.required_aal).ok_or(SessionError::Corrupt)?;
        let ev = names(&evidence);
        let reached_name = reached.map(aal_name);
        if reached.is_none_or(|r| r < required) {
            tx.transition(
                a.id,
                &NewTransition {
                    seq,
                    state: State::Requested.name(),
                    required_aal: Some(&a.required_aal),
                    achieved_aal: reached_name,
                    evidence: &ev,
                    reason: "evidence_added",
                    until_ms: None,
                    at_ms: at,
                },
            )
            .await?;
            return Ok(());
        }
        tx.transition(
            a.id,
            &NewTransition {
                seq,
                state: State::EvidenceMet.name(),
                required_aal: Some(&a.required_aal),
                achieved_aal: reached_name,
                evidence: &ev,
                reason: "evidence_met",
                until_ms: None,
                at_ms: at,
            },
        )
        .await?;
        RECOVERY_TRANSITIONS.incr([path_word(&a.path), State::EvidenceMet.name()]);
        let table: CoolingTable =
            serde_json::from_slice(&a.cooling).map_err(|_| SessionError::Corrupt)?;
        let cooling = table.cooling(&evidence, false, a.high_value);
        let subject = a.subject.ok_or(SessionError::Corrupt)?;
        let target = self.external(subject)?;
        if cooling == 0 {
            let met = tx.transitions(a.id).await?;
            let (m, _) = last(&met)?;
            let m = m.clone();
            self.open_rebind(tx, a, &m, now, out).await?;
        } else {
            let until = now.saturating_add(cooling);
            tx.transition(
                a.id,
                &NewTransition {
                    seq: seq.checked_add(1).ok_or(SessionError::Corrupt)?,
                    state: State::CoolingDown.name(),
                    required_aal: Some(&a.required_aal),
                    achieved_aal: reached_name,
                    evidence: &ev,
                    reason: "cooling",
                    until_ms: Some(i64_of(until)?),
                    at_ms: at,
                },
            )
            .await?;
            RECOVERY_TRANSITIONS.incr([path_word(&a.path), State::CoolingDown.name()]);
            // TN-57, U67
            self.notice(tx, subject, Notice::RecoveryCooling, Some(until), now)
                .await?;
        }
        audit(tx, "recovery.evidence_met", ANONYMOUS, &target, correlation).await?;
        Ok(())
    }

    /// `REBIND_OPEN`: hands the browser the credential-only rebind token (TN-53 rule 2).
    async fn open_rebind(
        &self,
        tx: &mut D::Tx,
        a: &AttemptRow,
        t: &TransitionRow,
        now: u64,
        out: &mut Recovered,
    ) -> Result<(), SessionError> {
        let subject = a.subject.ok_or(SessionError::Corrupt)?;
        tx.transition(
            a.id,
            &NewTransition {
                seq: t.seq.checked_add(1).ok_or(SessionError::Corrupt)?,
                state: State::RebindOpen.name(),
                required_aal: t.required_aal.as_deref(),
                achieved_aal: t.achieved_aal.as_deref(),
                evidence: &t.evidence,
                reason: "rebind_open",
                until_ms: None,
                at_ms: i64_of(now)?,
            },
        )
        .await?;
        RECOVERY_TRANSITIONS.incr([path_word(&a.path), State::RebindOpen.name()]);
        let token = encode(&self.random32()?);
        tx.insert_token(&NewToken {
            subject,
            kind: REBIND,
            token_hash: &tokens::digest(&token),
            attempt: Some(a.id),
            exercise: None,
            address: None,
            entropy_bits: 256,
            one_time: true,
            at_ms: i64_of(now)?,
            expires_ms: i64_of(now.saturating_add(REBIND_TTL_MS))?,
        })
        .await?
        .ok_or(SessionError::Corrupt)?;
        out.cookies.push(set_cookie(
            REBIND_COOKIE,
            &token,
            Some(REBIND_TTL_MS / 1000),
        ));
        Ok(())
    }

    /// `REBIND_OPEN`: queues the realm issuer's `recovery_result` Claim naming `kid` as the
    /// successor that may self-sign `instance_recover` (OP-153 m.3 (c), INV-40, §7.7). The
    /// rebind token proves the browser and is not spent; naming another key supersedes the
    /// first (one line per attempt). An account without a Party has no Instance to recover.
    #[expect(clippy::too_many_arguments, reason = "one step and its context")]
    async fn successor(
        &self,
        tx: &mut D::Tx,
        a: &AttemptRow,
        t: &TransitionRow,
        kid: [u8; 32],
        rebind: Option<&str>,
        now: u64,
        out: &mut Recovered,
        correlation: &str,
    ) -> Result<Result<(), Problem>, SessionError> {
        let subject = a.subject.ok_or(SessionError::Corrupt)?;
        let Some(token) = rebind else {
            return Ok(Err(RECOVERY_STEP));
        };
        if tx
            .token(&tokens::digest(token), &kinds(&[REBIND]), i64_of(now)?)
            .await?
            .is_none_or(|r| r.attempt != Some(a.id) || r.subject != subject)
        {
            return Ok(Err(RECOVERY_STEP));
        }
        let (Some(party), Some(predecessor)) = (
            tx.subject_party(subject).await?,
            tx.subject_instance(subject).await?,
        ) else {
            return Ok(Err(NO_PARTY));
        };
        let achieved = t
            .achieved_aal
            .as_deref()
            .and_then(aal_of)
            .unwrap_or(Aal::Aal1);
        let result = RecoveryResult {
            party: access_kernel::model::Id(party),
            successor: kid,
            attempt: access_kernel::model::Id(a.id),
            path: path(&a.path).ok_or(SessionError::Corrupt)?,
            achieved_aal: crate::domain::recovery::aal_level(achieved),
        };
        emit(tx, &recovery_result(subject, &result, now)).await?;
        let target = self.external(subject)?;
        audit(
            tx,
            "recovery.successor_named",
            &target,
            &target,
            correlation,
        )
        .await?;
        out.successor = Some((party, predecessor));
        Ok(Ok(()))
    }

    /// The successor the signed-in subject of `cookie` may now recover in `domain` (OP-153
    /// m.3 (c)): its attempt is in the grace period that followed the rebind and the realm
    /// issuer's `recovery_result` of that attempt reached Claim Ingest. The authority plane
    /// checks that the Claim names the key.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn recovered_successor(
        &self,
        cookie: &str,
        domain: [u8; 32],
    ) -> Result<Result<Successor, Problem>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(subject) = self.signed_in(&mut tx, cookie, now).await? else {
            tx.commit().await?;
            return Ok(Err(SESSION_REQUIRED));
        };
        let since = i64_of(now.saturating_sub(LIVE_WINDOW_MS))?;
        let mut found = None;
        for a in tx.attempts_since(subject, since).await? {
            let ts = tx.transitions(a.id).await?;
            if matches!(last(&ts), Ok((_, State::GracePeriod))) {
                found = Some(a.id);
            }
        }
        let (Some(attempt), Some(party), Some(predecessor)) = (
            found,
            tx.subject_party(subject).await?,
            tx.subject_instance(subject).await?,
        ) else {
            tx.commit().await?;
            return Ok(Err(NO_PARTY));
        };
        let line = access_identity_account::domain::claims::recovery_result_line(&attempt);
        let claim = tx.issued_in_line(subject, domain, line).await?;
        tx.commit().await?;
        Ok(claim.map_or(Err(RESULT_PENDING), |claim| {
            Ok(Successor {
                subject,
                attempt,
                party,
                predecessor,
                claim,
            })
        }))
    }

    /// Binds a new password in the rebind window, the one atomic unit of TN-54: the state is
    /// `REBIND_OPEN`, the rebind token is spent once, the password is stored and the grace period
    /// starts, in one transaction. The other sessions and refresh families end (TN-64), the
    /// federated links are cut and counted (TN-64), and the browser is signed in under the
    /// grace period (TN-56).
    #[expect(clippy::too_many_arguments, reason = "one rebind and its context")]
    #[expect(clippy::too_many_lines, reason = "one atomic unit of TN-54")]
    async fn bind(
        &self,
        tx: &mut D::Tx,
        a: &AttemptRow,
        t: &TransitionRow,
        raw: &str,
        rebind: Option<&str>,
        now: u64,
        out: &mut Recovered,
        correlation: &str,
    ) -> Result<Result<(), Problem>, SessionError> {
        let subject = a.subject.ok_or(SessionError::Corrupt)?;
        let Some(token) = rebind else {
            return Ok(Err(RECOVERY_STEP));
        };
        let Some(row) = tx
            .token(&tokens::digest(token), &kinds(&[REBIND]), i64_of(now)?)
            .await?
            .filter(|r| r.attempt == Some(a.id) && r.subject == subject)
        else {
            return Ok(Err(RECOVERY_STEP));
        };
        let Ok(password) = Password::new(raw) else {
            return Ok(Err(PASSWORD_REFUSED));
        };
        match self.risk.services.breach.check(&password).await {
            Breach::Clean => {}
            Breach::Listed => return Ok(Err(PASSWORD_REFUSED)),
            Breach::Unavailable | Breach::NotChecked => {
                return Err(SessionError::Account(
                    access_identity_account::AccountError::BreachUnavailable,
                ));
            }
        }
        // TN-54
        if !tx.use_token(row.id, i64_of(now)?).await? {
            return Ok(Err(RECOVERY_STEP));
        }
        let phc = self.hasher.hash(&password, self.random.salt()?).await?;
        let target = self.external(subject)?;
        let who = Actor {
            actor: &target,
            correlation,
        };
        store_password(tx, &self.realm, subject, phc.expose(), &who).await?;
        let until = now.saturating_add(GRACE_MS);
        if !tx
            .transition(
                a.id,
                &NewTransition {
                    seq: t.seq.checked_add(1).ok_or(SessionError::Corrupt)?,
                    state: State::GracePeriod.name(),
                    required_aal: t.required_aal.as_deref(),
                    achieved_aal: t.achieved_aal.as_deref(),
                    evidence: &t.evidence,
                    reason: "authenticator_bound",
                    until_ms: Some(i64_of(until)?),
                    at_ms: i64_of(now)?,
                },
            )
            .await?
        {
            return Err(SessionError::Conflict);
        }
        RECOVERY_TRANSITIONS.incr([path_word(&a.path), State::GracePeriod.name()]);
        // TN-64
        let ended = tx.live_sessions(subject).await?;
        let epoch = tx
            .end_sessions(subject)
            .await?
            .ok_or(SessionError::Corrupt)?;
        events::sessions_ended(tx, &self.realm, subject, epoch).await?;
        for s in ended {
            emit(tx, &authentication_ended(subject, s.id, now)).await?;
        }
        let s = Signal::session_revoked(fresh_id()?, subject, Initiator::User, now);
        signal(tx, &s).await?;
        tx.revoke_tokens(
            subject,
            &kinds(&[REBIND, RESET_INTENT, TEMPORARY_ACCESS_PASS]),
        )
        .await?;
        // TN-64
        out.links_cut = tx.cut_federated_links(subject).await?;
        let cookie = self.random32()?;
        let assurance = serde_json::to_vec(&vector(&[Factor::password(now)]))
            .map_err(|_| SessionError::Corrupt)?;
        tx.insert_session(&NewSession {
            cookie_hash: &cookie_digest(&cookie),
            subject,
            session_epoch: epoch,
            keep_signed_in: false,
            created_ms: i64_of(now)?,
            auth_time_ms: i64_of(now.max(1))?,
            idle_ms: i64_of(self.lifetimes.idle_ms)?,
            expires_ms: i64_of(now.saturating_add(self.lifetimes.absolute_ms))?,
            assurance: &assurance,
        })
        .await?;
        out.cookies
            .push(set_cookie(SESSION_COOKIE, &encode(&cookie), None));
        out.cookies.push(clear_cookie(REBIND_COOKIE));
        out.cookies.push(clear_cookie(RECOVERY_COOKIE));
        out.sensitive_after_ms = Some(until);
        // TN-57, Ek B 3657
        self.notice(tx, subject, Notice::RecoveryCompleted, None, now)
            .await?;
        if let Some(to) = address(tx.contact(subject).await?) {
            let valid_since_ms = valid_since(&to, tx.mailbox_since(subject).await?.unwrap_or(1));
            tx.notify(
                self.notifier,
                &Message {
                    subject,
                    to,
                    locale: None,
                    valid_since_ms,
                    body: Body::PasswordChanged { at_ms: now },
                },
            )
            .await?;
        }
        audit(tx, "recovery.completed", &target, &target, correlation).await?;
        audit(tx, "session.created", &target, &target, correlation).await?;
        Ok(Ok(()))
    }

    /// `POST /v1/recovery/intents/{token}` (TN-61, TN-62): a reset intent or a temporary access
    /// pass opens an attempt straight at its rebind window: the token is spent once, its use is
    /// its own audit event apart from its issue, and the window binds a credential only. The
    /// answer for an unknown, used or expired token is the one neutral `410`.
    ///
    /// # Errors
    /// [`SessionError`].
    #[expect(
        clippy::too_many_lines,
        reason = "one token, one attempt, one rebind window"
    )]
    pub async fn redeem(&self, token: &str, correlation: &str) -> Result<Answer, SessionError> {
        if token.is_empty() || token.len() > 128 {
            return Ok(Answer::Refused(RECOVERY_GONE));
        }
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut found = tx
            .token(
                &tokens::digest(token),
                &kinds(&[RESET_INTENT]),
                i64_of(now)?,
            )
            .await?;
        if found.is_none() {
            found = tx
                .token(
                    &tokens::typed_digest(token),
                    &kinds(&[TEMPORARY_ACCESS_PASS]),
                    i64_of(now)?,
                )
                .await?;
        }
        let Some(row) = found else {
            return Ok(Answer::Refused(RECOVERY_GONE));
        };
        let subject = row.subject;
        tx.recovery_lock(&subject).await?;
        let pass = row.kind == TEMPORARY_ACCESS_PASS;
        let start = if pass {
            RecoveryPath::TemporaryAccessPass
        } else {
            RecoveryPath::ResetIntent
        };
        let policy = self.realm_policy(&mut tx).await?;
        let required = self.required(&mut tx, subject, &policy).await?;
        // TN-53 rule 1, TN-60
        if label(start) < required || !self.assisted(&mut tx, subject).await? {
            tx.commit().await?;
            return Ok(Answer::Refused(RECOVERY_TOO_WEAK));
        }
        if !tx.use_token(row.id, i64_of(now)?).await? {
            return Ok(Answer::Refused(RECOVERY_GONE));
        }
        let handle = encode(&self.random32()?);
        let cooling = serde_json::to_vec(&policy.cooling).map_err(|_| SessionError::Corrupt)?;
        let high_value = self.high_value(&mut tx, subject).await?;
        let id = tx
            .insert_attempt(&NewAttempt {
                subject: Some(subject),
                handle_hash: &tokens::digest(&handle),
                path: start.name(),
                required_aal: aal_name(required),
                cooling: &cooling,
                high_value,
                at_ms: i64_of(now)?,
            })
            .await?;
        let at = i64_of(now)?;
        tx.transition(
            id,
            &NewTransition {
                seq: 0,
                state: State::Requested.name(),
                required_aal: Some(aal_name(required)),
                achieved_aal: None,
                evidence: &[],
                reason: "token_presented",
                until_ms: None,
                at_ms: at,
            },
        )
        .await?;
        let a = AttemptRow {
            id,
            subject: Some(subject),
            path: String::from(start.name()),
            required_aal: String::from(aal_name(required)),
            cooling,
            high_value,
            opened_ms: at,
        };
        let t = tx.transitions(id).await?;
        let (first, _) = last(&t)?;
        let first = first.clone();
        let mut out = Recovered::default();
        self.proved(&mut tx, &a, &first, Some(start), now, &mut out, correlation)
            .await?;
        let target = self.external(subject)?;
        if pass {
            audit(&mut tx, "recovery.tap.used", &target, &target, correlation).await?;
        } else {
            audit(
                &mut tx,
                "recovery.reset_intent.used",
                &target,
                &target,
                correlation,
            )
            .await?;
        }
        self.notice(&mut tx, subject, Notice::RecoveryRequested, None, now)
            .await?;
        let ts = tx.transitions(id).await?;
        out.view = Some(view(&a, &ts)?);
        tx.commit().await?;
        out.cookies
            .push(set_cookie(RECOVERY_COOKIE, &handle, Some(ATTEMPT_COOKIE_S)));
        Ok(Answer::Done(Box::new(out)))
    }

    /// The signed-in subject of `cookie`, or `None` when the session is not live (G57).
    async fn signed_in(
        &self,
        tx: &mut D::Tx,
        cookie: &str,
        now: u64,
    ) -> Result<Option<[u8; 16]>, SessionError> {
        Ok(self
            .live_session(tx, cookie, now)
            .await?
            .ok()
            .map(|s| s.subject))
    }

    async fn configured(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
    ) -> Result<Vec<RecoveryPath>, SessionError> {
        let mut classes: Vec<RecoveryPath> = tx
            .recovery_methods(subject)
            .await?
            .iter()
            .filter_map(|m| path(&m.class))
            .collect();
        if !tx.credentials(subject, RECOVERY_CODE).await?.is_empty() {
            classes.push(RecoveryPath::RegisteredCode);
        }
        if !tx.credentials(subject, PASSWORD).await?.is_empty() {
            classes.push(RecoveryPath::SecondAuthenticator);
        }
        classes.dedup();
        Ok(classes)
    }

    /// `GET /v1/account/recovery-contacts`: the account's recovery addresses, the classes a
    /// recovery can prove with and the weakest path (TN-53 rule 3).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn recovery_setup(
        &self,
        cookie: &str,
    ) -> Result<Result<RecoverySetup, Problem>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(subject) = self.signed_in(&mut tx, cookie, now).await? else {
            tx.commit().await?;
            return Ok(Err(SESSION_REQUIRED));
        };
        let setup = self.setup_of(&mut tx, subject).await?;
        tx.commit().await?;
        Ok(Ok(setup))
    }

    async fn setup_of(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
    ) -> Result<RecoverySetup, SessionError> {
        let rows = tx.notice_addresses(subject).await?;
        let policy = self.realm_policy(tx).await?;
        let required = self.required(tx, subject, &policy).await?;
        let classes = self.configured(tx, subject).await?;
        let weakest = classes.iter().map(|c| label(*c)).min();
        Ok(RecoverySetup {
            contacts: rows
                .iter()
                .filter(|a| a.recovery_contact)
                .map(|a| shown(&a.to))
                .collect(),
            recovery_email: rows
                .iter()
                .find(|a| a.recovery_target && !a.recovery_contact)
                .map(|a| shown(&a.to)),
            notice_addresses: rows.iter().filter(|a| !a.recovery_target).count(),
            classes,
            weakest,
            required,
            assisted: self.assisted(tx, subject).await?,
        })
    }

    /// `PUT /v1/account/recovery-contacts` (TN-52, TN-53, TN-57, TN-60): replaces the account's
    /// recovery addresses. A configuration that cannot reach the account's AAL is refused now,
    /// never at run time; the sign-in contact stays a notice address, so a recovery target is
    /// never the only one; the grace period refuses a new recovery address.
    ///
    /// # Errors
    /// [`SessionError`].
    #[expect(
        clippy::too_many_lines,
        reason = "one configuration, checked then written"
    )]
    pub async fn set_recovery_setup(
        &self,
        cookie: &str,
        change: &SetupChange,
        correlation: &str,
    ) -> Result<Result<RecoverySetup, Problem>, SessionError> {
        if change.contacts.len() > MAX_CONTACTS
            || (!change.assisted && !change.permanent_loss_acknowledged)
        {
            return Ok(Err(RECOVERY_INVALID));
        }
        let contacts: Option<Vec<Address>> = change.contacts.iter().map(|c| email(c)).collect();
        let recovery = change.recovery_email.as_deref().map(email);
        let (Some(contacts), Some(recovery)) =
            (contacts, recovery.map_or(Some(None), |r| r.map(Some)))
        else {
            return Ok(Err(RECOVERY_INVALID));
        };
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(subject) = self.signed_in(&mut tx, cookie, now).await? else {
            tx.commit().await?;
            return Ok(Err(SESSION_REQUIRED));
        };
        tx.recovery_lock(&subject).await?;
        if let Err(p) = grace_check(&mut tx, subject, now, Restricted::RecoveryAddress).await? {
            tx.commit().await?;
            return Ok(Err(p));
        }
        let login = address(tx.contact(subject).await?);
        if recovery.is_some() && login.is_none() {
            return Ok(Err(RECOVERY_INVALID));
        }
        let mut planned: Vec<RecoveryPath> = Vec::new();
        if recovery.is_some() {
            planned.push(RecoveryPath::SentCode);
        }
        if !contacts.is_empty() {
            planned.push(RecoveryPath::RecoveryContact);
        }
        if !tx.credentials(subject, RECOVERY_CODE).await?.is_empty() {
            planned.push(RecoveryPath::RegisteredCode);
        }
        if !tx.credentials(subject, PASSWORD).await?.is_empty() {
            planned.push(RecoveryPath::SecondAuthenticator);
        }
        let policy = self.realm_policy(&mut tx).await?;
        let required = self.required(&mut tx, subject, &policy).await?;
        // TN-53 rule 1, INV-40 (i), TNI-4
        if !planned.is_empty() && too_weak(required, &planned) {
            tx.commit().await?;
            return Ok(Err(RECOVERY_TOO_WEAK));
        }
        for m in tx.recovery_methods(subject).await? {
            tx.retire_recovery_method(subject, m.id).await?;
        }
        for a in tx.notice_addresses(subject).await? {
            tx.retire_notice_address(subject, a.id).await?;
        }
        if let Some(to) = login {
            tx.add_notice_address(
                subject,
                &NoticeAddress {
                    id: [0; 16],
                    to,
                    recovery_target: false,
                    recovery_contact: false,
                    since_ms: 0,
                },
            )
            .await?;
        }
        if let Some(to) = recovery {
            let id = tx
                .add_notice_address(
                    subject,
                    &NoticeAddress {
                        id: [0; 16],
                        to,
                        recovery_target: true,
                        recovery_contact: false,
                        since_ms: 0,
                    },
                )
                .await?;
            tx.add_recovery_method(
                subject,
                RecoveryPath::SentCode.name(),
                aal_name(label(RecoveryPath::SentCode)),
                Some(id),
            )
            .await?;
        }
        for to in contacts {
            let id = tx
                .add_notice_address(
                    subject,
                    &NoticeAddress {
                        id: [0; 16],
                        to,
                        recovery_target: true,
                        recovery_contact: true,
                        since_ms: 0,
                    },
                )
                .await?;
            tx.add_recovery_method(
                subject,
                RecoveryPath::RecoveryContact.name(),
                aal_name(label(RecoveryPath::RecoveryContact)),
                Some(id),
            )
            .await?;
        }
        let current = tx.account_recovery_policy(subject).await?;
        if current.as_ref().is_none_or(|p| p.assisted_recovery) != change.assisted {
            tx.set_account_recovery_policy(
                subject,
                &access_store::recovery::AccountPolicyRow {
                    assisted_recovery: change.assisted,
                    permanent_loss_acknowledged_ms: (!change.assisted)
                        .then(|| i64_of(now))
                        .transpose()?,
                    high_value: current.is_some_and(|p| p.high_value),
                },
            )
            .await?;
        }
        let setup = self.setup_of(&mut tx, subject).await?;
        if let Some(w) = setup.classes.iter().min_by_key(|c| label(**c)) {
            RECOVERY_WEAKEST_PATH.incr([w.name()]);
        }
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "recovery.setup.changed",
            &target,
            &target,
            correlation,
        )
        .await?;
        // SEC18, Ek B 3657
        self.notice(&mut tx, subject, Notice::NewMethod, None, now)
            .await?;
        tx.commit().await?;
        Ok(Ok(setup))
    }

    /// TN-56: whether the grace period after a recovery lets the signed-in subject of `cookie`
    /// do `action` now; a cookie that is not live passes here and is answered by the action
    /// itself (G57).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn recovery_grace(
        &self,
        cookie: &str,
        action: Restricted,
    ) -> Result<Result<(), Problem>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(subject) = self.signed_in(&mut tx, cookie, now).await? else {
            tx.commit().await?;
            return Ok(Ok(()));
        };
        let r = grace_check(&mut tx, subject, now, action).await?;
        tx.commit().await?;
        Ok(r)
    }

    /// `POST /v1/account/link-codes` (TN-59): a cross-device link code, 40 bits when the new
    /// device also types the identifier and 112 otherwise, single use, ten minutes, never sent
    /// by e-mail: the answer shows it once for a QR code or manual entry.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn link_code(
        &self,
        cookie: &str,
        with_identifier: bool,
        correlation: &str,
    ) -> Result<Result<LinkCode, Problem>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Some(subject) = self.signed_in(&mut tx, cookie, now).await? else {
            tx.commit().await?;
            return Ok(Err(SESSION_REQUIRED));
        };
        if let Err(p) = grace_check(&mut tx, subject, now, Restricted::LinkCode).await? {
            tx.commit().await?;
            return Ok(Err(p));
        }
        let mut raw = [0; 14];
        self.random.fill(&mut raw)?;
        let code = link_code(&raw, with_identifier);
        let bits = link_code_bits(with_identifier);
        let expires = now.saturating_add(LINK_CODE_TTL_MS);
        tx.insert_token(&NewToken {
            subject,
            kind: LINK_CODE,
            token_hash: &tokens::typed_digest(&code),
            attempt: None,
            exercise: None,
            address: None,
            entropy_bits: i16::try_from(bits).map_err(|_| SessionError::Corrupt)?,
            one_time: true,
            at_ms: i64_of(now)?,
            expires_ms: i64_of(expires)?,
        })
        .await?
        .ok_or(SessionError::Corrupt)?;
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "recovery.link_code.created",
            &target,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Ok(LinkCode {
            code: Secret::new(code),
            bits,
            expires_ms: expires,
        }))
    }
}

/// The range checks of a reset intent's or a pass's lifetime and length (TN-61, TN-62).
#[must_use]
pub const fn token_bounds(pass: bool, ttl_ms: u64, length: usize) -> bool {
    if pass {
        ttl_ms >= TAP_TTL_MIN_MS
            && ttl_ms <= TAP_TTL_MAX_MS
            && length >= TAP_LENGTH_MIN
            && length <= TAP_LENGTH_MAX
    } else {
        ttl_ms > 0 && ttl_ms <= INTENT_TTL_MAX_MS
    }
}

/// The decoded handle of a cookie value, for callers that keep it.
#[must_use]
pub fn handle_ok(handle: &str) -> bool {
    decode32(handle).is_some()
}
