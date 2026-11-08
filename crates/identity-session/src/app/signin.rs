//! Sign-in steps (TN-96, TN-132, TN-102, §10.2): identifier first, then any step the realm
//! allows, in any order; the flow completes when the requirement list is empty. The second
//! answer of identifier-first is the same whether the account exists or not.

use std::net::IpAddr;

use access_crypto::Secret;
use access_identity_account::AccountError;
use access_identity_account::app::login::{Attempt, LoginServices, password_login};
use access_identity_account::app::sealing::{open, subject_key};
use access_identity_account::app::signal::{emit as signal, fresh_id};
use access_identity_account::domain::gcra::Gcra;
use access_identity_account::domain::identifier::{MAX_CHARS, normalize};
use access_identity_account::domain::login::{PasswordLogin, counter_key};
use access_identity_account::domain::password::Password;
use access_identity_account::domain::signal::Signal;
use access_identity_account::domain::throttle::{
    DAY_MS as THROTTLE_DAY_MS, Gate, HARD_LOCK_AT, KeyKind, KeyPolicy, KeyState, Penalty,
};
use access_identity_account::notify::message::{Address, Body, Message, OtpPurpose};
use access_identity_account::ports::Entropy;
use access_identity_webauthn::app::{AuthenticationOutcome, Identified};
use access_identity_webauthn::domain::assurance::Binding;
use access_identity_webauthn::domain::ceremony::{AssertionResponse, AuthenticationState};
use access_identity_webauthn::domain::ids::{CredentialId, UserHandle};
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::accounts::Revoke;
use access_store::sessions::{NewFlow, NewSession};
use access_store::throttle::ThrottleRow;
use serde_json::Value;

use super::{
    Auth, CODE_NOT_ACCEPTED, FACTOR_LOCKED, FlowRef, Loaded, RECOVERY_CODE, Resume,
    STEP_NOT_ALLOWED, SignedIn, Step, TOTP, active, audit, decode32, encode, gone, hex_decode,
    i64_of, load, neutral, partition, refuse, save,
};
use access_identity_account::ports::AccountTx;

use super::Notifier;
use crate::SessionError;
use crate::domain::assurance::{Aal, AuthenticationResult, Factor, MethodClass, vector};
use crate::domain::codes::{canonical_recovery_code, email_code};
use crate::domain::flow::{
    Ceremony, EMAIL_CODE_ATTEMPTS, FlowRejection, FlowState, Pending, Purpose, RiskNote,
    SUSPENSION_TTL_MS, code_digest, device_digest, handle_digest, identifier_digest, resume_digest,
};
use crate::domain::requirement::{AuthPolicy, Enrolled, Requirement, missing, with_step_up};
use crate::domain::session::{
    MARKER_COOKIE, SESSION_COOKIE, cookie_digest, marker_digest, set_cookie,
};
use crate::ports::{Clock, Random, SessionDb, SessionTx};
use access_identity_risk::app::sl2::{SignIn, evaluate, record_sign_in};
use access_identity_risk::domain::assess::Breach;
use access_identity_risk::domain::score::Level;
use access_identity_risk::domain::signal::RiskSignal;

/// The audit actor before authentication.
pub const ANONYMOUS: &str = "anonymous";
/// The audit target when no account is known.
pub const UNKNOWN: &str = "unknown";

/// The first request of a sign-in.
#[derive(Clone, Copy, Debug, Default)]
pub struct Identify<'a> {
    /// The identifier as typed; `None` starts "sign in with a passkey" (discoverable, TN-96).
    pub identifier: Option<&'a str>,
    /// The flow cookie, when the browser has one.
    pub device: Option<&'a str>,
    /// The device marker cookie, when the browser has one (X33).
    pub marker: Option<&'a str>,
    /// "Keep me signed in on this device" (TN-36).
    pub keep_signed_in: bool,
    /// "Don't ask for a second step on this device for 30 days" (X33).
    pub remember_device: bool,
}

/// What the second screen offers: the same for every identifier (TN-96, CR-40).
#[derive(Clone, Debug, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each first step the realm offers is one flag (TN-132)"
)]
pub struct StepOptions {
    /// `PublicKeyCredentialRequestOptionsJSON`, with real or decoy credentials (TN-97).
    pub passkey: Value,
    /// The password form, when the realm allows it (TN-132).
    pub password: bool,
    /// Passkey sign-in, when the realm allows it (TN-132); the options are drawn either way so
    /// the answer's shape does not depend on the policy's internals.
    pub passkey_offered: bool,
    /// E-mail code, when the realm allows it.
    pub email_code: bool,
    /// E-mail link, when the realm allows it.
    pub magic_link: bool,
}

/// A started flow.
#[derive(Clone, Debug, PartialEq)]
pub struct Started {
    /// The flow handle for the page.
    pub handle: String,
    /// The flow cookie's `Set-Cookie` value when the browser had none.
    pub set_cookie: Option<String>,
    /// The flow cookie's value.
    pub device: String,
    /// What the screen offers.
    pub options: StepOptions,
}

/// A password step. `Debug` shows neither the password nor who or where (OP-64).
#[derive(Clone, Copy)]
pub struct PasswordStep<'a> {
    /// The identifier, as on the first screen.
    pub identifier: &'a str,
    /// The password.
    pub password: &'a str,
    /// The client's address.
    pub ip: IpAddr,
    /// Request correlation id.
    pub correlation: &'a str,
}

impl core::fmt::Debug for PasswordStep<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordStep")
            .field("identifier", &"[redacted]")
            .field("password", &"[redacted]")
            .field("ip", &"[redacted]")
            .field("correlation", &self.correlation)
            .finish()
    }
}

/// What opening a magic link shows; nothing is consumed (§10.2.2: preview bots).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkPreview {
    /// A confirmation page.
    Confirm {
        /// The link is opened in the browser that started the sign-in.
        same_device: bool,
    },
    /// Expired, used or never valid.
    Invalid,
}

/// The outcome of confirming a magic link (POST).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkOutcome {
    /// Done; the starting browser continues the sign-in.
    Confirmed {
        /// Confirmed in the starting browser.
        same_device: bool,
    },
    /// Another browser opened it: an explicit confirmation is required first.
    NeedsConfirmation,
    /// Expired, used or never valid.
    Invalid,
}

/// TN-59: at most 100 consecutive failures per authenticator, waits doubling from 1 s to
/// 30 s (PD).
pub const FACTOR_THROTTLE: KeyPolicy = KeyPolicy {
    rate: Gcra {
        interval_ms: 6_000,
        burst: 10,
    },
    penalty: Penalty::Doubling {
        first_ms: 1_000,
        cap_ms: 30_000,
        lock_at: Some(HARD_LOCK_AT),
    },
};

const FACTOR_HORIZON_DAYS: i32 = 30;

struct Salts<'a, R>(&'a R);

impl<R: Random> Entropy for Salts<'_, R> {
    fn salt(&self) -> Result<[u8; 16], AccountError> {
        self.0.salt().map_err(|_| AccountError::Random)
    }
}

fn address(contact: Option<(String, String)>) -> Option<Address> {
    match contact {
        Some((kind, value)) if kind == "email" => Some(Address::Email(value)),
        Some((kind, value)) if kind == "phone" => Some(Address::Phone(value)),
        _ => None,
    }
}

fn key_state(r: &ThrottleRow) -> Result<KeyState, SessionError> {
    let u = |v: i64| u64::try_from(v).map_err(|_| SessionError::Corrupt);
    Ok(KeyState {
        tat_ms: u(r.tat_ms)?,
        failures: u32::try_from(r.failures).map_err(|_| SessionError::Corrupt)?,
        last_failure_ms: u(r.last_failure_ms)?,
        blocked_until_ms: u(r.blocked_until_ms)?,
        locked: r.locked,
    })
}

fn throttle_row(s: &KeyState) -> ThrottleRow {
    let i = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    ThrottleRow {
        tat_ms: i(s.tat_ms),
        failures: i32::try_from(s.failures).unwrap_or(i32::MAX),
        last_failure_ms: i(s.last_failure_ms),
        blocked_until_ms: i(s.blocked_until_ms),
        locked: s.locked,
    }
}

fn ceremony_of(state: &AuthenticationState) -> Ceremony {
    Ceremony {
        challenge: state.challenge,
        user: state.user.map(|u| u.as_bytes().to_vec()),
        allowed: state
            .allowed
            .iter()
            .map(|c| c.as_bytes().to_vec())
            .collect(),
        require_uv: state.require_user_verification,
        expires_at_s: state.expires_at,
    }
}

fn state_of(
    realm: access_identity_webauthn::domain::ids::RealmId,
    c: &Ceremony,
) -> Result<AuthenticationState, SessionError> {
    let user = match &c.user {
        Some(u) => Some(UserHandle::from_slice(u).ok_or(SessionError::Corrupt)?),
        None => None,
    };
    let allowed = c
        .allowed
        .iter()
        .map(|a| CredentialId::new(a).ok_or(SessionError::Corrupt))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AuthenticationState {
        realm,
        challenge: c.challenge,
        user,
        allowed,
        require_user_verification: c.require_uv,
        expires_at: c.expires_at_s,
    })
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
    fn folded(raw: &str) -> Result<String, SessionError> {
        let n = normalize(raw);
        if n.is_empty() || n.chars().count() > MAX_CHARS || n.chars().any(char::is_control) {
            return Err(SessionError::Invalid);
        }
        Ok(n.to_lowercase())
    }

    fn identifier_digest(&self, folded: &str) -> [u8; 32] {
        identifier_digest(
            self.realm.tenant.as_bytes(),
            self.realm.realm.as_bytes(),
            folded,
        )
    }

    async fn ceremony(
        &self,
        who: Identified<'_>,
        require_uv: bool,
    ) -> Result<(Ceremony, Value), SessionError> {
        let start = self
            .webauthn()
            .start_authentication(self.passkeys.rp, self.passkeys.policy, who, require_uv)
            .await?;
        Ok((ceremony_of(&start.state), start.options))
    }

    /// The first step: the identifier (TN-96). Whatever the identifier names (an account,
    /// none, a locked or deactivated one) the answer has the same shape; the passkey options
    /// carry real or decoy credentials (TN-97). Storage failure is `503`, never a sign-in
    /// (G48).
    ///
    /// # Errors
    /// [`SessionError::Invalid`] for an empty or oversized identifier; [`SessionError`].
    pub async fn identify(&self, req: &Identify<'_>) -> Result<Started, SessionError> {
        let now = self.now();
        let mut state = FlowState::new(Purpose::Login, now);
        state.keep_signed_in = req.keep_signed_in;
        state.remember_device = req.remember_device;
        state.marker = req.marker.and_then(decode32).map(|m| marker_digest(&m));
        let folded = req.identifier.map(Self::folded).transpose()?;
        let mut tx = self.begin().await?;
        let mut user = None;
        if let Some(f) = &folded {
            state.identifier = Some(self.identifier_digest(f));
            state.subject = tx.subject_by_identifier(f).await?;
            if let Some(s) = state.subject {
                user = tx.user_handle(s).await?.map(UserHandle::from_bytes);
            }
        }
        let who = match &folded {
            Some(f) => Identified::Identifier {
                normalized: f,
                user,
            },
            None => Identified::Discoverable,
        };
        let (ceremony, passkey) = self.ceremony(who, false).await?;
        state.ceremony = Some(ceremony);
        let handle = self.random32()?;
        let (device, fresh) = match req.device.and_then(decode32) {
            Some(d) => (d, false),
            None => (self.random32()?, true),
        };
        let encoded = state.encode().map_err(|_| SessionError::Corrupt)?;
        tx.insert_flow(&NewFlow {
            day: partition(now)?,
            flow_hash: &handle_digest(&handle),
            device_hash: &device_digest(&device),
            resume_hash: None,
            expires_ms: i64_of(state.expires_ms)?,
            state: &encoded,
        })
        .await?;
        tx.commit().await?;
        let device = encode(&device);
        Ok(Started {
            handle: encode(&handle),
            set_cookie: fresh
                .then(|| set_cookie(crate::domain::session::FLOW_COOKIE, &device, None)),
            device,
            options: StepOptions {
                passkey,
                password: self.policy.password,
                passkey_offered: self.policy.passkey,
                email_code: self.policy.email_otp,
                magic_link: self.policy.magic_link,
            },
        })
    }

    /// The password step (§10.2.1): the identity-account building block counts, pads and
    /// audits; this records the factor and moves the flow.
    ///
    /// # Errors
    /// [`SessionError`]; `503` when storage or the hash queue is unavailable.
    pub async fn password(
        &self,
        flow: &FlowRef<'_>,
        step: &PasswordStep<'_>,
    ) -> Result<Step, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(gone(e)),
        };
        tx.commit().await?;
        let folded = Self::folded(step.identifier)?;
        let named = l
            .state
            .identifier
            .is_none_or(|d| d == self.identifier_digest(&folded));
        if !named {
            return Ok(neutral(self.gate.mean_ms()));
        }
        if l.state.first_done() && matches!(l.state.purpose, Purpose::Login) {
            return Ok(refuse(STEP_NOT_ALLOWED));
        }
        // TN-132
        if !self.policy.password {
            return Ok(refuse(STEP_NOT_ALLOWED));
        }
        let salts = Salts(self.random);
        let services = LoginServices {
            gate: self.gate,
            clock: self.clock,
            entropy: &salts,
            hasher: self.hasher,
        };
        let outcome = password_login(
            self.db,
            &self.realm,
            &services,
            &Attempt {
                identifier: &folded,
                password: step.password,
                ip: step.ip,
                correlation: step.correlation,
            },
        )
        .await?;
        let (subject, prior_failures) = match outcome {
            PasswordLogin::Accepted {
                subject,
                prior_failures,
                ..
            } => (subject, prior_failures),
            PasswordLogin::Rejected { pad_ms } => return Ok(neutral(pad_ms)),
            PasswordLogin::Throttled { retry_after_s } => {
                return Ok(Step::Throttled { retry_after_s });
            }
        };
        // IDP-39, OP-151 m.3 (o)
        let breach = match Password::presented(step.password) {
            Some(p) => self.risk.services.breach.check(&p).await,
            None => Breach::Unavailable,
        };
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(gone(e)),
        };
        if l.state.record(subject, Factor::password(now)).is_err() {
            return Ok(neutral(0));
        }
        if matches!(l.state.purpose, Purpose::Login) {
            let note = l.state.risk.get_or_insert_with(RiskNote::default);
            note.breach = Some(breach.name().to_owned());
            note.prior_failures = Some(prior_failures);
        }
        self.advance(tx, l, now, step.correlation).await
    }

    /// A fresh passkey challenge for the flow: on retry, or for a passkey as second step.
    /// Before authentication the identifier must be given again, so decoys stay the same.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn passkey_options(
        &self,
        flow: &FlowRef<'_>,
        identifier: Option<&str>,
    ) -> Result<Result<Value, Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(Err(gone(e))),
        };
        let folded = identifier.map(Self::folded).transpose()?;
        let user = match l.state.subject {
            Some(s) => tx.user_handle(s).await?.map(UserHandle::from_bytes),
            None => None,
        };
        let authenticated = l.state.first_done();
        // TN-132
        if !authenticated && matches!(l.state.purpose, Purpose::Login) && !self.policy.passkey {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        }
        let who = match (&folded, l.state.identifier) {
            (Some(f), Some(d)) if d == self.identifier_digest(f) => Identified::Identifier {
                normalized: f,
                user,
            },
            (_, None) if authenticated || !matches!(l.state.purpose, Purpose::Login) => {
                Identified::Identifier {
                    normalized: "",
                    user,
                }
            }
            // IDP-8
            (None, Some(_)) if authenticated => Identified::Identifier {
                normalized: "",
                user,
            },
            (_, None) => Identified::Discoverable,
            _ => return Ok(Err(neutral(0))),
        };
        let require_uv = matches!(l.state.purpose, Purpose::StepUp { .. });
        let (ceremony, options) = self.ceremony(who, require_uv).await?;
        l.state.ceremony = Some(ceremony);
        save(&mut tx, &l, "open", Resume::Keep).await?;
        tx.commit().await?;
        Ok(Ok(options))
    }

    /// The passkey step (§10.2.4): the ceremony is taken out of the flow before it is
    /// verified, so it is used once.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn passkey(
        &self,
        flow: &FlowRef<'_>,
        response: &AssertionResponse<'_>,
        correlation: &str,
    ) -> Result<Step, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(gone(e)),
        };
        let authenticated = l.state.first_done();
        // TN-132
        if !authenticated && matches!(l.state.purpose, Purpose::Login) && !self.policy.passkey {
            return Ok(refuse(STEP_NOT_ALLOWED));
        }
        let Some(ceremony) = l.state.ceremony.take() else {
            return Ok(neutral(0));
        };
        save(&mut tx, &l, "open", Resume::Keep).await?;
        tx.commit().await?;
        let state = state_of(self.wa_realm(), &ceremony)?;
        let outcome = self
            .webauthn()
            .finish_authentication(self.passkeys.rp, self.passkeys.policy, &state, response)
            .await?;
        let (user, credential, assurance, signals, facts) = match outcome {
            AuthenticationOutcome::Authenticated {
                user,
                credential,
                assurance,
                signals,
                facts,
            } => (user, credential, assurance, signals, facts),
            AuthenticationOutcome::Rejected(r) if authenticated => {
                return Ok(refuse(access_identity_account::domain::login::Problem {
                    status: 401,
                    code: r.code(),
                    title: "That passkey isn't registered for this account",
                    retry_after_s: None,
                }));
            }
            AuthenticationOutcome::Rejected(_) => return Ok(neutral(0)),
        };
        let mut tx = self.begin().await?;
        let Some(subject) = tx.subject_by_user_handle(user.as_bytes()).await? else {
            return Ok(neutral(0));
        };
        let live = tx
            .subject(subject, false)
            .await?
            .is_some_and(|r| active(&r.status));
        if !live {
            return Ok(neutral(0));
        }
        let sibling = tx
            .passkey_credential(credential.as_bytes())
            .await?
            .ok_or(SessionError::Corrupt)?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(gone(e)),
        };
        let mut factor = Factor::passkey(
            sibling,
            assurance.binding == Binding::Synced,
            assurance.user_verified,
            assurance.session_login_only,
            now,
        );
        // §10.1.2, TN-63, OP-150 L2
        factor.webauthn = Some(super::claims::detail(&facts, response));
        super::claims::passkey_signals(&mut tx, subject, &signals, now).await?;
        if l.state.record(subject, factor).is_err() {
            return Ok(if authenticated {
                refuse(STEP_NOT_ALLOWED)
            } else {
                neutral(0)
            });
        }
        self.advance(tx, l, now, correlation).await
    }

    async fn factor_gate(
        &self,
        tx: &mut D::Tx,
        key: &[u8; 32],
        now: u64,
    ) -> Result<Result<KeyState, Step>, SessionError> {
        let day = i32::try_from(now / THROTTLE_DAY_MS).map_err(|_| SessionError::Corrupt)?;
        let s = key_state(&tx.throttle(key, day, FACTOR_HORIZON_DAYS).await?)?;
        match FACTOR_THROTTLE.admit(&s, now) {
            Gate::Open(opened) => {
                tx.put_throttle(key, day, &throttle_row(&opened)).await?;
                Ok(Ok(opened))
            }
            Gate::Wait { retry_after_ms } => Ok(Err(Step::Throttled {
                retry_after_s: access_identity_account::domain::login::ceil_seconds(retry_after_ms),
            })),
            Gate::Locked => Ok(Err(refuse(FACTOR_LOCKED))),
        }
    }

    async fn factor_counted(
        &self,
        tx: &mut D::Tx,
        key: &[u8; 32],
        s: &KeyState,
        ok: bool,
        now: u64,
    ) -> Result<(), SessionError> {
        let day = i32::try_from(now / THROTTLE_DAY_MS).map_err(|_| SessionError::Corrupt)?;
        let next = if ok {
            FACTOR_THROTTLE.succeed(s)
        } else {
            FACTOR_THROTTLE.fail(s, now)
        };
        tx.put_throttle(key, day, &throttle_row(&next)).await?;
        Ok(())
    }

    fn factor_key(&self, subject: [u8; 16], kind: &str) -> [u8; 32] {
        let id = format!("factor:{}:{kind}", encode(&subject));
        counter_key(
            KeyKind::Account,
            self.realm.tenant.as_bytes(),
            self.realm.realm.as_bytes(),
            Some(&id),
            Some(b"second-factor"),
        )
    }

    /// The TOTP step (RFC 6238, §10.2.2): a second factor only; a used step is refused; at
    /// most 100 consecutive failures (TN-59).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn totp(
        &self,
        flow: &FlowRef<'_>,
        code: &str,
        correlation: &str,
    ) -> Result<Step, SessionError> {
        self.second_factor(flow, code, TOTP, correlation).await
    }

    /// The recovery code step (§10.2.2, TN-59): single use, Argon2id-hashed.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn recovery_code(
        &self,
        flow: &FlowRef<'_>,
        code: &str,
        correlation: &str,
    ) -> Result<Step, SessionError> {
        self.second_factor(flow, code, RECOVERY_CODE, correlation)
            .await
    }

    async fn second_factor(
        &self,
        flow: &FlowRef<'_>,
        code: &str,
        kind: &str,
        correlation: &str,
    ) -> Result<Step, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(gone(e)),
        };
        let Some(subject) = l.state.subject.filter(|_| l.state.first_done()) else {
            return Ok(neutral(0));
        };
        let key = self.factor_key(subject, kind);
        let gate = match self.factor_gate(&mut tx, &key, now).await? {
            Ok(s) => s,
            Err(step) => {
                tx.commit().await?;
                return Ok(step);
            }
        };
        let row = tx
            .subject(subject, false)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let dek = subject_key(&self.realm, &row)?;
        let mut matched = None;
        for c in tx.credentials(subject, kind).await? {
            let secret = open(&self.realm, &dek, &subject, kind, &c.sealed)?;
            if kind == TOTP {
                let key = Secret::new(hex_decode(secret.expose()).ok_or(SessionError::Corrupt)?);
                let params = access_crypto::totp::TotpParams::DEFAULT;
                if let Some(step) =
                    access_crypto::totp::matching_step(&key, &params, now / 1000, code.trim())
                    && tx.use_otp_step(c.id, i64_of(step)?).await?
                {
                    matched = Some(Factor::totp(c.id, now));
                    break;
                }
            } else {
                let Some(typed) = Password::presented(&canonical_recovery_code(code)) else {
                    continue;
                };
                if self.hasher.verify(&typed, secret).await?.matched {
                    if tx.revoke(subject, c.id).await? != Revoke::Done {
                        return Err(SessionError::Corrupt);
                    }
                    matched = Some(Factor::recovery_code(c.id, now));
                    break;
                }
            }
        }
        self.factor_counted(&mut tx, &key, &gate, matched.is_some(), now)
            .await?;
        let target = self.external(subject)?;
        let Some(factor) = matched else {
            audit(
                &mut tx,
                &format!("login.{kind}.failed"),
                ANONYMOUS,
                &target,
                correlation,
            )
            .await?;
            tx.commit().await?;
            return Ok(refuse(CODE_NOT_ACCEPTED));
        };
        audit(
            &mut tx,
            &format!("login.{kind}.succeeded"),
            ANONYMOUS,
            &target,
            correlation,
        )
        .await?;
        if l.state.record(subject, factor).is_err() {
            tx.commit().await?;
            return Ok(refuse(STEP_NOT_ALLOWED));
        }
        self.advance(tx, l, now, correlation).await
    }

    /// Suspends the flow on an e-mail code or link (§10.2.2, TN-102). The answer is the same
    /// whether a message was sent or not; only an active account gets one.
    ///
    /// # Errors
    /// [`SessionError::Invalid`] when the realm does not offer `method`; [`SessionError`].
    pub async fn send_email(
        &self,
        flow: &FlowRef<'_>,
        method: MethodClass,
        correlation: &str,
    ) -> Result<Step, SessionError> {
        let offered = match method {
            MethodClass::EmailOtp => self.policy.email_otp,
            MethodClass::MagicLink => self.policy.magic_link,
            _ => false,
        };
        if !offered {
            return Err(SessionError::Invalid);
        }
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(gone(e)),
        };
        let mut live = None;
        if let Some(s) = l.state.subject
            && tx
                .subject(s, false)
                .await?
                .is_some_and(|r| active(&r.status))
        {
            live = Some(s);
        }
        let mut code_bytes = [0; 8];
        self.random.fill(&mut code_bytes)?;
        let code = email_code(&code_bytes);
        let token = self.random32()?;
        let expires_ms = now.saturating_add(SUSPENSION_TTL_MS);
        let (pending, resume, body) = if method == MethodClass::EmailOtp {
            let digest = live.map(|_| code_digest(&l.row.flow_hash, &code));
            (
                Pending::EmailCode {
                    digest,
                    expires_ms,
                    attempts_left: EMAIL_CODE_ATTEMPTS,
                },
                Resume::Clear,
                Body::Otp {
                    code: Secret::new(code),
                    purpose: OtpPurpose::SignIn,
                    expires_at_ms: expires_ms,
                },
            )
        } else {
            (
                Pending::MagicLink {
                    expires_ms,
                    live: live.is_some(),
                },
                Resume::Set(resume_digest(&token)),
                Body::MagicLink {
                    link: Secret::new(format!("{}{}", self.link_base, encode(&token))),
                    expires_at_ms: expires_ms,
                },
            )
        };
        if l.state.suspend(pending).is_err() {
            return Ok(if l.state.first_done() {
                refuse(STEP_NOT_ALLOWED)
            } else {
                neutral(0)
            });
        }
        save(&mut tx, &l, "open", resume).await?;
        let target = match live {
            Some(s) => self.external(s)?,
            None => super::signin::UNKNOWN.to_owned(),
        };
        audit(
            &mut tx,
            "auth.flow.suspended",
            ANONYMOUS,
            &target,
            correlation,
        )
        .await?;
        if let Some(subject) = live
            && let Some(to) = address(tx.contact(subject).await?)
        {
            tx.notify(
                self.notifier,
                &Message {
                    subject,
                    to,
                    locale: None,
                    body,
                },
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Step::Suspended { method })
    }

    /// Resumes an e-mail code step (TN-102): it completes only that step; wrong codes are
    /// counted and the code dies after five.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn email_code(
        &self,
        flow: &FlowRef<'_>,
        code: &str,
        correlation: &str,
    ) -> Result<Step, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(gone(e)),
        };
        let pending = match l.state.take_pending(MethodClass::EmailOtp, now) {
            Ok(p) => p,
            Err(FlowRejection::Expired) => {
                save(&mut tx, &l, "open", Resume::Keep).await?;
                audit(
                    &mut tx,
                    "auth.flow.expired",
                    ANONYMOUS,
                    UNKNOWN,
                    correlation,
                )
                .await?;
                tx.commit().await?;
                return Ok(neutral(0));
            }
            Err(_) => return Ok(neutral(0)),
        };
        let Pending::EmailCode {
            digest,
            expires_ms,
            attempts_left,
        } = pending
        else {
            return Ok(neutral(0));
        };
        let presented = code_digest(&l.row.flow_hash, code.trim());
        let matches = digest.is_some_and(|d| Secret::new(d).ct_eq_bytes(&presented));
        let subject = l.state.subject.filter(|_| matches);
        let Some(subject) = subject else {
            if attempts_left > 1 {
                l.state.pending = Some(Pending::EmailCode {
                    digest,
                    expires_ms,
                    attempts_left: attempts_left.saturating_sub(1),
                });
            }
            save(&mut tx, &l, "open", Resume::Keep).await?;
            tx.commit().await?;
            return Ok(neutral(0));
        };
        if l.state
            .record(subject, Factor::email(MethodClass::EmailOtp, now))
            .is_err()
        {
            return Ok(neutral(0));
        }
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "auth.flow.resumed",
            ANONYMOUS,
            &target,
            correlation,
        )
        .await?;
        self.advance(tx, l, now, correlation).await
    }

    /// What opening a magic link shows. Read only: a preview bot that follows the link
    /// consumes nothing (§10.2.2, TN-102 rule 6).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn preview_link(
        &self,
        token: &str,
        device: Option<&str>,
    ) -> Result<LinkPreview, SessionError> {
        let now = self.now();
        let Some(token) = decode32(token) else {
            return Ok(LinkPreview::Invalid);
        };
        let mut tx = self.begin().await?;
        let row = tx
            .flow_by_resume(super::from_day(now), &resume_digest(&token))
            .await?;
        tx.commit().await?;
        let Some(row) = row else {
            return Ok(LinkPreview::Invalid);
        };
        let state = FlowState::decode(&row.state).map_err(|_| SessionError::Corrupt)?;
        let usable = row.status == "open"
            && !state.expired(now)
            && matches!(state.pending, Some(Pending::MagicLink { live: true, expires_ms }) if now < expires_ms);
        if !usable {
            return Ok(LinkPreview::Invalid);
        }
        let same_device = device
            .and_then(decode32)
            .is_some_and(|d| device_digest(&d) == row.device_hash);
        Ok(LinkPreview::Confirm { same_device })
    }

    /// Confirms a magic link (POST, never a consuming GET). The step completes in the flow;
    /// the session goes only to the browser that started it (§10.2.2). Another browser must
    /// confirm explicitly.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn confirm_link(
        &self,
        token: &str,
        device: Option<&str>,
        other_device_confirmed: bool,
        correlation: &str,
    ) -> Result<LinkOutcome, SessionError> {
        let now = self.now();
        let Some(token) = decode32(token) else {
            return Ok(LinkOutcome::Invalid);
        };
        let mut tx = self.begin().await?;
        let Some(row) = tx
            .flow_by_resume(super::from_day(now), &resume_digest(&token))
            .await?
        else {
            return Ok(LinkOutcome::Invalid);
        };
        let state = FlowState::decode(&row.state).map_err(|_| SessionError::Corrupt)?;
        let mut l = Loaded { row, state };
        if l.row.status != "open" || l.state.expired(now) {
            return Ok(LinkOutcome::Invalid);
        }
        let same_device = device
            .and_then(decode32)
            .is_some_and(|d| device_digest(&d) == l.row.device_hash);
        if !same_device && !other_device_confirmed {
            return Ok(LinkOutcome::NeedsConfirmation);
        }
        let live = match l.state.take_pending(MethodClass::MagicLink, now) {
            Ok(Pending::MagicLink { live, .. }) => live,
            Err(FlowRejection::Expired) => {
                save(&mut tx, &l, "open", Resume::Clear).await?;
                audit(
                    &mut tx,
                    "auth.flow.expired",
                    ANONYMOUS,
                    UNKNOWN,
                    correlation,
                )
                .await?;
                tx.commit().await?;
                return Ok(LinkOutcome::Invalid);
            }
            _ => return Ok(LinkOutcome::Invalid),
        };
        let Some(subject) = l.state.subject.filter(|_| live) else {
            return Ok(LinkOutcome::Invalid);
        };
        let active_now = tx
            .subject(subject, false)
            .await?
            .is_some_and(|r| active(&r.status));
        if !active_now
            || l.state
                .record(subject, Factor::email(MethodClass::MagicLink, now))
                .is_err()
        {
            return Ok(LinkOutcome::Invalid);
        }
        save(&mut tx, &l, "open", Resume::Clear).await?;
        let target = self.external(subject)?;
        audit(
            &mut tx,
            "auth.flow.resumed",
            ANONYMOUS,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(LinkOutcome::Confirmed { same_device })
    }

    /// Continues a flow from the starting browser: after a magic link was confirmed, or to
    /// poll.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn resume(
        &self,
        flow: &FlowRef<'_>,
        correlation: &str,
    ) -> Result<Step, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(gone(e)),
        };
        if let Some(p) = &l.state.pending {
            return Ok(Step::Suspended { method: p.method() });
        }
        self.advance(tx, l, now, correlation).await
    }

    async fn enrolled(&self, tx: &mut D::Tx, subject: [u8; 16]) -> Result<Enrolled, SessionError> {
        Ok(Enrolled {
            totp: !tx.credentials(subject, TOTP).await?.is_empty(),
            recovery_codes: !tx.credentials(subject, RECOVERY_CODE).await?.is_empty(),
            passkeys: !tx
                .credentials(subject, crate::adapters::passkeys::WEBAUTHN)
                .await?
                .is_empty(),
        })
    }

    async fn marker_ok(
        &self,
        tx: &mut D::Tx,
        state: &FlowState,
        subject: [u8; 16],
        epoch: i64,
        now: u64,
    ) -> Result<bool, SessionError> {
        if self.policy.remember_device_days.is_none() || !matches!(state.purpose, Purpose::Login) {
            return Ok(false);
        }
        let Some(hash) = state.marker else {
            return Ok(false);
        };
        Ok(tx.marker(&hash).await?.is_some_and(|m| {
            m.subject == subject
                && m.revoked_ms.is_none()
                && m.session_epoch == epoch
                && i64::try_from(now).is_ok_and(|n| n < m.expires_ms)
        }))
    }

    fn policy_for(&self, purpose: &Purpose) -> AuthPolicy {
        match purpose {
            Purpose::StepUp { min_aal, .. } => AuthPolicy {
                min_aal: (*min_aal).max(self.policy.min_aal),
                ..self.policy
            },
            _ => self.policy,
        }
    }

    #[expect(clippy::too_many_arguments, reason = "one completed flow's facts")]
    async fn issue_login(
        &self,
        tx: &mut D::Tx,
        l: &Loaded,
        subject: [u8; 16],
        epoch: i64,
        now: u64,
        result: AuthenticationResult,
        assurance: &[u8],
        correlation: &str,
    ) -> Result<SignedIn, SessionError> {
        let target = self.external(subject)?;
        let cookie = self.random32()?;
        let keep = l.state.keep_signed_in;
        let expires_ms = now.saturating_add(self.lifetimes.absolute_ms);
        let session = tx
            .insert_session(&NewSession {
                cookie_hash: &cookie_digest(&cookie),
                subject,
                session_epoch: epoch,
                keep_signed_in: keep,
                created_ms: i64_of(now)?,
                auth_time_ms: i64_of(result.assurance.auth_time_ms.max(1))?,
                idle_ms: i64_of(self.lifetimes.idle_ms)?,
                expires_ms: i64_of(expires_ms)?,
                assurance,
            })
            .await?;
        let mut marker_cookie = None;
        let second_step_done = l.state.factors.len() >= 2;
        if let (true, true, Some(days)) = (
            l.state.remember_device,
            second_step_done,
            self.policy.remember_device_days,
        ) {
            let value = self.random32()?;
            let ttl = u64::from(days).saturating_mul(86_400_000);
            tx.insert_marker(
                &marker_digest(&value),
                subject,
                epoch,
                i64_of(now)?,
                i64_of(now.saturating_add(ttl))?,
            )
            .await?;
            marker_cookie = Some(set_cookie(MARKER_COOKIE, &encode(&value), Some(ttl / 1000)));
        }
        audit(tx, "session.created", &target, &target, correlation).await?;
        // TN-41
        let s = Signal::session_established(fresh_id()?, subject, now);
        signal(tx, &s).await?;
        Ok(SignedIn {
            session,
            set_cookie: Some(set_cookie(
                SESSION_COOKIE,
                &encode(&cookie),
                keep.then_some(self.lifetimes.absolute_ms / 1000),
            )),
            marker_cookie,
            result,
        })
    }

    /// Whether the realm's `post_login` hook refused a login; a refused flow is abandoned and
    /// audited (TN-135).
    async fn refused_by_hook(
        &self,
        tx: &mut D::Tx,
        l: &Loaded,
        result: &AuthenticationResult,
        target: &str,
        correlation: &str,
    ) -> Result<bool, SessionError> {
        if !matches!(l.state.purpose, Purpose::Login) || self.post_login(result, target).await {
            return Ok(false);
        }
        save(tx, l, "abandoned", Resume::Clear).await?;
        audit(tx, "session.hook_refused", target, target, correlation).await?;
        Ok(true)
    }

    /// Whether the realm's `post_login` hook lets the sign-in through (TN-135): no hook does;
    /// a refusal, no answer or a bad answer does not (MD-8).
    async fn post_login(&self, result: &AuthenticationResult, account: &str) -> bool {
        use access_identity_hooks::domain::{Call, Outcome, PostLogin};
        let aal = match result.assurance.aal {
            crate::domain::assurance::Aal::Aal1 => 1,
            crate::domain::assurance::Aal::Aal2 => 2,
            crate::domain::assurance::Aal::Aal3 => 3,
        };
        let call = Call::PostLogin(PostLogin {
            account: String::from(account),
            aal,
            methods: result.methods.iter().map(|m| m.amr()).collect(),
        });
        matches!(
            self.hooks
                .call(self.realm.tenant, self.realm.realm, call)
                .await,
            Outcome::Proceed { .. }
        )
    }

    /// Moves the flow after a step: saves what is missing, or completes it (TN-132).
    #[expect(
        clippy::too_many_lines,
        reason = "one completed flow: requirements, post_login hook, session and signals"
    )]
    pub(crate) async fn advance(
        &self,
        mut tx: D::Tx,
        mut l: Loaded,
        now: u64,
        correlation: &str,
    ) -> Result<Step, SessionError> {
        let Some(subject) = l.state.subject.filter(|_| l.state.first_done()) else {
            save(&mut tx, &l, "open", Resume::Keep).await?;
            tx.commit().await?;
            return Ok(Step::Continue {
                needs: vec![Requirement::FirstFactor],
                enrolled: None,
            });
        };
        let row = tx
            .subject(subject, false)
            .await?
            .ok_or(SessionError::Corrupt)?;
        if !active(&row.status) {
            save(&mut tx, &l, "abandoned", Resume::Clear).await?;
            tx.commit().await?;
            return Ok(neutral(0));
        }
        let enrolled = self.enrolled(&mut tx, subject).await?;
        let marker = self
            .marker_ok(&mut tx, &l.state, subject, row.session_epoch, now)
            .await?;
        if self
            .sl2(&mut tx, &mut l.state, subject, now, marker)
            .await?
        {
            save(&mut tx, &l, "abandoned", Resume::Clear).await?;
            tx.commit().await?;
            return Ok(neutral(self.gate.mean_ms()));
        }
        let needs = self.needs(&l.state, enrolled, marker);
        if !needs.is_empty() {
            save(&mut tx, &l, "open", Resume::Keep).await?;
            tx.commit().await?;
            return Ok(Step::Continue {
                needs,
                enrolled: Some(enrolled),
            });
        }
        let result = AuthenticationResult::of(
            *self.realm.tenant.as_bytes(),
            *self.realm.realm.as_bytes(),
            subject,
            &l.state.factors,
        );
        let assurance =
            serde_json::to_vec(&vector(&l.state.factors)).map_err(|_| SessionError::Corrupt)?;
        let target = self.external(subject)?;
        // TN-135, OP-151 m.3 (j)
        if self
            .refused_by_hook(&mut tx, &l, &result, &target, correlation)
            .await?
        {
            tx.commit().await?;
            return Ok(refuse(super::HOOK_REFUSED));
        }
        let signed = match &l.state.purpose {
            Purpose::Login => {
                self.issue_login(
                    &mut tx,
                    &l,
                    subject,
                    row.session_epoch,
                    now,
                    result,
                    &assurance,
                    correlation,
                )
                .await?
            }
            Purpose::StepUp { session, .. } => {
                let restamped = tx
                    .restamp_session(
                        *session,
                        row.session_epoch,
                        row.session_epoch,
                        i64_of(result.assurance.auth_time_ms.max(1))?,
                        &assurance,
                        true,
                    )
                    .await?;
                if !restamped {
                    save(&mut tx, &l, "abandoned", Resume::Clear).await?;
                    tx.commit().await?;
                    return Ok(refuse(STEP_NOT_ALLOWED));
                }
                audit(&mut tx, "session.stepped_up", &target, &target, correlation).await?;
                // TN-41
                let level = match result.assurance.aal {
                    Aal::Aal1 => "aal1",
                    Aal::Aal2 => "aal2",
                    Aal::Aal3 => "aal3",
                };
                let s = Signal::assurance_level(fresh_id()?, subject, level, None, now);
                signal(&mut tx, &s).await?;
                SignedIn {
                    session: *session,
                    set_cookie: None,
                    marker_cookie: None,
                    result,
                }
            }
            Purpose::EnrollTotp { .. }
            | Purpose::RegisterPasskey { .. }
            | Purpose::InstanceKey { .. } => {
                return Ok(refuse(STEP_NOT_ALLOWED));
            }
        };
        // F17, TN-103, OP-150 L2
        let unknown_device = self.policy.remember_device_days.is_some() && !marker;
        super::claims::signed_in(&mut tx, &l.state, &signed, unknown_device).await?;
        if matches!(l.state.purpose, Purpose::Login) {
            self.sl2_signed_in(&mut tx, &l.state, subject, now, marker)
                .await?;
        }
        save(&mut tx, &l, "done", Resume::Clear).await?;
        tx.commit().await?;
        Ok(Step::SignedIn(Box::new(signed)))
    }

    /// SL2 once per login, when its first step has passed (TN-46, IDP-39): notes the level and
    /// the step-up in the flow. True for a canary match, whose flow ends with the generic
    /// failure and never gets a session (§4.4).
    async fn sl2(
        &self,
        tx: &mut D::Tx,
        state: &mut FlowState,
        subject: [u8; 16],
        now: u64,
        marker: bool,
    ) -> Result<bool, SessionError> {
        let assessed = state.risk.as_ref().is_some_and(|n| n.level.is_some());
        if !matches!(state.purpose, Purpose::Login) || assessed {
            return Ok(false);
        }
        let facts = self.sign_in_facts(state, subject, now, marker);
        let a = evaluate(tx, &self.risk, &facts).await?;
        if a.signals.contains(&RiskSignal::CanaryHit) {
            return Ok(true);
        }
        let note = state.risk.get_or_insert_with(RiskNote::default);
        note.level = Some(a.level.name().to_owned());
        note.step_up = a.step_up;
        Ok(false)
    }

    /// What is still missing (TN-132), with SL2's step-up added when it asked for one (TN-46).
    fn needs(&self, state: &FlowState, enrolled: Enrolled, marker: bool) -> Vec<Requirement> {
        let policy = self.policy_for(&state.purpose);
        let needs = missing(&policy, &enrolled, &state.factors, marker);
        if state.risk.as_ref().is_some_and(|n| n.step_up) {
            with_step_up(needs, &state.factors)
        } else {
            needs
        }
    }

    /// TN-46: only a session moves the account's last sign-in.
    async fn sl2_signed_in(
        &self,
        tx: &mut D::Tx,
        state: &FlowState,
        subject: [u8; 16],
        now: u64,
        marker: bool,
    ) -> Result<(), SessionError> {
        let level = state
            .risk
            .as_ref()
            .and_then(|n| n.level.as_deref())
            .and_then(Level::parse);
        let facts = self.sign_in_facts(state, subject, now, marker);
        record_sign_in(tx, &self.risk, &facts, level).await?;
        Ok(())
    }

    fn sign_in_facts(
        &self,
        state: &FlowState,
        subject: [u8; 16],
        now: u64,
        marker: bool,
    ) -> SignIn {
        let note = state.risk.clone().unwrap_or_default();
        SignIn {
            tenant: *self.realm.tenant.as_bytes(),
            realm: *self.realm.realm.as_bytes(),
            subject,
            now_ms: now,
            device_known: self.policy.remember_device_days.map(|_| marker),
            prior_failures: note.prior_failures,
            breach: note
                .breach
                .as_deref()
                .and_then(Breach::parse)
                .unwrap_or_default(),
        }
    }
}
