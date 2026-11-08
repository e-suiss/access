//! Use cases over the domain and its ports (OP-63): the hosted login's flows and the signed-in
//! user's sessions and methods, as transport-neutral [`Reply`] values (OP-146 m.12 (b)).
//!
//! Every login answer is a [`Ui`]. Before the first factor the step is built from realm policy
//! and from what the browser sent, never from the account, and every refusal that could tell
//! whether an account exists is the one neutral `401` (CR-40, X34, TN-82).

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

mod account;
mod approve;
mod credential;
pub mod devices;
mod me;
pub mod privacy;
pub mod recovery;
pub mod shell;
pub mod signup;

pub use me::Devices;

use std::net::IpAddr;
use std::sync::Arc;

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::app::hasher::Hasher;
use access_identity_account::app::login::LoginGate;
use access_identity_account::domain::login::{Problem, REJECTED};
use access_identity_account::notify::ports::Notifier;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::SessionError;
use access_identity_session::adapters::OsRandom;
use access_identity_session::adapters::passkeys::PgPasskeys;
use access_identity_session::app::signin::{Identify, LinkOutcome, LinkPreview, PasswordStep};
use access_identity_session::app::{
    Auth, CODE_NOT_ACCEPTED, FLOW_GONE, FlowRef, Refusal, Step as Outcome,
};
use access_identity_session::domain::assurance::{Aal, MethodClass};
use access_identity_session::domain::requirement::MfaPolicy;
use access_identity_session::domain::session::{clear_cookie, set_cookie};
use access_identity_session::ports::Clock;
use access_identity_webauthn::domain::rp::{LastLabel, related_origins_document};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::Pool;
use serde_json::{Value, json};

use crate::adapters::LogSignals;
use crate::domain::flow::{EmailMethods, EmailWait, FlowId, Requirement, SecondFactors, Ui};
use crate::domain::message::{Message, TextId};
use crate::domain::node::{FieldName, Method, PasskeyOptions};
use crate::domain::submission::{Checked, Submission};
use crate::ports::{Kits, Messages, RealmKit};

pub use access_identity_session::domain::session::{FLOW_COOKIE, MARKER_COOKIE, SESSION_COOKIE};

/// The cookie that remembers the identifier typed on the first screen for one flow, so the
/// next step can echo it and the password step can name it (TN-96). The flow table keeps only
/// digests (OP-146 m.5 (f)); the identifier stays in the browser that typed it.
pub const LOGIN_COOKIE: &str = "__Host-access-login";

/// How long the identifier cookie lives: the flow's lifetime (OP-146 m.14 (d)).
const LOGIN_COOKIE_MAX_AGE_S: u64 = 1_800;

/// What the browser presented with a request.
#[derive(Clone, Copy, Debug)]
pub struct Browser<'a> {
    /// The flow cookie.
    pub flow: Option<&'a str>,
    /// The session cookie.
    pub session: Option<&'a str>,
    /// The device marker cookie (X33).
    pub marker: Option<&'a str>,
    /// The identifier cookie.
    pub login: Option<&'a str>,
    /// The client's address.
    pub ip: IpAddr,
    /// Request correlation id.
    pub correlation: &'a str,
}

/// A reply body.
#[derive(Clone, Debug, PartialEq)]
pub enum Body {
    /// A login step.
    Ui(Box<Ui>),
    /// An RFC 9457 problem.
    Problem(Problem),
    /// A JSON document.
    Json(Value),
    /// A hosted page (`text/html`), served with the hosted login's security headers.
    Html(&'static str),
    /// A hosted page's script (`text/javascript`).
    Script(&'static str),
    /// Nothing.
    Empty,
}

/// A transport-neutral answer.
#[derive(Clone, Debug, PartialEq)]
pub struct Reply {
    /// HTTP status.
    pub status: u16,
    /// Body.
    pub body: Body,
    /// `Set-Cookie` values.
    pub cookies: Vec<String>,
    /// `Retry-After`, whole seconds.
    pub retry_after_s: Option<u64>,
    /// Wait this long before answering (adaptive delay, TN-82); never on the wire.
    pub pad_ms: u64,
}

impl Reply {
    fn new(status: u16, body: Body) -> Self {
        Self {
            status,
            body,
            cookies: Vec::new(),
            retry_after_s: None,
            pad_ms: 0,
        }
    }

    fn ui(status: u16, ui: Ui) -> Self {
        Self::new(status, Body::Ui(Box::new(ui)))
    }

    /// A problem answer.
    #[must_use]
    pub fn problem(p: Problem) -> Self {
        let mut r = Self::new(p.status, Body::Problem(p));
        r.retry_after_s = p.retry_after_s;
        r
    }

    fn json(status: u16, value: Value) -> Self {
        Self::new(status, Body::Json(value))
    }

    fn html(page: &'static str) -> Self {
        Self::new(200, Body::Html(page))
    }

    /// A hosted script.
    #[must_use]
    pub fn script(source: &'static str) -> Self {
        Self::new(200, Body::Script(source))
    }

    fn cookie(mut self, c: Option<String>) -> Self {
        self.cookies.extend(c);
        self
    }
}

/// The step a submission is checked against (TN-106).
const INVALID_SUBMISSION: Problem = Problem {
    status: 400,
    code: "invalid-submission",
    title: "The submission does not match the sign-in step",
    retry_after_s: None,
};

/// No live session on a request that needs one (G57).
pub const SESSION_REQUIRED: Problem = Problem {
    status: 401,
    code: "session-required",
    title: "Sign in first",
    retry_after_s: None,
};

/// A step after the first factor was refused (X34: honest after authentication).
const NOT_ALLOWED: Problem = Problem {
    status: 409,
    code: "step-not-allowed",
    title: "That step isn't available here",
    retry_after_s: None,
};

/// Where a flow stands, read without consuming anything.
enum Current {
    Identifier,
    Authenticate(String),
    Email(EmailWait),
    Second(SecondFactors),
    Done(Reply),
}

type Signin<'a, C, N> = Auth<'a, PgAccounts, C, OsRandom, N, PgPasskeys<'a>, LogSignals>;

/// Builds the sign-in service of one realm for one request.
macro_rules! signin {
    ($self:ident, $kit:ident, $auth:ident) => {
        $crate::app::signin!($self, $kit, $auth, None);
    };
    ($self:ident, $kit:ident, $auth:ident, $client:expr) => {
        let db = ::access_identity_account::adapters::pg::PgAccounts::sealed(
            $self.db.clone(),
            $kit.vault(),
        );
        let registry = ::access_identity_session::adapters::passkeys::PgPasskeys {
            pool: &$self.db,
            tenant: $kit.tenant,
            kek: &*$kit.kek,
            ids: &$kit.ids,
        };
        let notifier_realm = $kit.realm();
        let notifier = $self.messages.notifier(&notifier_realm);
        let link_base = format!("{}/login/link#", $kit.issuer);
        let $auth = ::access_identity_session::app::Auth {
            db: &db,
            realm: $kit.realm(),
            policy: $kit.auth,
            lifetimes: $kit.lifetimes,
            clock: &$self.clock,
            random: &::access_identity_session::adapters::OsRandom,
            notifier: &notifier,
            link_base: &link_base,
            gate: &$self.gate,
            hasher: &$self.hasher,
            hooks: &*$self.hooks,
            passkeys: ::access_identity_session::app::Passkeys {
                registry: &registry,
                signals: &$crate::adapters::LogSignals,
                decoys: &$kit.decoys,
                rp: &$kit.rp,
                policy: &$kit.webauthn,
            },
            risk: ::access_identity_session::app::Sl2 {
                services: &$self.risk,
                client: $client,
            },
        };
    };
}

pub(crate) use signin;

/// The hosted login of every realm this process serves (CMP-15.6).
pub struct Hosted<K, C, M> {
    /// Realm keys and settings.
    pub kits: K,
    /// The `access_app` pool.
    pub db: Pool,
    /// The outbox reader pool, which sees the platform product clients across tenants: the
    /// Approval Surface accepts a product's registered return address from any realm with it
    /// (OP-149 m.26 (a), m.33 (d)).
    pub products: Pool,
    /// Trusted time.
    pub clock: C,
    /// The Relay seam.
    pub messages: M,
    /// The password step's process state.
    pub gate: LoginGate,
    /// The Argon2id service.
    pub hasher: Hasher,
    /// Where a completed sign-in goes (`redirect_to`).
    pub redirect_to: String,
    /// The realms' inline hooks (TN-135): `post_login` may refuse a sign-in.
    pub hooks: std::sync::Arc<dyn ::access_identity_hooks::ports::HookCaller + Sync>,
    /// SL2 risk sources (TN-46, OP-151 m.1 (b)).
    pub risk: access_identity_session::app::RiskServices,
    /// What sign-up needs: the bot signal and the disposable list (OP-153 m.1 (b), m.3 (h)).
    pub signup: signup::Signup,
}

fn failed(e: &SessionError) -> Reply {
    if !matches!(e, SessionError::Invalid) {
        tracing::warn!(error = %e, "sign-in step failed");
    }
    Reply::problem(e.problem())
}

/// The realm's requirement list before the first factor: realm policy only (OP-146 m.12 (c)).
fn policy(kit: &RealmKit) -> Vec<Requirement> {
    let mfa = kit.auth.mfa == MfaPolicy::Required || kit.auth.min_aal >= Aal::Aal2;
    if mfa {
        vec![Requirement::SecondFactor]
    } else {
        Vec::new()
    }
}

fn email(kit: &RealmKit) -> EmailMethods {
    EmailMethods {
        code: kit.auth.email_otp,
        link: kit.auth.magic_link,
    }
}

fn flow_id(handle: &str) -> Result<FlowId, Reply> {
    FlowId::parse(handle).ok_or_else(|| Reply::problem(FLOW_GONE))
}

fn options(v: Value) -> Result<PasskeyOptions, Reply> {
    PasskeyOptions::new(v).ok_or_else(|| Reply::problem(SessionError::Corrupt.problem()))
}

/// The identifier cookie: `<flow handle>.<base64url identifier>`.
fn login_cookie(handle: &str, identifier: &str) -> String {
    let value = format!("{handle}.{}", b64url_encode(identifier.as_bytes()));
    set_cookie(LOGIN_COOKIE, &value, Some(LOGIN_COOKIE_MAX_AGE_S))
}

/// The identifier the browser typed for `handle`, if its cookie names that flow.
fn typed(b: &Browser<'_>, handle: &str) -> Option<String> {
    let (h, id) = b.login?.split_once('.')?;
    if h != handle {
        return None;
    }
    String::from_utf8(b64url_decode(id).ok()?).ok()
}

/// The first step of a realm in strict enumeration mode (OP-153 m.3 (j), TN-96): identifier and
/// password on one screen, submitted together, with the passkey path kept; nothing branches on
/// the identifier before the answer.
fn strict(mut ui: Ui) -> Ui {
    let mut nodes = Vec::with_capacity(ui.nodes.len().saturating_add(1));
    for node in ui.nodes {
        match node {
            crate::domain::node::Node::Input {
                name: FieldName::Identifier,
                kind,
                autocomplete,
                required,
                max_length,
                label,
                value,
                read_only,
                ..
            } => nodes.push(crate::domain::node::Node::Input {
                name: FieldName::Identifier,
                method: Method::Password,
                kind,
                autocomplete,
                required,
                max_length,
                label,
                value,
                read_only,
            }),
            crate::domain::node::Node::Submit {
                method: Method::Identifier,
                ..
            } => {
                nodes.push(crate::domain::node::Node::input(
                    FieldName::Password,
                    Method::Password,
                    crate::domain::node::InputKind::Password,
                    crate::domain::node::Autocomplete::CurrentPassword,
                    TextId::PasswordLabel.into(),
                ));
                nodes.push(crate::domain::node::Node::Submit {
                    method: Method::Password,
                    label: TextId::SignIn.into(),
                });
            }
            other => nodes.push(other),
        }
    }
    ui.nodes = nodes;
    ui
}

/// The identifier step as the realm's enumeration mode draws it.
fn first_step(kit: &RealmKit, ui: Ui) -> Ui {
    if kit.signin.strict && kit.auth.password {
        strict(ui)
    } else {
        ui
    }
}

fn shape(kit: &RealmKit, flow: &FlowId, current: &Current) -> Option<Ui> {
    let blank = PasskeyOptions::new(json!({}))?;
    let reqs = policy(kit);
    Some(match current {
        Current::Identifier => first_step(
            kit,
            Ui::identifier(flow.clone(), blank, &reqs)
                .with_first_steps(kit.auth.password, kit.auth.passkey),
        ),
        Current::Authenticate(id) => Ui::authenticate(flow.clone(), id, blank, &reqs)
            .with_email(email(kit))
            .with_first_steps(kit.auth.password, kit.auth.passkey),
        Current::Email(wait) => Ui::email_sent(flow.clone(), *wait, &reqs),
        Current::Second(offered) => Ui::second_factor(flow.clone(), *offered, Some(blank), &reqs),
        Current::Done(_) => return None,
    })
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    async fn kit(&self, entry: &RealmEntry) -> Result<Arc<RealmKit>, Reply> {
        self.kits.kit(entry).await.map_err(|_| {
            Reply::problem(Problem {
                status: 503,
                code: "unavailable",
                title: "Temporarily unavailable",
                retry_after_s: Some(1),
            })
        })
    }

    /// The realm's `/.well-known/webauthn` document (TN-18).
    ///
    /// # Errors
    /// The reply to send instead: no kit, or a list browsers would cut.
    pub async fn related_origins(&self, entry: &RealmEntry) -> Result<String, Reply> {
        let kit = self.kit(entry).await?;
        related_origins_document(&kit.rp, &LastLabel)
            .map_err(|_| Reply::problem(SessionError::Corrupt.problem()))
    }

    /// `POST /v1/login/flows`: a new flow at the identifier step, with discoverable passkey
    /// options (TN-96, TN-99).
    pub async fn create(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        self.start(&auth, &kit, b, None, 201)
            .await
            .unwrap_or_else(|r| r)
    }

    /// `POST /v1/login/step-up`: re-authenticates the live session in place when the
    /// authorization request's `max_age` or `acr_values` asks for it (`reason` `reauthenticate`
    /// or `step_up` on `/login`): fresh steps reaching the asked AAL, never below the realm's,
    /// restamp the session (TN-44, RFC 9470, §8.17.5.4, X-L3). The step is a passkey; a realm
    /// without passkey sign-in, or a browser without a live session, answers with a problem
    /// and the page signs in afresh.
    pub async fn step_up(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        max_age_s: u64,
        acr: Option<&str>,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        if !kit.auth.passkey {
            return Reply::problem(NOT_ALLOWED);
        }
        let Some(session) = b.session else {
            return Reply::problem(SESSION_REQUIRED);
        };
        signin!(self, kit, auth, Some(b.ip));
        let asked = acr
            .and_then(access_identity_oauth::domain::tokens::aal_of)
            .unwrap_or(Aal::Aal1);
        let started = match auth
            .step_up(
                session,
                b.flow,
                max_age_s.saturating_mul(1000),
                asked.max(kit.auth.min_aal),
            )
            .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(_)) => return Reply::problem(SESSION_REQUIRED),
            Err(e) => return failed(&e),
        };
        let ui = flow_id(&started.handle).and_then(|flow| {
            Ok(
                Ui::identifier(flow, options(started.options.passkey)?, &policy(&kit))
                    .with_first_steps(false, true),
            )
        });
        match ui {
            Ok(ui) => Reply::ui(201, ui).cookie(started.set_cookie),
            Err(r) => r,
        }
    }

    async fn start<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        b: &Browser<'_>,
        identifier: Option<&str>,
        status: u16,
    ) -> Result<Reply, Reply> {
        let started = auth
            .identify(&Identify {
                identifier,
                device: b.flow,
                marker: b.marker,
                keep_signed_in: false,
                remember_device: false,
            })
            .await
            .map_err(|e| failed(&e))?;
        let flow = flow_id(&started.handle)?;
        let passkey = options(started.options.passkey)?;
        let reqs = policy(kit);
        let (ui, login) = match identifier {
            None => (
                first_step(
                    kit,
                    Ui::identifier(flow, passkey, &reqs)
                        .with_first_steps(kit.auth.password, kit.auth.passkey),
                ),
                clear_cookie(LOGIN_COOKIE),
            ),
            Some(id) => (
                Ui::authenticate(flow, id, passkey, &reqs)
                    .with_email(email(kit))
                    .with_first_steps(kit.auth.password, kit.auth.passkey),
                login_cookie(&started.handle, id),
            ),
        };
        Ok(Reply::ui(status, ui)
            .cookie(started.set_cookie)
            .cookie(Some(login)))
    }

    /// `GET /v1/login/flows/{flow}`: the flow's current step; a flow completed elsewhere (a
    /// confirmed magic link) signs this browser in here.
    pub async fn get(&self, entry: &RealmEntry, b: &Browser<'_>, handle: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        let flow = match flow_id(handle) {
            Ok(f) => f,
            Err(r) => return r,
        };
        let fref = FlowRef {
            handle,
            device: b.flow.unwrap_or_default(),
        };
        let current = match self.current(&auth, &kit, b, &fref).await {
            Ok(c) => c,
            Err(r) => return r,
        };
        self.render(&auth, &kit, &flow, &fref, current, 200)
            .await
            .unwrap_or_else(|r| r)
    }

    /// `POST /v1/login/flows/{flow}`: one method of the current step. Fields and methods the
    /// step did not offer are refused (TN-106); refusals before the first factor are the one
    /// neutral `401` (CR-40).
    pub async fn submit(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        handle: &str,
        submission: Submission,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        self.submitted(&auth, &kit, b, handle, submission)
            .await
            .unwrap_or_else(|r| r)
    }

    async fn submitted<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        b: &Browser<'_>,
        handle: &str,
        submission: Submission,
    ) -> Result<Reply, Reply> {
        let flow = flow_id(handle)?;
        let fref = FlowRef {
            handle,
            device: b.flow.unwrap_or_default(),
        };
        let current = self.current(auth, kit, b, &fref).await?;
        if let Current::Done(reply) = current {
            return Ok(reply);
        }
        let checked: Checked = shape(kit, &flow, &current)
            .ok_or_else(|| Reply::problem(FLOW_GONE))?
            .check(submission)
            .map_err(|_| Reply::problem(INVALID_SUBMISSION))?;
        let field = |name| checked.get(name).unwrap_or_default();
        let corr = b.correlation;
        steps(checked.method);
        let outcome = match (checked.method, &current) {
            (Method::Identifier, _) => {
                return self
                    .start(auth, kit, b, Some(field(FieldName::Identifier)), 200)
                    .await;
            }
            (Method::Restart, _) => return self.start(auth, kit, b, None, 200).await,
            // OP-153 m.3 (j), TN-96
            (Method::Password, Current::Identifier) if kit.signin.strict => {
                return self
                    .strict_password(
                        auth,
                        kit,
                        b,
                        field(FieldName::Identifier),
                        field(FieldName::Password),
                    )
                    .await;
            }
            (Method::Password, Current::Authenticate(identifier)) => auth
                .password(
                    &fref,
                    &PasswordStep {
                        identifier,
                        password: field(FieldName::Password),
                        ip: b.ip,
                        correlation: corr,
                    },
                )
                .await
                .map_err(|e| failed(&e))?,
            (Method::Passkey, _) => {
                let Some(owned) = credential::assertion(field(FieldName::PasskeyCredential)) else {
                    return self.refused(auth, kit, b, &flow, &fref, REJECTED, 0).await;
                };
                auth.passkey(&fref, &owned.response(), corr)
                    .await
                    .map_err(|e| failed(&e))?
            }
            (Method::Totp, _) => auth
                .totp(&fref, field(FieldName::TotpCode), corr)
                .await
                .map_err(|e| failed(&e))?,
            (Method::RecoveryCode, _) => auth
                .recovery_code(&fref, field(FieldName::RecoveryCode), corr)
                .await
                .map_err(|e| failed(&e))?,
            (Method::EmailCode, Current::Email(EmailWait::Code)) => auth
                .email_code(&fref, field(FieldName::EmailCode), corr)
                .await
                .map_err(|e| failed(&e))?,
            (Method::EmailCode, _) => auth
                .send_email(&fref, MethodClass::EmailOtp, corr)
                .await
                .map_err(|e| failed(&e))?,
            (Method::MagicLink, _) => auth
                .send_email(&fref, MethodClass::MagicLink, corr)
                .await
                .map_err(|e| failed(&e))?,
            _ => return Err(Reply::problem(INVALID_SUBMISSION)),
        };
        self.outcome(auth, kit, b, &flow, &fref, outcome).await
    }

    /// The strict mode's one-screen step (OP-153 m.3 (j)): the identifier opens the flow and the
    /// password is checked in the same request, so the answer never depends on the identifier
    /// alone.
    async fn strict_password<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        b: &Browser<'_>,
        identifier: &str,
        password: &str,
    ) -> Result<Reply, Reply> {
        let started = auth
            .identify(&Identify {
                identifier: Some(identifier),
                device: b.flow,
                marker: b.marker,
                keep_signed_in: false,
                remember_device: false,
            })
            .await
            .map_err(|e| failed(&e))?;
        let flow = flow_id(&started.handle)?;
        let fref = FlowRef {
            handle: &started.handle,
            device: &started.device,
        };
        let outcome = auth
            .password(
                &fref,
                &PasswordStep {
                    identifier,
                    password,
                    ip: b.ip,
                    correlation: b.correlation,
                },
            )
            .await
            .map_err(|e| failed(&e))?;
        if let Outcome::Rejected(Refusal { problem, pad_ms }) = outcome
            && problem.status == 401
        {
            let mut reply = self.start(auth, kit, b, None, 401).await?;
            if let Body::Ui(ui) = &mut reply.body {
                ui.messages.push(Message::error(TextId::LoginFailed));
            }
            reply.pad_ms = pad_ms;
            return Ok(reply.cookie(started.set_cookie));
        }
        if let Outcome::Throttled { retry_after_s } = outcome {
            let mut reply = self.start(auth, kit, b, None, 429).await?;
            if let Body::Ui(ui) = &mut reply.body {
                let seconds = u32::try_from(retry_after_s).unwrap_or(u32::MAX);
                ui.messages
                    .push(Message::error(TextId::TooManyAttempts).retry_after(seconds));
            }
            reply.retry_after_s = Some(retry_after_s);
            return Ok(reply.cookie(started.set_cookie));
        }
        let reply = match self.outcome(auth, kit, b, &flow, &fref, outcome).await {
            Ok(r) | Err(r) => r,
        };
        Ok(reply.cookie(started.set_cookie))
    }

    /// Where the flow stands: `resume` moves nothing but a flow whose e-mail step was
    /// confirmed elsewhere, which it completes.
    async fn current<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        b: &Browser<'_>,
        fref: &FlowRef<'_>,
    ) -> Result<Current, Reply> {
        let step = auth
            .resume(fref, b.correlation)
            .await
            .map_err(|e| failed(&e))?;
        Ok(match step {
            Outcome::Continue { enrolled: None, .. } => match typed(b, fref.handle) {
                Some(id) => Current::Authenticate(id),
                None => Current::Identifier,
            },
            Outcome::Continue {
                enrolled: Some(e), ..
            } => Current::Second(SecondFactors {
                totp: e.totp,
                recovery_code: e.recovery_codes,
                passkey: e.passkeys,
            }),
            Outcome::Suspended {
                method: MethodClass::MagicLink,
            } => Current::Email(EmailWait::Link),
            Outcome::Suspended { .. } => Current::Email(EmailWait::Code),
            Outcome::SignedIn(s) => {
                let flow = flow_id(fref.handle)?;
                Current::Done(
                    Reply::ui(
                        200,
                        Ui::complete(flow, self.redirect_to.clone(), &policy(kit)),
                    )
                    .cookie(s.set_cookie)
                    .cookie(s.marker_cookie)
                    .cookie(Some(clear_cookie(LOGIN_COOKIE))),
                )
            }
            Outcome::Throttled { retry_after_s } => {
                let mut r = Reply::problem(Problem {
                    status: 429,
                    code: "login-throttled",
                    title: "Too many attempts",
                    retry_after_s: Some(retry_after_s),
                });
                r.retry_after_s = Some(retry_after_s);
                Current::Done(r)
            }
            Outcome::Rejected(Refusal { problem, .. }) => Current::Done(Reply::problem(problem)),
        })
    }

    async fn render<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        flow: &FlowId,
        fref: &FlowRef<'_>,
        current: Current,
        status: u16,
    ) -> Result<Reply, Reply> {
        let reqs = policy(kit);
        let fresh = async |identifier: Option<&str>| match auth
            .passkey_options(fref, identifier)
            .await
            .map_err(|e| failed(&e))?
        {
            Ok(v) => options(v),
            Err(_) => Err(Reply::problem(FLOW_GONE)),
        };
        let blank = || options(json!({}));
        let ui = match current {
            Current::Done(r) => return Ok(r),
            // TN-132
            Current::Identifier if !kit.auth.passkey => first_step(
                kit,
                Ui::identifier(flow.clone(), blank()?, &reqs)
                    .with_first_steps(kit.auth.password, false),
            ),
            Current::Identifier => first_step(
                kit,
                Ui::identifier(flow.clone(), fresh(None).await?, &reqs)
                    .with_first_steps(kit.auth.password, true),
            ),
            Current::Authenticate(id) => {
                let passkey = if kit.auth.passkey {
                    fresh(Some(&id)).await?
                } else {
                    blank()?
                };
                Ui::authenticate(flow.clone(), &id, passkey, &reqs)
                    .with_email(email(kit))
                    .with_first_steps(kit.auth.password, kit.auth.passkey)
            }
            Current::Email(wait) => Ui::email_sent(flow.clone(), wait, &reqs),
            Current::Second(offered) => {
                let passkey = if offered.passkey {
                    Some(fresh(None).await?)
                } else {
                    None
                };
                Ui::second_factor(flow.clone(), offered, passkey, &reqs)
            }
        };
        Ok(Reply::ui(status, ui))
    }

    /// A refusal answered with the same step: the one neutral `401` before the first factor
    /// (CR-40), the honest one after it (X34).
    #[expect(clippy::too_many_arguments, reason = "one refused step's context")]
    async fn refused<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        b: &Browser<'_>,
        flow: &FlowId,
        fref: &FlowRef<'_>,
        problem: Problem,
        pad_ms: u64,
    ) -> Result<Reply, Reply> {
        if problem == FLOW_GONE {
            return Err(Reply::problem(FLOW_GONE));
        }
        if problem.status != 401 {
            let p = if problem.status == 409 {
                NOT_ALLOWED
            } else {
                problem
            };
            return Err(Reply::problem(p));
        }
        let current = self.current(auth, kit, b, fref).await?;
        let second = matches!(current, Current::Second(_));
        let mut reply = self.render(auth, kit, flow, fref, current, 401).await?;
        if let Body::Ui(ui) = &mut reply.body {
            let id = if !second {
                TextId::LoginFailed
            } else if problem == CODE_NOT_ACCEPTED || problem == REJECTED {
                TextId::SecondFactorFailed
            } else {
                TextId::PasskeyNotRegistered
            };
            ui.messages.push(Message::error(id));
        }
        reply.pad_ms = pad_ms;
        Ok(reply)
    }

    async fn outcome<N: Notifier + Sync>(
        &self,
        auth: &Signin<'_, C, N>,
        kit: &RealmKit,
        b: &Browser<'_>,
        flow: &FlowId,
        fref: &FlowRef<'_>,
        outcome: Outcome,
    ) -> Result<Reply, Reply> {
        let reqs = policy(kit);
        match outcome {
            Outcome::Continue {
                enrolled: Some(e), ..
            } => {
                let offered = SecondFactors {
                    totp: e.totp,
                    recovery_code: e.recovery_codes,
                    passkey: e.passkeys,
                };
                let passkey = if e.passkeys {
                    match auth
                        .passkey_options(fref, None)
                        .await
                        .map_err(|e| failed(&e))?
                    {
                        Ok(v) => Some(options(v)?),
                        Err(_) => return Err(Reply::problem(FLOW_GONE)),
                    }
                } else {
                    None
                };
                Ok(Reply::ui(
                    200,
                    Ui::second_factor(flow.clone(), offered, passkey, &reqs),
                ))
            }
            Outcome::Continue { enrolled: None, .. } => {
                let current = self.current(auth, kit, b, fref).await?;
                self.render(auth, kit, flow, fref, current, 200).await
            }
            Outcome::Suspended { method } => {
                let wait = if method == MethodClass::MagicLink {
                    EmailWait::Link
                } else {
                    EmailWait::Code
                };
                Ok(Reply::ui(200, Ui::email_sent(flow.clone(), wait, &reqs)))
            }
            Outcome::SignedIn(s) => Ok(Reply::ui(
                200,
                Ui::complete(flow.clone(), self.redirect_to.clone(), &reqs),
            )
            .cookie(s.set_cookie)
            .cookie(s.marker_cookie)
            .cookie(Some(clear_cookie(LOGIN_COOKIE)))),
            Outcome::Throttled { retry_after_s } => {
                let current = self.current(auth, kit, b, fref).await?;
                let mut reply = self.render(auth, kit, flow, fref, current, 429).await?;
                if let Body::Ui(ui) = &mut reply.body {
                    let seconds = u32::try_from(retry_after_s).unwrap_or(u32::MAX);
                    ui.messages
                        .push(Message::error(TextId::TooManyAttempts).retry_after(seconds));
                }
                reply.retry_after_s = Some(retry_after_s);
                Ok(reply)
            }
            Outcome::Rejected(Refusal { problem, pad_ms }) => {
                self.refused(auth, kit, b, flow, fref, problem, pad_ms)
                    .await
            }
        }
    }

    /// `POST /v1/login/link/preview`: what opening a magic link shows; consumes nothing
    /// (TN-102 rule 6).
    pub async fn preview_link(&self, entry: &RealmEntry, b: &Browser<'_>, token: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        match auth.preview_link(token, b.flow).await {
            Ok(LinkPreview::Confirm { same_device }) => Reply::json(
                200,
                json!({ "state": "confirm", "same_device": same_device }),
            ),
            Ok(LinkPreview::Invalid) => Reply::problem(FLOW_GONE),
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/login/link/confirm`: confirms a magic link (never a consuming GET). Another
    /// browser must say so explicitly; the session goes only to the browser that started the
    /// sign-in (§10.2.2, OP-146 m.14 (h)).
    pub async fn confirm_link(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        token: &str,
        other_device: bool,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        match auth
            .confirm_link(token, b.flow, other_device, b.correlation)
            .await
        {
            Ok(LinkOutcome::Confirmed { same_device }) => Reply::json(
                200,
                json!({ "state": "confirmed", "same_device": same_device }),
            ),
            Ok(LinkOutcome::NeedsConfirmation) => {
                Reply::json(200, json!({ "state": "needs_confirmation" }))
            }
            Ok(LinkOutcome::Invalid) => Reply::problem(FLOW_GONE),
            Err(e) => failed(&e),
        }
    }
}

/// §13.9 factor distribution and TN-99: the factor class of a submitted step; a passkey
/// assertion is the conditional UI stage the server sees. Telemetry only (TI-18).
fn steps(method: Method) {
    use access_telemetry::signals::{PASSKEY_CONDITIONAL_UI, SIGN_IN_FACTORS};
    let factor = match method {
        Method::Password => "password",
        Method::Passkey => {
            PASSKEY_CONDITIONAL_UI.incr(["assertion", "submitted"]);
            "passkey"
        }
        Method::Totp => "totp",
        Method::RecoveryCode => "recovery_code",
        Method::EmailCode => "email_code",
        Method::MagicLink => "magic_link",
        _ => return,
    };
    SIGN_IN_FACTORS.incr([factor]);
}
