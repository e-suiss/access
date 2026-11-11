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
mod approve_batch;
mod approve_inline;
pub mod certificate;
pub mod cloud_key;
mod credential;
pub mod devices;
pub mod did;
pub mod first_contact;
pub mod handle;
pub mod household;
pub mod hrd;
pub mod ldap;
mod me;
pub mod orgs;
pub mod pages;
pub mod payment;
pub mod privacy;
pub mod push;
pub mod recovery;
mod saml;
pub mod shell;
pub mod signup;
pub mod social;
pub mod sso_setup;
pub mod support;
pub mod upstream;
pub mod vault;
pub mod workloads;

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
use access_identity_session::app::push::{PushEnd, PushPoll, PushWait};
use access_identity_session::app::signin::{Identify, LinkOutcome, LinkPreview, PasswordStep};
use access_identity_session::app::{
    Auth, CODE_NOT_ACCEPTED, FLOW_GONE, FlowRef, Refusal, Step as Outcome,
};
use access_identity_session::domain::assurance::{Aal, MethodClass};
use access_identity_session::domain::requirement::MfaPolicy;
use access_identity_session::domain::session::{clear_cookie, set_cookie};
use access_identity_session::ports::Clock;
use access_identity_webauthn::domain::psl::Psl;
use access_identity_webauthn::domain::rp::related_origins_document;
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
    /// A `303 See Other` to this URL: the browser leaves for a provider or comes back from one
    /// (OP-153 m.3 (l)).
    Redirect(String),
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
    /// N5: further response headers (DBSC, TN-33), lower-case names.
    pub headers: Vec<(&'static str, String)>,
    /// N5: the problem's stable `reason` member ("Signed out because …", OP-153 m.3 (y)).
    pub reason: Option<&'static str>,
}

impl Reply {
    pub(crate) fn new(status: u16, body: Body) -> Self {
        Self {
            status,
            body,
            cookies: Vec::new(),
            retry_after_s: None,
            pad_ms: 0,
            headers: Vec::new(),
            reason: None,
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

    pub(crate) fn json(status: u16, value: Value) -> Self {
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

    pub(crate) fn cookie(mut self, c: Option<String>) -> Self {
        self.cookies.extend(c);
        self
    }

    pub(crate) fn header(mut self, name: &'static str, value: String) -> Self {
        self.headers.push((name, value));
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
    /// OP-156 m.3 (d): a push waits; the page shows the number until the end.
    Push(PushWait),
    /// OP-156 m.3 (d): the push ended without an approval; the second step again, with why.
    PushEnded(SecondFactors, TextId),
    /// OP-156 m.3 (d): "This wasn't me" stopped the sign-in.
    Stopped,
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
        let realm_hasher = $self.hasher.for_policy($kit.hash);
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
            hasher: &realm_hasher,
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

/// N5: the step-wide options of a login step (TN-36, X33, X-L2): "Keep me signed in" before
/// the first factor, the 30-day second-step marker on the second step when the realm allows
/// it. Neither starts checked.
fn with_options(kit: &RealmKit, mut ui: Ui) -> Ui {
    use crate::domain::flow::Step;
    use crate::domain::node::Node;
    if !ui.kind.is_login() {
        return ui;
    }
    let option = |name, id: TextId| Node::Option {
        name,
        label: id.into(),
        checked: false,
    };
    match ui.step {
        Step::Identifier | Step::Authenticate => ui
            .nodes
            .push(option(FieldName::KeepSignedIn, TextId::KeepSignedInLabel)),
        Step::SecondFactor if kit.auth.remember_device_days.is_some() => ui.nodes.push(option(
            FieldName::RememberDevice,
            TextId::RememberDeviceLabel,
        )),
        _ => {}
    }
    ui
}

/// Which options `ui` offered, as [`Signin::options`] takes them.
fn offered_options(ui: &Ui, checked: &Checked) -> (Option<bool>, Option<bool>) {
    use crate::domain::node::Node;
    let mut out = (None, None);
    for n in &ui.nodes {
        if let Node::Option { name, .. } = n {
            let on = checked.get(*name) == Some("true");
            match name {
                FieldName::KeepSignedIn => out.0 = Some(on),
                FieldName::RememberDevice => out.1 = Some(on),
                _ => {}
            }
        }
    }
    out
}

/// The path of an issuer URL below its host: empty for a host issuer, `/realms/{slug}` for a
/// path one (§17.9.6).
fn issuer_path(issuer: &str) -> &str {
    let rest = issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))
        .unwrap_or(issuer);
    rest.find('/')
        .and_then(|i| rest.get(i..))
        .unwrap_or_default()
        .trim_end_matches('/')
}

/// The shipped sign-in provider presets, for their names (OP-153 m.3 (l)).
fn shipped_presets() -> Option<&'static access_identity_federation::domain::preset::Presets> {
    static PRESETS: std::sync::OnceLock<
        Option<access_identity_federation::domain::preset::Presets>,
    > = std::sync::OnceLock::new();
    PRESETS
        .get_or_init(|| access_identity_federation::app::presets().ok())
        .as_ref()
}

fn shape(kit: &RealmKit, flow: &FlowId, current: &Current) -> Option<Ui> {
    shape_bare(kit, flow, current).map(|ui| with_options(kit, ui))
}

fn shape_bare(kit: &RealmKit, flow: &FlowId, current: &Current) -> Option<Ui> {
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
        Current::Second(offered) | Current::PushEnded(offered, _) => {
            Ui::second_factor(flow.clone(), *offered, Some(blank), &reqs)
        }
        Current::Push(w) => Ui::push_sent(
            flow.clone(),
            w.number,
            w.approver.clone(),
            crate::domain::frontend::rfc3339(w.expires_ms),
            &reqs,
        ),
        Current::Stopped => Ui::push_stopped(flow.clone(), &reqs),
        Current::Done(_) => return None,
    })
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    pub(crate) async fn kit(&self, entry: &RealmEntry) -> Result<Arc<RealmKit>, Reply> {
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
        related_origins_document(&kit.rp, &Psl)
            .map_err(|_| Reply::problem(SessionError::Corrupt.problem()))
    }

    /// N5: a login step as drawn: its step-wide options and, on the first step, a button for
    /// each active sign-in provider of the realm (TN-36, X33, OP-153 m.3 (l)). A provider list
    /// that cannot be read now leaves the buttons out; the step itself is unchanged.
    async fn drawn(&self, kit: &RealmKit, mut reply: Reply) -> Reply {
        use crate::domain::flow::Step;
        use crate::domain::node::Node;
        let Body::Ui(ui) = &mut reply.body else {
            return reply;
        };
        if !ui.kind.is_login() {
            return reply;
        }
        **ui = with_options(kit, (**ui).clone());
        if ui.step != Step::Identifier {
            return reply;
        }
        let rows = async {
            let mut t =
                access_store::identity::TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let rows = t.social_providers().await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(rows)
        };
        let Ok(rows) = rows.await else {
            return reply;
        };
        for row in rows.into_iter().filter(|r| r.active) {
            let name = shipped_presets()
                .and_then(|p| p.get(&row.preset))
                .map_or_else(|| row.preset.clone(), |p| p.display_name.clone());
            ui.nodes.push(Node::Provider {
                label: crate::domain::message::Text {
                    id: TextId::ContinueWith,
                    text: format!("Continue with {name}"),
                },
                href: format!("/v1/login/social/{}", row.preset),
                provider: row.preset,
            });
        }
        // TN-95, OP-155 m.3 (h), Ek B 4678
        for (name, display) in self.upstream_buttons(kit).await {
            ui.nodes.push(Node::Provider {
                label: crate::domain::message::Text {
                    id: TextId::SignInWith,
                    text: format!("Sign in with {display}"),
                },
                href: format!("/v1/login/upstream/{name}"),
                provider: name,
            });
        }
        reply
    }

    /// The realm's active upstream connections that sign anyone in: not an organization's,
    /// which home realm discovery names (TN-98), with the name on their button.
    async fn upstream_buttons(&self, kit: &RealmKit) -> Vec<(String, String)> {
        use access_identity_federation::domain::connection::Profile;
        let rows = async {
            let mut t =
                access_store::identity::TenantTx::begin(&self.db, kit.tenant, kit.realm).await?;
            let rows = access_store::idp::realm::upstreams(&mut t, "", 32).await?;
            t.commit().await?;
            Ok::<_, access_store::StoreError>(rows)
        };
        let Ok(rows) = rows.await else {
            return Vec::new();
        };
        rows.into_iter()
            .filter(|r| r.active)
            .filter_map(|r| {
                let p =
                    Profile::stored(r.profile.as_deref(), r.client_secret_ref.is_some()).ok()?;
                if p.organization.is_some() {
                    return None;
                }
                let display =
                    p.display_name
                        .clone()
                        .or_else(|| {
                            p.preset.as_deref().and_then(
                            access_identity_federation::domain::connection::UpstreamPreset::get,
                        ).map(|x| x.display_name.clone())
                        })
                        .unwrap_or_else(|| r.name.clone());
                Some((r.name, display))
            })
            .collect()
    }

    /// `POST /v1/login/flows`: a new flow at the identifier step, with discoverable passkey
    /// options (TN-96, TN-99).
    pub async fn create(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        signin!(self, kit, auth, Some(b.ip));
        let reply = self
            .start(&auth, &kit, b, None, 201, false)
            .await
            .unwrap_or_else(|r| r);
        self.drawn(&kit, reply).await
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
        keep_signed_in: bool,
    ) -> Result<Reply, Reply> {
        let started = auth
            .identify(&Identify {
                identifier,
                device: b.flow,
                marker: b.marker,
                keep_signed_in,
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
        let reply = self
            .render(&auth, &kit, &flow, &fref, current, 200)
            .await
            .unwrap_or_else(|r| r);
        self.drawn(&kit, reply).await
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
        let reply = self
            .submitted(&auth, &kit, b, handle, submission)
            .await
            .unwrap_or_else(|r| r);
        self.drawn(&kit, reply).await
    }

    #[expect(clippy::too_many_lines, reason = "one dispatch arm per method")]
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
        let step = shape(kit, &flow, &current).ok_or_else(|| Reply::problem(FLOW_GONE))?;
        let checked: Checked = step
            .check(submission)
            .map_err(|_| Reply::problem(INVALID_SUBMISSION))?;
        let (keep, remember) = offered_options(&step, &checked);
        // TN-36, X33
        let opens_flow = matches!(checked.method, Method::Identifier | Method::Restart)
            || (checked.method == Method::Password && kit.signin.strict);
        if !opens_flow && (keep.is_some() || remember.is_some()) {
            auth.options(&fref, keep, remember)
                .await
                .map_err(|e| failed(&e))?;
        }
        let field = |name| checked.get(name).unwrap_or_default();
        let corr = b.correlation;
        steps(checked.method);
        let outcome = match (checked.method, &current) {
            (Method::Identifier, _) => {
                return self
                    .start(
                        auth,
                        kit,
                        b,
                        Some(field(FieldName::Identifier)),
                        200,
                        keep == Some(true),
                    )
                    .await;
            }
            (Method::Restart, _) => return self.start(auth, kit, b, None, 200, false).await,
            // OP-153 m.3 (j), TN-96
            (Method::Password, Current::Identifier) if kit.signin.strict => {
                return self
                    .strict_password(
                        auth,
                        kit,
                        b,
                        field(FieldName::Identifier),
                        field(FieldName::Password),
                        keep == Some(true),
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
            // OP-156 m.3 (d)
            (Method::Push, _) => return self.push_step(auth, kit, b, &flow, &fref, current).await,
            // OP-156 m.3 (f)
            (Method::SendSms, _) => {
                return self.sms_step(auth, kit, b, &flow, &fref, current).await;
            }
            (Method::Sms, _) => auth
                .sms(&fref, field(FieldName::SmsCode), corr)
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
        keep_signed_in: bool,
    ) -> Result<Reply, Reply> {
        let started = auth
            .identify(&Identify {
                identifier: Some(identifier),
                device: b.flow,
                marker: b.marker,
                keep_signed_in,
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
            let mut reply = self.start(auth, kit, b, None, 401, false).await?;
            if let Body::Ui(ui) = &mut reply.body {
                ui.messages.push(Message::error(TextId::LoginFailed));
            }
            reply.pad_ms = pad_ms;
            return Ok(reply.cookie(started.set_cookie));
        }
        if let Outcome::Throttled { retry_after_s } = outcome {
            let mut reply = self.start(auth, kit, b, None, 429, false).await?;
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
        // OP-156 m.3 (d), TN-102
        let mut ended = None;
        let step = match auth
            .poll_push(fref, b.correlation)
            .await
            .map_err(|e| failed(&e))?
        {
            PushPoll::Step(s) => s,
            PushPoll::Waiting(w) => {
                return Ok(Current::Push(w));
            }
            PushPoll::Ended(PushEnd::NotMe) => return Ok(Current::Stopped),
            PushPoll::Ended(end) => {
                ended = Some(if end == PushEnd::Expired {
                    TextId::PushExpired
                } else {
                    TextId::PushDenied
                });
                auth.resume(fref, b.correlation)
                    .await
                    .map_err(|e| failed(&e))?
            }
        };
        Ok(match step {
            Outcome::Continue { enrolled: None, .. } => match typed(b, fref.handle) {
                Some(id) => Current::Authenticate(id),
                None => Current::Identifier,
            },
            Outcome::Continue {
                enrolled: Some(e), ..
            } => {
                let offered = SecondFactors {
                    totp: e.totp,
                    recovery_code: e.recovery_codes,
                    passkey: e.passkeys,
                    push: e.push,
                    sms: e.sms,
                };
                match ended {
                    Some(why) => Current::PushEnded(offered, why),
                    None => Current::Second(offered),
                }
            }
            Outcome::Suspended {
                method: MethodClass::MagicLink,
            } => Current::Email(EmailWait::Link),
            Outcome::Suspended {
                method: MethodClass::Push,
            } => Current::Done(Reply::problem(FLOW_GONE)),
            Outcome::Suspended { .. } => Current::Email(EmailWait::Code),
            Outcome::SignedIn(s) => {
                let flow = flow_id(fref.handle)?;
                let reply = Reply::ui(
                    200,
                    Ui::complete(flow, self.redirect_to.clone(), &policy(kit)),
                )
                .cookie(s.set_cookie)
                .cookie(s.marker_cookie)
                .cookie(Some(clear_cookie(LOGIN_COOKIE)));
                // TN-33, OP-153 m.3 (y)
                Current::Done(self.offer_dbsc(auth, kit, s.session, reply).await)
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
            // OP-156 m.3 (d)
            Current::PushEnded(offered, why) => {
                let passkey = if offered.passkey {
                    Some(fresh(None).await?)
                } else {
                    None
                };
                let mut ui = Ui::second_factor(flow.clone(), offered, passkey, &reqs);
                ui.messages.push(Message::error(why));
                ui
            }
            Current::Push(w) => Ui::push_sent(
                flow.clone(),
                w.number,
                w.approver,
                crate::domain::frontend::rfc3339(w.expires_ms),
                &reqs,
            ),
            Current::Stopped => Ui::push_stopped(flow.clone(), &reqs),
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
        let second = matches!(current, Current::Second(_) | Current::PushEnded(..));
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
                    push: e.push,
                    sms: e.sms,
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
            Outcome::SignedIn(s) => {
                let reply = Reply::ui(
                    200,
                    Ui::complete(flow.clone(), self.redirect_to.clone(), &reqs),
                )
                .cookie(s.set_cookie)
                .cookie(s.marker_cookie)
                .cookie(Some(clear_cookie(LOGIN_COOKIE)));
                // TN-33, OP-153 m.3 (y)
                Ok(self.offer_dbsc(auth, kit, s.session, reply).await)
            }
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
        Method::Push => "push",
        Method::Sms => "sms",
        _ => return,
    };
    SIGN_IN_FACTORS.incr([factor]);
}
