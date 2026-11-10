//! The hosted sign-up flow and the e-mail change of S11 (§12.3.6, TN-80–83, OP-153 m.3 (g)–(i)).
//!
//! A sign-up flow handle is `r` followed by 43 base64url characters, so it never reads as a
//! login flow. The first step takes the address (and the page's bot token); the second step,
//! the same for every address, takes the code with the display name; a password or a passkey is
//! added once signed in.
//! Every answer of the first step is padded to the 250 ms floor and says nothing about whether
//! the address has an account (TN-80 invariants 2 and 4, CR-40).

use std::sync::Arc;

use access_identity_account::adapters::bot::BotProviders;
use access_identity_account::app::Actor;
use access_identity_account::app::registration::{
    Proven, Refused, Registrar, Rules, Start, Started, prefix,
};
use access_identity_account::domain::login::Problem;
use access_identity_account::domain::registration::{
    DisposableDomains, DisposableListError, FLOOR_MS,
};
use access_identity_account::ports::{MailDomains, NoResolver};
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::app::sessions::SessionStatus;
use access_identity_session::app::{FLOW_GONE, Step as Outcome};
use access_identity_session::domain::flow::{device_digest, handle_digest};
use access_identity_session::domain::session::{FLOW_COOKIE, set_cookie};
use access_identity_session::ports::Clock;
use access_kernel::json::{b64url_decode, b64url_encode};
use serde_json::json;

use super::{Body, Browser, Hosted, Reply, SESSION_REQUIRED, failed, signin};
use crate::domain::flow::{
    CONTRACT_VERSION, FlowId, FlowKind, Requirement, RequirementState, RequirementStatus,
    SecondFactors, Step, Ui,
};
use crate::domain::message::{Message, TextId};
use crate::domain::node::{Autocomplete, FieldName, InputKind, Method, Node};
use crate::domain::submission::Submission;
use crate::ports::{Kits, Messages, RealmKit};

/// The prefix of a sign-up flow handle.
const PREFIX: char = 'r';

/// How fresh the session's last authentication must be to change the address (OP-153 m.3 (i)).
pub const STEP_UP_MAX_AGE_MS: u64 = 300_000;

/// The step-up an e-mail change needs first (X29).
pub const STEP_UP_REQUIRED: Problem = Problem {
    status: 401,
    code: "step-up-required",
    title: "Confirm it's you to continue with this action",
    retry_after_s: None,
};

/// What sign-up needs beyond the login's services.
#[derive(Clone)]
pub struct Signup {
    /// The bot signal sources (OP-153 m.1 (b)).
    pub bots: BotProviders,
    /// The disposable-domain list (TN-81).
    pub disposable: DisposableDomains,
    /// The MX/A lookup of the first step (OP-153 m.11 (f)).
    pub mail: Arc<dyn MailDomains>,
}

impl core::fmt::Debug for Signup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signup")
            .field("bots", &self.bots)
            .finish_non_exhaustive()
    }
}

impl Signup {
    /// No bot provider and no resolver: every signal is `Unavailable`, every domain `Unknown`,
    /// and sign-up goes on through the cheap gate and the out-of-band code (OP-153 m.1 (b)).
    ///
    /// # Errors
    /// [`DisposableListError`] when the shipped list is outside its format.
    pub fn without_providers() -> Result<Self, DisposableListError> {
        Ok(Self {
            bots: BotProviders::default(),
            disposable: DisposableDomains::embedded()?,
            mail: Arc::new(NoResolver),
        })
    }
}

/// Whether `handle` is a sign-up flow's.
#[must_use]
pub fn is_signup(handle: &str) -> bool {
    handle.len() == 44 && handle.starts_with(PREFIX)
}

fn signup_secret(handle: &str) -> Option<[u8; 32]> {
    let rest = handle.strip_prefix(PREFIX)?;
    <[u8; 32]>::try_from(b64url_decode(rest).ok()?).ok()
}

fn device_secret(cookie: Option<&str>) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(b64url_decode(cookie?).ok()?).ok()
}

fn requirements(step: Step) -> Vec<RequirementStatus> {
    [Requirement::Identifier, Requirement::FirstFactor]
        .into_iter()
        .map(|requirement| RequirementStatus {
            requirement,
            state: if step == Step::Authenticate && requirement == Requirement::Identifier {
                RequirementState::Satisfied
            } else {
                RequirementState::Missing
            },
        })
        .collect()
}

fn ui(flow: FlowId, step: Step, nodes: Vec<Node>) -> Ui {
    Ui {
        version: CONTRACT_VERSION,
        action: flow.path(),
        flow,
        kind: FlowKind::Registration,
        step,
        requirements: requirements(step),
        nodes,
        messages: Vec::new(),
        redirect_to: None,
    }
}

/// The first step: the address and the page's bot token (OP-153 m.3 (g)).
#[must_use]
pub fn address_step(flow: FlowId) -> Ui {
    let nodes = vec![
        Node::input(
            FieldName::Email,
            Method::Register,
            InputKind::Text,
            Autocomplete::Email,
            TextId::EmailLabel.into(),
        ),
        Node::Input {
            name: FieldName::BotToken,
            method: Method::Register,
            kind: InputKind::Hidden,
            autocomplete: Autocomplete::Off,
            required: false,
            max_length: FieldName::BotToken.max_length(),
            label: TextId::RegistrationTitle.into(),
            value: None,
            read_only: false,
        },
        Node::Submit {
            method: Method::Register,
            label: TextId::CreateAccount.into(),
        },
    ];
    ui(flow, Step::Identifier, nodes)
}

/// The second step, the same for every address: the code and the display name (required when
/// the realm says so).
#[must_use]
pub fn code_step(flow: FlowId, name_required: bool) -> Ui {
    let mut nodes = vec![Node::input(
        FieldName::EmailCode,
        Method::EmailCode,
        InputKind::Code,
        Autocomplete::OneTimeCode,
        TextId::EmailCodeLabel.into(),
    )];
    nodes.push(Node::Input {
        name: FieldName::DisplayName,
        method: Method::EmailCode,
        kind: InputKind::Text,
        autocomplete: Autocomplete::Name,
        required: name_required,
        max_length: FieldName::DisplayName.max_length(),
        label: TextId::DisplayNameLabel.into(),
        value: None,
        read_only: false,
    });
    nodes.push(Node::Submit {
        method: Method::EmailCode,
        label: TextId::Verify.into(),
    });
    let mut u = ui(flow, Step::Authenticate, nodes);
    u.messages.push(Message::info(TextId::RegistrationCodeSent));
    u
}

fn rules(kit: &RealmKit, email: &str) -> Rules {
    Rules {
        domain_allowed: kit.signin.registration_allowed(email),
        name_required: kit.signin.name_required(),
    }
}

impl<K, C, M> Hosted<K, C, M>
where
    K: Kits,
    C: Clock + Sync,
    M: Messages,
{
    /// `POST /v1/login/flows` with `kind: registration` (OP-153 m.3 (g)): a new sign-up flow at
    /// its address step, and the flow cookie when the browser has none.
    pub async fn create_signup(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        if let Err(r) = self.kit(entry).await {
            return r;
        }
        let Ok(secret) = access_crypto::random::bytes::<32>() else {
            return Reply::problem(FLOW_GONE);
        };
        let Some(flow) = FlowId::parse(&format!("{PREFIX}{}", b64url_encode(&secret))) else {
            return Reply::problem(FLOW_GONE);
        };
        let cookie = if device_secret(b.flow).is_some() {
            None
        } else {
            access_crypto::random::bytes::<32>()
                .ok()
                .map(|d| set_cookie(FLOW_COOKIE, &b64url_encode(&d), None))
        };
        Reply::ui(201, address_step(flow)).cookie(cookie)
    }

    /// `GET /v1/login/flows/{flow}` of a sign-up flow: the address step until a challenge exists
    /// for it, then the code step.
    pub async fn get_signup(&self, entry: &RealmEntry, b: &Browser<'_>, handle: &str) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        let (Some(flow), Some(_)) = (FlowId::parse(handle), signup_secret(handle)) else {
            return Reply::problem(FLOW_GONE);
        };
        if device_secret(b.flow).is_none() {
            return Reply::problem(FLOW_GONE);
        }
        Reply::ui(200, code_step(flow, kit.signin.name_required()))
    }

    /// `POST /v1/login/flows/{flow}` of a sign-up flow.
    #[expect(
        clippy::too_many_lines,
        reason = "both steps of one flow: the request and the code"
    )]
    pub async fn submit_signup(
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
        let (Some(flow), Some(secret), Some(device)) = (
            FlowId::parse(handle),
            signup_secret(handle),
            device_secret(b.flow),
        ) else {
            return Reply::problem(FLOW_GONE);
        };
        let flow_hash = handle_digest(&secret);
        let device_hash = device_digest(&device);
        let step = if submission.method == Method::Register {
            address_step(flow.clone())
        } else {
            code_step(flow.clone(), kit.signin.name_required())
        };
        let Ok(checked) = step.check(submission) else {
            return Reply::problem(super::INVALID_SUBMISSION);
        };
        let field = |n| checked.get(n).map(str::to_owned);
        let realm = kit.realm();
        let vault = kit.vault();
        let notifier = self.messages.notifier(&realm);
        let registrar = Registrar {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
            bots: &self.signup.bots,
            disposable: &self.signup.disposable,
            mail: self.signup.mail.as_ref(),
            notifier: &notifier,
        };
        let actor = Actor {
            actor: "anonymous",
            correlation: b.correlation,
        };
        let started_ms = self.clock.now_ms();
        if checked.method == Method::Register {
            let email = field(FieldName::Email).unwrap_or_default();
            let token = field(FieldName::BotToken);
            let net = prefix(b.ip);
            let r = registrar
                .start(
                    &Start {
                        email: &email,
                        bot_token: token.as_deref(),
                        prefix: &net,
                        flow_hash,
                        device_hash,
                        now_ms: started_ms,
                    },
                    &rules(&kit, &email),
                    &actor,
                )
                .await;
            let mut reply = match r {
                Ok(Started::Sent { .. }) => {
                    Reply::ui(200, code_step(flow, kit.signin.name_required()))
                }
                Ok(Started::Refused(Refused::Throttled { retry_after_ms })) => {
                    let s = retry_after_ms.div_ceil(1000);
                    let mut u = address_step(flow);
                    u.messages = vec![
                        Message::error(TextId::TooManyAttempts)
                            .retry_after(u32::try_from(s).unwrap_or(u32::MAX)),
                    ];
                    let mut r = Reply::ui(429, u);
                    r.retry_after_s = Some(s);
                    r
                }
                Ok(Started::Refused(_)) => {
                    let mut u = address_step(flow);
                    u.messages = vec![Message::error(TextId::RegistrationFailed)];
                    Reply::ui(400, u)
                }
                Err(e) => return failed(&e.into()),
            };
            // TN-80
            let spent = self.clock.now_ms().saturating_sub(started_ms);
            reply.pad_ms = FLOOR_MS.saturating_sub(spent);
            return reply;
        }
        let code = field(FieldName::EmailCode).unwrap_or_default();
        let name = field(FieldName::DisplayName).filter(|n| !n.trim().is_empty());
        if kit.signin.name_required() && name.is_none() {
            let mut u = code_step(flow, true);
            u.messages = vec![Message::error(TextId::RegistrationFailed)];
            return Reply::ui(400, u);
        }
        let proven = registrar
            .complete(
                &flow_hash,
                &device_hash,
                &code,
                name.as_deref(),
                started_ms,
                &actor,
            )
            .await;
        let (subject, since) = match proven {
            Ok(Proven::Done {
                subject,
                owner_since_ms,
            }) => (subject, owner_since_ms),
            Ok(Proven::Wrong) => {
                let mut u = code_step(flow, kit.signin.name_required());
                u.messages = vec![Message::error(TextId::RegistrationFailed)];
                return Reply::ui(401, u);
            }
            Ok(Proven::Gone) => return Reply::problem(FLOW_GONE),
            Err(e) => return failed(&e.into()),
        };
        signin!(self, kit, auth, Some(b.ip));
        match auth.registered(subject, since, b.flow, b.correlation).await {
            Ok(opened) => {
                let Some(next) = FlowId::parse(&opened.handle) else {
                    return Reply::problem(FLOW_GONE);
                };
                let reqs = super::policy(&kit);
                match opened.step {
                    Outcome::SignedIn(s) => {
                        Reply::ui(200, Ui::complete(next, self.redirect_to.clone(), &reqs))
                            .cookie(s.set_cookie)
                            .cookie(s.marker_cookie)
                    }
                    Outcome::Continue {
                        enrolled: Some(e), ..
                    } => Reply::ui(
                        200,
                        Ui::second_factor(
                            next,
                            SecondFactors {
                                totp: e.totp,
                                recovery_code: e.recovery_codes,
                                passkey: e.passkeys,
                                push: e.push,
                            },
                            None,
                            &reqs,
                        ),
                    ),
                    _ => Reply::problem(FLOW_GONE),
                }
            }
            Err(e) => failed(&e),
        }
    }

    async fn fresh_subject(&self, kit: &RealmKit, b: &Browser<'_>) -> Result<[u8; 16], Reply> {
        signin!(self, kit, auth);
        let Some(cookie) = b.session else {
            return Err(Reply::problem(SESSION_REQUIRED));
        };
        let v = match auth.check_session(cookie).await {
            Ok(SessionStatus::Valid(v)) => v,
            Ok(_) => return Err(Reply::problem(SESSION_REQUIRED)),
            Err(e) => return Err(failed(&e)),
        };
        let last = v.step_up_ms.unwrap_or(v.auth_time_ms).max(v.auth_time_ms);
        if self.clock.now_ms().saturating_sub(last) > STEP_UP_MAX_AGE_MS {
            return Err(Reply::problem(STEP_UP_REQUIRED));
        }
        Ok(v.subject)
    }

    /// `POST /v1/account/credential-export` (TN-86, B19): after a fresh step-up, the owner's
    /// password hash and authenticator app seeds; refused in a recovery's grace period (TN-56).
    pub async fn export_credentials(&self, entry: &RealmEntry, b: &Browser<'_>) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        // TN-56, OP-153 m.3 (e)
        if let Some(r) = self
            .grace_refusal(
                &kit,
                b,
                access_identity_session::domain::recovery::Restricted::Export,
            )
            .await
        {
            return r;
        }
        let subject = match self.fresh_subject(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        signin!(self, kit, auth);
        match auth.export_credentials(subject, b.correlation).await {
            Ok(x) => {
                let password = x.password.map(|p| {
                    json!({
                        "algorithm": p.algorithm,
                        "hash": p.hash.expose(),
                        "hash_transform": p.transform.as_ref().map(|t| t.expose().clone()),
                    })
                });
                let totp: Vec<_> = x
                    .totp
                    .iter()
                    .map(|s| {
                        json!({
                            "secret": s.expose(),
                            "algorithm": "SHA1",
                            "digits": 6,
                            "period": 30,
                        })
                    })
                    .collect();
                Reply::json(200, json!({ "password": password, "totp": totp }))
            }
            Err(e) => failed(&e),
        }
    }

    /// `POST /v1/account/email` (OP-153 m.3 (i)): after a fresh step-up, a code goes to the new
    /// address; the answer is the same whether or not another account holds it.
    pub async fn start_email_change(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        email: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        // TN-56, OP-153 m.3 (e)
        if let Some(r) = self
            .grace_refusal(
                &kit,
                b,
                access_identity_session::domain::recovery::Restricted::ContactChange,
            )
            .await
        {
            return r;
        }
        let subject = match self.fresh_subject(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let (Ok(secret), Some(session)) = (access_crypto::random::bytes::<32>(), b.session) else {
            return Reply::problem(SESSION_REQUIRED);
        };
        let handle = format!("{PREFIX}{}", b64url_encode(&secret));
        let realm = kit.realm();
        let vault = kit.vault();
        let notifier = self.messages.notifier(&realm);
        let registrar = Registrar {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
            bots: &self.signup.bots,
            disposable: &self.signup.disposable,
            mail: self.signup.mail.as_ref(),
            notifier: &notifier,
        };
        let actor_ref = kit.realm().external(subject).unwrap_or_default();
        let actor = Actor {
            actor: &actor_ref,
            correlation: b.correlation,
        };
        let net = prefix(b.ip);
        let now = self.clock.now_ms();
        match registrar
            .start_change(
                subject,
                &Start {
                    email,
                    bot_token: None,
                    prefix: &net,
                    flow_hash: handle_digest(&secret),
                    device_hash: session_digest(session),
                    now_ms: now,
                },
                &rules(&kit, email),
                &actor,
            )
            .await
        {
            Ok(Started::Sent { .. }) => Reply::json(202, json!({ "change": handle })),
            Ok(Started::Refused(Refused::Throttled { retry_after_ms })) => {
                Reply::problem(Problem {
                    status: 429,
                    code: "too-many-requests",
                    title: "Too many attempts",
                    retry_after_s: Some(retry_after_ms.div_ceil(1000)),
                })
            }
            Ok(Started::Refused(_)) => Reply::problem(Problem {
                status: 400,
                code: "invalid-email",
                title: "This address can't be used here",
                retry_after_s: None,
            }),
            Err(e) => failed(&e.into()),
        }
    }

    /// `POST /v1/account/email/{change}` (OP-153 m.3 (i), TN-64): the code from the new address
    /// makes it the account's; the old address is told and every session ends.
    pub async fn confirm_email_change(
        &self,
        entry: &RealmEntry,
        b: &Browser<'_>,
        change: &str,
        code: &str,
    ) -> Reply {
        let kit = match self.kit(entry).await {
            Ok(k) => k,
            Err(r) => return r,
        };
        // TN-56, OP-153 m.3 (e)
        if let Some(r) = self
            .grace_refusal(
                &kit,
                b,
                access_identity_session::domain::recovery::Restricted::ContactChange,
            )
            .await
        {
            return r;
        }
        let subject = match self.fresh_subject(&kit, b).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let (Some(secret), Some(session)) = (signup_secret(change), b.session) else {
            return Reply::problem(FLOW_GONE);
        };
        let realm = kit.realm();
        let vault = kit.vault();
        let notifier = self.messages.notifier(&realm);
        let registrar = Registrar {
            pool: &self.db,
            realm: &realm,
            vault: &vault,
            bots: &self.signup.bots,
            disposable: &self.signup.disposable,
            mail: self.signup.mail.as_ref(),
            notifier: &notifier,
        };
        let actor_ref = kit.realm().external(subject).unwrap_or_default();
        let actor = Actor {
            actor: &actor_ref,
            correlation: b.correlation,
        };
        match registrar
            .complete_change(
                subject,
                &handle_digest(&secret),
                &session_digest(session),
                code,
                kit.signin.email_keep_days,
                self.clock.now_ms(),
                &actor,
            )
            .await
        {
            Ok(Proven::Done { .. }) => Reply::new(204, Body::Empty).cookie(Some(
                access_identity_session::domain::session::clear_cookie(
                    access_identity_session::domain::session::SESSION_COOKIE,
                ),
            )),
            Ok(Proven::Wrong) => Reply::problem(access_identity_session::app::CODE_NOT_ACCEPTED),
            Ok(Proven::Gone) => Reply::problem(FLOW_GONE),
            Err(e) => failed(&e.into()),
        }
    }
}

fn session_digest(cookie: &str) -> [u8; 32] {
    let mut m = b"access/address-challenge-session/v1\0".to_vec();
    m.extend_from_slice(cookie.as_bytes());
    suiss_crypto::digest::sha256(&m)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-153 m.3 (g), TN-106
    #[test]
    fn signup_handles_never_read_as_login_handles() {
        let login = b64url_encode(&[7_u8; 32]);
        assert_eq!(login.len(), 43);
        assert!(!is_signup(&login));
        let signup = format!("{PREFIX}{login}");
        assert!(is_signup(&signup));
        assert_eq!(signup_secret(&signup), Some([7; 32]));
        let a = address_step(FlowId::parse(&signup).unwrap());
        assert_eq!(a.kind, FlowKind::Registration);
        assert!(a.messages.iter().all(|m| m.id.pre_auth()));
        let c = code_step(FlowId::parse(&signup).unwrap(), true);
        assert!(c.messages.iter().all(|m| m.id.pre_auth()));
    }
}
