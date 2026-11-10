//! A login step as the client sees it: the requirement list, the nodes and the messages
//! (TN-106, TN-132).
//!
//! The server decides what is required; the client decides order and screens. Before the first
//! factor succeeds a step is built only from realm policy and from what the client sent, never
//! from the account, so it reads the same whether or not the account exists (CR-40, X34).

use core::fmt;

use serde::{Deserialize, Serialize};

use super::message::{Message, Text, TextId};
use super::node::{
    Autocomplete, CreateMediation, FieldName, InputKind, Method, Node, PasskeyOptions,
    PasskeySignal,
};

/// Contract version; additive changes keep it (OP-65).
pub const CONTRACT_VERSION: u32 = 1;

/// Frontend API path that creates a flow (`POST`).
pub const FLOWS_PATH: &str = "/v1/login/flows";

/// An opaque login flow handle (TN-102 rule 1): 1–128 characters of `[A-Za-z0-9_-]`. It
/// carries no authority; `Debug` does not print it.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FlowId(String);

impl FlowId {
    /// Longest handle.
    pub const MAX_LEN: usize = 128;

    /// Parses a handle.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let ok = !text.is_empty()
            && text.len() <= Self::MAX_LEN
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        ok.then(|| Self(text.to_owned()))
    }

    /// The handle.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The step's submit and fetch path.
    #[must_use]
    pub fn path(&self) -> String {
        format!("{FLOWS_PATH}/{}", self.0)
    }
}

impl fmt::Debug for FlowId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FlowId(..)")
    }
}

impl TryFrom<String> for FlowId {
    type Error = ContractError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse(&text).ok_or(ContractError::FlowId)
    }
}

impl From<FlowId> for String {
    fn from(id: FlowId) -> Self {
        id.0
    }
}

/// What a flow is for (OP-153 m.2 N0). A step names its kind; `login` is the default and is
/// left out on the wire, so a login step reads as it did before.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    /// Sign in (TN-96).
    #[default]
    Login,
    /// Create an account (OP-153 m.3 (g)).
    Registration,
    /// Get back into an account (OP-153 m.3 (d)).
    Recovery,
    /// Change the account's own settings (S11).
    Settings,
    /// Share claims with an app (OP-153 m.3 (z)).
    Consent,
    /// Accept an organization's invitation (OP-153 m.3 (o)).
    Invitation,
    /// Link another sign-in (OP-153 m.3 (m)).
    Link,
}

impl FlowKind {
    /// Every kind.
    pub const ALL: [Self; 7] = [
        Self::Login,
        Self::Registration,
        Self::Recovery,
        Self::Settings,
        Self::Consent,
        Self::Invitation,
        Self::Link,
    ];

    /// Whether this is the default kind, left out on the wire.
    #[must_use]
    pub fn is_login(&self) -> bool {
        *self == Self::Login
    }
}

/// Where the flow is. Informational: the server's rules depend on the requirement list, not
/// on the order of steps (TN-132).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Collect the identifier, or sign in with a passkey directly (TN-96).
    Identifier,
    /// The first factor: password or passkey, offered whether or not the account exists.
    Authenticate,
    /// MFA, after the first factor.
    SecondFactor,
    /// Done; follow `redirect_to`.
    Complete,
}

/// Something the flow must have before a session exists (TN-132).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// An identifier, or a discoverable passkey that names the account itself.
    Identifier,
    /// A password or a passkey.
    FirstFactor,
    /// A second factor, when realm policy requires MFA.
    SecondFactor,
}

/// Whether a requirement is met.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementState {
    /// Still to do.
    Missing,
    /// Done.
    Satisfied,
}

/// One entry of the requirement list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementStatus {
    /// What.
    pub requirement: Requirement,
    /// Whether it is met.
    pub state: RequirementState,
}

/// A misuse of the contract builders: a server bug, not a user outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ContractError {
    /// The flow handle is malformed.
    #[error("malformed flow id")]
    FlowId,
    /// A text that tells something about the account, on a step before the first factor (X34).
    #[error("message {0:?} is not allowed before the first factor")]
    Message(TextId),
    /// A Signal API call that names the account, before the first factor (TN-97).
    #[error("passkey signal is not allowed before the first factor")]
    Signal,
    /// Passkey creation outside the completed step.
    #[error("passkey creation is offered only once the user is signed in")]
    PasskeyCreate,
}

/// Which second factors the step offers.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each second factor the step offers is one flag"
)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecondFactors {
    /// TOTP.
    pub totp: bool,
    /// Recovery code.
    pub recovery_code: bool,
    /// A passkey: possession and UV after the password (IDP-8, §10.2 AAL2 table).
    pub passkey: bool,
    /// A push to the account's approvers (OP-156 m.3 (d)).
    pub push: bool,
}

/// Which e-mail first steps the realm offers (TN-102). Realm policy, never the account.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EmailMethods {
    /// A code by e-mail.
    pub code: bool,
    /// A sign-in link by e-mail.
    pub link: bool,
}

/// What an e-mail step is waiting for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailWait {
    /// The code from the e-mail.
    Code,
    /// The link in the e-mail, confirmed elsewhere; the client polls the flow.
    Link,
}

/// One login step for a client to draw (TN-106).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ui {
    /// [`CONTRACT_VERSION`].
    pub version: u32,
    /// Flow handle.
    pub flow: FlowId,
    /// What the flow is for.
    #[serde(default, skip_serializing_if = "FlowKind::is_login")]
    pub kind: FlowKind,
    /// Where the flow is.
    pub step: Step,
    /// Path to `POST` a submission to.
    pub action: String,
    /// What is still required (TN-132).
    pub requirements: Vec<RequirementStatus>,
    /// What to draw.
    pub nodes: Vec<Node>,
    /// Messages about the last submission.
    pub messages: Vec<Message>,
    /// Where to go once complete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
}

fn requirements(policy: &[Requirement], step: Step) -> Vec<RequirementStatus> {
    let mut list = vec![Requirement::Identifier, Requirement::FirstFactor];
    for r in policy {
        if !list.contains(r) {
            list.push(*r);
        }
    }
    list.into_iter()
        .map(|requirement| {
            let done = matches!(
                (step, requirement),
                (Step::Complete, _)
                    | (Step::Authenticate, Requirement::Identifier)
                    | (
                        Step::SecondFactor,
                        Requirement::Identifier | Requirement::FirstFactor
                    )
            );
            RequirementStatus {
                requirement,
                state: if done {
                    RequirementState::Satisfied
                } else {
                    RequirementState::Missing
                },
            }
        })
        .collect()
}

impl Ui {
    fn new(flow: FlowId, step: Step, policy: &[Requirement], nodes: Vec<Node>) -> Self {
        Self {
            version: CONTRACT_VERSION,
            action: flow.path(),
            flow,
            kind: FlowKind::Login,
            step,
            requirements: requirements(policy, step),
            nodes,
            messages: Vec::new(),
            redirect_to: None,
        }
    }

    /// The first step: the identifier field with passkey autofill, and the explicit passkey
    /// button with an empty `allowCredentials` (TN-96, TN-97, TN-99). `policy` is the realm's
    /// requirement list.
    #[must_use]
    pub fn identifier(flow: FlowId, passkey: PasskeyOptions, policy: &[Requirement]) -> Self {
        let nodes = vec![
            Node::input(
                FieldName::Identifier,
                Method::Identifier,
                InputKind::Text,
                Autocomplete::UsernameWebauthn,
                TextId::IdentifierLabel.into(),
            ),
            Node::Submit {
                method: Method::Identifier,
                label: TextId::Continue.into(),
            },
            Node::PasskeyAutofill {
                field: FieldName::Identifier,
                options: passkey.clone(),
            },
            Node::PasskeyGet {
                label: TextId::PasskeySignIn.into(),
                options: passkey,
            },
        ];
        Self::new(flow, Step::Identifier, policy, nodes)
    }

    /// The first factor, the same whether or not the account exists: the password form and the
    /// passkey button are both always there (§10.2.1 rule 1, CR-40). `identifier` is what the
    /// client sent, echoed read-only; `passkey` carries the real or decoy `allowCredentials`
    /// (TN-97).
    #[must_use]
    pub fn authenticate(
        flow: FlowId,
        identifier: &str,
        passkey: PasskeyOptions,
        policy: &[Requirement],
    ) -> Self {
        let echo = Node::Input {
            name: FieldName::Identifier,
            method: Method::Restart,
            kind: InputKind::Text,
            autocomplete: Autocomplete::Username,
            required: false,
            max_length: FieldName::Identifier.max_length(),
            label: TextId::IdentifierLabel.into(),
            value: Some(identifier.to_owned()),
            read_only: true,
        };
        let nodes = vec![
            echo,
            Node::input(
                FieldName::Password,
                Method::Password,
                InputKind::Password,
                Autocomplete::CurrentPassword,
                TextId::PasswordLabel.into(),
            ),
            Node::Submit {
                method: Method::Password,
                label: TextId::SignIn.into(),
            },
            Node::PasskeyGet {
                label: TextId::PasskeySignIn.into(),
                options: passkey,
            },
            Node::Submit {
                method: Method::Restart,
                label: TextId::Restart.into(),
            },
        ];
        Self::new(flow, Step::Authenticate, policy, nodes)
    }

    /// Keeps only the first steps the realm enabled (TN-132): without password sign-in the
    /// password field and button go, without passkey sign-in the passkey button and autofill
    /// go. Only the identifier and first-factor steps change; later steps keep a passkey as a
    /// second factor.
    #[must_use]
    pub fn with_first_steps(mut self, memorized: bool, passkey: bool) -> Self {
        if !matches!(self.step, Step::Identifier | Step::Authenticate) {
            return self;
        }
        self.nodes.retain(|n| match n.method() {
            Some(Method::Password) => memorized,
            Some(Method::Passkey) => passkey,
            _ => true,
        });
        self
    }

    /// Adds the realm's e-mail first steps to the first-factor step (TN-102). They come from
    /// realm policy, so the step reads the same for every account (OP-146 m.12 (c)); other
    /// steps are returned unchanged.
    #[must_use]
    pub fn with_email(mut self, offered: EmailMethods) -> Self {
        if self.step != Step::Authenticate {
            return self;
        }
        if offered.code {
            self.nodes.push(Node::Submit {
                method: Method::EmailCode,
                label: TextId::SendEmailCode.into(),
            });
        }
        if offered.link {
            self.nodes.push(Node::Submit {
                method: Method::MagicLink,
                label: TextId::SendMagicLink.into(),
            });
        }
        self
    }

    /// An e-mail step is waiting (TN-102): the same step and words whether or not anything
    /// was sent. A code is entered here; a link is confirmed elsewhere while the client polls.
    #[must_use]
    pub fn email_sent(flow: FlowId, wait: EmailWait, policy: &[Requirement]) -> Self {
        let mut nodes = Vec::new();
        if wait == EmailWait::Code {
            nodes.push(Node::input(
                FieldName::EmailCode,
                Method::EmailCode,
                InputKind::Code,
                Autocomplete::OneTimeCode,
                TextId::EmailCodeLabel.into(),
            ));
            nodes.push(Node::Submit {
                method: Method::EmailCode,
                label: TextId::Verify.into(),
            });
        }
        nodes.push(Node::Submit {
            method: Method::Restart,
            label: TextId::Restart.into(),
        });
        let mut ui = Self::new(flow, Step::Authenticate, policy, nodes);
        ui.messages.push(Message::info(TextId::EmailSent));
        ui
    }

    /// MFA, after the first factor; `passkey` is the assertion request when the account holds a
    /// passkey, so a password-and-passkey account is never stuck here (IDP-8).
    #[must_use]
    pub fn second_factor(
        flow: FlowId,
        offered: SecondFactors,
        passkey: Option<PasskeyOptions>,
        policy: &[Requirement],
    ) -> Self {
        let mut nodes = Vec::new();
        if offered.passkey
            && let Some(options) = passkey
        {
            nodes.push(Node::PasskeyGet {
                label: TextId::PasskeySignIn.into(),
                options,
            });
        }
        if offered.totp {
            nodes.push(Node::input(
                FieldName::TotpCode,
                Method::Totp,
                InputKind::Code,
                Autocomplete::OneTimeCode,
                TextId::TotpLabel.into(),
            ));
            nodes.push(Node::Submit {
                method: Method::Totp,
                label: TextId::Verify.into(),
            });
        }
        if offered.push {
            nodes.push(Node::Submit {
                method: Method::Push,
                label: TextId::SendPush.into(),
            });
        }
        if offered.recovery_code {
            nodes.push(Node::input(
                FieldName::RecoveryCode,
                Method::RecoveryCode,
                InputKind::Text,
                Autocomplete::Off,
                TextId::RecoveryCodeLabel.into(),
            ));
            nodes.push(Node::Submit {
                method: Method::RecoveryCode,
                label: TextId::UseRecoveryCode.into(),
            });
        }
        Self::new(flow, Step::SecondFactor, policy, nodes)
    }

    /// A push waits for the approver (OP-156 m.3 (d), TN-102): the number to type, a check that
    /// submits [`Method::Push`] again, and the way back. The client polls the flow until
    /// `expires_at`.
    #[must_use]
    pub fn push_sent(
        flow: FlowId,
        number: u8,
        approver: Option<String>,
        expires_at: String,
        policy: &[Requirement],
    ) -> Self {
        let mut label = Text::from(TextId::PushNumber);
        label.text = label
            .text
            .replace("{ $number }", &number.to_string())
            .replace(
                "{ $approver }",
                approver.as_deref().unwrap_or("your approver app"),
            );
        let nodes = vec![
            Node::PushNumber {
                number,
                approver,
                label,
                expires_at,
            },
            Node::Submit {
                method: Method::Restart,
                label: TextId::Restart.into(),
            },
        ];
        let mut ui = Self::new(flow, Step::SecondFactor, policy, nodes);
        ui.messages.push(Message::info(TextId::PushWaiting));
        ui
    }

    /// The sign-in was stopped by a "This wasn't me" answer: only starting again is left.
    #[must_use]
    pub fn push_stopped(flow: FlowId, policy: &[Requirement]) -> Self {
        let nodes = vec![Node::Submit {
            method: Method::Restart,
            label: TextId::Restart.into(),
        }];
        let mut ui = Self::new(flow, Step::SecondFactor, policy, nodes);
        ui.messages.push(Message::error(TextId::PushNotMe));
        ui
    }

    /// Done: every requirement is met.
    #[must_use]
    pub fn complete(flow: FlowId, redirect_to: String, policy: &[Requirement]) -> Self {
        let mut ui = Self::new(flow, Step::Complete, policy, Vec::new());
        ui.redirect_to = Some(redirect_to);
        ui
    }

    fn pre_auth(&self) -> bool {
        matches!(self.step, Step::Identifier | Step::Authenticate)
    }

    /// Adds a message.
    ///
    /// # Errors
    ///
    /// [`ContractError::Message`] for a text that tells something about the account on a step
    /// before the first factor (X34).
    pub fn with_message(mut self, message: Message) -> Result<Self, ContractError> {
        if self.pre_auth() && !message.id.pre_auth() {
            return Err(ContractError::Message(message.id));
        }
        self.messages.push(message);
        Ok(self)
    }

    /// The one neutral refusal (CR-40, X-L1).
    #[must_use]
    pub fn login_failed(mut self) -> Self {
        self.messages.push(Message::error(TextId::LoginFailed));
        self
    }

    /// Adds a Signal API call.
    ///
    /// # Errors
    ///
    /// [`ContractError::Signal`] for a call that names the account before the first factor.
    pub fn with_signal(mut self, signal: PasskeySignal) -> Result<Self, ContractError> {
        if self.step != Step::Complete && !signal.pre_auth() {
            return Err(ContractError::Signal);
        }
        self.nodes.push(Node::PasskeySignal { signal });
        Ok(self)
    }

    /// Offers passkey creation once signed in; an explicit offer comes with a skip button.
    ///
    /// # Errors
    ///
    /// [`ContractError::PasskeyCreate`] unless the step is [`Step::Complete`].
    pub fn with_passkey_create(
        mut self,
        mediation: CreateMediation,
        options: PasskeyOptions,
    ) -> Result<Self, ContractError> {
        if self.step != Step::Complete {
            return Err(ContractError::PasskeyCreate);
        }
        self.nodes.push(Node::PasskeyCreate {
            mediation,
            label: Text::from(TextId::PasskeyCreate),
            options,
        });
        if mediation == CreateMediation::Explicit {
            self.nodes.push(Node::Submit {
                method: Method::Skip,
                label: TextId::Skip.into(),
            });
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn flow() -> FlowId {
        FlowId::parse("lgf_01").unwrap()
    }

    fn options(allow: &[&str]) -> PasskeyOptions {
        PasskeyOptions::new(json!({
            "challenge": "AAAA",
            "rpId": "acme.localhost",
            "allowCredentials": allow.iter().map(|id| json!({"type": "public-key", "id": id})).collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    // TN-96, TN-99
    #[test]
    fn the_first_step_always_offers_a_passkey_button_and_autofill() {
        let ui = Ui::identifier(flow(), options(&[]), &[]);
        assert!(
            ui.nodes
                .iter()
                .any(|n| matches!(n, Node::PasskeyGet { .. }))
        );
        assert!(ui.nodes.iter().any(|n| matches!(
            n,
            Node::PasskeyAutofill {
                field: FieldName::Identifier,
                ..
            }
        )));
        assert!(ui.nodes.iter().any(|n| matches!(
            n,
            Node::Input {
                name: FieldName::Identifier,
                autocomplete: Autocomplete::UsernameWebauthn,
                ..
            }
        )));
    }

    // CR-40, TN-96, X34
    #[test]
    fn the_first_factor_step_has_one_shape_for_every_account() {
        let known = Ui::authenticate(flow(), "ada@example.org", options(&["AQID"]), &[]);
        let unknown = Ui::authenticate(flow(), "bob@example.org", options(&["BAUG"]), &[]);
        let shape = |ui: &Ui| {
            ui.nodes
                .iter()
                .map(|n| match n {
                    Node::Input { name, .. } => format!("input:{}", name.as_str()),
                    Node::Submit { method, .. } => format!("submit:{}", method.as_str()),
                    Node::PasskeyGet { .. } => "passkey_get".into(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(shape(&known), shape(&unknown));
        assert!(shape(&known).contains(&"input:password".to_owned()));
        assert!(shape(&known).contains(&"passkey_get".to_owned()));
        let a = serde_json::to_vec(&known.login_failed()).unwrap();
        let b = serde_json::to_vec(&unknown.login_failed()).unwrap();
        assert_eq!(a.len(), b.len());
    }

    // X34, XI-24
    #[test]
    fn account_specific_texts_wait_for_the_first_factor() {
        let ui = Ui::authenticate(flow(), "ada", options(&[]), &[]);
        assert_eq!(
            ui.clone()
                .with_message(Message::error(TextId::PasskeyNotRegistered)),
            Err(ContractError::Message(TextId::PasskeyNotRegistered))
        );
        assert!(
            Ui::second_factor(flow(), SecondFactors::default(), None, &[])
                .with_message(Message::error(TextId::SecondFactorFailed))
                .is_ok()
        );
        assert!(
            ui.with_message(Message::error(TextId::TooManyAttempts).retry_after(3))
                .is_ok()
        );
    }

    // IDP-8, §10.2 AAL2
    #[test]
    fn a_passkey_is_offered_as_the_second_factor() {
        let offered = SecondFactors {
            totp: false,
            recovery_code: false,
            passkey: true,
            push: false,
        };
        let ui = Ui::second_factor(flow(), offered, Some(options(&[])), &[]);
        assert!(
            ui.nodes
                .iter()
                .any(|n| matches!(n, Node::PasskeyGet { .. }))
        );
        let none = Ui::second_factor(flow(), SecondFactors::default(), Some(options(&[])), &[]);
        assert_eq!(none.nodes, []);
    }

    // TN-97
    #[test]
    fn only_the_unknown_credential_signal_is_sent_before_sign_in() {
        let unknown = PasskeySignal::UnknownCredential {
            rp_id: "acme.localhost".into(),
            credential_id: "AQID".into(),
        };
        let all = PasskeySignal::AllAcceptedCredentials {
            rp_id: "acme.localhost".into(),
            user_id: "dXNlcg".into(),
            all_accepted_credential_ids: vec!["AQID".into()],
        };
        let ui = Ui::identifier(flow(), options(&[]), &[]);
        assert!(ui.clone().with_signal(unknown).is_ok());
        assert_eq!(ui.with_signal(all.clone()), Err(ContractError::Signal));
        assert!(
            Ui::complete(flow(), "/".into(), &[])
                .with_signal(all)
                .is_ok()
        );
    }

    // §10.2.4
    #[test]
    fn passkey_creation_is_offered_only_after_sign_in() {
        assert_eq!(
            Ui::identifier(flow(), options(&[]), &[])
                .with_passkey_create(CreateMediation::Conditional, options(&[])),
            Err(ContractError::PasskeyCreate)
        );
        let ui = Ui::complete(flow(), "/".into(), &[])
            .with_passkey_create(CreateMediation::Explicit, options(&[]))
            .unwrap();
        assert!(ui.nodes.iter().any(|n| n.method() == Some(Method::Skip)));
    }

    // TN-132
    #[test]
    fn requirements_follow_the_step_not_the_order() {
        use Requirement::{FirstFactor, Identifier, SecondFactor};
        use RequirementState::{Missing, Satisfied};
        let policy = [Requirement::SecondFactor];
        let states = |ui: Ui| {
            ui.requirements
                .iter()
                .map(|r| (r.requirement, r.state))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            states(Ui::identifier(flow(), options(&[]), &policy)),
            [
                (Identifier, Missing),
                (FirstFactor, Missing),
                (SecondFactor, Missing)
            ]
        );
        assert_eq!(
            states(Ui::second_factor(
                flow(),
                SecondFactors {
                    totp: true,
                    recovery_code: true,
                    passkey: false,
                    push: false,
                },
                None,
                &policy
            )),
            [
                (Identifier, Satisfied),
                (FirstFactor, Satisfied),
                (SecondFactor, Missing)
            ]
        );
        assert!(
            states(Ui::complete(flow(), "/".into(), &policy))
                .iter()
                .all(|(_, s)| *s == Satisfied)
        );
    }

    // TN-102, OP-146 m.12 (c)
    #[test]
    fn email_steps_come_from_realm_policy_and_read_the_same() {
        let both = EmailMethods {
            code: true,
            link: true,
        };
        let ui = Ui::authenticate(flow(), "ada", options(&[]), &[]).with_email(both);
        let methods: Vec<_> = ui.nodes.iter().filter_map(Node::method).collect();
        assert!(methods.contains(&Method::EmailCode) && methods.contains(&Method::MagicLink));
        let first = Ui::identifier(flow(), options(&[]), &[]).with_email(both);
        assert!(
            first
                .nodes
                .iter()
                .all(|n| n.method() != Some(Method::EmailCode))
        );
        let code = Ui::email_sent(flow(), EmailWait::Code, &[]);
        assert!(code.nodes.iter().any(|n| matches!(
            n,
            Node::Input {
                name: FieldName::EmailCode,
                ..
            }
        )));
        assert_eq!(code.messages, [Message::info(TextId::EmailSent)]);
        let link = Ui::email_sent(flow(), EmailWait::Link, &[]);
        assert!(
            link.nodes
                .iter()
                .all(|n| n.method() == Some(Method::Restart))
        );
    }

    // TN-102
    #[test]
    fn flow_ids_are_opaque_and_bounded() {
        assert!(FlowId::parse("lgf_AbC-09").is_some());
        for bad in ["", "a/b", "a b", "ü", &"x".repeat(129)] {
            assert!(FlowId::parse(bad).is_none(), "{bad}");
        }
        assert_eq!(format!("{:?}", flow()), "FlowId(..)");
        assert_eq!(flow().path(), "/v1/login/flows/lgf_01");
    }
}
