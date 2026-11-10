//! UI nodes: the closed set of things a login step can ask a client to draw (TN-106).
//!
//! There is no node that carries markup, script, an expression or a flow definition; a
//! client cannot be told to run anything the contract does not name (TN-105, TN-106).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::message::Text;

/// A submittable field. The set is closed; the server refuses any other name (TN-106).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldName {
    /// E-mail address or username.
    Identifier,
    /// Password.
    Password,
    /// TOTP code.
    TotpCode,
    /// Recovery code.
    RecoveryCode,
    /// The `PublicKeyCredential` JSON (`toJSON()`) from a passkey ceremony.
    PasskeyCredential,
    /// A code sent by e-mail (TN-102).
    EmailCode,
    /// The e-mail address of a new account (OP-153 m.3 (g)).
    Email,
    /// A new password, at registration or reset.
    NewPassword,
    /// The display name of a new account.
    DisplayName,
    /// The "I saved them" acknowledgement of new recovery codes (OP-153 m.3 (d)).
    Acknowledged,
    /// An invitation's magic code (OP-153 m.3 (o)).
    InvitationCode,
    /// The cross-device link code shown on the other device (OP-153 m.3 (d)).
    LinkCode,
    /// N1: the hosted page's non-interactive bot token, if any (OP-153 m.1 (b), m.3 (h)).
    BotToken,
    /// N5: "Keep me signed in on this device" (TN-36, X33), an [`Node::Option`].
    KeepSignedIn,
    /// N5: "Don't ask for a second step on this device for 30 days" (X33, X-L2), an
    /// [`Node::Option`].
    RememberDevice,
}

impl FieldName {
    /// All names.
    pub const ALL: [Self; 15] = [
        Self::Identifier,
        Self::Password,
        Self::TotpCode,
        Self::RecoveryCode,
        Self::PasskeyCredential,
        Self::EmailCode,
        Self::Email,
        Self::NewPassword,
        Self::DisplayName,
        Self::Acknowledged,
        Self::InvitationCode,
        Self::LinkCode,
        Self::BotToken,
        Self::KeepSignedIn,
        Self::RememberDevice,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identifier => "identifier",
            Self::Password => "password",
            Self::TotpCode => "totp_code",
            Self::RecoveryCode => "recovery_code",
            Self::PasskeyCredential => "passkey_credential",
            Self::EmailCode => "email_code",
            Self::Email => "email",
            Self::NewPassword => "new_password",
            Self::DisplayName => "display_name",
            Self::Acknowledged => "acknowledged",
            Self::InvitationCode => "invitation_code",
            Self::LinkCode => "link_code",
            Self::BotToken => "bot_token",
            Self::KeepSignedIn => "keep_signed_in",
            Self::RememberDevice => "remember_device",
        }
    }

    /// Parses a wire name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.as_str() == name)
    }

    /// Longest accepted value, in characters.
    #[must_use]
    pub const fn max_length(self) -> u32 {
        match self {
            Self::Identifier | Self::Email => 320,
            // OP-146 m.10 (c)
            Self::Password | Self::NewPassword => 128,
            Self::TotpCode => 10,
            Self::RecoveryCode => 64,
            // CR-10
            Self::PasskeyCredential => 16_384,
            // OP-153 m.3 (o)
            Self::EmailCode | Self::InvitationCode => 16,
            Self::DisplayName => 200,
            Self::Acknowledged | Self::KeepSignedIn | Self::RememberDevice => 8,
            // OP-153 m.3 (d)
            Self::LinkCode => 32,
            Self::BotToken => 4096,
        }
    }

    /// Whether the value is a secret that must never be echoed back.
    #[must_use]
    pub const fn secret(self) -> bool {
        matches!(
            self,
            Self::Password
                | Self::TotpCode
                | Self::RecoveryCode
                | Self::EmailCode
                | Self::NewPassword
                | Self::InvitationCode
                | Self::LinkCode
        )
    }
}

/// What a submission does. The set is closed (TN-105).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// Submit the identifier (TN-96).
    Identifier,
    /// Sign in with the password.
    Password,
    /// Sign in with a passkey assertion.
    Passkey,
    /// Verify a TOTP code.
    Totp,
    /// Verify a recovery code.
    RecoveryCode,
    /// Register a passkey.
    PasskeyRegister,
    /// Decline an optional step.
    Skip,
    /// Start again with another identifier.
    Restart,
    /// Send a code by e-mail, or verify it once sent (TN-102).
    EmailCode,
    /// Send a sign-in link by e-mail (TN-102).
    MagicLink,
    /// Create an account (OP-153 m.3 (g)).
    Register,
    /// Start or continue a recovery (OP-153 m.3 (d)).
    Recover,
    /// Set a new password.
    NewPassword,
    /// Share the listed claims with the app (OP-153 m.3 (z)).
    Share,
    /// Decline to share.
    DontShare,
    /// Accept an invitation (OP-153 m.3 (o)).
    AcceptInvitation,
    /// Link another sign-in to the account (OP-153 m.3 (m)).
    Link,
    /// Acknowledge new recovery codes (OP-153 m.3 (d)).
    Acknowledge,
    /// Send a push verification to the account's approvers, or check on it (OP-156 m.3 (d)).
    Push,
}

impl Method {
    /// All methods.
    pub const ALL: [Self; 19] = [
        Self::Identifier,
        Self::Password,
        Self::Passkey,
        Self::Totp,
        Self::RecoveryCode,
        Self::PasskeyRegister,
        Self::Skip,
        Self::Restart,
        Self::EmailCode,
        Self::MagicLink,
        Self::Register,
        Self::Recover,
        Self::NewPassword,
        Self::Share,
        Self::DontShare,
        Self::AcceptInvitation,
        Self::Link,
        Self::Acknowledge,
        Self::Push,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identifier => "identifier",
            Self::Password => "password",
            Self::Passkey => "passkey",
            Self::Totp => "totp",
            Self::RecoveryCode => "recovery_code",
            Self::PasskeyRegister => "passkey_register",
            Self::Skip => "skip",
            Self::Restart => "restart",
            Self::EmailCode => "email_code",
            Self::MagicLink => "magic_link",
            Self::Register => "register",
            Self::Recover => "recover",
            Self::NewPassword => "new_password",
            Self::Share => "share",
            Self::DontShare => "dont_share",
            Self::AcceptInvitation => "accept_invitation",
            Self::Link => "link",
            Self::Acknowledge => "acknowledge",
            Self::Push => "push",
        }
    }
}

/// How an input is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    /// Free text.
    Text,
    /// Masked secret.
    Password,
    /// Short numeric or alphanumeric code.
    Code,
    /// N1: not drawn; the page fills it itself (a bot token, OP-153 m.1 (b)).
    Hidden,
}

/// The HTML `autocomplete` token list of an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Autocomplete {
    /// The identifier field that also offers passkeys in autofill (conditional get, TN-99).
    #[serde(rename = "username webauthn")]
    UsernameWebauthn,
    /// A read-only identifier echo.
    #[serde(rename = "username")]
    Username,
    /// The password of the account.
    #[serde(rename = "current-password")]
    CurrentPassword,
    /// A one-time code.
    #[serde(rename = "one-time-code")]
    OneTimeCode,
    /// No autofill.
    #[serde(rename = "off")]
    Off,
    /// A new password (OP-153 m.3 (g)).
    #[serde(rename = "new-password")]
    NewPassword,
    /// An e-mail address.
    #[serde(rename = "email")]
    Email,
    /// A person's name.
    #[serde(rename = "name")]
    Name,
}

/// WebAuthn options in their JSON form (`parseRequestOptionsFromJSON` /
/// `parseCreationOptionsFromJSON`), as the relying party produced them.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PasskeyOptions(Map<String, Value>);

impl PasskeyOptions {
    /// Wraps a JSON object; `None` for anything else.
    #[must_use]
    pub fn new(options: Value) -> Option<Self> {
        match options {
            Value::Object(map) => Some(Self(map)),
            _ => None,
        }
    }

    /// The JSON object.
    #[must_use]
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }
}

/// How a passkey creation is offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreateMediation {
    /// Behind a visible button.
    Explicit,
    /// `mediation: "conditional"` right after a password sign-in (§10.2.4 conditional create).
    Conditional,
}

/// A WebAuthn Signal API call for the client to make (TN-97, §10.2.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PasskeySignal {
    /// `signalUnknownCredential`: the credential the client just used is not known. Safe
    /// before sign-in: it names one id the client sent and says nothing about any account.
    UnknownCredential {
        /// RP ID.
        rp_id: String,
        /// Base64url credential id.
        credential_id: String,
    },
    /// `signalAllAcceptedCredentials`: the full list, only for the signed-in user.
    AllAcceptedCredentials {
        /// RP ID.
        rp_id: String,
        /// Base64url `user.id`.
        user_id: String,
        /// Every accepted credential id, base64url; never a partial list.
        all_accepted_credential_ids: Vec<String>,
    },
    /// `signalCurrentUserDetails`: the signed-in user's names.
    CurrentUserDetails {
        /// RP ID.
        rp_id: String,
        /// Base64url `user.id`.
        user_id: String,
        /// `user.name`.
        name: String,
        /// `user.displayName`.
        display_name: String,
    },
}

impl PasskeySignal {
    /// Whether the signal may be sent before the first factor succeeds (TN-97, X34).
    #[must_use]
    pub const fn pre_auth(&self) -> bool {
        matches!(self, Self::UnknownCredential { .. })
    }
}

/// One thing to draw.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Node {
    /// An input field.
    Input {
        /// Field name.
        name: FieldName,
        /// The method this field is submitted with.
        method: Method,
        /// How to draw it.
        kind: InputKind,
        /// HTML `autocomplete`.
        autocomplete: Autocomplete,
        /// Must be non-empty when its method is submitted.
        required: bool,
        /// Longest value, in characters.
        max_length: u32,
        /// Label.
        label: Text,
        /// Pre-filled value; never set for a secret.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        /// Shown, but not editable.
        #[serde(default, skip_serializing_if = "core::ops::Not::not")]
        read_only: bool,
    },
    /// A button that submits its method with that method's inputs.
    Submit {
        /// Method.
        method: Method,
        /// Caption.
        label: Text,
    },
    /// The explicit passkey button: `navigator.credentials.get` behind a visible button,
    /// always offered next to autofill (TN-96, TN-99). Submits [`Method::Passkey`].
    PasskeyGet {
        /// Caption.
        label: Text,
        /// Request options.
        options: PasskeyOptions,
    },
    /// Conditional mediation (`mediation: "conditional"`) on an input whose autocomplete is
    /// [`Autocomplete::UsernameWebauthn`]. A hint: it never replaces [`Node::PasskeyGet`]
    /// (TN-99). Submits [`Method::Passkey`].
    PasskeyAutofill {
        /// The input that hosts the autofill.
        field: FieldName,
        /// Request options.
        options: PasskeyOptions,
    },
    /// Passkey creation. Submits [`Method::PasskeyRegister`].
    PasskeyCreate {
        /// Explicit or conditional.
        mediation: CreateMediation,
        /// Caption.
        label: Text,
        /// Creation options.
        options: PasskeyOptions,
    },
    /// A Signal API call for the client to make.
    PasskeySignal {
        /// The call.
        signal: PasskeySignal,
    },
    /// N5: a checkbox that belongs to the whole step: when checked, the client sends
    /// `fields[name] = "true"` with every submission of the step (TN-36, X33).
    Option {
        /// [`FieldName::KeepSignedIn`] or [`FieldName::RememberDevice`].
        name: FieldName,
        /// Caption.
        label: Text,
        /// Whether it starts checked; never for the second-step marker (X-L2).
        checked: bool,
    },
    /// N5: a sign-in provider of the realm (OP-153 m.3 (l)): a button that navigates the whole
    /// page to `href`, a path under the realm issuer.
    Provider {
        /// The preset name.
        provider: String,
        /// Caption.
        label: Text,
        /// `GET` target that starts the provider sign-in, below the realm issuer like every
        /// action of the contract.
        href: String,
    },
    /// Q5: the number to type into the approver while a push waits (OP-156 m.3 (d)). Only the
    /// sign-in page shows it; the push never carries it. The client polls the flow until
    /// `expires_at`.
    PushNumber {
        /// Two digits, 10 to 99.
        number: u8,
        /// Caption, with `{ $number }` filled.
        label: Text,
        /// RFC 3339.
        expires_at: String,
    },
}

impl Node {
    /// The method this node submits, if it submits one.
    #[must_use]
    pub const fn method(&self) -> Option<Method> {
        match self {
            Self::Input { method, .. } | Self::Submit { method, .. } => Some(*method),
            Self::PasskeyGet { .. } | Self::PasskeyAutofill { .. } => Some(Method::Passkey),
            Self::PasskeyCreate { .. } => Some(Method::PasskeyRegister),
            Self::PasskeySignal { .. }
            | Self::Option { .. }
            | Self::Provider { .. }
            | Self::PushNumber { .. } => None,
        }
    }

    /// An input with its name's length limit.
    #[must_use]
    pub fn input(
        name: FieldName,
        method: Method,
        kind: InputKind,
        autocomplete: Autocomplete,
        label: Text,
    ) -> Self {
        Self::Input {
            name,
            method,
            kind,
            autocomplete,
            required: true,
            max_length: name.max_length(),
            label,
            value: None,
            read_only: false,
        }
    }
}
