//! Texts with stable ids. Clients translate or restyle by id; the English text is the default.

use serde::{Deserialize, Serialize};

/// Every text the contract can carry. The set is closed: there is no free-text message, so a
/// login screen cannot be made to say something the contract does not (X29, X34).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TextId {
    /// One neutral refusal for every failed first factor (CR-40, X34).
    #[serde(rename = "login.failed")]
    LoginFailed,
    /// Too many attempts; the same for every identifier.
    #[serde(rename = "login.throttled")]
    TooManyAttempts,
    /// Capacity shedding (OP-36).
    #[serde(rename = "login.unavailable")]
    Unavailable,
    /// The flow ran out or was already used.
    #[serde(rename = "flow.expired")]
    FlowExpired,
    /// A second-factor code did not verify. Only after the first factor (X34).
    #[serde(rename = "second_factor.failed")]
    SecondFactorFailed,
    /// A passkey is not registered for the signed-in account. Only after the first factor (X34).
    #[serde(rename = "passkey.not_registered")]
    PasskeyNotRegistered,
    /// Identifier field.
    #[serde(rename = "label.identifier")]
    IdentifierLabel,
    /// Password field.
    #[serde(rename = "label.password")]
    PasswordLabel,
    /// TOTP field.
    #[serde(rename = "label.totp_code")]
    TotpLabel,
    /// Recovery code field.
    #[serde(rename = "label.recovery_code")]
    RecoveryCodeLabel,
    /// Continue after the identifier.
    #[serde(rename = "action.continue")]
    Continue,
    /// Sign in with the password.
    #[serde(rename = "action.sign_in")]
    SignIn,
    /// The explicit passkey button (TN-99).
    #[serde(rename = "action.passkey")]
    PasskeySignIn,
    /// Create a passkey.
    #[serde(rename = "action.passkey_create")]
    PasskeyCreate,
    /// Verify a second-factor code.
    #[serde(rename = "action.verify")]
    Verify,
    /// Use a recovery code instead.
    #[serde(rename = "action.recovery_code")]
    UseRecoveryCode,
    /// Decline an optional step.
    #[serde(rename = "action.skip")]
    Skip,
    /// Start again with another identifier.
    #[serde(rename = "action.restart")]
    Restart,
    /// E-mail code field.
    #[serde(rename = "label.email_code")]
    EmailCodeLabel,
    /// Ask for a code by e-mail.
    #[serde(rename = "action.email_code")]
    SendEmailCode,
    /// Ask for a sign-in link by e-mail.
    #[serde(rename = "action.magic_link")]
    SendMagicLink,
    /// An e-mail step is waiting; the same words whether or not anything was sent (TN-102).
    #[serde(rename = "email.sent")]
    EmailSent,
}

impl TextId {
    /// All ids, in declaration order.
    pub const ALL: [Self; 22] = [
        Self::LoginFailed,
        Self::TooManyAttempts,
        Self::Unavailable,
        Self::FlowExpired,
        Self::SecondFactorFailed,
        Self::PasskeyNotRegistered,
        Self::IdentifierLabel,
        Self::PasswordLabel,
        Self::TotpLabel,
        Self::RecoveryCodeLabel,
        Self::Continue,
        Self::SignIn,
        Self::PasskeySignIn,
        Self::PasskeyCreate,
        Self::Verify,
        Self::UseRecoveryCode,
        Self::Skip,
        Self::Restart,
        Self::EmailCodeLabel,
        Self::SendEmailCode,
        Self::SendMagicLink,
        Self::EmailSent,
    ];

    /// The stable id on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LoginFailed => "login.failed",
            Self::TooManyAttempts => "login.throttled",
            Self::Unavailable => "login.unavailable",
            Self::FlowExpired => "flow.expired",
            Self::SecondFactorFailed => "second_factor.failed",
            Self::PasskeyNotRegistered => "passkey.not_registered",
            Self::IdentifierLabel => "label.identifier",
            Self::PasswordLabel => "label.password",
            Self::TotpLabel => "label.totp_code",
            Self::RecoveryCodeLabel => "label.recovery_code",
            Self::Continue => "action.continue",
            Self::SignIn => "action.sign_in",
            Self::PasskeySignIn => "action.passkey",
            Self::PasskeyCreate => "action.passkey_create",
            Self::Verify => "action.verify",
            Self::UseRecoveryCode => "action.recovery_code",
            Self::Skip => "action.skip",
            Self::Restart => "action.restart",
            Self::EmailCodeLabel => "label.email_code",
            Self::SendEmailCode => "action.email_code",
            Self::SendMagicLink => "action.magic_link",
            Self::EmailSent => "email.sent",
        }
    }

    /// The default English text.
    #[must_use]
    pub const fn default_text(self) -> &'static str {
        match self {
            // X-L1
            Self::LoginFailed => "We couldn't sign you in with these details.",
            Self::TooManyAttempts => "Too many attempts. Try again in a moment.",
            Self::Unavailable => "Sign-in is briefly unavailable. Try again shortly.",
            Self::FlowExpired => "This sign-in page has expired. Start again.",
            Self::SecondFactorFailed => "That code didn't work. Check it and try again.",
            Self::PasskeyNotRegistered => "That passkey isn't registered for this account.",
            Self::IdentifierLabel => "Email or username",
            Self::PasswordLabel => "Password",
            Self::TotpLabel => "Code from your authenticator app",
            Self::RecoveryCodeLabel => "Recovery code",
            Self::Continue => "Continue",
            Self::SignIn => "Sign in",
            Self::PasskeySignIn => "Sign in with a passkey",
            Self::PasskeyCreate => "Create a passkey",
            Self::Verify => "Verify",
            Self::UseRecoveryCode => "Use a recovery code",
            Self::Skip => "Not now",
            Self::Restart => "Use a different account",
            Self::EmailCodeLabel => "Code from your email",
            Self::SendEmailCode => "Email me a code",
            Self::SendMagicLink => "Email me a sign-in link",
            Self::EmailSent => "If these details match an account, we've sent an email.",
        }
    }

    /// Whether the text may be shown before the first factor succeeds: it must say nothing
    /// about whether an account exists or what state it is in (X34, XI-24).
    #[must_use]
    pub const fn pre_auth(self) -> bool {
        !matches!(self, Self::SecondFactorFailed | Self::PasskeyNotRegistered)
    }
}

/// A label or button caption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Text {
    /// Stable id.
    pub id: TextId,
    /// Default English text.
    pub text: String,
}

impl From<TextId> for Text {
    fn from(id: TextId) -> Self {
        Self {
            id,
            text: id.default_text().to_owned(),
        }
    }
}

/// How a message is presented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Neutral information.
    Info,
    /// The last submission did not succeed.
    Error,
}

/// A message about the step as a whole.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    /// Stable id.
    pub id: TextId,
    /// Default English text.
    pub text: String,
    /// Presentation.
    pub severity: Severity,
    /// Seconds to wait before retrying, for [`TextId::TooManyAttempts`] and
    /// [`TextId::Unavailable`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u32>,
}

impl Message {
    /// An error message with its default text.
    #[must_use]
    pub fn error(id: TextId) -> Self {
        Self {
            id,
            text: id.default_text().to_owned(),
            severity: Severity::Error,
            retry_after_s: None,
        }
    }

    /// An information message with its default text.
    #[must_use]
    pub fn info(id: TextId) -> Self {
        Self {
            id,
            text: id.default_text().to_owned(),
            severity: Severity::Info,
            retry_after_s: None,
        }
    }

    /// With a retry hint.
    #[must_use]
    pub fn retry_after(mut self, seconds: u32) -> Self {
        self.retry_after_s = Some(seconds);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-40, X34, X-L1, XI-24
    #[test]
    fn the_neutral_refusal_claims_nothing_about_the_account() {
        let text = TextId::LoginFailed.default_text();
        assert_eq!(text, "We couldn't sign you in with these details.");
        for id in TextId::ALL.into_iter().filter(|t| t.pre_auth()) {
            let t = id.default_text().to_lowercase();
            for banned in [
                "wrong password",
                "no account",
                "locked",
                "disabled",
                "doesn't exist",
                "not found",
                "isn't registered",
            ] {
                assert!(!t.contains(banned), "{id:?}: {t}");
            }
        }
    }

    // TN-106
    #[test]
    fn wire_ids_match_serde() {
        for id in TextId::ALL {
            let wire = serde_json::to_value(id).unwrap();
            assert_eq!(wire, id.as_str());
            let back: TextId = serde_json::from_value(wire).unwrap();
            assert_eq!(back, id);
        }
    }
}
