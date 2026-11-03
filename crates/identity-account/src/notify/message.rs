//! The Relay message contract, version 1 (E42 m.1, OP-146 m.4 (b)): what Access asks Relay to
//! deliver to a person. Access owns the content and "to whom, why"; channel, timing, retry and
//! fallback are Relay's (§7.9.8).
//!
//! Redaction rules (OP-64):
//! - a recipient address is personal data and prints as `[redacted]`;
//! - the one-time code and the magic link are the only secrets a message carries; they are
//!   [`Secret`]s and have no `Debug` of their own;
//! - nothing else is carried: no password, no token, no IP address, no device fingerprint.

use core::fmt;

use access_crypto::Secret;
use serde_json::{Map, Value, json};

use crate::domain::status::AccountStatus;

/// Prefix of every outbox kind and `CloudEvents` `type` of the contract.
pub const KIND_PREFIX: &str = "relay.message.";

/// Contract version, the last segment of every kind.
pub const VERSION: &str = "v1";

/// A message the contract cannot carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid relay message: {0}")]
pub struct Invalid(pub &'static str);

/// Where Relay delivers. Relay picks the channel for it (E42 m.1).
#[derive(Clone, PartialEq, Eq)]
pub enum Address {
    /// An e-mail address, at most 320 characters.
    Email(String),
    /// An E.164 phone number.
    Phone(String),
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Email(_) => f.write_str("Email([redacted])"),
            Self::Phone(_) => f.write_str("Phone([redacted])"),
        }
    }
}

impl Address {
    fn validate(&self) -> Result<(), Invalid> {
        match self {
            Self::Email(a) => {
                let ok = (3..=320).contains(&a.chars().count())
                    && a.split_once('@')
                        .is_some_and(|(l, d)| !l.is_empty() && !d.is_empty() && !d.contains('@'))
                    && !a.chars().any(|c| c.is_control() || c.is_whitespace());
                if ok {
                    Ok(())
                } else {
                    Err(Invalid("email address"))
                }
            }
            Self::Phone(p) => {
                let digits = p.strip_prefix('+').unwrap_or("");
                let ok = (7..=15).contains(&digits.len())
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && !digits.starts_with('0');
                if ok {
                    Ok(())
                } else {
                    Err(Invalid("phone number"))
                }
            }
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Self::Email(a) => json!({ "email": a }),
            Self::Phone(p) => json!({ "phone": p }),
        }
    }

    fn from_json(v: &Value) -> Result<Self, Invalid> {
        let a = match (v.get("email"), v.get("phone")) {
            (Some(Value::String(e)), None) => Self::Email(e.clone()),
            (None, Some(Value::String(p))) => Self::Phone(p.clone()),
            _ => return Err(Invalid("recipient")),
        };
        a.validate()?;
        Ok(a)
    }
}

/// Why a one-time code was sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpPurpose {
    /// Sign-in factor.
    SignIn,
    /// Proving control of an address.
    VerifyAddress,
    /// Account recovery.
    Recovery,
}

impl OtpPurpose {
    const ALL: [Self; 3] = [Self::SignIn, Self::VerifyAddress, Self::Recovery];

    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::VerifyAddress => "verify_address",
            Self::Recovery => "recovery",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == s)
    }
}

/// How a new sign-in authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInMethod {
    /// Password.
    Password,
    /// Passkey or security key.
    Passkey,
    /// One-time code.
    Otp,
    /// Magic link.
    MagicLink,
    /// Federated identity provider.
    Federated,
}

impl SignInMethod {
    const ALL: [Self; 5] = [
        Self::Password,
        Self::Passkey,
        Self::Otp,
        Self::MagicLink,
        Self::Federated,
    ];

    /// Wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Passkey => "passkey",
            Self::Otp => "otp",
            Self::MagicLink => "magic_link",
            Self::Federated => "federated",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == s)
    }
}

/// What the message says.
pub enum Body {
    /// A one-time code (`relay.message.otp.v1`).
    Otp {
        /// The code: 4–12 ASCII letters or digits.
        code: Secret<String>,
        /// Why.
        purpose: OtpPurpose,
        /// Unix ms after which it is worthless; Relay is not asked to send it later.
        expires_at_ms: u64,
    },
    /// A sign-in link (`relay.message.magic_link.v1`).
    MagicLink {
        /// The `https` link, at most 2048 bytes.
        link: Secret<String>,
        /// Unix ms after which it is worthless.
        expires_at_ms: u64,
    },
    /// The password was set or reset (`relay.message.password_changed.v1`).
    PasswordChanged {
        /// When, Unix ms.
        at_ms: u64,
    },
    /// A new sign-in (`relay.message.new_sign_in.v1`, SEC18).
    NewSignIn {
        /// When, Unix ms.
        at_ms: u64,
        /// How.
        method: SignInMethod,
    },
    /// The account's status changed (`relay.message.account_status.v1`, TN-49).
    AccountStatus {
        /// The new status.
        status: AccountStatus,
        /// When, Unix ms.
        at_ms: u64,
    },
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Otp {
                purpose,
                expires_at_ms,
                ..
            } => f
                .debug_struct("Otp")
                .field("code", &"[redacted]")
                .field("purpose", purpose)
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::MagicLink { expires_at_ms, .. } => f
                .debug_struct("MagicLink")
                .field("link", &"[redacted]")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::PasswordChanged { at_ms } => f
                .debug_struct("PasswordChanged")
                .field("at_ms", at_ms)
                .finish(),
            Self::NewSignIn { at_ms, method } => f
                .debug_struct("NewSignIn")
                .field("at_ms", at_ms)
                .field("method", method)
                .finish(),
            Self::AccountStatus { status, at_ms } => f
                .debug_struct("AccountStatus")
                .field("status", status)
                .field("at_ms", at_ms)
                .finish(),
        }
    }
}

/// Every kind of the contract, as outbox kind and `CloudEvents` `type`.
pub const KINDS: [&str; 5] = [
    "relay.message.otp.v1",
    "relay.message.magic_link.v1",
    "relay.message.password_changed.v1",
    "relay.message.new_sign_in.v1",
    "relay.message.account_status.v1",
];

impl Body {
    /// The outbox kind and `CloudEvents` `type`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Otp { .. } => KINDS[0],
            Self::MagicLink { .. } => KINDS[1],
            Self::PasswordChanged { .. } => KINDS[2],
            Self::NewSignIn { .. } => KINDS[3],
            Self::AccountStatus { .. } => KINDS[4],
        }
    }

    /// When the message stops being worth sending.
    #[must_use]
    pub const fn expires_at_ms(&self) -> Option<u64> {
        match self {
            Self::Otp { expires_at_ms, .. } | Self::MagicLink { expires_at_ms, .. } => {
                Some(*expires_at_ms)
            }
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), Invalid> {
        match self {
            Self::Otp { code, .. } => {
                let c = code.expose();
                if (4..=12).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    Ok(())
                } else {
                    Err(Invalid("code"))
                }
            }
            Self::MagicLink { link, .. } => {
                let l = link.expose();
                if l.len() <= 2048
                    && l.strip_prefix("https://").is_some_and(|r| !r.is_empty())
                    && !l.chars().any(|c| c.is_control() || c.is_whitespace())
                {
                    Ok(())
                } else {
                    Err(Invalid("link"))
                }
            }
            _ => Ok(()),
        }
    }
}

/// One message to one person.
#[derive(Debug)]
pub struct Message {
    /// The identity subject it concerns (internal id).
    pub subject: [u8; 16],
    /// Where to deliver.
    pub to: Address,
    /// BCP 47 language tag for Relay's template, when the person has one.
    pub locale: Option<String>,
    /// What it says.
    pub body: Body,
}

fn valid_locale(l: &str) -> bool {
    (2..=35).contains(&l.len())
        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !l.starts_with('-')
        && !l.ends_with('-')
}

impl Message {
    /// Checks every field against the contract.
    ///
    /// # Errors
    /// [`Invalid`] naming the field.
    pub fn validate(&self) -> Result<(), Invalid> {
        self.to.validate()?;
        if self.locale.as_deref().is_some_and(|l| !valid_locale(l)) {
            return Err(Invalid("locale"));
        }
        self.body.validate()
    }

    /// The sealed form stored in the outbox: integer times, no wire formatting.
    pub(crate) fn to_sealed_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("recipient".into(), self.to.to_json());
        if let Some(l) = &self.locale {
            m.insert("locale".into(), Value::String(l.clone()));
        }
        match &self.body {
            Body::Otp {
                code,
                purpose,
                expires_at_ms,
            } => {
                m.insert("code".into(), Value::String(code.expose().clone()));
                m.insert("purpose".into(), purpose.name().into());
                m.insert("expires_at_ms".into(), (*expires_at_ms).into());
            }
            Body::MagicLink {
                link,
                expires_at_ms,
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert("expires_at_ms".into(), (*expires_at_ms).into());
            }
            Body::PasswordChanged { at_ms } => {
                m.insert("at_ms".into(), (*at_ms).into());
            }
            Body::NewSignIn { at_ms, method } => {
                m.insert("at_ms".into(), (*at_ms).into());
                m.insert("method".into(), method.name().into());
            }
            Body::AccountStatus { status, at_ms } => {
                m.insert("status".into(), status.name().into());
                m.insert("at_ms".into(), (*at_ms).into());
            }
        }
        Value::Object(m)
    }

    /// Reads the sealed form back and validates it.
    pub(crate) fn from_sealed_json(
        kind: &str,
        subject: [u8; 16],
        v: &Value,
    ) -> Result<Self, Invalid> {
        let int = |k: &'static str| v.get(k).and_then(Value::as_u64).ok_or(Invalid(k));
        let text = |k: &'static str| v.get(k).and_then(Value::as_str).ok_or(Invalid(k));
        let body = match kind {
            "relay.message.otp.v1" => Body::Otp {
                code: Secret::new(text("code")?.to_owned()),
                purpose: OtpPurpose::parse(text("purpose")?).ok_or(Invalid("purpose"))?,
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.magic_link.v1" => Body::MagicLink {
                link: Secret::new(text("link")?.to_owned()),
                expires_at_ms: int("expires_at_ms")?,
            },
            "relay.message.password_changed.v1" => Body::PasswordChanged {
                at_ms: int("at_ms")?,
            },
            "relay.message.new_sign_in.v1" => Body::NewSignIn {
                at_ms: int("at_ms")?,
                method: SignInMethod::parse(text("method")?).ok_or(Invalid("method"))?,
            },
            "relay.message.account_status.v1" => Body::AccountStatus {
                status: AccountStatus::parse(text("status")?).ok_or(Invalid("status"))?,
                at_ms: int("at_ms")?,
            },
            _ => return Err(Invalid("kind")),
        };
        let locale = match v.get("locale") {
            None => None,
            Some(Value::String(l)) => Some(l.clone()),
            Some(_) => return Err(Invalid("locale")),
        };
        let m = Self {
            subject,
            to: Address::from_json(v.get("recipient").ok_or(Invalid("recipient"))?)?,
            locale,
            body,
        };
        m.validate()?;
        Ok(m)
    }

    /// The `CloudEvents` `data` member: RFC 3339 times, the secret in clear for Relay only.
    pub(crate) fn to_wire_data(&self) -> Result<Value, Invalid> {
        let mut m = Map::new();
        m.insert("recipient".into(), self.to.to_json());
        if let Some(l) = &self.locale {
            m.insert("locale".into(), Value::String(l.clone()));
        }
        match &self.body {
            Body::Otp {
                code,
                purpose,
                expires_at_ms,
            } => {
                m.insert("code".into(), Value::String(code.expose().clone()));
                m.insert("purpose".into(), purpose.name().into());
                m.insert("expires_at".into(), rfc3339(*expires_at_ms)?.into());
            }
            Body::MagicLink {
                link,
                expires_at_ms,
            } => {
                m.insert("link".into(), Value::String(link.expose().clone()));
                m.insert("expires_at".into(), rfc3339(*expires_at_ms)?.into());
            }
            Body::PasswordChanged { at_ms } => {
                m.insert("at".into(), rfc3339(*at_ms)?.into());
            }
            Body::NewSignIn { at_ms, method } => {
                m.insert("at".into(), rfc3339(*at_ms)?.into());
                m.insert("method".into(), method.name().into());
            }
            Body::AccountStatus { status, at_ms } => {
                m.insert("status".into(), status.name().into());
                m.insert("at".into(), rfc3339(*at_ms)?.into());
            }
        }
        Ok(Value::Object(m))
    }
}

/// Unix ms as RFC 3339 UTC with milliseconds.
///
/// # Errors
/// [`Invalid`] past year 9999.
pub fn rfc3339(ms: u64) -> Result<String, Invalid> {
    let nanos = i128::from(ms)
        .checked_mul(1_000_000)
        .ok_or(Invalid("time"))?;
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(nanos).map_err(|_| Invalid("time"))?;
    let f = time::macros::format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    );
    t.format(&f).map_err(|_| Invalid("time"))
}
