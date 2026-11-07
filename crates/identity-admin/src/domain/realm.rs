//! The realm resources the management API adds to the `idp.*` catalogue (OP-151 m.2 M1): groups
//! with one membership issuer (TN-117), account suspension (§12.3.1), upstream identity provider
//! registrations (OP-150 m.11 (j)), the sign-in requirements (TN-132) and the console session
//! policy (TN-129, OP-151 m.3 (f)). Data only; each is written by its own Exercise.

use std::collections::BTreeSet;

use suiss_crypto::dcbor::Value;

use super::Invalid;

/// Most members one change adds or removes.
pub const MAX_MEMBERS_PER_CHANGE: usize = 100;

/// Most entries of a registration domain list (TN-132).
pub const MAX_DOMAIN_LIST: usize = 256;

/// Longest console session, absolute (OP-151 m.3 (f)): 12 hours.
pub const CONSOLE_ABSOLUTE_MAX_MS: u64 = 12 * 3_600_000;

/// Longest console idle time (OP-151 m.3 (f)): 15 minutes.
pub const CONSOLE_IDLE_MAX_MS: u64 = 15 * 60_000;

/// Shortest console session or idle time a realm may set.
pub const CONSOLE_MIN_MS: u64 = 60_000;

/// The profile fields a realm may require at registration (TN-132).
pub const REQUIRED_FIELDS: [&str; 7] = [
    "email",
    "phone_number",
    "username",
    "given_name",
    "family_name",
    "birthdate",
    "locale",
];

fn ident(s: &str) -> bool {
    let b = s.as_bytes();
    (1..=64).contains(&b.len())
        && b.first().is_some_and(u8::is_ascii_lowercase)
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-'))
}

fn display(s: &str) -> bool {
    let n = s.chars().count();
    (1..=128).contains(&n) && !s.chars().any(char::is_control)
}

fn text_array<'a>(items: impl Iterator<Item = &'a str>) -> Value {
    Value::Array(items.map(Value::text).collect())
}

/// A natural key of a group or an upstream provider: `^[a-z][a-z0-9_-]{0,63}$`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

impl Name {
    /// Checks a name.
    ///
    /// # Errors
    /// [`Invalid::Name`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        if ident(s) {
            Ok(Self(String::from(s)))
        } else {
            Err(Invalid::Name)
        }
    }

    /// The text form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who issues a group's memberships (TN-117): exactly one. The realm's administration through
/// `idp.group.members_*`, or one upstream provider's mapping; never both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipIssuer {
    /// The realm's administration.
    Admin,
    /// The named upstream identity provider.
    Upstream(Name),
}

impl MembershipIssuer {
    /// The text form: `admin` or `upstream:<name>`.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Admin => String::from("admin"),
            Self::Upstream(n) => format!("upstream:{}", n.as_str()),
        }
    }

    /// From the text form.
    ///
    /// # Errors
    /// [`Invalid::MembershipIssuer`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        match s.split_once(':') {
            None if s == "admin" => Ok(Self::Admin),
            Some(("upstream", n)) => Name::parse(n)
                .map(Self::Upstream)
                .map_err(|_| Invalid::MembershipIssuer),
            _ => Err(Invalid::MembershipIssuer),
        }
    }
}

/// A group (TN-117). Membership is an identity Claim, never authority (§9.9.6, P55).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// The natural key.
    pub name: Name,
    /// The display name.
    pub display_name: String,
    /// Its one membership issuer.
    pub issuer: MembershipIssuer,
}

impl Group {
    /// Checks the display name.
    ///
    /// # Errors
    /// [`Invalid::DisplayName`].
    pub fn check(&self) -> Result<(), Invalid> {
        if display(&self.display_name) {
            Ok(())
        } else {
            Err(Invalid::DisplayName)
        }
    }

    /// The deterministic CBOR the change and its stored form carry.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("name"), Value::text(self.name.as_str())),
            (Value::text("display_name"), Value::text(&self.display_name)),
            (
                Value::text("membership_issuer"),
                Value::text(&self.issuer.text()),
            ),
        ])
    }
}

/// A change of a group's members: the realm subjects, by their internal ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Members {
    /// The group.
    pub group: Name,
    /// The subjects; at least one, at most [`MAX_MEMBERS_PER_CHANGE`].
    pub subjects: BTreeSet<[u8; 16]>,
}

impl Members {
    /// Checks the count.
    ///
    /// # Errors
    /// [`Invalid::Members`].
    pub fn check(&self) -> Result<(), Invalid> {
        if (1..=MAX_MEMBERS_PER_CHANGE).contains(&self.subjects.len()) {
            Ok(())
        } else {
            Err(Invalid::Members)
        }
    }

    /// The deterministic CBOR the change and its stored form carry.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("group"), Value::text(self.group.as_str())),
            (
                Value::text("subjects"),
                Value::Array(
                    self.subjects
                        .iter()
                        .map(|s| Value::Bytes(s.to_vec()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// An upstream identity provider's registration (OP-150 m.11 (j)): the storage contract only.
/// Its client secret is a reference to a secret store entry, never the secret; the live
/// federation adapter comes with its own stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upstream {
    /// The natural key.
    pub name: Name,
    /// The provider's issuer, `https`.
    pub issuer: String,
    /// The client id Access holds at the provider.
    pub client_id: String,
    /// A reference to the client secret, `secret://…`; `None` for `private_key_jwt`.
    pub client_secret_ref: Option<String>,
    /// The provider's JWKS, `https`.
    pub jwks_uri: String,
    /// The provider's SSF transmitter configuration, `https`, for the receiver (OP-151 m.3 (l)).
    pub ssf_configuration_uri: Option<String>,
}

impl Upstream {
    /// Checks the URLs, the client id and the secret reference.
    ///
    /// # Errors
    /// [`Invalid::Upstream`].
    pub fn check(&self) -> Result<(), Invalid> {
        let id_ok = (1..=255).contains(&self.client_id.len())
            && self.client_id.bytes().all(|c| c.is_ascii_graphic());
        let ref_ok = self.client_secret_ref.as_deref().is_none_or(|r| {
            r.len() <= 255
                && r.strip_prefix("secret://").is_some_and(|rest| {
                    !rest.is_empty()
                        && rest.bytes().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, b'/' | b'-' | b'_' | b'.')
                        })
                })
        });
        let urls_ok = super::https(&self.issuer)
            && super::https(&self.jwks_uri)
            && self
                .ssf_configuration_uri
                .as_deref()
                .is_none_or(super::https);
        if id_ok && ref_ok && urls_ok {
            Ok(())
        } else {
            Err(Invalid::Upstream)
        }
    }

    /// The deterministic CBOR the change and its stored form carry.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = vec![
            (Value::text("name"), Value::text(self.name.as_str())),
            (Value::text("issuer"), Value::text(&self.issuer)),
            (Value::text("client_id"), Value::text(&self.client_id)),
            (Value::text("jwks_uri"), Value::text(&self.jwks_uri)),
        ];
        if let Some(r) = &self.client_secret_ref {
            m.push((Value::text("client_secret_ref"), Value::text(r)));
        }
        if let Some(u) = &self.ssf_configuration_uri {
            m.push((Value::text("ssf_configuration_uri"), Value::text(u)));
        }
        Value::Map(m)
    }
}

/// A sign-in method a realm may enable (TN-132).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigninMethod {
    /// Email and a one-time code or password.
    Email,
    /// Phone number and a one-time code.
    Phone,
    /// Username and password.
    Username,
    /// A passkey.
    Passkey,
    /// A registered upstream provider.
    Social(Name),
}

impl SigninMethod {
    /// The text form: `email`, `phone`, `username`, `passkey` or `social:<provider>`.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Email => String::from("email"),
            Self::Phone => String::from("phone"),
            Self::Username => String::from("username"),
            Self::Passkey => String::from("passkey"),
            Self::Social(n) => format!("social:{}", n.as_str()),
        }
    }

    /// From the text form.
    ///
    /// # Errors
    /// [`Invalid::SigninPolicy`].
    pub fn parse(s: &str) -> Result<Self, Invalid> {
        match s {
            "email" => Ok(Self::Email),
            "phone" => Ok(Self::Phone),
            "username" => Ok(Self::Username),
            "passkey" => Ok(Self::Passkey),
            _ => s
                .strip_prefix("social:")
                .and_then(|n| Name::parse(n).ok())
                .map(Self::Social)
                .ok_or(Invalid::SigninPolicy),
        }
    }
}

/// The realm's sign-in requirements (TN-132): what must be complete, never the order. The
/// server keeps the rules no order breaks: unverified data activates nothing, required MFA is
/// never skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigninPolicy {
    /// Enabled methods; at least one.
    pub methods: BTreeSet<SigninMethod>,
    /// Profile fields required at registration, from [`REQUIRED_FIELDS`].
    pub required_fields: BTreeSet<String>,
    /// Whether a second factor is required.
    pub mfa_required: bool,
    /// Email domains registration is limited to; empty allows every domain not denied.
    pub domain_allow: BTreeSet<String>,
    /// Email domains registration is refused for.
    pub domain_deny: BTreeSet<String>,
}

impl SigninPolicy {
    /// Checks the policy.
    ///
    /// # Errors
    /// [`Invalid::SigninPolicy`].
    pub fn check(&self) -> Result<(), Invalid> {
        let fields_ok = self
            .required_fields
            .iter()
            .all(|f| REQUIRED_FIELDS.contains(&f.as_str()));
        let lists_ok = [&self.domain_allow, &self.domain_deny]
            .iter()
            .all(|l| l.len() <= MAX_DOMAIN_LIST && l.iter().all(|d| super::host(d)))
            && self.domain_allow.is_disjoint(&self.domain_deny);
        let methods_ok = !self.methods.is_empty();
        if fields_ok && lists_ok && methods_ok {
            Ok(())
        } else {
            Err(Invalid::SigninPolicy)
        }
    }

    /// The deterministic CBOR the change and its stored form carry.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (
                Value::text("methods"),
                Value::Array(
                    self.methods
                        .iter()
                        .map(|m| Value::text(&m.text()))
                        .collect(),
                ),
            ),
            (
                Value::text("required_fields"),
                text_array(self.required_fields.iter().map(String::as_str)),
            ),
            (Value::text("mfa_required"), Value::Bool(self.mfa_required)),
            (
                Value::text("domain_allow"),
                text_array(self.domain_allow.iter().map(String::as_str)),
            ),
            (
                Value::text("domain_deny"),
                text_array(self.domain_deny.iter().map(String::as_str)),
            ),
        ])
    }
}

/// What a console session is bound to (TN-129, OP-151 m.1 (b)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// The client's ASN when a `GeoIP` source is configured, else its IP prefix (/24, /48).
    Asn,
    /// The client's full IP address.
    Ip,
    /// Nothing; never allowed for the management surface.
    None,
}

impl Binding {
    /// The text form.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Asn => "asn",
            Self::Ip => "ip",
            Self::None => "none",
        }
    }

    /// From the text form.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "asn" => Some(Self::Asn),
            "ip" => Some(Self::Ip),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// The realm's console session policy (TN-129, OP-151 m.3 (f)): at most 12 hours absolute and
/// 15 minutes idle, bound to the ASN or the IP; a realm may only tighten it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Absolute lifetime.
    pub absolute_ms: u64,
    /// Idle lifetime.
    pub idle_ms: u64,
    /// The binding; [`Binding::None`] is refused.
    pub binding: Binding,
}

impl SessionPolicy {
    /// The default (OP-151 m.3 (f)).
    pub const DEFAULT: Self = Self {
        absolute_ms: CONSOLE_ABSOLUTE_MAX_MS,
        idle_ms: CONSOLE_IDLE_MAX_MS,
        binding: Binding::Asn,
    };

    /// Checks the bounds and the binding.
    ///
    /// # Errors
    /// [`Invalid::SessionPolicy`].
    pub fn check(&self) -> Result<(), Invalid> {
        let ok = (CONSOLE_MIN_MS..=CONSOLE_ABSOLUTE_MAX_MS).contains(&self.absolute_ms)
            && (CONSOLE_MIN_MS..=CONSOLE_IDLE_MAX_MS).contains(&self.idle_ms)
            && self.idle_ms <= self.absolute_ms
            && self.binding != Binding::None;
        if ok {
            Ok(())
        } else {
            Err(Invalid::SessionPolicy)
        }
    }

    /// The deterministic CBOR the change and its stored form carry.
    #[must_use]
    pub fn to_value(self) -> Value {
        Value::Map(vec![
            (
                Value::text("absolute_ms"),
                Value::Unsigned(self.absolute_ms),
            ),
            (Value::text("idle_ms"), Value::Unsigned(self.idle_ms)),
            (Value::text("binding"), Value::text(self.binding.name())),
        ])
    }
}
