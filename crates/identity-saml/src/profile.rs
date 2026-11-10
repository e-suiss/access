//! Interop (divergence) profiles of service providers as data (IDP-28, IDP-40, OP-155 m.3 (q),
//! `conformance/cddl/interop-profile.cddl`): the known format differences of one counterpart,
//! tolerated when the catalog template that names the profile is chosen. A profile tolerates
//! format only: a rule that would relax signature verification, time or skew checks, audience or
//! recipient checks, parser isolation or a limit does not exist, so a profile naming one is
//! invalid as a whole and refused at load; so is a known rule whose value would weaken output
//! (SHA-1, unsigned output).

use serde::Deserialize;

use crate::alg::SigAlg;
use crate::sp::{Aal3Class, NameFormat, NameIdFormat, Sp, SpError};

/// The SAML rule names of the profile schema; only ever appended.
pub const RULES: [&str; 15] = [
    "saml.nameid_format",
    "saml.sign_assertion",
    "saml.sign_response",
    "saml.signature_alg",
    "saml.key_info_certificate",
    "saml.attribute_name_format",
    "saml.attribute_names",
    "saml.attribute_multi_value",
    "saml.audience_value",
    "saml.acs_binding",
    "saml.authn_context_class",
    "saml.idp_initiated",
    "saml.slo_binding",
    "saml.encrypt_assertion",
    "saml.relay_state_echo",
];

/// The shipped profiles, one per profiled service provider (§10.6.1 table).
pub const SHIPPED: [(&str, &str); 11] = [
    ("aws", include_str!("../profiles/aws.toml")),
    ("aws-iam", include_str!("../profiles/aws-iam.toml")),
    (
        "aws-identity-center",
        include_str!("../profiles/aws-identity-center.toml"),
    ),
    ("entra", include_str!("../profiles/entra.toml")),
    (
        "google-workspace",
        include_str!("../profiles/google-workspace.toml"),
    ),
    ("salesforce", include_str!("../profiles/salesforce.toml")),
    ("servicenow", include_str!("../profiles/servicenow.toml")),
    ("workday", include_str!("../profiles/workday.toml")),
    ("slack", include_str!("../profiles/slack.toml")),
    ("zoom", include_str!("../profiles/zoom.toml")),
    ("atlassian", include_str!("../profiles/atlassian.toml")),
];

/// Why a profile was refused at load.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// Not a profile document of version 1 for SAML.
    #[error("malformed profile: {0}")]
    Malformed(String),
    /// A rule outside [`RULES`]: it could only relax security (IDP-40 (5)).
    #[error("unknown rule {0}: a profile tolerates format only")]
    Unknown(String),
    /// A known rule whose value would weaken security.
    #[error("rule {0} would relax security")]
    Relaxes(String),
    /// A rule's value has the wrong shape.
    #[error("rule {0} has an invalid value")]
    Value(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Doc {
    v: u64,
    profile: String,
    protocol: String,
    counterpart: String,
    revision: u64,
    template: Option<String>,
    tolerances: Vec<RawTolerance>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTolerance {
    rule: String,
    value: Option<toml::Value>,
    test: String,
    source: Option<String>,
}

/// One tolerated difference, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tolerance {
    /// The `NameID` format the counterpart needs.
    NameIdFormat(NameIdFormat),
    /// The counterpart requires the Assertion signature.
    SignAssertion,
    /// The counterpart requires the Response signature.
    SignResponse,
    /// The signature algorithm (never SHA-1).
    SignatureAlg(SigAlg),
    /// Whether `KeyInfo` carries the certificate.
    KeyInfoCertificate(bool),
    /// The attributes' default `NameFormat`.
    AttributeNameFormat(NameFormat),
    /// Attribute names the counterpart requires, case-sensitive.
    AttributeNames(Vec<String>),
    /// Multi-valued attributes are written as one `Attribute` with several values.
    AttributeMultiValue(bool),
    /// The audience value the counterpart expects instead of its entity ID.
    AudienceValue(String),
    /// The ACS binding (HTTP-POST).
    AcsBinding(String),
    /// How AAL3 is named.
    AuthnContextClass(Aal3Class),
    /// The counterpart commonly uses IdP-initiated SSO; the registration still opts in.
    IdpInitiated(bool),
    /// The counterpart's logout binding, or `none`.
    SloBinding(String),
    /// Whether the counterpart can take an encrypted assertion.
    EncryptAssertion(Encryption),
    /// Whether `RelayState` is echoed unchanged.
    RelayStateEcho(bool),
}

/// The counterpart's encryption support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encryption {
    /// It cannot decrypt: a registration may not ask for encryption.
    Unsupported,
    /// It may decrypt.
    Optional,
    /// It requires an encrypted assertion.
    Required,
}

/// A checked profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Its name, `saml.<counterpart>`.
    pub name: String,
    /// The counterpart.
    pub counterpart: String,
    /// Its revision.
    pub revision: u64,
    /// The template it belongs to.
    pub template: Option<String>,
    /// Its tolerances with the tests that pin them.
    pub tolerances: Vec<(Tolerance, String)>,
}

fn name_ok(s: &str) -> bool {
    let Some((head, tail)) = s.split_once('.') else {
        return false;
    };
    head.len() == 4
        && head.bytes().all(|b| b.is_ascii_lowercase())
        && !tail.is_empty()
        && tail.len() <= 63
        && tail
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && tail
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn test_ok(s: &str) -> bool {
    let parts: Vec<&str> = s.split("::").collect();
    (2..=7).contains(&parts.len())
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 64
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

fn text<'a>(rule: &str, v: Option<&'a toml::Value>) -> Result<&'a str, ProfileError> {
    v.and_then(toml::Value::as_str)
        .ok_or_else(|| ProfileError::Value(String::from(rule)))
}

fn flag(rule: &str, v: Option<&toml::Value>) -> Result<bool, ProfileError> {
    v.and_then(toml::Value::as_bool)
        .ok_or_else(|| ProfileError::Value(String::from(rule)))
}

fn tolerance(rule: &str, v: Option<&toml::Value>) -> Result<Tolerance, ProfileError> {
    let bad = || ProfileError::Value(String::from(rule));
    let relaxes = || ProfileError::Relaxes(String::from(rule));
    Ok(match rule {
        "saml.nameid_format" => Tolerance::NameIdFormat(match text(rule, v)? {
            "persistent" => NameIdFormat::Persistent,
            "transient" => NameIdFormat::Transient,
            "email" => NameIdFormat::Email,
            "unspecified" => NameIdFormat::Unspecified,
            _ => return Err(bad()),
        }),
        "saml.sign_assertion" | "saml.sign_response" => {
            if !flag(rule, v)? {
                return Err(relaxes());
            }
            if rule == "saml.sign_assertion" {
                Tolerance::SignAssertion
            } else {
                Tolerance::SignResponse
            }
        }
        "saml.signature_alg" => {
            let name = text(rule, v)?;
            Tolerance::SignatureAlg(SigAlg::of_name(name).ok_or_else(relaxes)?)
        }
        "saml.key_info_certificate" => Tolerance::KeyInfoCertificate(flag(rule, v)?),
        "saml.attribute_name_format" => Tolerance::AttributeNameFormat(match text(rule, v)? {
            "uri" => NameFormat::Uri,
            "basic" => NameFormat::Basic,
            "unspecified" => NameFormat::Unspecified,
            _ => return Err(bad()),
        }),
        "saml.attribute_names" => {
            let list = v.and_then(toml::Value::as_array).ok_or_else(bad)?;
            let names = list
                .iter()
                .map(|n| n.as_str().map(String::from).ok_or_else(bad))
                .collect::<Result<Vec<_>, _>>()?;
            if names.is_empty() || names.iter().any(|n| n.is_empty() || n.len() > 256) {
                return Err(bad());
            }
            Tolerance::AttributeNames(names)
        }
        "saml.attribute_multi_value" => Tolerance::AttributeMultiValue(flag(rule, v)?),
        "saml.audience_value" => {
            let a = text(rule, v)?;
            if a.is_empty() || !a.contains(':') || a.len() > 1024 {
                return Err(bad());
            }
            Tolerance::AudienceValue(String::from(a))
        }
        "saml.acs_binding" => match text(rule, v)? {
            "post" => Tolerance::AcsBinding(String::from("post")),
            _ => return Err(bad()),
        },
        "saml.authn_context_class" => Tolerance::AuthnContextClass(match text(rule, v)? {
            "x509" => Aal3Class::X509,
            "refeds-mfa" => Aal3Class::RefedsMfa,
            _ => return Err(bad()),
        }),
        "saml.idp_initiated" => Tolerance::IdpInitiated(flag(rule, v)?),
        "saml.slo_binding" => match text(rule, v)? {
            b @ ("post" | "redirect" | "none") => Tolerance::SloBinding(String::from(b)),
            _ => return Err(bad()),
        },
        "saml.encrypt_assertion" => Tolerance::EncryptAssertion(match text(rule, v)? {
            "unsupported" => Encryption::Unsupported,
            "optional" => Encryption::Optional,
            "required" => Encryption::Required,
            _ => return Err(bad()),
        }),
        "saml.relay_state_echo" => Tolerance::RelayStateEcho(flag(rule, v)?),
        other => return Err(ProfileError::Unknown(String::from(other))),
    })
}

impl Profile {
    /// Loads and checks a profile document (TOML of the schema's JSON shape).
    ///
    /// # Errors
    /// [`ProfileError`]; one bad rule refuses the whole profile.
    pub fn load(source: &str) -> Result<Self, ProfileError> {
        let doc: Doc =
            toml::from_str(source).map_err(|e| ProfileError::Malformed(e.to_string()))?;
        if doc.v != 1 || doc.protocol != "saml" || !name_ok(&doc.profile) {
            return Err(ProfileError::Malformed(String::from("header")));
        }
        if doc.counterpart.is_empty() || doc.counterpart.len() > 128 {
            return Err(ProfileError::Malformed(String::from("counterpart")));
        }
        let mut tolerances = Vec::new();
        for t in &doc.tolerances {
            if !RULES.contains(&t.rule.as_str()) {
                return Err(ProfileError::Unknown(t.rule.clone()));
            }
            if !test_ok(&t.test)
                || t.source
                    .as_ref()
                    .is_some_and(|s| s.is_empty() || s.len() > 512)
            {
                return Err(ProfileError::Value(t.rule.clone()));
            }
            tolerances.push((tolerance(&t.rule, t.value.as_ref())?, t.test.clone()));
        }
        Ok(Self {
            name: doc.profile,
            counterpart: doc.counterpart,
            revision: doc.revision,
            template: doc.template,
            tolerances,
        })
    }

    /// The shipped profile of `template`.
    ///
    /// # Errors
    /// [`SpError::Template`] when none is shipped (or it does not load).
    pub fn shipped(template: &str) -> Result<Self, SpError> {
        let (_, source) = SHIPPED
            .iter()
            .find(|(t, _)| *t == template)
            .ok_or(SpError::Template)?;
        Self::load(source).map_err(|_| SpError::Template)
    }

    /// Applies the profile to a registration: what the counterpart requires is set where the
    /// registration left the default, and a registration that contradicts it is refused. The
    /// result is checked again.
    ///
    /// # Errors
    /// [`SpError::Profile`]; [`SpError`] from the check.
    pub fn apply(&self, mut sp: Sp) -> Result<Sp, SpError> {
        for (t, _) in &self.tolerances {
            match t {
                Tolerance::NameIdFormat(f) => sp.nameid_format = *f,
                Tolerance::SignAssertion => {
                    if !sp.sign_assertion {
                        return Err(SpError::Profile);
                    }
                }
                Tolerance::SignResponse => {
                    if !sp.sign_response {
                        return Err(SpError::Profile);
                    }
                }
                Tolerance::SignatureAlg(a) => {
                    sp.signature_alg.get_or_insert(*a);
                }
                Tolerance::KeyInfoCertificate(b) => sp.key_info_certificate = *b,
                Tolerance::AttributeNameFormat(f) => sp.attribute_name_format = *f,
                Tolerance::AttributeNames(names) => {
                    let has = |n: &String| sp.attributes.iter().any(|a| &a.name == n);
                    if !names.iter().all(has) {
                        return Err(SpError::Profile);
                    }
                }
                Tolerance::AudienceValue(a) => {
                    sp.audience.get_or_insert_with(|| a.clone());
                }
                Tolerance::AuthnContextClass(c) => sp.aal3_class = *c,
                Tolerance::EncryptAssertion(Encryption::Unsupported) => {
                    if sp.encrypt_assertion {
                        return Err(SpError::Profile);
                    }
                }
                Tolerance::EncryptAssertion(Encryption::Required) => {
                    if !sp.encrypt_assertion {
                        return Err(SpError::Profile);
                    }
                }
                Tolerance::SloBinding(b) if b == "none" => {
                    if !sp.slo.is_empty() {
                        return Err(SpError::Profile);
                    }
                }
                Tolerance::EncryptAssertion(Encryption::Optional)
                | Tolerance::AttributeMultiValue(_)
                | Tolerance::AcsBinding(_)
                | Tolerance::IdpInitiated(_)
                | Tolerance::SloBinding(_)
                | Tolerance::RelayStateEcho(_) => {}
            }
        }
        let template_asks_email = self
            .tolerances
            .iter()
            .any(|(t, _)| *t == Tolerance::NameIdFormat(NameIdFormat::Email));
        if sp.nameid_format == NameIdFormat::Email && !template_asks_email {
            return Err(SpError::EmailNameId);
        }
        sp.check()?;
        Ok(sp)
    }
}

/// Checks a registration and applies its template's profile, if it names one.
///
/// # Errors
/// [`SpError`].
pub fn register(sp: Sp) -> Result<Sp, SpError> {
    sp.check()?;
    match sp.template.clone() {
        Some(t) => Profile::shipped(&t)?.apply(sp),
        None => Ok(sp),
    }
}

#[cfg(test)]
mod tests;
