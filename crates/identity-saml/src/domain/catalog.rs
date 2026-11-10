//! The SSO app catalog (IDP-28, OP-155 m.3 (i)): 60 service provider templates as data, the
//! eleven profiled service providers first. A template names the values the administrator fills
//! in, the entity ID and ACS patterns, the `NameID` format and the attributes the provider expects,
//! and the shipped interop profile when it has one. Creating a connection from a template is
//! `idp.saml.sp_register`; a template that maps a Claim which selects authority is
//! `idp.saml.sp_mapping` (reserved, CT3, L6).

use serde::{Deserialize, Serialize};

use crate::profile::{Profile, SHIPPED, Tolerance};
use crate::sp::{NameIdFormat, Sp, SpError};

/// Every template, the eleven profiled service providers first.
pub const CATALOG: [(&str, &str); 60] = [
    ("aws", include_str!("../../catalog/aws.toml")),
    ("aws-iam", include_str!("../../catalog/aws-iam.toml")),
    (
        "aws-identity-center",
        include_str!("../../catalog/aws-identity-center.toml"),
    ),
    ("entra", include_str!("../../catalog/entra.toml")),
    (
        "google-workspace",
        include_str!("../../catalog/google-workspace.toml"),
    ),
    ("salesforce", include_str!("../../catalog/salesforce.toml")),
    ("servicenow", include_str!("../../catalog/servicenow.toml")),
    ("workday", include_str!("../../catalog/workday.toml")),
    ("slack", include_str!("../../catalog/slack.toml")),
    ("zoom", include_str!("../../catalog/zoom.toml")),
    ("atlassian", include_str!("../../catalog/atlassian.toml")),
    ("github", include_str!("../../catalog/github.toml")),
    ("gitlab", include_str!("../../catalog/gitlab.toml")),
    ("dropbox", include_str!("../../catalog/dropbox.toml")),
    ("box", include_str!("../../catalog/box.toml")),
    ("asana", include_str!("../../catalog/asana.toml")),
    ("notion", include_str!("../../catalog/notion.toml")),
    ("figma", include_str!("../../catalog/figma.toml")),
    ("miro", include_str!("../../catalog/miro.toml")),
    ("canva", include_str!("../../catalog/canva.toml")),
    ("zendesk", include_str!("../../catalog/zendesk.toml")),
    ("freshdesk", include_str!("../../catalog/freshdesk.toml")),
    ("intercom", include_str!("../../catalog/intercom.toml")),
    ("hubspot", include_str!("../../catalog/hubspot.toml")),
    ("docusign", include_str!("../../catalog/docusign.toml")),
    ("adobe", include_str!("../../catalog/adobe.toml")),
    ("tableau", include_str!("../../catalog/tableau.toml")),
    ("datadog", include_str!("../../catalog/datadog.toml")),
    ("pagerduty", include_str!("../../catalog/pagerduty.toml")),
    ("sentry", include_str!("../../catalog/sentry.toml")),
    ("new-relic", include_str!("../../catalog/new-relic.toml")),
    (
        "splunk-cloud",
        include_str!("../../catalog/splunk-cloud.toml"),
    ),
    ("snowflake", include_str!("../../catalog/snowflake.toml")),
    ("databricks", include_str!("../../catalog/databricks.toml")),
    ("cloudflare", include_str!("../../catalog/cloudflare.toml")),
    ("lucid", include_str!("../../catalog/lucid.toml")),
    ("smartsheet", include_str!("../../catalog/smartsheet.toml")),
    ("monday", include_str!("../../catalog/monday.toml")),
    ("clickup", include_str!("../../catalog/clickup.toml")),
    ("airtable", include_str!("../../catalog/airtable.toml")),
    ("webex", include_str!("../../catalog/webex.toml")),
    (
        "ringcentral",
        include_str!("../../catalog/ringcentral.toml"),
    ),
    ("gong", include_str!("../../catalog/gong.toml")),
    ("greenhouse", include_str!("../../catalog/greenhouse.toml")),
    ("lever", include_str!("../../catalog/lever.toml")),
    ("bamboohr", include_str!("../../catalog/bamboohr.toml")),
    ("gusto", include_str!("../../catalog/gusto.toml")),
    ("expensify", include_str!("../../catalog/expensify.toml")),
    ("coupa", include_str!("../../catalog/coupa.toml")),
    ("netsuite", include_str!("../../catalog/netsuite.toml")),
    (
        "sap-successfactors",
        include_str!("../../catalog/sap-successfactors.toml"),
    ),
    ("concur", include_str!("../../catalog/concur.toml")),
    ("jamf", include_str!("../../catalog/jamf.toml")),
    ("kandji", include_str!("../../catalog/kandji.toml")),
    ("1password", include_str!("../../catalog/1password.toml")),
    ("keeper", include_str!("../../catalog/keeper.toml")),
    ("bitwarden", include_str!("../../catalog/bitwarden.toml")),
    ("vercel", include_str!("../../catalog/vercel.toml")),
    ("linear", include_str!("../../catalog/linear.toml")),
    ("loom", include_str!("../../catalog/loom.toml")),
];

/// Most administrator values one template names.
pub const MAX_PARAMETERS: usize = 4;

/// The SAML side of a template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlSide {
    /// The service provider's entity ID, with `{parameter}` placeholders.
    pub entity_id: String,
    /// Its ACS URL, with `{parameter}` placeholders: always `https`.
    pub acs: String,
    /// The `NameID` format it expects.
    pub nameid_format: NameIdFormat,
    /// The attribute names it expects.
    pub attributes: Vec<String>,
}

/// The OIDC side of a template, for providers that also take OpenID Connect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcSide {
    /// Its redirect URIs, with `{parameter}` placeholders: always `https`.
    pub redirect_uris: Vec<String>,
}

/// One template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    /// Version of the format: 1.
    pub v: u64,
    /// Its id, the registration's `template`.
    pub template: String,
    /// The service provider's product name.
    pub name: String,
    /// What kind of application it is.
    pub category: String,
    /// The shipped interop profile it applies, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Whether it maps a Claim that selects authority (L6): its registration is
    /// `idp.saml.sp_mapping`.
    pub selects_authority: bool,
    /// The administrator's values its patterns name.
    pub parameters: Vec<String>,
    /// Its SAML side.
    pub saml: SamlSide,
    /// Its OIDC side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcSide>,
}

/// Why a template was refused at load.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    /// Not a template of version 1 under its own id.
    #[error("malformed template {0}")]
    Malformed(String),
    /// A pattern names a value the template does not list, or a URL that is not `https`.
    #[error("template {0} has an invalid pattern")]
    Pattern(String),
    /// It names a profile that is not shipped or belongs to another template, or its `NameID`
    /// contradicts the profile.
    #[error("template {0} disagrees with its profile")]
    Profile(String),
}

fn placeholders(pattern: &str) -> Vec<&str> {
    pattern
        .split('{')
        .skip(1)
        .filter_map(|p| p.split_once('}').map(|(n, _)| n))
        .collect()
}

fn https_pattern(p: &str) -> bool {
    p.strip_prefix("https://").is_some_and(|r| !r.is_empty())
        && p.len() <= crate::sp::MAX_URI
        && !p.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
}

/// Parses and checks one template.
///
/// # Errors
/// [`CatalogError`].
pub fn parse(id: &str, text: &str) -> Result<Template, CatalogError> {
    let t: Template = toml::from_str(text).map_err(|_| CatalogError::Malformed(id.to_owned()))?;
    let bounded = |s: &str| !s.is_empty() && s.chars().count() <= 100;
    if t.v != 1
        || t.template != id
        || !name_ok(id)
        || !bounded(&t.name)
        || !name_ok(&t.category)
        || t.parameters.len() > MAX_PARAMETERS
        || !t.parameters.iter().all(|p| name_ok(p))
    {
        return Err(CatalogError::Malformed(id.to_owned()));
    }
    let mut patterns = vec![t.saml.entity_id.as_str(), t.saml.acs.as_str()];
    if let Some(o) = &t.oidc {
        patterns.extend(o.redirect_uris.iter().map(String::as_str));
    }
    let named = patterns
        .iter()
        .flat_map(|p| placeholders(p))
        .all(|n| t.parameters.iter().any(|p| p == n));
    let urls = https_pattern(&t.saml.acs)
        && t.oidc.as_ref().is_none_or(|o| {
            !o.redirect_uris.is_empty() && o.redirect_uris.iter().all(|u| https_pattern(u))
        });
    if !named || !urls || t.saml.entity_id.is_empty() {
        return Err(CatalogError::Pattern(id.to_owned()));
    }
    if let Some(p) = &t.profile {
        let profile = Profile::shipped(p).map_err(|_| CatalogError::Profile(id.to_owned()))?;
        let asks_email = profile
            .tolerances
            .iter()
            .any(|(t, _)| *t == Tolerance::NameIdFormat(NameIdFormat::Email));
        if p != id
            || profile.template.as_deref() != Some(id)
            || (t.saml.nameid_format == NameIdFormat::Email && !asks_email)
        {
            return Err(CatalogError::Profile(id.to_owned()));
        }
    }
    Ok(t)
}

/// Every template, checked.
///
/// # Errors
/// [`CatalogError`] for the first that does not load.
pub fn all() -> Result<Vec<Template>, CatalogError> {
    CATALOG.iter().map(|(id, text)| parse(id, text)).collect()
}

/// The template `id`, checked; `None` when the catalog has none.
#[must_use]
pub fn find(id: &str) -> Option<Template> {
    CATALOG
        .iter()
        .find(|(t, _)| *t == id)
        .and_then(|(t, text)| parse(t, text).ok())
}

/// Whether registering from template `id` maps a Claim that selects authority (L6).
#[must_use]
pub fn selects_authority(id: &str) -> bool {
    find(id).is_some_and(|t| t.selects_authority)
}

impl Template {
    /// Applies the template to a registration: its profile when it has one; otherwise an
    /// e-mail `NameID` only when the template asks for it.
    ///
    /// # Errors
    /// [`SpError`].
    pub fn apply(&self, sp: Sp) -> Result<Sp, SpError> {
        if let Some(p) = &self.profile {
            return Profile::shipped(p)?.apply(sp);
        }
        if sp.nameid_format == NameIdFormat::Email && self.saml.nameid_format != NameIdFormat::Email
        {
            return Err(SpError::EmailNameId);
        }
        sp.check()?;
        Ok(sp)
    }
}

/// The profiled templates, in [`SHIPPED`] order.
#[must_use]
pub fn profiled() -> Vec<&'static str> {
    SHIPPED.iter().map(|(t, _)| *t).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // IDP-28, OP-155 m.3 (i)
    #[test]
    fn the_catalog_holds_sixty_templates_the_profiled_eleven_first() {
        let all = all().unwrap();
        assert_eq!(all.len(), 60);
        let first: Vec<&str> = all.iter().take(11).map(|t| t.template.as_str()).collect();
        assert_eq!(first, profiled());
        assert!(all.iter().take(11).all(|t| t.profile.is_some()));
        assert!(all.iter().skip(11).all(|t| t.profile.is_none()));
        let mut ids: Vec<&str> = all.iter().map(|t| t.template.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 60);
    }

    // IDP-28, L6
    #[test]
    fn a_template_mapping_an_authority_claim_is_marked() {
        assert!(selects_authority("aws"));
        assert!(selects_authority("aws-iam"));
        assert!(!selects_authority("slack"));
        assert!(!selects_authority("no-such-template"));
    }

    // IDP-28
    #[test]
    fn a_pattern_naming_an_unlisted_value_is_refused() {
        let text = r#"
v = 1
template = "x"
name = "X"
category = "misc"
selects_authority = false
parameters = []
[saml]
entity_id = "https://{host}/sp"
acs = "https://{host}/acs"
nameid_format = "persistent"
attributes = []
"#;
        assert_eq!(
            parse("x", text),
            Err(CatalogError::Pattern(String::from("x")))
        );
        let plain = text.replace("{host}", "x.example");
        assert!(parse("x", &plain).is_ok());
        let http = plain.replace("acs = \"https://", "acs = \"http://");
        assert!(parse("x", &http).is_err());
        let foreign = plain.replace(
            "selects_authority",
            "profile = \"slack\"\nselects_authority",
        );
        assert_eq!(
            parse("x", &foreign),
            Err(CatalogError::Profile(String::from("x")))
        );
    }
}
