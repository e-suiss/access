//! The organization SSO setup portal's rules (TN-134, OP-155 m.3 (i)): the identity provider
//! wizards as data steps, the values the administrator copies into the provider, the connection
//! a step drafts, and the scope rule that an upstream speaks only for the organization's
//! verified domains. Sans-I/O.

use serde::{Deserialize, Serialize};

/// The shipped wizards, in the order the portal offers them.
pub const WIZARDS: [(&str, &str); 9] = [
    ("entra", include_str!("../../wizards/entra.toml")),
    ("okta", include_str!("../../wizards/okta.toml")),
    (
        "google-workspace",
        include_str!("../../wizards/google-workspace.toml"),
    ),
    ("adfs", include_str!("../../wizards/adfs.toml")),
    ("jumpcloud", include_str!("../../wizards/jumpcloud.toml")),
    ("onelogin", include_str!("../../wizards/onelogin.toml")),
    ("ping", include_str!("../../wizards/ping.toml")),
    ("saml", include_str!("../../wizards/saml.toml")),
    ("oidc", include_str!("../../wizards/oidc.toml")),
];

/// The browser cookie a setup link is bound to on its first submitted step.
pub const SETUP_COOKIE: &str = "__Host-access-sso-setup";

/// A protocol a wizard drafts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// SAML 2.0.
    Saml,
    /// OpenID Connect.
    Oidc,
}

/// What a step asks of the administrator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Go to a place in the provider's console.
    Open,
    /// Copy one of Access's values into a field of the provider.
    Copy,
    /// Paste one of the provider's values here.
    Paste,
}

/// One of Access's values the administrator copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Value {
    /// The connection's SAML service provider entity ID (its metadata URL).
    EntityId,
    /// The connection's SAML Assertion Consumer Service URL.
    AcsUrl,
    /// The connection's SAML service provider metadata URL.
    MetadataUrl,
    /// The connection's OIDC redirect URI.
    RedirectUri,
    /// The realm's SCIM 2.0 base URL.
    ScimBaseUrl,
}

/// One of the provider's values the administrator pastes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Input {
    /// The SAML identity provider's entity ID.
    EntityId,
    /// The SAML identity provider's metadata URL.
    MetadataUrl,
    /// The OIDC issuer.
    Issuer,
    /// The client id at the OIDC issuer.
    ClientId,
}

/// One data step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// The protocol it belongs to; both when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// What it asks.
    pub action: Action,
    /// Where, for [`Action::Open`]: the provider's own menu path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    /// Which of Access's values, for [`Action::Copy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// Which of the provider's values, for [`Action::Paste`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Input>,
    /// The provider's own name of the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// A wizard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wizard {
    /// Version of the format: 1.
    pub v: u64,
    /// Its id.
    pub provider: String,
    /// The provider's product name.
    pub name: String,
    /// The protocols it drafts.
    pub protocols: Vec<Protocol>,
    /// Whether the provider provisions by SCIM.
    pub scim: bool,
    /// Its steps.
    pub steps: Vec<Step>,
}

/// Why a wizard was refused at load.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WizardError {
    /// Not a wizard of version 1.
    #[error("malformed wizard {0}")]
    Malformed(String),
    /// A step that does not fit its action or the wizard's protocols.
    #[error("wizard {0} has an invalid step")]
    Step(String),
}

fn step_ok(w: &Wizard, s: &Step) -> bool {
    let fits = match s.action {
        Action::Open => s.place.is_some() && s.value.is_none() && s.input.is_none(),
        Action::Copy => s.value.is_some() && s.input.is_none() && s.field.is_some(),
        Action::Paste => s.input.is_some() && s.value.is_none() && s.field.is_some(),
    };
    let protocol = s.protocol.is_none_or(|p| w.protocols.contains(&p));
    let bounded = [&s.place, &s.field]
        .into_iter()
        .flatten()
        .all(|t| !t.is_empty() && t.chars().count() <= 200 && !t.chars().any(char::is_control));
    let scim = s.value != Some(Value::ScimBaseUrl) || w.scim;
    fits && protocol && bounded && scim
}

/// Parses and checks one wizard.
///
/// # Errors
/// [`WizardError`].
pub fn parse(id: &str, text: &str) -> Result<Wizard, WizardError> {
    let w: Wizard = toml::from_str(text).map_err(|_| WizardError::Malformed(id.to_owned()))?;
    if w.v != 1 || w.provider != id || w.protocols.is_empty() || w.name.is_empty() {
        return Err(WizardError::Malformed(id.to_owned()));
    }
    if !w.steps.iter().all(|s| step_ok(&w, s)) {
        return Err(WizardError::Step(id.to_owned()));
    }
    let pastes = |p: Protocol| -> Vec<Input> {
        w.steps
            .iter()
            .filter(|s| s.protocol.is_none_or(|x| x == p))
            .filter_map(|s| s.input)
            .collect()
    };
    let complete = w.protocols.iter().all(|p| match p {
        Protocol::Saml => {
            let i = pastes(Protocol::Saml);
            i.contains(&Input::EntityId) && i.contains(&Input::MetadataUrl)
        }
        Protocol::Oidc => {
            let i = pastes(Protocol::Oidc);
            i.contains(&Input::Issuer) && i.contains(&Input::ClientId)
        }
    });
    if complete {
        Ok(w)
    } else {
        Err(WizardError::Step(id.to_owned()))
    }
}

/// Every shipped wizard, checked.
///
/// # Errors
/// [`WizardError`] for the first that does not load.
pub fn wizards() -> Result<Vec<Wizard>, WizardError> {
    WIZARDS.iter().map(|(id, text)| parse(id, text)).collect()
}

/// The connection name a setup link proposes for organization Party `org`: `org-` and twelve
/// hex digits of the Party, an upstream name the root's `idp.upstream.register` takes.
#[must_use]
pub fn connection_name(org: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::from("org-");
    for b in org.iter().take(6) {
        for n in [b >> 4, b & 0x0f] {
            out.push(char::from(HEX.get(usize::from(n)).copied().unwrap_or(b'0')));
        }
    }
    out
}

/// The values a wizard's copy steps hand out, under the realm's issuer `issuer`.
#[must_use]
pub fn values(issuer: &str, connection: &str) -> serde_json::Value {
    let base = issuer.trim_end_matches('/');
    let metadata = format!("{base}/v1/login/upstream/{connection}/saml/metadata");
    serde_json::json!({
        "entity_id": metadata,
        "acs_url": format!("{base}/v1/login/upstream/{connection}/saml/acs"),
        "metadata_url": metadata,
        "redirect_uri": format!("{base}/v1/login/upstream/{connection}/callback"),
        "scim_base_url": format!("{base}/scim/v2"),
    })
}

fn https(u: &str, query: bool) -> bool {
    u.strip_prefix("https://")
        .and_then(|r| r.split(['/', '?']).next())
        .is_some_and(|h| !h.is_empty() && !h.contains('@'))
        && u.len() <= 2048
        && !u
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '#' || (!query && c == '?'))
}

/// A connection a submitted step drafts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Draft {
    /// OIDC.
    Oidc {
        /// The issuer.
        issuer: String,
        /// The client id.
        client_id: String,
    },
    /// SAML.
    Saml {
        /// The identity provider's entity ID.
        entity_id: String,
        /// Its `https` metadata URL.
        metadata_url: String,
    },
}

impl Draft {
    /// Whether it is well formed: an `https` issuer without a query and a bounded client id, or
    /// a bounded entity ID and an `https` metadata URL.
    #[must_use]
    pub fn ok(&self) -> bool {
        match self {
            Self::Oidc { issuer, client_id } => {
                https(issuer, false)
                    && !client_id.is_empty()
                    && client_id.chars().count() <= 256
                    && !client_id.chars().any(char::is_control)
            }
            Self::Saml {
                entity_id,
                metadata_url,
            } => {
                https(metadata_url, true)
                    && !entity_id.is_empty()
                    && entity_id.len() <= 1024
                    && !entity_id
                        .chars()
                        .any(|c| c.is_whitespace() || c.is_control())
            }
        }
    }
}

/// Whether an upstream assertion naming the address `email` may speak for the organization
/// whose verified, uncontested domains are `verified` (TN-134 (1), (3)): only an exact domain
/// match counts; a lapsed or contested domain is not in `verified`, so its identities are
/// refused.
#[must_use]
pub fn admits(email: &str, verified: &[String]) -> bool {
    let Some((local, domain)) = email.rsplit_once('@') else {
        return false;
    };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    !local.is_empty() && verified.contains(&domain)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // TN-134, OP-155 m.3 (i)
    #[test]
    fn every_shipped_wizard_loads_with_the_listed_providers() {
        let all = wizards().unwrap();
        let ids: Vec<&str> = all.iter().map(|w| w.provider.as_str()).collect();
        assert_eq!(
            ids,
            [
                "entra",
                "okta",
                "google-workspace",
                "adfs",
                "jumpcloud",
                "onelogin",
                "ping",
                "saml",
                "oidc"
            ]
        );
    }

    // TN-134
    #[test]
    fn a_wizard_without_a_complete_paste_set_is_refused() {
        let text = r#"
v = 1
provider = "x"
name = "X"
protocols = ["oidc"]
scim = false
[[steps]]
action = "paste"
input = "issuer"
field = "Issuer"
"#;
        assert_eq!(parse("x", text), Err(WizardError::Step(String::from("x"))));
        let scim = text.replace(
            "[[steps]]",
            "[[steps]]\naction = \"copy\"\nvalue = \"scim_base_url\"\nfield = \"Base\"\n[[steps]]",
        );
        assert!(parse("x", &scim).is_err());
    }

    // TN-134 (1), (3)
    #[test]
    fn only_a_verified_domain_admits_an_upstream_identity() {
        let verified = vec![String::from("contoso.example")];
        assert!(admits("ada@contoso.example", &verified));
        assert!(admits("ada@CONTOSO.example", &verified));
        assert!(!admits("ada@evil.example", &verified));
        assert!(!admits("ada@sub.contoso.example", &verified));
        assert!(!admits("contoso.example", &verified));
        assert!(!admits("ada@contoso.example", &[]));
    }

    // TN-134
    #[test]
    fn drafts_need_https_and_bounded_values() {
        assert!(
            Draft::Saml {
                entity_id: String::from("http://www.okta.com/exk1"),
                metadata_url: String::from("https://acme.okta.com/app/exk1/sso/saml/metadata"),
            }
            .ok()
        );
        assert!(
            !Draft::Saml {
                entity_id: String::from("urn:x"),
                metadata_url: String::from("http://acme.example/metadata"),
            }
            .ok()
        );
        assert!(
            !Draft::Oidc {
                issuer: String::from("https://login.example/?x"),
                client_id: String::from("c"),
            }
            .ok()
        );
        assert_eq!(connection_name(&[0xab; 16]), "org-abababababab");
        let v = values("https://id.acme.example/", "org-1");
        assert_eq!(
            v["acs_url"],
            "https://id.acme.example/v1/login/upstream/org-1/saml/acs"
        );
    }
}
