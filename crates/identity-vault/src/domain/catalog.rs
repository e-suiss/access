//! The upstream catalog (AG-39, F23, OP-154 m.3 (t)): curated OAuth 2.0 metadata, scopes and the
//! refresh and revocation facts of 25 common services, shipped as `catalog/*.toml`. An entry is
//! data: it grants nothing to anyone (E36, EI-26). A realm uses one only after
//! `idp.vault.resource_enable`; a service the catalog does not have is the realm's own upstream,
//! `idp.vault.resource_register` (reserved).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How the upstream answers a refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Refresh {
    /// Each refresh returns a new refresh token; the old one stops working.
    Rotating,
    /// The refresh token is reused.
    Reusable,
    /// No refresh token; a lapsed connection needs the person again.
    None,
}

/// One upstream scope the catalog knows.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Its wire name.
    pub name: String,
    /// What it lets the upstream do, as people read it.
    pub description: String,
}

/// One upstream: an OAuth 2.0 authorization server and what Access knows of its tokens.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// The id, also the file name.
    pub id: String,
    /// The name people see.
    pub display_name: String,
    /// Authorization endpoint; `{name}` stands for a value of the realm's Resource
    /// (a Shopify shop, a Zendesk subdomain).
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// A token endpoint of its own for refreshes, when the upstream has one.
    #[serde(default)]
    pub refresh_endpoint: Option<String>,
    /// RFC 7009 revocation endpoint, when the upstream has one (AG-40 (5)).
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    /// Access token lifetime the upstream documents, for answers without `expires_in`.
    #[serde(default)]
    pub lifetime_s: Option<u64>,
    /// How refreshes behave.
    pub refresh: Refresh,
    /// Whether the authorization request carries PKCE `S256`.
    #[serde(default = "yes")]
    pub pkce: bool,
    /// Extra authorization request parameters (`access_type`, `audience`, `prompt`).
    #[serde(default)]
    pub authorize_params: BTreeMap<String, String>,
    /// How scopes are joined on the wire.
    #[serde(default = "space")]
    pub scope_separator: String,
    /// The placeholders the endpoints use; the Resource gives each a value.
    #[serde(default)]
    pub placeholders: Vec<String>,
    /// The scopes.
    #[serde(default)]
    pub scopes: Vec<Scope>,
}

const fn yes() -> bool {
    true
}

fn space() -> String {
    String::from(" ")
}

/// Why an upstream definition is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    /// Not the catalog format.
    #[error("upstream {0}: format")]
    Format(String),
    /// A URL, the id or a list is outside the rules.
    #[error("upstream {0}: invalid")]
    Invalid(String),
    /// Two entries share an id.
    #[error("upstream {0}: duplicate")]
    Duplicate(String),
}

/// Longest list the catalog keeps.
pub const MAX_SCOPES: usize = 64;

/// Whether `s` is a name: lower case, digits, `-` and `_`, starting with a letter, ≤ 64.
#[must_use]
pub fn name_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

fn scope_ok(s: &str) -> bool {
    (1..=256).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_graphic() && c != b',')
}

fn template_ok(u: &str, placeholders: &[String]) -> bool {
    let mut probe = String::from(u);
    for p in placeholders {
        probe = probe.replace(&format!("{{{p}}}"), "x");
    }
    !probe.contains('{')
        && !probe.contains('}')
        && access_identity_federation::domain::https(&probe)
}

impl Upstream {
    /// Parses and checks one catalog file.
    ///
    /// # Errors
    /// [`CatalogError`].
    pub fn parse(file: &str, text: &str) -> Result<Self, CatalogError> {
        let u: Self = toml::from_str(text).map_err(|_| CatalogError::Format(file.into()))?;
        if u.check() {
            Ok(u)
        } else {
            Err(CatalogError::Invalid(file.into()))
        }
    }

    /// Whether every field is inside the rules: https endpoints with only declared
    /// placeholders, names, bounded scope lists.
    #[must_use]
    pub fn check(&self) -> bool {
        let p = &self.placeholders;
        let urls = [
            Some(&self.authorization_endpoint),
            Some(&self.token_endpoint),
            self.refresh_endpoint.as_ref(),
            self.revocation_endpoint.as_ref(),
        ];
        name_ok(&self.id)
            && (1..=64).contains(&self.display_name.chars().count())
            && urls.iter().flatten().all(|u| template_ok(u, p))
            && p.len() <= 4
            && p.iter().all(|x| name_ok(x))
            && self.scopes.len() <= MAX_SCOPES
            && self
                .scopes
                .iter()
                .all(|s| scope_ok(&s.name) && s.description.len() <= 256)
            && matches!(self.scope_separator.as_str(), " " | ",")
            && self
                .lifetime_s
                .is_none_or(|s| (60..=31_536_000).contains(&s))
            && self.authorize_params.len() <= 8
            && self.authorize_params.iter().all(|(k, v)| {
                name_ok(k)
                    && !matches!(
                        k.as_str(),
                        "client_id" | "redirect_uri" | "state" | "scope" | "response_type"
                    )
                    && !k.starts_with("code_")
                    && v.len() <= 128
            })
    }

    /// Whether the catalog knows `scope`.
    #[must_use]
    pub fn knows(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s.name == scope)
    }

    /// This upstream with every `{name}` of its endpoints replaced by `values[name]`; `None`
    /// when a placeholder has no value or a value is not a DNS label.
    #[must_use]
    pub fn resolved(&self, values: &BTreeMap<String, String>) -> Option<Self> {
        let label = |v: &str| {
            (1..=63).contains(&v.len())
                && v.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
                && !v.starts_with('-')
                && !v.ends_with('-')
        };
        if values.keys().any(|k| !self.placeholders.contains(k)) {
            return None;
        }
        let mut out = self.clone();
        for p in &self.placeholders {
            let v = values.get(p).filter(|v| label(v))?;
            let needle = format!("{{{p}}}");
            out.authorization_endpoint = out.authorization_endpoint.replace(&needle, v);
            out.token_endpoint = out.token_endpoint.replace(&needle, v);
            out.refresh_endpoint = out.refresh_endpoint.map(|u| u.replace(&needle, v));
            out.revocation_endpoint = out.revocation_endpoint.map(|u| u.replace(&needle, v));
        }
        out.placeholders = Vec::new();
        out.check().then_some(out)
    }
}

const SHIPPED: [(&str, &str); 25] = [
    ("airtable", include_str!("../../catalog/airtable.toml")),
    ("asana", include_str!("../../catalog/asana.toml")),
    ("atlassian", include_str!("../../catalog/atlassian.toml")),
    ("box", include_str!("../../catalog/box.toml")),
    ("calendly", include_str!("../../catalog/calendly.toml")),
    ("clickup", include_str!("../../catalog/clickup.toml")),
    ("discord", include_str!("../../catalog/discord.toml")),
    ("dropbox", include_str!("../../catalog/dropbox.toml")),
    ("figma", include_str!("../../catalog/figma.toml")),
    ("github", include_str!("../../catalog/github.toml")),
    ("gitlab", include_str!("../../catalog/gitlab.toml")),
    ("google", include_str!("../../catalog/google.toml")),
    ("hubspot", include_str!("../../catalog/hubspot.toml")),
    ("intercom", include_str!("../../catalog/intercom.toml")),
    ("linear", include_str!("../../catalog/linear.toml")),
    (
        "microsoft-graph",
        include_str!("../../catalog/microsoft-graph.toml"),
    ),
    ("monday", include_str!("../../catalog/monday.toml")),
    ("notion", include_str!("../../catalog/notion.toml")),
    ("salesforce", include_str!("../../catalog/salesforce.toml")),
    ("shopify", include_str!("../../catalog/shopify.toml")),
    ("slack", include_str!("../../catalog/slack.toml")),
    ("stripe", include_str!("../../catalog/stripe.toml")),
    ("trello", include_str!("../../catalog/trello.toml")),
    ("zendesk", include_str!("../../catalog/zendesk.toml")),
    ("zoom", include_str!("../../catalog/zoom.toml")),
];

/// The upstreams this build ships, by id.
#[derive(Clone, Debug)]
pub struct Catalog(BTreeMap<String, Upstream>);

impl Catalog {
    /// The shipped catalog.
    ///
    /// # Errors
    /// [`CatalogError`] when a shipped file is outside the format.
    pub fn shipped() -> Result<Self, CatalogError> {
        Self::from_files(SHIPPED.iter().copied())
    }

    /// The shipped catalog, parsed once per process; `None` only if a shipped file were outside
    /// the format, which a test rules out.
    #[must_use]
    pub fn get_shipped() -> Option<&'static Self> {
        static SHIPPED_ONCE: std::sync::OnceLock<Option<Catalog>> = std::sync::OnceLock::new();
        SHIPPED_ONCE.get_or_init(|| Self::shipped().ok()).as_ref()
    }

    /// A catalog from `(file, text)` pairs; each file's name is its entry's id.
    ///
    /// # Errors
    /// [`CatalogError`].
    pub fn from_files<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, CatalogError> {
        let mut m = BTreeMap::new();
        for (file, text) in files {
            let u = Upstream::parse(file, text)?;
            if u.id != file {
                return Err(CatalogError::Invalid(file.into()));
            }
            if m.contains_key(&u.id) {
                return Err(CatalogError::Duplicate(u.id));
            }
            m.insert(u.id.clone(), u);
        }
        Ok(Self(m))
    }

    /// The entry `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Upstream> {
        self.0.get(id)
    }

    /// Every entry, by id.
    pub fn iter(&self) -> impl Iterator<Item = &Upstream> {
        self.0.values()
    }

    /// How many entries it has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether it is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // AG-39, OP-154 m.3 (t), Ek B 4487
    #[test]
    fn the_shipped_catalog_has_the_twenty_five_upstreams() {
        let c = Catalog::shipped().unwrap();
        assert_eq!(c.len(), 25);
        for id in [
            "google",
            "microsoft-graph",
            "github",
            "gitlab",
            "slack",
            "notion",
            "salesforce",
            "atlassian",
            "hubspot",
            "zoom",
            "dropbox",
            "box",
            "linear",
            "asana",
            "stripe",
            "shopify",
            "discord",
            "figma",
            "airtable",
            "intercom",
            "zendesk",
            "monday",
            "clickup",
            "trello",
            "calendly",
        ] {
            assert!(c.get(id).is_some(), "{id}");
        }
        let google = c.get("google").unwrap();
        for s in [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/calendar.events",
            "https://www.googleapis.com/auth/drive.readonly",
        ] {
            assert!(google.knows(s), "{s}");
        }
        let atlassian = c.get("atlassian").unwrap();
        assert!(
            atlassian.knows("read:jira-work") && atlassian.knows("read:confluence-content.all")
        );
    }

    #[test]
    fn an_entry_outside_the_rules_is_refused() {
        let ok = r#"
id = "x"
display_name = "X"
authorization_endpoint = "https://x.example/authorize"
token_endpoint = "https://x.example/token"
refresh = "none"
"#;
        assert!(Catalog::from_files([("x", ok)]).is_ok());
        assert!(Catalog::from_files([("y", ok)]).is_err());
        for bad in [
            ok.replace("https://x.example/token", "http://x.example/token"),
            ok.replace("refresh = \"none\"", "refresh = \"sometimes\""),
            format!("{ok}\nunknown = 1"),
            format!("{ok}\n[authorize_params]\nredirect_uri = \"https://evil.example\""),
            ok.replace("x.example/authorize", "{shop}.example/authorize"),
        ] {
            assert!(Catalog::from_files([("x", bad.as_str())]).is_err(), "{bad}");
        }
    }

    #[test]
    fn placeholders_take_only_dns_labels() {
        let c = Catalog::shipped().unwrap();
        let shopify = c.get("shopify").unwrap();
        assert!(shopify.resolved(&BTreeMap::new()).is_none());
        let ok = BTreeMap::from([(String::from("shop"), String::from("acme"))]);
        let r = shopify.resolved(&ok).unwrap();
        assert!(r.token_endpoint.starts_with("https://acme.myshopify.com/"));
        for v in ["acme.evil.example", "ACME", "a/b", ""] {
            let bad = BTreeMap::from([(String::from("shop"), String::from(v))]);
            assert!(shopify.resolved(&bad).is_none(), "{v}");
        }
        let extra = BTreeMap::from([
            (String::from("shop"), String::from("acme")),
            (String::from("other"), String::from("x")),
        ]);
        assert!(shopify.resolved(&extra).is_none());
    }
}
