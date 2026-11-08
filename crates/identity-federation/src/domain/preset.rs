//! Social provider presets as data (F23, IDP-31, OP-153 m.3 (l)): endpoints, scopes, logo, the
//! claims that key the subject and what the provider's e-mail address is worth. The day-one
//! presets ship in `presets/*.toml`; a second-wave provider is one more file.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::domain::https;

/// The protocol a provider speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// OpenID Connect: an ID token checked in the back end.
    Oidc,
    /// OAuth 2.0 with a user-info endpoint read in the back end with the code's access token.
    Oauth2,
}

/// What the provider's e-mail address is worth (IDP-31 (3)).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EmailAssurance {
    /// `email_verified = true` vouches for the address.
    VerifiedClaim,
    /// The provider is authoritative only for `domains`, and for the domain its
    /// `hosted_domain_claim` names when that claim equals the address's domain.
    AuthoritativeDomains {
        /// Consumer domains the provider owns.
        domains: Vec<String>,
        /// The claim naming a managed domain (`hd`).
        hosted_domain_claim: Option<String>,
    },
    /// The boolean claim `claim` must be `true` (Entra `xms_edov`).
    Claim {
        /// The claim.
        claim: String,
    },
    /// Only a verified primary address of the provider's address list counts.
    VerifiedPrimary,
    /// Never vouched for.
    None,
}

/// How the authorization response comes back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    /// A `GET` with the query.
    #[default]
    Query,
    /// A `POST` form (Apple).
    FormPost,
}

/// How Access authenticates to the provider's token endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuth {
    /// `client_secret_post` with the stored secret.
    #[default]
    SecretPost,
    /// `client_secret_post` with a fresh ES256 assertion signed by the realm's Sign in with
    /// Apple key (`crate::domain::apple`).
    AppleJwt,
}

/// One preset.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    /// The preset id, also the provider name in routes (`/v1/login/social/{id}`).
    pub id: String,
    /// The name the hosted page shows.
    pub display_name: String,
    /// The protocol.
    pub protocol: Protocol,
    /// The issuer; `{claim}` stands for a claim of the ID token (Entra's `{tid}`).
    pub issuer: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// JWKS, for OIDC.
    pub jwks_uri: Option<String>,
    /// User-info endpoint, for OAuth 2.0.
    pub userinfo_endpoint: Option<String>,
    /// Address list endpoint (GitHub).
    pub emails_endpoint: Option<String>,
    /// Requested scopes.
    pub scopes: Vec<String>,
    /// The bundled logo's key; the hosted page draws it only with `<img>` (OP-153 m.3 (t)).
    pub logo: String,
    /// The claims whose values, in order, are the provider's subject (TN-66).
    pub subject: Vec<String>,
    /// ID token algorithms accepted, from the preset and never from the token's header (MD-3).
    #[serde(default)]
    pub algorithms: Vec<String>,
    /// How the authorization response comes back.
    #[serde(default)]
    pub response_mode: ResponseMode,
    /// How the client authenticates at the token endpoint.
    #[serde(default)]
    pub client_auth: ClientAuth,
    /// What the address is worth.
    pub email: EmailAssurance,
}

/// Why a preset file is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PresetError {
    /// Not the preset format.
    #[error("preset {0}: format")]
    Format(String),
    /// A URL, the id or a list is outside the rules.
    #[error("preset {0}: invalid")]
    Invalid(String),
    /// Two presets share an id.
    #[error("preset {0}: duplicate")]
    Duplicate(String),
}

const SHIPPED: [(&str, &str); 6] = [
    ("google", include_str!("../../presets/google.toml")),
    ("apple", include_str!("../../presets/apple.toml")),
    ("microsoft", include_str!("../../presets/microsoft.toml")),
    ("github", include_str!("../../presets/github.toml")),
    ("linkedin", include_str!("../../presets/linkedin.toml")),
    ("facebook", include_str!("../../presets/facebook.toml")),
];

fn name_ok(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_')
}

impl Preset {
    /// Parses and checks one preset file.
    ///
    /// # Errors
    /// [`PresetError`].
    pub fn parse(file: &str, text: &str) -> Result<Self, PresetError> {
        let p: Self = toml::from_str(text).map_err(|_| PresetError::Format(file.into()))?;
        p.check().map_err(|()| PresetError::Invalid(file.into()))?;
        Ok(p)
    }

    fn check(&self) -> Result<(), ()> {
        let urls = [
            Some(&self.authorization_endpoint),
            Some(&self.token_endpoint),
            self.jwks_uri.as_ref(),
            self.userinfo_endpoint.as_ref(),
            self.emails_endpoint.as_ref(),
        ];
        let urls_ok = urls.iter().flatten().all(|u| https(u)) && https(&self.issuer);
        let shape_ok = match self.protocol {
            Protocol::Oidc => {
                self.jwks_uri.is_some()
                    && self.scopes.iter().any(|s| s == "openid")
                    && !self.algorithms.is_empty()
                    && self.algorithms.iter().all(|a| a == "RS256" || a == "ES256")
            }
            Protocol::Oauth2 => self.userinfo_endpoint.is_some(),
        };
        let email_ok = match &self.email {
            EmailAssurance::VerifiedPrimary => self.emails_endpoint.is_some(),
            EmailAssurance::AuthoritativeDomains { domains, .. } => !domains.is_empty(),
            _ => true,
        };
        let auth_ok = self.client_auth == ClientAuth::SecretPost || self.protocol == Protocol::Oidc;
        let ok = name_ok(&self.id)
            && auth_ok
            && !self.display_name.is_empty()
            && self.display_name.chars().count() <= 64
            && !self.subject.is_empty()
            && self.subject.len() <= 4
            && !self.scopes.is_empty()
            && name_ok(&self.logo)
            && urls_ok
            && shape_ok
            && email_ok;
        if ok { Ok(()) } else { Err(()) }
    }

    /// The issuer this token's claims form; `None` when a placeholder's claim is missing.
    #[must_use]
    pub fn issuer_for(&self, claims: &serde_json::Value) -> Option<String> {
        let mut out = String::with_capacity(self.issuer.len());
        let mut rest = self.issuer.as_str();
        while let Some(open) = rest.find('{') {
            let (head, tail) = rest.split_at(open);
            out.push_str(head);
            let close = tail.find('}')?;
            let name = tail.get(1..close)?;
            let v = claims.get(name)?.as_str()?;
            if v.is_empty() || !v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
                return None;
            }
            out.push_str(v);
            rest = tail.get(close.checked_add(1)?..)?;
        }
        out.push_str(rest);
        Some(out)
    }
}

/// The presets this build ships, by id.
#[derive(Clone, Debug)]
pub struct Presets(BTreeMap<String, Preset>);

impl Presets {
    /// The day-one presets.
    ///
    /// # Errors
    /// [`PresetError`] when a shipped file is outside the format.
    pub fn shipped() -> Result<Self, PresetError> {
        Self::from_files(SHIPPED.iter().copied())
    }

    /// Presets from `(file, text)` pairs.
    ///
    /// # Errors
    /// [`PresetError`].
    pub fn from_files<'a>(
        files: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, PresetError> {
        let mut m = BTreeMap::new();
        for (file, text) in files {
            let p = Preset::parse(file, text)?;
            if m.contains_key(&p.id) {
                return Err(PresetError::Duplicate(p.id));
            }
            m.insert(p.id.clone(), p);
        }
        Ok(Self(m))
    }

    /// The preset `id`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Preset> {
        self.0.get(id)
    }

    /// Every preset, by id.
    pub fn iter(&self) -> impl Iterator<Item = &Preset> {
        self.0.values()
    }

    /// These presets with the operator's `others` (the generic connector, IDP-31 (1)); an id
    /// already taken is refused.
    ///
    /// # Errors
    /// [`PresetError::Duplicate`].
    pub fn with(mut self, others: Self) -> Result<Self, PresetError> {
        for (id, p) in others.0 {
            if self.0.contains_key(&id) {
                return Err(PresetError::Duplicate(id));
            }
            self.0.insert(id, p);
        }
        Ok(self)
    }

    /// Makes `self` the process's preset set, which `idp.social.*` checks names against; set
    /// once at start-up.
    ///
    /// # Errors
    /// The presets back, when a set is already installed.
    pub fn install(self) -> Result<(), Self> {
        INSTALLED.set(self)
    }

    /// The installed preset set, or the shipped presets when none is installed.
    #[must_use]
    pub fn installed() -> Option<&'static Self> {
        INSTALLED
            .get()
            .or_else(|| SHIPPED_SET.get_or_init(|| Self::shipped().ok()).as_ref())
    }
}

static INSTALLED: std::sync::OnceLock<Presets> = std::sync::OnceLock::new();
static SHIPPED_SET: std::sync::OnceLock<Option<Presets>> = std::sync::OnceLock::new();

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // IDP-31, F23
    #[test]
    fn the_six_day_one_presets_are_data_with_their_email_assurance() {
        let p = Presets::shipped().unwrap();
        let ids: Vec<_> = p.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "apple",
                "facebook",
                "github",
                "google",
                "linkedin",
                "microsoft"
            ]
        );
        assert_eq!(
            p.get("google").unwrap().email,
            EmailAssurance::AuthoritativeDomains {
                domains: vec!["gmail.com".into(), "googlemail.com".into()],
                hosted_domain_claim: Some("hd".into()),
            }
        );
        assert_eq!(p.get("apple").unwrap().email, EmailAssurance::VerifiedClaim);
        assert_eq!(
            p.get("microsoft").unwrap().email,
            EmailAssurance::Claim {
                claim: "xms_edov".into()
            }
        );
        assert_eq!(
            p.get("github").unwrap().email,
            EmailAssurance::VerifiedPrimary
        );
        assert_eq!(p.get("facebook").unwrap().email, EmailAssurance::None);
        assert_eq!(p.get("microsoft").unwrap().subject, ["tid", "oid"]);
        assert_eq!(
            p.get("apple").unwrap().response_mode,
            ResponseMode::FormPost
        );
    }

    // IDP-31
    #[test]
    fn a_preset_outside_the_rules_is_refused() {
        let bad = r#"
id = "x"
display_name = "X"
protocol = "oidc"
issuer = "http://x.example"
authorization_endpoint = "https://x.example/a"
token_endpoint = "https://x.example/t"
jwks_uri = "https://x.example/k"
scopes = ["openid"]
logo = "x"
subject = ["sub"]
algorithms = ["RS256"]
[email]
kind = "none"
"#;
        assert!(matches!(
            Preset::parse("x", bad),
            Err(PresetError::Invalid(_))
        ));
        let alg = bad
            .replace("http://x", "https://x")
            .replace("RS256", "HS256");
        assert!(matches!(
            Preset::parse("x", &alg),
            Err(PresetError::Invalid(_))
        ));
        assert!(Preset::parse("x", &bad.replace("http://x", "https://x")).is_ok());
    }

    // TN-66
    #[test]
    fn the_entra_issuer_is_formed_from_the_tenant_claim() {
        let p = Presets::shipped().unwrap();
        let ms = p.get("microsoft").unwrap();
        let claims = serde_json::json!({ "tid": "9188040d-6c67-4c5b-b112-36a304b66dad" });
        assert_eq!(
            ms.issuer_for(&claims).unwrap(),
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
        );
        assert!(ms.issuer_for(&serde_json::json!({})).is_none());
        assert!(
            ms.issuer_for(&serde_json::json!({ "tid": "a/../b" }))
                .is_none()
        );
    }
}
