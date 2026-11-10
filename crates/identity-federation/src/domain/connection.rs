//! Enterprise upstream connections, sans I/O (OP-155 m.3 (h); IDP-27, IDP-34, TN-66, TN-95,
//! TN-108).
//!
//! - Each connection carries its own profile: protocol, subject key (`sub` or `[tid, oid]`),
//!   client authentication (`private_key_jwt` unless a secret method is chosen) and an optional
//!   preset (e-Devlet, mobile signature).
//! - Its ID token algorithms come from the upstream's discovery document, cut down to what the
//!   back end verifies: never `none`, never an HMAC algorithm.
//! - The authorization response's `iss` (RFC 9207) must be the registered issuer, and must be
//!   present when the upstream says it sends it.
//! - Upstream `acr`/`amr`/`AuthnContextClassRef` reach assurance only through the connection's
//!   assurance map; without a map, or without a match, the lowest class applies.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::digest::context_digest;

use super::preset::{ClientAuth, EmailAssurance, Preset, Protocol, ResponseMode};
use super::token::MAX_ANSWER;
use crate::domain::https;

/// Digest context of a raw upstream assertion, the evidence its Claims name.
pub const EVIDENCE_CONTEXT: &str = "access/upstream-assertion/v1";

/// Digest context of an upstream issuer's Party id, the one its Acceptance names.
pub const ISSUER_CONTEXT: &str = "access/upstream-issuer/v1";

/// The ID token algorithms the back end verifies.
pub const VERIFIED_ALGS: [&str; 2] = ["ES256", "RS256"];

/// The protocol of a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionProtocol {
    /// OpenID Connect.
    #[default]
    Oidc,
    /// SAML 2.0, Access in the SP role.
    Saml,
}

/// What keys a person at the upstream (TN-66).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKey {
    /// `sub`, with the registered issuer.
    #[default]
    Sub,
    /// Entra's `[tid, oid]`.
    TidOid,
}

/// How Access authenticates to the upstream's token endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethod {
    /// RFC 7523 with a key of the realm (the default).
    #[default]
    PrivateKeyJwt,
    /// `client_secret_post`, opted into per connection.
    ClientSecretPost,
    /// `client_secret_basic`, opted into per connection.
    ClientSecretBasic,
}

impl ClientAuthMethod {
    /// The discovery name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::ClientSecretPost => "client_secret_post",
            Self::ClientSecretBasic => "client_secret_basic",
        }
    }

    /// Whether it needs a stored secret.
    #[must_use]
    pub const fn secret(self) -> bool {
        !matches!(self, Self::PrivateKeyJwt)
    }
}

/// A SAML IdP as the connection names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlIdp {
    /// The IdP's entity ID.
    pub entity_id: String,
    /// Its SSO service, HTTP-Redirect binding.
    pub sso_url: String,
    /// Its signing certificates, base64 DER; at most four.
    pub certificates: Vec<String>,
}

/// A connection's own profile, kept as canonical JSON with its registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// The protocol.
    #[serde(default)]
    pub protocol: ConnectionProtocol,
    /// The name on the button ("Sign in with *Provider*").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// The subject key.
    #[serde(default)]
    pub subject_key: SubjectKey,
    /// Client authentication.
    #[serde(default)]
    pub client_auth: ClientAuthMethod,
    /// An upstream preset ([`UpstreamPreset`]), by id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// The organization whose sign-in it is, as its Party id in base64url (TN-98).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// SAML only: whether an unsolicited Response is accepted (off by default).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub allow_unsolicited: bool,
    /// SAML only: the IdP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml: Option<SamlIdp>,
}

/// Why a profile, a discovery document or an answer does not fit the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectionError {
    /// The profile is outside its rules.
    #[error("profile")]
    Profile,
    /// The discovery document is missing or malformed.
    #[error("discovery")]
    Discovery,
    /// The discovery document names another issuer.
    #[error("issuer")]
    Issuer,
    /// No algorithm the upstream signs with is one the back end verifies.
    #[error("algorithms")]
    Algorithms,
    /// The upstream does not take the connection's client authentication.
    #[error("client authentication")]
    ClientAuth,
    /// The authorization response's `iss` is missing or not the registered issuer.
    #[error("iss parameter")]
    IssParameter,
    /// The assurance map is outside its rules.
    #[error("assurance map")]
    Map,
}

fn text_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)
}

impl Profile {
    /// The profile of a registration made before profiles: OIDC, `sub`, and the secret method
    /// it was registered with.
    #[must_use]
    pub fn legacy(has_secret: bool) -> Self {
        Self {
            protocol: ConnectionProtocol::Oidc,
            display_name: None,
            subject_key: SubjectKey::Sub,
            client_auth: if has_secret {
                ClientAuthMethod::ClientSecretPost
            } else {
                ClientAuthMethod::PrivateKeyJwt
            },
            preset: None,
            organization: None,
            allow_unsolicited: false,
            saml: None,
        }
    }

    /// The stored profile, or the legacy one when none is stored.
    ///
    /// # Errors
    /// [`ConnectionError::Profile`].
    pub fn stored(json: Option<&str>, has_secret: bool) -> Result<Self, ConnectionError> {
        match json {
            None => Ok(Self::legacy(has_secret)),
            Some(j) => serde_json::from_str(j).map_err(|_| ConnectionError::Profile),
        }
    }

    /// Checks the profile against the registration's secret reference.
    ///
    /// # Errors
    /// [`ConnectionError::Profile`].
    pub fn check(&self, has_secret: bool) -> Result<(), ConnectionError> {
        let name_ok = self.display_name.as_deref().is_none_or(|n| text_ok(n, 64));
        let preset_ok = self
            .preset
            .as_deref()
            .is_none_or(|p| UpstreamPreset::get(p).is_some());
        let org_ok = self
            .organization
            .as_deref()
            .is_none_or(|o| access_kernel::json::b64url_decode(o).is_ok_and(|v| v.len() == 16));
        let secret_ok = self.client_auth.secret() == has_secret;
        let saml_ok = match (self.protocol, &self.saml) {
            (ConnectionProtocol::Oidc, None) => !self.allow_unsolicited,
            (ConnectionProtocol::Saml, Some(s)) => {
                text_ok(&s.entity_id, 1024)
                    && https(&s.sso_url)
                    && (1..=4).contains(&s.certificates.len())
                    && s.certificates.iter().all(|c| {
                        c.len() <= 16_384
                            && c.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
                    })
                    && self.subject_key == SubjectKey::Sub
            }
            _ => false,
        };
        if name_ok && preset_ok && org_ok && secret_ok && saml_ok {
            Ok(())
        } else {
            Err(ConnectionError::Profile)
        }
    }

    /// The canonical JSON kept with the registration.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The organization's Party id, when the connection is an organization's.
    #[must_use]
    pub fn organization_party(&self) -> Option<[u8; 16]> {
        self.organization
            .as_deref()
            .and_then(|o| access_kernel::json::b64url_decode(o).ok())
            .and_then(|v| <[u8; 16]>::try_from(v).ok())
    }

    /// The claims that, in order, are the upstream's subject: the preset's, else the subject
    /// key's.
    #[must_use]
    pub fn subject_claims(&self) -> Vec<String> {
        if let Some(p) = self.preset.as_deref().and_then(UpstreamPreset::get) {
            return p.subject.clone();
        }
        match self.subject_key {
            SubjectKey::Sub => vec![String::from("sub")],
            SubjectKey::TidOid => vec![String::from("tid"), String::from("oid")],
        }
    }
}

/// An upstream preset as data (OP-155 m.3 (h)): no provider-specific client; the connection's
/// own discovery and keys do the rest.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamPreset {
    /// The id the profile names.
    pub id: String,
    /// The name on the button.
    pub display_name: String,
    /// The bundled logo's key.
    pub logo: String,
    /// The scopes asked for.
    pub scopes: Vec<String>,
    /// The claims or attributes that, in order, are the subject.
    pub subject: Vec<String>,
    /// The claim or attribute carrying a national identity number (TCKN): sealed with the raw
    /// assertion, and only its keyed digest enters a Claim.
    pub national_id: Option<String>,
}

const UPSTREAM_PRESETS: [&str; 2] = [
    include_str!("../../presets/upstream/edevlet.toml"),
    include_str!("../../presets/upstream/mobile-signature.toml"),
];

static PRESETS: std::sync::OnceLock<Vec<UpstreamPreset>> = std::sync::OnceLock::new();

impl UpstreamPreset {
    /// Every shipped upstream preset.
    #[must_use]
    pub fn all() -> &'static [UpstreamPreset] {
        PRESETS.get_or_init(|| {
            UPSTREAM_PRESETS
                .iter()
                .filter_map(|t| toml::from_str::<Self>(t).ok())
                .filter(Self::ok)
                .collect()
        })
    }

    /// The shipped preset `id`.
    #[must_use]
    pub fn get(id: &str) -> Option<&'static Self> {
        Self::all().iter().find(|p| p.id == id)
    }

    fn ok(&self) -> bool {
        let names = |v: &[String]| {
            !v.is_empty() && v.len() <= 4 && v.iter().all(|s| text_ok(s, 255) && !s.contains(' '))
        };
        text_ok(&self.id, 64)
            && text_ok(&self.display_name, 64)
            && text_ok(&self.logo, 64)
            && names(&self.subject)
            && self
                .scopes
                .iter()
                .all(|s| text_ok(s, 64) && !s.contains(' '))
            && self.national_id.as_deref().is_none_or(|n| text_ok(n, 255))
    }
}

/// What the upstream's discovery document says, cut down to the connection's rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovered {
    /// The issuer, equal to the registered one.
    pub issuer: String,
    /// Authorization endpoint, `https`.
    pub authorization_endpoint: String,
    /// Token endpoint, `https`.
    pub token_endpoint: String,
    /// The ID token algorithms accepted: the upstream's, among [`VERIFIED_ALGS`].
    pub algorithms: Vec<String>,
    /// Whether the upstream sends `iss` with its authorization response (RFC 9207).
    pub iss_parameter: bool,
    /// The `ui_locales` it supports; empty when it says none (TN-108).
    pub ui_locales: Vec<String>,
    /// The algorithm the client assertion is signed with, for `private_key_jwt`.
    pub assertion_alg: Option<&'static str>,
}

fn strings(doc: &Value, name: &str) -> Option<Vec<String>> {
    doc.get(name).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .take(64)
            .map(String::from)
            .collect()
    })
}

/// Reads the discovery document `body` of the connection registered with `issuer` for client
/// authentication `auth`.
///
/// # Errors
/// [`ConnectionError`].
pub fn discovered(
    body: &[u8],
    issuer: &str,
    auth: ClientAuthMethod,
) -> Result<Discovered, ConnectionError> {
    if body.len() > MAX_ANSWER {
        return Err(ConnectionError::Discovery);
    }
    let doc: Value = serde_json::from_slice(body).map_err(|_| ConnectionError::Discovery)?;
    let text = |n: &str| doc.get(n).and_then(Value::as_str).map(String::from);
    if text("issuer").as_deref() != Some(issuer) {
        return Err(ConnectionError::Issuer);
    }
    let (Some(authorization_endpoint), Some(token_endpoint)) =
        (text("authorization_endpoint"), text("token_endpoint"))
    else {
        return Err(ConnectionError::Discovery);
    };
    if !https(&authorization_endpoint) || !https(&token_endpoint) {
        return Err(ConnectionError::Discovery);
    }
    // MD-3, OIDC Discovery §3: RS256 when the upstream names none
    let offered = strings(&doc, "id_token_signing_alg_values_supported")
        .unwrap_or_else(|| vec!["RS256".into()]);
    let algorithms: Vec<String> = offered
        .iter()
        .filter(|a| VERIFIED_ALGS.contains(&a.as_str()))
        .cloned()
        .collect();
    if algorithms.is_empty() {
        return Err(ConnectionError::Algorithms);
    }
    let methods = strings(&doc, "token_endpoint_auth_methods_supported")
        .unwrap_or_else(|| vec!["client_secret_basic".into()]);
    if !methods.iter().any(|m| m == auth.name()) {
        return Err(ConnectionError::ClientAuth);
    }
    let assertion_alg = if auth == ClientAuthMethod::PrivateKeyJwt {
        let algs = strings(&doc, "token_endpoint_auth_signing_alg_values_supported");
        match algs {
            None => Some("ES256"),
            Some(a) if a.iter().any(|x| x == "ES256") => Some("ES256"),
            Some(a) if a.iter().any(|x| x == "RS256") => Some("RS256"),
            Some(_) => return Err(ConnectionError::ClientAuth),
        }
    } else {
        None
    };
    Ok(Discovered {
        issuer: String::from(issuer),
        authorization_endpoint,
        token_endpoint,
        algorithms,
        iss_parameter: doc
            .get("authorization_response_iss_parameter_supported")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ui_locales: strings(&doc, "ui_locales_supported").unwrap_or_default(),
        assertion_alg,
    })
}

impl Discovered {
    /// The relying party's view of the connection `name` with `profile`, its ID tokens checked
    /// against `jwks_uri`. Its addresses carry no assurance.
    #[must_use]
    pub fn preset(&self, name: &str, profile: &Profile, jwks_uri: &str) -> Preset {
        let up = profile.preset.as_deref().and_then(UpstreamPreset::get);
        let scopes = match up {
            Some(p) if !p.scopes.is_empty() => {
                let mut s = vec![String::from("openid")];
                s.extend(p.scopes.iter().filter(|x| *x != "openid").cloned());
                s
            }
            _ => vec!["openid".into(), "email".into(), "profile".into()],
        };
        Preset {
            id: name.into(),
            display_name: profile
                .display_name
                .clone()
                .or_else(|| up.map(|p| p.display_name.clone()))
                .unwrap_or_else(|| name.into()),
            protocol: Protocol::Oidc,
            issuer: self.issuer.clone(),
            authorization_endpoint: self.authorization_endpoint.clone(),
            token_endpoint: self.token_endpoint.clone(),
            jwks_uri: Some(jwks_uri.into()),
            userinfo_endpoint: None,
            emails_endpoint: None,
            scopes,
            logo: up.map_or_else(|| String::from("oidc"), |p| p.logo.clone()),
            subject: profile.subject_claims(),
            algorithms: self.algorithms.clone(),
            response_mode: ResponseMode::Query,
            client_auth: ClientAuth::SecretPost,
            email: EmailAssurance::None,
        }
    }

    /// The `ui_locales` to forward (TN-108): the asked tags the upstream supports, in order;
    /// `None` when it supports none of them or advertises none.
    #[must_use]
    pub fn ui_locales(&self, asked: Option<&str>) -> Option<String> {
        let asked = asked?;
        let kept: Vec<&str> = asked
            .split(' ')
            .filter(|t| !t.is_empty() && t.len() <= 35)
            .filter(|t| self.ui_locales.iter().any(|s| s.eq_ignore_ascii_case(t)))
            .take(8)
            .collect();
        (!kept.is_empty()).then(|| kept.join(" "))
    }

    /// RFC 9207: the response's `iss` must be the issuer, and present when the upstream sends
    /// it.
    ///
    /// # Errors
    /// [`ConnectionError::IssParameter`].
    pub fn check_iss(&self, iss: Option<&str>) -> Result<(), ConnectionError> {
        match iss {
            Some(i) if i == self.issuer => Ok(()),
            None if !self.iss_parameter => Ok(()),
            _ => Err(ConnectionError::IssParameter),
        }
    }
}

/// The claims of an RFC 7523 client assertion for `client_id` at `audience`, `jti` from the
/// caller's RNG, valid for one minute from `now_s`.
#[must_use]
pub fn assertion_claims(client_id: &str, audience: &str, jti: &str, now_s: u64) -> Vec<u8> {
    serde_json::json!({
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": jti,
        "iat": now_s,
        "exp": now_s.saturating_add(60),
    })
    .to_string()
    .into_bytes()
}

/// The token request's form body for `private_key_jwt`.
#[must_use]
pub fn assertion_form(
    client_id: &str,
    assertion: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> String {
    form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion),
        ("code_verifier", verifier),
    ])
}

/// The token request's form body and `Authorization` value for `client_secret_basic`
/// (RFC 6749 §2.3.1).
#[must_use]
pub fn basic_form(
    client_id: &str,
    secret: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> (String, String) {
    let mut user = String::new();
    access_identity_oauth::domain::issuer::form_encode(client_id, &mut user);
    let mut pass = String::new();
    access_identity_oauth::domain::issuer::form_encode(secret, &mut pass);
    let header = format!(
        "Basic {}",
        access_crypto::webhook::b64_encode(format!("{user}:{pass}").as_bytes())
    );
    let body = form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ]);
    (body, header)
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (n, v) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(n);
        out.push('=');
        access_identity_oauth::domain::issuer::form_encode(v, &mut out);
    }
    out
}

/// What an upstream said about the authentication itself (§10.1.2): its declarations, kept
/// apart from assurance until the assurance map reads them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declared {
    /// `acr`, or SAML's `AuthnContextClassRef`.
    pub acr: Option<String>,
    /// `amr`.
    pub amr: Vec<String>,
    /// `auth_time` or `AuthnInstant`, Unix milliseconds.
    pub auth_time_ms: Option<u64>,
}

/// The declarations of ID token `claims`; values outside their bounds are left out.
#[must_use]
pub fn declared(claims: &Value) -> Declared {
    Declared {
        acr: claims
            .get("acr")
            .and_then(Value::as_str)
            .filter(|a| text_ok(a, 255))
            .map(String::from),
        amr: claims
            .get("amr")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .filter(|v| text_ok(v, 64))
                    .take(16)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
        auth_time_ms: claims
            .get("auth_time")
            .and_then(Value::as_u64)
            .and_then(|s| s.checked_mul(1000)),
    }
}

/// The evidence digest of a raw upstream assertion as received.
#[must_use]
pub fn evidence(raw: &[u8]) -> [u8; 32] {
    context_digest(EVIDENCE_CONTEXT, raw).0
}

/// The Party id of upstream issuer `issuer`: the id the governing domain's actor-binding
/// Acceptance of the connection names.
#[must_use]
pub fn issuer_id(issuer: &str) -> [u8; 16] {
    let bytes = dcbor::encode(&dcbor::Value::text(issuer), Limits::CEILING).unwrap_or_default();
    let d = context_digest(ISSUER_CONTEXT, &bytes).0;
    let mut out = [0_u8; 16];
    out.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    out
}

/// What a value is matched against in an assurance map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchOn {
    /// `acr` or `AuthnContextClassRef`.
    Acr,
    /// One `amr` value.
    Amr,
}

/// One row of an assurance map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MapEntry {
    /// What the value is matched against.
    #[serde(rename = "match")]
    pub on: MatchOn,
    /// The declared value.
    pub value: String,
    /// The AAL it stands for, 1 to 3.
    pub aal: u8,
    /// The eIDAS level it stands for, 1 to 3, when the upstream is a notified eID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loa_eidas: Option<u8>,
}

/// A connection's assurance map (`idp.upstream.assurance_map`, reserved, CT3).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssuranceMap {
    /// Its rows.
    pub entries: Vec<MapEntry>,
}

/// The assurance an upstream authentication maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mapped {
    /// AAL, 1 to 3.
    pub aal: u8,
    /// eIDAS level, 1 to 3.
    pub loa_eidas: Option<u8>,
}

/// The lowest class: AAL1, no eIDAS level.
pub const LOWEST: Mapped = Mapped {
    aal: 1,
    loa_eidas: None,
};

impl AssuranceMap {
    /// Parses and checks a stored or requested map.
    ///
    /// # Errors
    /// [`ConnectionError::Map`].
    pub fn parse(json: &str) -> Result<Self, ConnectionError> {
        let m: Self = serde_json::from_str(json).map_err(|_| ConnectionError::Map)?;
        m.check()?;
        Ok(m)
    }

    /// At most 64 rows, each value at most once per kind, levels 1 to 3.
    ///
    /// # Errors
    /// [`ConnectionError::Map`].
    pub fn check(&self) -> Result<(), ConnectionError> {
        let mut seen = std::collections::BTreeSet::new();
        let ok = self.entries.len() <= 64
            && self.entries.iter().all(|e| {
                text_ok(&e.value, 255)
                    && (1..=3).contains(&e.aal)
                    && e.loa_eidas.is_none_or(|l| (1..=3).contains(&l))
                    && seen.insert((e.on, e.value.clone()))
            });
        if ok {
            Ok(())
        } else {
            Err(ConnectionError::Map)
        }
    }

    /// The canonical JSON kept.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// IDP-27, §10.1.2 rule 2: an `acr` row decides; else the highest `amr` row that matches;
    /// else the lowest class.
    #[must_use]
    pub fn apply(&self, d: &Declared) -> Mapped {
        let of = |e: &MapEntry| Mapped {
            aal: e.aal,
            loa_eidas: e.loa_eidas,
        };
        if let Some(acr) = &d.acr
            && let Some(e) = self
                .entries
                .iter()
                .find(|e| e.on == MatchOn::Acr && &e.value == acr)
        {
            return of(e);
        }
        self.entries
            .iter()
            .filter(|e| e.on == MatchOn::Amr && d.amr.contains(&e.value))
            .map(of)
            .max_by_key(|m| (m.aal, m.loa_eidas))
            .unwrap_or(LOWEST)
    }
}

/// The assurance of `d` under the connection's stored map, the lowest class without one.
#[must_use]
pub fn mapped(map: Option<&str>, d: &Declared) -> Mapped {
    map.and_then(|m| AssuranceMap::parse(m).ok())
        .map_or(LOWEST, |m| m.apply(d))
}

#[cfg(test)]
mod tests;
