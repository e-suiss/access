//! Each client's high-assurance and legacy profile (OP-155 m.3 (k), IDP-12, IDP-24, MD-3, CR-4,
//! CR-38, TN-27): FAPI 2.0, the legacy token endpoint methods, mutual TLS client authentication,
//! RS256 and the algorithm of its ID tokens, JWE, the SAML 2.0 bearer grant, the legacy bearer
//! exception and front-channel logout. Every loosening is one client's CT2 decision; there is no
//! realm-wide switch (TI-9).

use access_crypto::jwe::KeyAlg;
use access_kernel::verify::dpop::jkt_text;
use access_store::client_profiles::{ClientProfileRow, SealedJwtSecret};

use crate::domain::client::ClientAuth;
use crate::domain::dpop::Jkt;

/// A legacy token endpoint method a client opted in to (`idp.client.auth_method_legacy`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegacyAuth {
    /// `client_secret_post`: the registered secret in the form body (CR-38).
    SecretPost,
    /// `client_secret_jwt`: an HS256 assertion under the secret sealed by the realm KEK
    /// (OP-148 m.16 (l)).
    SecretJwt(SealedJwtSecret),
}

impl LegacyAuth {
    /// The `token_endpoint_auth_method`.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::SecretPost => CLIENT_SECRET_POST,
            Self::SecretJwt(_) => CLIENT_SECRET_JWT,
        }
    }
}

/// `client_secret_post` (RFC 6749 §2.3.1).
pub const CLIENT_SECRET_POST: &str = "client_secret_post";
/// `client_secret_jwt` (OIDC Core §9).
pub const CLIENT_SECRET_JWT: &str = "client_secret_jwt";
/// `tls_client_auth` (RFC 8705 §2.1).
pub const TLS_CLIENT_AUTH: &str = "tls_client_auth";
/// `self_signed_tls_client_auth` (RFC 8705 §2.2).
pub const SELF_SIGNED_TLS_CLIENT_AUTH: &str = "self_signed_tls_client_auth";

/// The one certificate name a PKI mutual TLS client registered (RFC 8705 §2.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsName {
    /// `tls_client_auth_subject_dn`, RFC 4514.
    SubjectDn(String),
    /// `tls_client_auth_san_dns`.
    Dns(String),
    /// `tls_client_auth_san_uri`.
    Uri(String),
    /// `tls_client_auth_san_ip`.
    Ip(String),
    /// `tls_client_auth_san_email`.
    Email(String),
}

impl TlsName {
    fn of(kind: &str, value: String) -> Option<Self> {
        Some(match kind {
            "subject_dn" => Self::SubjectDn(value),
            "san_dns" => Self::Dns(value),
            "san_uri" => Self::Uri(value),
            "san_ip" => Self::Ip(value),
            "san_email" => Self::Email(value),
            _ => return None,
        })
    }

    /// The stored kind and value.
    #[must_use]
    pub fn stored(&self) -> (&'static str, &str) {
        match self {
            Self::SubjectDn(v) => ("subject_dn", v),
            Self::Dns(v) => ("san_dns", v),
            Self::Uri(v) => ("san_uri", v),
            Self::Ip(v) => ("san_ip", v),
            Self::Email(v) => ("san_email", v),
        }
    }
}

/// How a mutual TLS client authenticates (RFC 8705 §2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsAuth {
    /// `tls_client_auth`: a certificate the realm's trusted CAs issued, not revoked, naming
    /// the registered subject.
    Pki(TlsName),
    /// `self_signed_tls_client_auth`: one of the certificates in the registered JWKS `x5c`.
    SelfSigned {
        /// The registered JWKS.
        jwks: String,
    },
}

impl TlsAuth {
    /// The `token_endpoint_auth_method`.
    #[must_use]
    pub const fn method(&self) -> &'static str {
        match self {
            Self::Pki(_) => TLS_CLIENT_AUTH,
            Self::SelfSigned { .. } => SELF_SIGNED_TLS_CLIENT_AUTH,
        }
    }
}

/// `id_token_signed_response_alg` (OIDC Registration §2, MD-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdAlg {
    /// ES256.
    Es256,
    /// Ed25519.
    Ed25519,
    /// RS256 with the realm's `rsa-id` key; identity plane only, after the opt-in (CR-2).
    Rs256,
    /// ML-DSA-44 with the realm's post-quantum key set, while its signing profile holds it
    /// (CR-41, OP-159 m.3 (o)).
    MlDsa44,
    /// ML-DSA-65, likewise.
    MlDsa65,
    /// ML-DSA-87, likewise.
    MlDsa87,
}

impl IdAlg {
    /// The JOSE name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Ed25519 => "Ed25519",
            Self::Rs256 => "RS256",
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// From the JOSE name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Es256,
            Self::Ed25519,
            Self::Rs256,
            Self::MlDsa44,
            Self::MlDsa65,
            Self::MlDsa87,
        ]
        .into_iter()
        .find(|a| a.name() == name)
    }

    /// The ML-DSA parameter set, for a post-quantum algorithm (OP-159 m.3 (o)).
    #[must_use]
    pub const fn ml_dsa(self) -> Option<access_crypto::jose::JwsAlg> {
        match self {
            Self::MlDsa44 => Some(access_crypto::jose::JwsAlg::MlDsa44),
            Self::MlDsa65 => Some(access_crypto::jose::JwsAlg::MlDsa65),
            Self::MlDsa87 => Some(access_crypto::jose::JwsAlg::MlDsa87),
            Self::Es256 | Self::Ed25519 | Self::Rs256 => None,
        }
    }
}

/// What a client asked to have encrypted to it, and with which key (CR-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Encryption {
    /// `ECDH-ES+A256KW`, or `RSA-OAEP-256` by opt-in; never `RSA1_5`.
    pub alg: KeyAlg,
    /// The client's encryption JWKS.
    pub jwks: String,
    /// ID tokens.
    pub id_token: bool,
    /// Userinfo answers.
    pub userinfo: bool,
    /// JARM responses.
    pub jarm: bool,
}

/// A client's profile; the default is the realm's baseline: DPoP, no legacy method, the
/// realm's algorithm, nothing encrypted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one decision about the client"
)]
pub struct ClientProfile {
    /// Under FAPI 2.0 Security Profile and Message Signing.
    pub fapi2: bool,
    /// A legacy token endpoint method.
    pub legacy: Option<LegacyAuth>,
    /// Mutual TLS client authentication.
    pub tls: Option<TlsAuth>,
    /// RS256 identity assertions opted in.
    pub rs256: bool,
    /// The algorithm of its ID tokens; the realm's when absent.
    pub id_alg: Option<IdAlg>,
    /// JWE towards the client.
    pub encryption: Option<Encryption>,
    /// Userinfo as a JWT signed by the realm key.
    pub userinfo_signed: bool,
    /// The accepted SAML upstream the SAML 2.0 bearer grant takes assertions from.
    pub saml_bearer: Option<String>,
    /// The legacy bearer exception.
    pub legacy_bearer: bool,
    /// The front-channel logout URI.
    pub frontchannel: Option<String>,
}

impl ClientProfile {
    /// The profile of a stored row; `None` when the row does not fit the model (fail closed).
    #[must_use]
    pub fn from_row(r: ClientProfileRow) -> Option<Self> {
        let legacy = match (r.legacy_auth.as_deref(), r.jwt_secret) {
            (None, None) => None,
            (Some(CLIENT_SECRET_POST), None) => Some(LegacyAuth::SecretPost),
            (Some(CLIENT_SECRET_JWT), Some(s)) => Some(LegacyAuth::SecretJwt(s)),
            _ => return None,
        };
        let tls = match (r.tls_auth.as_deref(), r.tls_name, r.tls_jwks) {
            (None, None, None) => None,
            (Some(TLS_CLIENT_AUTH), Some((k, v)), None) => Some(TlsAuth::Pki(TlsName::of(&k, v)?)),
            (Some(SELF_SIGNED_TLS_CLIENT_AUTH), None, Some(jwks)) => {
                Some(TlsAuth::SelfSigned { jwks })
            }
            _ => return None,
        };
        let id_alg = match r.id_token_alg.as_deref() {
            None => None,
            Some(a) => Some(IdAlg::from_name(a)?),
        };
        let encryption = match (r.enc_alg.as_deref(), r.enc_jwks) {
            (None, None) => None,
            (Some(a), Some(jwks)) => Some(Encryption {
                alg: KeyAlg::from_name(a)?,
                jwks,
                id_token: r.enc_id_token,
                userinfo: r.enc_userinfo,
                jarm: r.enc_jarm,
            }),
            _ => return None,
        };
        let p = Self {
            fapi2: r.fapi2,
            legacy,
            tls,
            rs256: r.rs256,
            id_alg,
            encryption,
            userinfo_signed: r.userinfo_signed,
            saml_bearer: r.saml_bearer_upstream,
            legacy_bearer: r.legacy_bearer,
            frontchannel: r.frontchannel_logout_uri,
        };
        p.consistent().then_some(p)
    }

    /// The stored form of the profile; the caller seals the `client_secret_jwt` secret.
    #[must_use]
    pub fn to_row(&self) -> ClientProfileRow {
        let (legacy_auth, jwt_secret) = match &self.legacy {
            None => (None, None),
            Some(LegacyAuth::SecretPost) => (Some(String::from(CLIENT_SECRET_POST)), None),
            Some(LegacyAuth::SecretJwt(s)) => {
                (Some(String::from(CLIENT_SECRET_JWT)), Some(s.clone()))
            }
        };
        let (tls_auth, tls_name, tls_jwks) = match &self.tls {
            None => (None, None, None),
            Some(TlsAuth::Pki(n)) => {
                let (k, v) = n.stored();
                (
                    Some(String::from(TLS_CLIENT_AUTH)),
                    Some((String::from(k), String::from(v))),
                    None,
                )
            }
            Some(TlsAuth::SelfSigned { jwks }) => (
                Some(String::from(SELF_SIGNED_TLS_CLIENT_AUTH)),
                None,
                Some(jwks.clone()),
            ),
        };
        let e = self.encryption.as_ref();
        ClientProfileRow {
            fapi2: self.fapi2,
            legacy_auth,
            jwt_secret,
            tls_auth,
            tls_name,
            tls_jwks,
            rs256: self.rs256,
            id_token_alg: self.id_alg.map(|a| String::from(a.name())),
            enc_alg: e.map(|e| String::from(e.alg.name())),
            enc_jwks: e.map(|e| e.jwks.clone()),
            enc_id_token: e.is_some_and(|e| e.id_token),
            enc_userinfo: e.is_some_and(|e| e.userinfo),
            enc_jarm: e.is_some_and(|e| e.jarm),
            userinfo_signed: self.userinfo_signed,
            saml_bearer_upstream: self.saml_bearer.clone(),
            legacy_bearer: self.legacy_bearer,
            frontchannel_logout_uri: self.frontchannel.clone(),
        }
    }

    fn consistent(&self) -> bool {
        (self.id_alg != Some(IdAlg::Rs256) || self.rs256)
            && (self.legacy.is_none() || self.tls.is_none())
            && (!self.fapi2 || (self.legacy.is_none() && !self.rs256 && !self.legacy_bearer))
    }

    /// The `token_endpoint_auth_method` the profile puts in place of the registered one.
    #[must_use]
    pub fn method(&self) -> Option<&'static str> {
        self.tls
            .as_ref()
            .map(TlsAuth::method)
            .or_else(|| self.legacy.as_ref().map(LegacyAuth::method))
    }
}

/// Why a client may not hold a profile (OP-155 m.3 (k), §10.4.3, IDP-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileRefusal {
    /// FAPI 2.0 takes confidential clients only.
    #[error("fapi2 needs a confidential client")]
    FapiPublic,
    /// FAPI 2.0 takes `private_key_jwt` or mutual TLS only: no `client_secret_*`.
    #[error("fapi2 needs private_key_jwt or mutual TLS")]
    FapiMethod,
    /// FAPI 2.0 never signs or verifies with RSA (no RS256, no PS256).
    #[error("fapi2 forbids RSA signatures")]
    FapiRsa,
    /// FAPI 2.0 takes no bearer token.
    #[error("fapi2 forbids bearer tokens")]
    FapiBearer,
    /// A browser, mobile or single-page app binds its tokens with DPoP, never mutual TLS
    /// (§10.4.3).
    #[error("public clients use DPoP")]
    PublicMtls,
    /// A legacy secret method stands on a registered `client_secret_basic` secret (CR-38).
    #[error("legacy methods need a registered secret")]
    LegacyWithoutSecret,
    /// The legacy bearer exception is for confidential clients only.
    #[error("legacy bearer needs a confidential client")]
    PublicBearer,
    /// RS256 ID tokens need the RS256 opt-in (MD-6, CR-2).
    #[error("RS256 needs the opt-in")]
    Rs256WithoutOptIn,
    /// Two token endpoint methods at once.
    #[error("one token endpoint method")]
    TwoMethods,
}

impl ProfileRefusal {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FapiPublic => "fapi2-public-client",
            Self::FapiMethod => "fapi2-client-method",
            Self::FapiRsa => "fapi2-rsa",
            Self::FapiBearer => "fapi2-bearer",
            Self::PublicMtls => "public-client-mtls",
            Self::LegacyWithoutSecret => "legacy-method-without-secret",
            Self::PublicBearer => "public-client-bearer",
            Self::Rs256WithoutOptIn => "rs256-without-opt-in",
            Self::TwoMethods => "two-token-endpoint-methods",
        }
    }
}

/// IDP-12, OP-155 m.3 (k), §10.4.3, Ek B 4854: whether a client registered with `auth` may hold
/// profile `p`. FAPI 2.0 is confidential, `private_key_jwt` or mutual TLS, sender-constrained
/// and RSA-free; mutual TLS is for confidential (M2M, FAPI) clients, a public client binds with
/// DPoP; a legacy secret method stands on the registered secret.
///
/// # Errors
/// [`ProfileRefusal`].
pub fn check(auth: &ClientAuth, p: &ClientProfile) -> Result<(), ProfileRefusal> {
    let public = matches!(auth, ClientAuth::None);
    if p.legacy.is_some() && p.tls.is_some() {
        return Err(ProfileRefusal::TwoMethods);
    }
    if p.id_alg == Some(IdAlg::Rs256) && !p.rs256 {
        return Err(ProfileRefusal::Rs256WithoutOptIn);
    }
    if public && p.tls.is_some() {
        return Err(ProfileRefusal::PublicMtls);
    }
    if public && p.legacy_bearer {
        return Err(ProfileRefusal::PublicBearer);
    }
    if p.legacy.is_some() && !matches!(auth, ClientAuth::SecretBasic { .. }) {
        return Err(ProfileRefusal::LegacyWithoutSecret);
    }
    if p.fapi2 {
        if public {
            return Err(ProfileRefusal::FapiPublic);
        }
        let key_method = p.tls.is_some()
            || matches!(
                auth,
                ClientAuth::PrivateKeyJwt { .. } | ClientAuth::PrivateKeyJwtKey { .. }
            );
        if p.legacy.is_some() || !key_method {
            return Err(ProfileRefusal::FapiMethod);
        }
        if p.rs256 || p.id_alg == Some(IdAlg::Rs256) {
            return Err(ProfileRefusal::FapiRsa);
        }
        if p.legacy_bearer {
            return Err(ProfileRefusal::FapiBearer);
        }
    }
    Ok(())
}

/// How an issued access token is bound to its holder (TN-27, PI-11, RFC 8705 §3, RFC 9449).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// `cnf.jkt`: the DPoP proof key.
    Dpop(Jkt),
    /// `cnf.x5t#S256`: the client certificate of the mutual TLS connection.
    Mtls([u8; 32]),
    /// No `cnf`: the legacy bearer exception of one client, identity plane tokens only.
    Bearer,
}

impl Binding {
    /// The DPoP key, when bound to one.
    #[must_use]
    pub const fn jkt(&self) -> Option<Jkt> {
        match self {
            Self::Dpop(j) => Some(*j),
            Self::Mtls(_) | Self::Bearer => None,
        }
    }

    /// The `token_type` of the token response (RFC 9449 §5, RFC 8705 §3).
    #[must_use]
    pub const fn token_type(&self) -> &'static str {
        match self {
            Self::Dpop(_) => "DPoP",
            Self::Mtls(_) | Self::Bearer => "Bearer",
        }
    }

    /// The `cnf` claim, when bound.
    #[must_use]
    pub fn confirmation(&self) -> Option<serde_json::Value> {
        match self {
            Self::Dpop(j) => Some(serde_json::json!({ "jkt": jkt_text(&j.0) })),
            Self::Mtls(x5t) => Some(serde_json::json!({ "x5t#S256": jkt_text(x5t) })),
            Self::Bearer => None,
        }
    }
}

/// The front-channel logout URI of one client's session (OIDC Front-Channel Logout §3, IDP-24):
/// its registered URI with `iss` and `sid`.
#[must_use]
pub fn frontchannel_uri(registered: &str, issuer: &str, sid: &str) -> String {
    let mut out = String::from(registered);
    out.push(if registered.contains('?') { '&' } else { '?' });
    out.push_str("iss=");
    crate::domain::issuer::form_encode(issuer, &mut out);
    out.push_str("&sid=");
    crate::domain::issuer::form_encode(sid, &mut out);
    out
}

fn html_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The origin (`scheme://host[:port]`) of an absolute URI, for a page's CSP.
#[must_use]
pub fn origin(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b)))
    .then(|| format!("{scheme}://{host}"))
}

/// The sign-out page that loads each client's front-channel logout URI in a hidden frame, then
/// goes on to `then` (OIDC Front-Channel Logout §4, IDP-24); no script.
#[must_use]
pub fn frontchannel_page(frames: &[String], then: &str) -> String {
    let mut body = String::from(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Signed out</title>",
    );
    body.push_str("<meta http-equiv=\"refresh\" content=\"2;url=");
    body.push_str(&html_attr(then));
    body.push_str("\"></head><body>");
    for f in frames {
        body.push_str("<iframe hidden src=\"");
        body.push_str(&html_attr(f));
        body.push_str("\"></iframe>");
    }
    body.push_str("<a href=\"");
    body.push_str(&html_attr(then));
    body.push_str("\">Continue</a></body></html>");
    body
}

/// The names a client certificate shows, once its chain verified to a CA the realm trusts and
/// its revocation status is known good (RFC 8705 §2.1, MD-8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertificateNames {
    /// The subject DN, RFC 4514.
    pub subject_dn: String,
    /// `dNSName` SANs.
    pub dns: Vec<String>,
    /// `uniformResourceIdentifier` SANs.
    pub uri: Vec<String>,
    /// `iPAddress` SANs, in text form.
    pub ip: Vec<String>,
    /// `rfc822Name` SANs.
    pub email: Vec<String>,
}

fn one(values: &[String], registered: &str, fold: bool) -> bool {
    match values {
        [only] if fold => only.eq_ignore_ascii_case(registered),
        [only] => only == registered,
        _ => false,
    }
}

/// RFC 8705 §2.1.2, TN-32: whether a PKI client certificate names the registered subject. The
/// subject DN compares as its RFC 4514 string; a SAN matches only when the certificate holds
/// exactly one SAN of that type and it is the registered one (the single-SAN rule).
#[must_use]
pub fn names_match(registered: &TlsName, names: &CertificateNames) -> bool {
    match registered {
        TlsName::SubjectDn(dn) => !dn.is_empty() && names.subject_dn == *dn,
        TlsName::Dns(v) => one(&names.dns, v, true),
        TlsName::Uri(v) => one(&names.uri, v, false),
        TlsName::Ip(v) => one(&names.ip, v, false),
        TlsName::Email(v) => one(&names.email, v, false),
    }
}

/// RFC 8705 §2.2: whether the leaf certificate a self-signed client presented is the first
/// `x5c` certificate of one key of its registered JWKS, compared as DER bytes. A document with
/// private key material matches nothing.
#[must_use]
pub fn self_signed_match(jwks: &str, leaf: &[u8]) -> bool {
    use access_kernel::json::{self, Json};
    const PRIVATE: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    let Ok(top) = json::parse(jwks.as_bytes(), crate::domain::jwt::MAX_JWKS) else {
        return false;
    };
    let Some(Json::Array(keys)) = top.get("keys") else {
        return false;
    };
    let mut found = false;
    for k in keys.iter().take(crate::domain::jwt::MAX_KEYS) {
        let Json::Object(members) = k else {
            return false;
        };
        if members.iter().any(|(n, _)| PRIVATE.contains(&n.as_str())) {
            return false;
        }
        let first = match k.get("x5c") {
            Some(Json::Array(chain)) => chain.first().and_then(Json::as_str),
            _ => None,
        };
        if first
            .and_then(crate::domain::client::b64_std_decode)
            .is_some_and(|der| der == leaf)
        {
            found = true;
        }
    }
    found
}

#[cfg(test)]
mod tests;
