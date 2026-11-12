//! The realm's discovery documents: OIDC Discovery and RFC 8414 AS metadata with the Access
//! corrections, and RFC 9728 Protected Resource Metadata. Only what is served is declared
//! (§10.4.6, §11.4.5, CMP-15.1).

use serde_json::{Map, Value, json};

pub use access_identity_signer::domain::{CACHE_CONTROL as JWKS_CACHE_CONTROL, JWKS_CONTENT_TYPE};

use crate::domain::issuer::Issuer;

/// An endpoint of the realm's authorization server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Endpoint {
    /// `GET /authorize`.
    Authorize,
    /// `POST /token`.
    Token,
    /// `POST /par` (RFC 9126).
    Par,
    /// `GET /userinfo`.
    Userinfo,
    /// `POST /revoke` (RFC 7009).
    Revoke,
    /// `POST /introspect` (RFC 7662).
    Introspect,
    /// `GET`/`POST /end-session` (OIDC RP-Initiated Logout 1.0).
    EndSession,
    /// `POST /device_authorization` (RFC 8628), turned on per realm by
    /// `idp.realm.device_code` (OP-154 m.3 (p)).
    DeviceAuthorization,
    /// `POST /bc-authorize`, the CIBA backchannel authentication endpoint, turned on per realm
    /// by `idp.realm.ciba` (OP-155 m.3 (l)).
    BackchannelAuthentication,
}

impl Endpoint {
    /// The endpoint's path under the issuer.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Authorize => "/authorize",
            Self::Token => "/token",
            Self::Par => "/par",
            Self::Userinfo => "/userinfo",
            Self::Revoke => "/revoke",
            Self::Introspect => "/introspect",
            Self::EndSession => "/end-session",
            Self::DeviceAuthorization => "/device_authorization",
            Self::BackchannelAuthentication => "/bc-authorize",
        }
    }
}

/// A protocol feature the metadata declares once it is served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Feature {
    /// `DPoP` (RFC 9449).
    Dpop,
    /// Client ID Metadata Documents.
    ClientIdMetadataDocument,
    /// OIDC Back-Channel Logout 1.0 with `sid`.
    BackchannelLogout,
    /// RFC 9396 `authorization_details` for authority token projections, with client
    /// credentials for them (OP-150 m.2, §10.4.1).
    AuthorizationDetails,
    /// RFC 8693 token exchange (OP-154 m.3 (m)).
    TokenExchange,
    /// RFC 7523 JWT bearer assertions, ID-JAG and cloud workload OIDC (OP-154 m.3 (q)).
    JwtBearer,
    /// JWT-SVID client authentication, `spiffe_jwt` (`draft-ietf-oauth-spiffe-client-auth` §4,
    /// OP-154 m.3 (r)).
    SpiffeClientAuth,
    /// Signed request objects at `/par` (RFC 9101, OP-155 m.3 (k)).
    Jar,
    /// JWT Secured Authorization Response Mode (OP-155 m.3 (k)).
    Jarm,
    /// JWE of ID tokens, userinfo and JARM towards a client (CR-4, OP-155 m.3 (k)).
    Jwe,
    /// Mutual TLS client authentication and certificate-bound tokens (RFC 8705, OP-155 m.3
    /// (k)).
    Mtls,
    /// The SAML 2.0 bearer grant and SAML 2.0 subject tokens, per-client opt-ins that are not
    /// advertised (RFC 7522, OP-155 m.3 (k)).
    SamlBearer,
}

/// Grant type of RFC 8628.
pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Grant type of RFC 8693.
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// Grant type of RFC 7523.
pub const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// Grant type of RFC 7522.
pub const SAML2_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:saml2-bearer";
/// Grant type of OpenID CIBA Core 1.0 (OP-155 m.3 (l)).
pub const CIBA_GRANT: &str = "urn:openid:params:grant-type:ciba";

/// What the realm's authorization server serves; the metadata declares nothing else (§10.4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Served {
    /// Endpoints in service.
    pub endpoints: &'static [Endpoint],
    /// Features in service.
    pub features: &'static [Feature],
}

impl Served {
    /// Whether `e` is served.
    #[must_use]
    pub fn has(&self, e: Endpoint) -> bool {
        self.endpoints.contains(&e)
    }

    /// Whether `f` is served.
    #[must_use]
    pub fn feature(&self, f: Feature) -> bool {
        self.features.contains(&f)
    }
}

/// The single list of what is in service. A slice that brings an endpoint or feature into
/// service adds it here, and the metadata declares it from then on.
pub const SERVED: Served = Served {
    endpoints: &[
        Endpoint::Authorize,
        Endpoint::Token,
        Endpoint::Par,
        Endpoint::Userinfo,
        Endpoint::Revoke,
        Endpoint::Introspect,
        Endpoint::EndSession,
        Endpoint::DeviceAuthorization,
        Endpoint::BackchannelAuthentication,
    ],
    features: &[
        Feature::Dpop,
        Feature::ClientIdMetadataDocument,
        Feature::BackchannelLogout,
        Feature::AuthorizationDetails,
        Feature::TokenExchange,
        Feature::JwtBearer,
        Feature::SpiffeClientAuth,
        Feature::Jar,
        Feature::Jarm,
        Feature::Jwe,
        Feature::Mtls,
        Feature::SamlBearer,
    ],
};

/// The protocol scopes the metadata declares (OP-146 m.5 (c)).
const SCOPES: [&str; 3] = ["openid", "email", "profile"];
const CLAIMS: [&str; 16] = [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "sid",
    "email",
    "email_verified",
    "name",
    "given_name",
    "family_name",
    "locale",
    "zoneinfo",
];

/// The JWKS path under the issuer (§11.4.5).
pub const JWKS_PATH: &str = "/jwks.json";

/// RFC 8414 well-known suffix.
pub const AS_SUFFIX: &str = "oauth-authorization-server";

/// OIDC Discovery well-known suffix.
pub const OIDC_SUFFIX: &str = "openid-configuration";

/// RFC 9728 well-known suffix.
pub const PRM_SUFFIX: &str = "oauth-protected-resource";

/// RFC 9864 fully specified names; `EdDSA` is never declared (MD-3, §11.4.5 (b)).
const SIGNING_ALGS: [&str; 2] = ["ES256", "Ed25519"];

/// Client assertion verification allowlist: ES256 by default, RS256 per client opt-in in the
/// identity plane only (§11.4.5 (a), CR-2).
const CLIENT_ASSERTION_ALGS: [&str; 2] = ["ES256", "RS256"];

/// What a realm's AS metadata says about the realm itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one realm decision the metadata declares"
)]
pub struct RealmFacts {
    /// At least one active client of the realm opted in to the public `sub` (MD-10).
    pub public_sub: bool,
    /// The address of the governing domain's signed Domain Metadata (§9.15.1 k.2, P60).
    pub domain_metadata: Option<String>,
    /// The realm accepts CIMD clients (`idp.client.cimd_policy`); without it the member is
    /// absent, which reads as unsupported (§11.3.3).
    pub cimd: bool,
    /// The realm's DCR profile is open (`idp.client.dcr_policy`); without it no
    /// `registration_endpoint` is declared (§10.1.2, OP-154 m.3 (j)).
    pub dcr: bool,
    /// The realm offers the device authorization grant (`idp.realm.device_code`); without it
    /// neither its endpoint nor its grant type is declared (TN-35, OP-154 m.3 (dd)).
    pub device_code: bool,
    /// The realm lets its clients opt in to front-channel logout (`idp.realm.frontchannel_logout`);
    /// without it nothing about front-channel logout is declared (IDP-24, OP-155 m.3 (k)).
    pub frontchannel: bool,
    /// The realm offers CIBA (`idp.realm.ciba`); without it neither its endpoint, its grant type
    /// nor its delivery modes are declared (OP-155 m.3 (l)).
    pub ciba: bool,
    /// An active client opted in to `client_secret_post`; without one it is not declared.
    pub secret_post: bool,
    /// An active client opted in to `client_secret_jwt`; without one it is not declared.
    pub secret_jwt: bool,
    /// The port of the mTLS listener when the server runs one and the realm publishes its
    /// aliases (`idp.realm.mtls_aliases`); without it `mtls_endpoint_aliases` is absent
    /// (RFC 8705 §5, OP-155 m.3 (m)).
    pub mtls_port: Option<u16>,
    /// The JWS name of the realm's open post-quantum signing profile; without it no ML-DSA
    /// algorithm is declared (CR-41, OP-159 m.3 (o)).
    pub pq_alg: Option<&'static str>,
}

/// The endpoints `mtls_endpoint_aliases` names on the mTLS listener (RFC 8705 §5): those a
/// client authenticates at or presents a certificate-bound token to.
const MTLS_ALIASED: [(Endpoint, &str); 7] = [
    (Endpoint::Token, "token_endpoint"),
    (Endpoint::Par, "pushed_authorization_request_endpoint"),
    (Endpoint::Revoke, "revocation_endpoint"),
    (Endpoint::Introspect, "introspection_endpoint"),
    (Endpoint::Userinfo, "userinfo_endpoint"),
    (
        Endpoint::DeviceAuthorization,
        "device_authorization_endpoint",
    ),
    (
        Endpoint::BackchannelAuthentication,
        "backchannel_authentication_endpoint",
    ),
];

/// `mtls_endpoint_aliases` (RFC 8705 §5, §10.2.5, OP-155 m.3 (m)): the declared endpoints of
/// [`MTLS_ALIASED`] on the mTLS listener's port; nothing when the realm has no port to name.
fn mtls_aliases(m: &mut Map<String, Value>, issuer: &Issuer, facts: &RealmFacts) {
    let Some(port) = facts.mtls_port else {
        return;
    };
    let mut aliases = Map::new();
    for (e, key) in MTLS_ALIASED {
        if m.contains_key(key) {
            aliases.insert(key.into(), issuer.endpoint_on_port(port, e.path()).into());
        }
    }
    if !aliases.is_empty() {
        m.insert("mtls_endpoint_aliases".into(), Value::Object(aliases));
    }
}

/// The RFC 7591 registration endpoint under the issuer.
pub const REGISTER_PATH: &str = "/register";

/// The endpoints a realm turns on itself: `/register` while its DCR profile is open (§10.1.2,
/// OP-154 m.3 (j)).
fn realm_endpoints(m: &mut Map<String, Value>, issuer: &Issuer, facts: &RealmFacts) {
    if facts.dcr {
        m.insert(
            "registration_endpoint".into(),
            issuer.endpoint(REGISTER_PATH).into(),
        );
    }
}

/// The AS metadata member that names the governing domain's Domain Metadata: the AS metadata
/// is the realm's identity document and refers to the authority document, never replaces it
/// (§9.15.1 k.2, MD-5, P60).
pub const DOMAIN_METADATA_MEMBER: &str = "suiss_domain_metadata";

/// The AS metadata of the realm `issuer`, served both as OIDC Discovery and as RFC 8414
/// metadata (§10.4.6, §11.4.5), with nothing known about the realm: pairwise `sub` only and no
/// Domain Metadata reference.
#[must_use]
pub fn authorization_server(issuer: &Issuer, served: &Served) -> String {
    authorization_server_of(issuer, served, &RealmFacts::default())
}

/// The grant types the token endpoint serves (OP-154 m.4).
fn grant_types(served: &Served, facts: &RealmFacts) -> Vec<&'static str> {
    let mut grants = vec!["authorization_code", "refresh_token"];
    if served.feature(Feature::AuthorizationDetails) {
        grants.push("client_credentials");
    }
    if served.has(Endpoint::DeviceAuthorization) && facts.device_code {
        grants.push(DEVICE_CODE_GRANT);
    }
    if served.feature(Feature::TokenExchange) {
        grants.push(TOKEN_EXCHANGE_GRANT);
    }
    if served.feature(Feature::JwtBearer) {
        grants.push(JWT_BEARER_GRANT);
    }
    // OP-155 m.3 (l)
    if served.has(Endpoint::BackchannelAuthentication) && facts.ciba {
        grants.push(CIBA_GRANT);
    }
    grants
}

/// The CIBA members (OP-155 m.3 (l), IDP-14): poll and ping, never push; no user code; signed
/// authentication requests with the client assertion algorithms.
fn ciba_members(m: &mut Map<String, Value>, served: &Served, facts: &RealmFacts) {
    if !(served.has(Endpoint::BackchannelAuthentication) && facts.ciba) {
        return;
    }
    m.insert(
        "backchannel_token_delivery_modes_supported".into(),
        json!(["poll", "ping"]),
    );
    m.insert(
        "backchannel_user_code_parameter_supported".into(),
        Value::Bool(false),
    );
    if served.feature(Feature::Jar) {
        m.insert(
            "backchannel_authentication_request_signing_alg_values_supported".into(),
            json!(CLIENT_ASSERTION_ALGS),
        );
    }
}

/// The agent members of the AS metadata (§11.11.1, §11.21.5): ID-JAG as an identity chaining
/// token type once token exchange is served, and the ID-JAG grant profile once JWT bearer is.
fn agent_members(m: &mut Map<String, Value>, served: &Served) {
    if served.feature(Feature::TokenExchange) {
        m.insert(
            "identity_chaining_requested_token_types_supported".into(),
            json!([crate::domain::exchange::ID_JAG]),
        );
    }
    if served.feature(Feature::JwtBearer) {
        m.insert(
            "authorization_grant_profiles_supported".into(),
            json!([crate::domain::exchange::ID_JAG_PROFILE]),
        );
    }
}

/// The token endpoint's client authentication methods; the SPIFFE ones once served (OP-154
/// m.3 (r)); mutual TLS once served, and a legacy secret method only while a client of the
/// realm opted in to it (OP-155 m.3 (k)).
fn auth_methods(served: &Served, facts: &RealmFacts) -> Vec<&'static str> {
    use crate::domain::fapi::{
        CLIENT_SECRET_JWT, CLIENT_SECRET_POST, SELF_SIGNED_TLS_CLIENT_AUTH, TLS_CLIENT_AUTH,
    };
    let mut methods = vec!["none", "private_key_jwt", "client_secret_basic"];
    if served.feature(Feature::SpiffeClientAuth) {
        methods.push(crate::domain::client::SPIFFE_JWT);
        methods.push(crate::domain::client::SPIFFE_X509);
    }
    if served.feature(Feature::Mtls) {
        methods.push(TLS_CLIENT_AUTH);
        methods.push(SELF_SIGNED_TLS_CLIENT_AUTH);
    }
    if facts.secret_post {
        methods.push(CLIENT_SECRET_POST);
    }
    if facts.secret_jwt {
        methods.push(CLIENT_SECRET_JWT);
    }
    methods
}

/// JWE key management algorithms a client may choose; never `RSA1_5` (CR-4).
const ENCRYPTION_ALGS: [&str; 2] = ["ECDH-ES+A256KW", "RSA-OAEP-256"];

/// The high-assurance members (OP-155 m.3 (k)): JAR, JARM, JWE and mutual TLS, each once
/// served; front-channel logout only when the realm turned it on (IDP-24).
fn assurance_members(m: &mut Map<String, Value>, served: &Served, facts: &RealmFacts) {
    // OP-159 m.3 (o)
    let signing = match facts.pq_alg {
        Some(pq) => json!(["ES256", "Ed25519", "RS256", pq]),
        None => json!(["ES256", "Ed25519", "RS256"]),
    };
    if served.feature(Feature::Jar) {
        m.insert(
            "request_object_signing_alg_values_supported".into(),
            json!(CLIENT_ASSERTION_ALGS),
        );
    }
    if served.feature(Feature::Jarm) {
        m.insert(
            "response_modes_supported".into(),
            json!(["query", "jwt", "query.jwt", "form_post.jwt"]),
        );
        m.insert(
            "authorization_signing_alg_values_supported".into(),
            signing.clone(),
        );
    }
    m.insert(
        "id_token_signing_alg_values_supported".into(),
        signing.clone(),
    );
    m.insert("userinfo_signing_alg_values_supported".into(), signing);
    if served.feature(Feature::Jwe) {
        for prefix in ["id_token", "userinfo", "authorization"] {
            m.insert(
                format!("{prefix}_encryption_alg_values_supported"),
                json!(ENCRYPTION_ALGS),
            );
            m.insert(
                format!("{prefix}_encryption_enc_values_supported"),
                json!([access_crypto::jwe::ENC]),
            );
        }
    }
    if served.feature(Feature::Mtls) {
        m.insert(
            "tls_client_certificate_bound_access_tokens".into(),
            Value::Bool(true),
        );
    }
    if facts.frontchannel {
        m.insert("frontchannel_logout_supported".into(), Value::Bool(true));
        m.insert(
            "frontchannel_logout_session_supported".into(),
            Value::Bool(true),
        );
    }
}

/// The AS metadata of the realm `issuer` with what is known about the realm (`facts`).
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one metadata member after another, each behind its served flag"
)]
pub fn authorization_server_of(issuer: &Issuer, served: &Served, facts: &RealmFacts) -> String {
    let mut m = Map::new();
    m.insert("issuer".into(), issuer.as_str().into());
    m.insert("jwks_uri".into(), issuer.endpoint(JWKS_PATH).into());
    if served.has(Endpoint::Authorize) {
        m.insert(
            "authorization_endpoint".into(),
            issuer.endpoint(Endpoint::Authorize.path()).into(),
        );
        m.insert("response_types_supported".into(), json!(["code"]));
        m.insert("response_modes_supported".into(), json!(["query"]));
        // IDP-7, §11.4.5
        m.insert("code_challenge_methods_supported".into(), json!(["S256"]));
        // RFC 9207, TN-11
        m.insert(
            "authorization_response_iss_parameter_supported".into(),
            Value::Bool(true),
        );
        // MD-10, IDP-24
        let subjects = if facts.public_sub {
            json!(["pairwise", "public"])
        } else {
            json!(["pairwise"])
        };
        m.insert("subject_types_supported".into(), subjects);
        m.insert("scopes_supported".into(), json!(SCOPES));
        m.insert("claims_supported".into(), json!(CLAIMS));
        // §10.4.6, OP-148
        m.insert("claims_parameter_supported".into(), Value::Bool(true));
        m.insert(
            "prompt_values_supported".into(),
            json!(["none", "login", "create"]),
        );
        m.insert(
            "id_token_signing_alg_values_supported".into(),
            json!(SIGNING_ALGS),
        );
    }
    if served.has(Endpoint::Token) {
        m.insert(
            "token_endpoint".into(),
            issuer.endpoint(Endpoint::Token.path()).into(),
        );
        m.insert(
            "grant_types_supported".into(),
            json!(grant_types(served, facts)),
        );
        m.insert(
            "token_endpoint_auth_methods_supported".into(),
            json!(auth_methods(served, facts)),
        );
        m.insert(
            "token_endpoint_auth_signing_alg_values_supported".into(),
            json!(CLIENT_ASSERTION_ALGS),
        );
        agent_members(&mut m, served);
    }
    if served.has(Endpoint::Par) {
        m.insert(
            "pushed_authorization_request_endpoint".into(),
            issuer.endpoint(Endpoint::Par.path()).into(),
        );
        m.insert(
            "require_pushed_authorization_requests".into(),
            Value::Bool(false),
        );
    }
    for (e, key) in [
        (Endpoint::Userinfo, "userinfo_endpoint"),
        (Endpoint::Revoke, "revocation_endpoint"),
        (Endpoint::Introspect, "introspection_endpoint"),
        (Endpoint::EndSession, "end_session_endpoint"),
        (
            Endpoint::DeviceAuthorization,
            "device_authorization_endpoint",
        ),
        (
            Endpoint::BackchannelAuthentication,
            "backchannel_authentication_endpoint",
        ),
    ] {
        // OP-154 m.3 (dd), OP-155 m.3 (l)
        let realm_on = match e {
            Endpoint::DeviceAuthorization => facts.device_code,
            Endpoint::BackchannelAuthentication => facts.ciba,
            _ => true,
        };
        if served.has(e) && realm_on {
            m.insert(key.into(), issuer.endpoint(e.path()).into());
        }
    }
    if served.feature(Feature::Dpop) {
        m.insert(
            "dpop_signing_alg_values_supported".into(),
            json!(SIGNING_ALGS),
        );
    }
    realm_endpoints(&mut m, issuer, facts);
    ciba_members(&mut m, served, facts);
    // §11.3.3, AG-3
    if served.feature(Feature::ClientIdMetadataDocument) && facts.cimd {
        m.insert(
            "client_id_metadata_document_supported".into(),
            Value::Bool(true),
        );
    }
    if served.feature(Feature::BackchannelLogout) {
        m.insert("backchannel_logout_supported".into(), Value::Bool(true));
        m.insert(
            "backchannel_logout_session_supported".into(),
            Value::Bool(true),
        );
    }
    if let Some(u) = &facts.domain_metadata {
        m.insert(DOMAIN_METADATA_MEMBER.into(), u.as_str().into());
    }
    mtls_aliases(&mut m, issuer, facts);
    if served.has(Endpoint::Authorize) {
        assurance_members(&mut m, served, facts);
    }
    Value::Object(m).to_string()
}

/// The RFC 9728 Protected Resource Metadata of the realm's own resource (its `userinfo`),
/// whose authorization server is the realm (§9.4 A).
#[must_use]
pub fn protected_resource(issuer: &Issuer, served: &Served) -> String {
    let mut m = Map::new();
    m.insert("resource".into(), issuer.as_str().into());
    m.insert("authorization_servers".into(), json!([issuer.as_str()]));
    m.insert("jwks_uri".into(), issuer.endpoint(JWKS_PATH).into());
    m.insert("bearer_methods_supported".into(), json!(["header"]));
    if served.feature(Feature::Dpop) {
        m.insert(
            "dpop_signing_alg_values_supported".into(),
            json!(SIGNING_ALGS),
        );
    }
    Value::Object(m).to_string()
}

/// A realm document the HTTP surface serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Document {
    /// `/.well-known/openid-configuration`.
    OpenIdConfiguration,
    /// `/.well-known/oauth-authorization-server`.
    AuthorizationServer,
    /// `/.well-known/oauth-protected-resource`.
    ProtectedResource,
    /// `/jwks.json`.
    Jwks,
    /// `/.well-known/suiss-configuration` (OP-149 m.3).
    SuissConfiguration,
}

/// Every request path at which `issuer` serves `doc`. A path issuer serves OIDC Discovery at
/// both the inserted and the appended well-known path (TN-10, §11.4.5).
#[must_use]
pub fn paths(issuer: &Issuer, doc: Document) -> Vec<String> {
    match doc {
        Document::OpenIdConfiguration => {
            let appended = issuer.well_known_appended(OIDC_SUFFIX);
            let inserted = issuer.well_known_inserted(OIDC_SUFFIX);
            if appended == inserted {
                vec![appended]
            } else {
                vec![inserted, appended]
            }
        }
        Document::AuthorizationServer => vec![issuer.well_known_inserted(AS_SUFFIX)],
        Document::ProtectedResource => vec![issuer.well_known_inserted(PRM_SUFFIX)],
        Document::Jwks => vec![format!("{}{JWKS_PATH}", issuer.path())],
        Document::SuissConfiguration => {
            let appended = issuer.well_known_appended(crate::domain::suiss::SUFFIX);
            let inserted = issuer.well_known_inserted(crate::domain::suiss::SUFFIX);
            if appended == inserted {
                vec![appended]
            } else {
                vec![inserted, appended]
            }
        }
    }
}
