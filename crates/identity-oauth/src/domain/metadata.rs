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
    /// RFC 9396 `authorization_details` for authority token projections (OP-150 m.2); not
    /// served yet.
    AuthorizationDetails,
}

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
    ],
    features: &[Feature::Dpop, Feature::BackchannelLogout],
};

/// The protocol scopes the metadata declares (OP-146 m.5 (c)).
const SCOPES: [&str; 1] = ["openid"];
const CLAIMS: [&str; 9] = [
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "sid",
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

/// The AS metadata of the realm `issuer`, served both as OIDC Discovery and as RFC 8414
/// metadata (§10.4.6, §11.4.5).
#[must_use]
pub fn authorization_server(issuer: &Issuer, served: &Served) -> String {
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
        // IDP-7, §11.4.5 #1
        m.insert("code_challenge_methods_supported".into(), json!(["S256"]));
        // RFC 9207, TN-11
        m.insert(
            "authorization_response_iss_parameter_supported".into(),
            Value::Bool(true),
        );
        // MD-10, IDP-24
        m.insert("subject_types_supported".into(), json!(["pairwise"]));
        m.insert("scopes_supported".into(), json!(SCOPES));
        m.insert("claims_supported".into(), json!(CLAIMS));
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
            json!(["authorization_code", "refresh_token"]),
        );
        m.insert(
            "token_endpoint_auth_methods_supported".into(),
            json!(["none", "private_key_jwt", "client_secret_basic"]),
        );
        m.insert(
            "token_endpoint_auth_signing_alg_values_supported".into(),
            json!(CLIENT_ASSERTION_ALGS),
        );
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
    ] {
        if served.has(e) {
            m.insert(key.into(), issuer.endpoint(e.path()).into());
        }
    }
    if served.feature(Feature::Dpop) {
        m.insert(
            "dpop_signing_alg_values_supported".into(),
            json!(SIGNING_ALGS),
        );
    }
    if served.feature(Feature::ClientIdMetadataDocument) {
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
