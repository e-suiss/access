//! Protected Resource Metadata (RFC 9728; §11.5.2, §11.5.6, RS-M1, RS-M2, AG-9, AG-10). The
//! document is this PEP's configuration (MD-14): not a Claim source, not an authority document
//! and not Domain Metadata (P60). Trust in the authorization server's keys comes from the
//! domain's Domain Metadata the resource server pins, never from this document.

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::json::b64url_encode;

use super::json::text;
use crate::auth::dpop::{ProofKey, jwk};

/// The well-known suffix (RFC 9728 §3).
pub const WELL_KNOWN: &str = "/.well-known/oauth-protected-resource";

/// `Cache-Control` of the metadata answer (RFC 9728 §7.10).
pub const CACHE_CONTROL: &str = "max-age=300";

/// The scope never put in metadata or a challenge (§11.5.1 SHOULD NOT).
pub const OFFLINE_ACCESS: &str = "offline_access";

/// How tokens are bound to their holder (AG-9): DPoP, or an mTLS certificate. Bearer is not an
/// option.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Binding {
    /// `dpop_bound_access_tokens_required: true` with these algorithms (RFC 9864 names).
    Dpop(Vec<String>),
    /// `tls_client_certificate_bound_access_tokens: true` (RFC 8705).
    Mtls,
}

/// A human-readable member, optionally per BCP 47 language tag (`resource_name#tr-TR`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Localized {
    /// The language tag; `None` for the default.
    pub language: Option<String>,
    /// The text.
    pub text: String,
}

/// What a resource server publishes about itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedResource {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    binding: Binding,
    authorization_details_types: Vec<String>,
    names: Vec<Localized>,
    documentation: Option<String>,
    policy_uri: Option<String>,
    tos_uri: Option<String>,
    jwks_uri: Option<String>,
}

/// Why a configuration is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PrmError {
    /// The resource is not an absolute `https` URI without query or fragment (a local server
    /// may use `http://127.0.0.1`).
    #[error("prm-resource")]
    Resource,
    /// No authorization server, or one that is not `https`.
    #[error("prm-authorization-servers")]
    AuthorizationServers,
    /// A scope that is not an RFC 6749 scope token, or `offline_access`.
    #[error("prm-scope")]
    Scope,
    /// DPoP without an algorithm, or with `none`.
    #[error("prm-binding")]
    Binding,
    /// A language tag or URI member that cannot be published.
    #[error("prm-member")]
    Member,
}

fn https(uri: &str) -> bool {
    uri.strip_prefix("https://")
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
        && !uri.contains(['?', '#', ' ', '"', '\\'])
}

fn local(uri: &str) -> bool {
    uri.strip_prefix("http://127.0.0.1")
        .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        && !uri.contains(['?', '#', ' ', '"', '\\'])
}

/// An RFC 6749 §3.3 scope token.
#[must_use]
pub fn scope_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
}

fn tag(s: &str) -> bool {
    !s.is_empty() && s.len() <= 35 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

impl ProtectedResource {
    /// A configuration for `resource` (the canonical MCP server URI, RFC 8707) guarded by
    /// `authorization_servers` (MUST, at least one) with a minimal `scopes_supported`.
    ///
    /// # Errors
    /// [`PrmError`].
    pub fn new(
        resource: &str,
        authorization_servers: Vec<String>,
        scopes_supported: Vec<String>,
        binding: Binding,
    ) -> Result<Self, PrmError> {
        if !(https(resource) || local(resource)) {
            return Err(PrmError::Resource);
        }
        if authorization_servers.is_empty() || !authorization_servers.iter().all(|a| https(a)) {
            return Err(PrmError::AuthorizationServers);
        }
        // §11.5.1
        if scopes_supported
            .iter()
            .any(|s| !scope_token(s) || s == OFFLINE_ACCESS)
        {
            return Err(PrmError::Scope);
        }
        if let Binding::Dpop(algs) = &binding
            && (algs.is_empty()
                || algs
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case("none") || !scope_token(a)))
        {
            return Err(PrmError::Binding);
        }
        Ok(Self {
            resource: String::from(resource.trim_end_matches('/')),
            authorization_servers,
            scopes_supported,
            binding,
            authorization_details_types: Vec::new(),
            names: Vec::new(),
            documentation: None,
            policy_uri: None,
            tos_uri: None,
            jwks_uri: None,
        })
    }

    /// Adds `resource_name` (shown to the end user; authority-opaque).
    ///
    /// # Errors
    /// [`PrmError::Member`].
    pub fn named(mut self, name: Localized) -> Result<Self, PrmError> {
        if name.language.as_deref().is_some_and(|l| !tag(l)) {
            return Err(PrmError::Member);
        }
        self.names.push(name);
        Ok(self)
    }

    /// Adds the RAR types of the SPPs this resource accepts (RFC 9396, §9.13.8).
    ///
    /// # Errors
    /// [`PrmError::Member`].
    pub fn details_types(mut self, types: Vec<String>) -> Result<Self, PrmError> {
        if types.iter().any(|t| !scope_token(t)) {
            return Err(PrmError::Member);
        }
        self.authorization_details_types = types;
        Ok(self)
    }

    /// Adds the documentation, policy and terms URIs and the server's own `jwks_uri`.
    ///
    /// # Errors
    /// [`PrmError::Member`].
    pub fn documents(
        mut self,
        documentation: Option<String>,
        policy_uri: Option<String>,
        tos_uri: Option<String>,
        jwks_uri: Option<String>,
    ) -> Result<Self, PrmError> {
        let all = [&documentation, &policy_uri, &tos_uri, &jwks_uri];
        if all.iter().any(|u| u.as_deref().is_some_and(|u| !https(u))) {
            return Err(PrmError::Member);
        }
        self.documentation = documentation;
        self.policy_uri = policy_uri;
        self.tos_uri = tos_uri;
        self.jwks_uri = jwks_uri;
        Ok(self)
    }

    /// The canonical resource identifier: the token's only audience.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// The scopes this server publishes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes_supported
    }

    /// The token binding.
    #[must_use]
    pub const fn binding(&self) -> &Binding {
        &self.binding
    }

    /// The path the metadata is served at on this server's origin (RFC 9728 §3.1): the
    /// well-known suffix between the host and the resource's path, the path's trailing slash
    /// removed first.
    #[must_use]
    pub fn well_known_path(&self) -> String {
        let (_, path) = split(&self.resource);
        let mut out = String::from(WELL_KNOWN);
        out.push_str(path.trim_end_matches('/'));
        out
    }

    /// The absolute metadata URL, the `resource_metadata` of every challenge.
    #[must_use]
    pub fn metadata_url(&self) -> String {
        let (origin, _) = split(&self.resource);
        let mut out = String::from(origin);
        out.push_str(&self.well_known_path());
        out
    }

    /// The metadata members as a JSON object body, without `signed_metadata`.
    #[must_use]
    pub fn json(&self) -> String {
        self.members(None)
    }

    /// The metadata with `signed_metadata` (RFC 9728 §2.2): a JWS by the PEP key over the same
    /// members with `iss` = the resource. Only when a PEP key is configured; by default the
    /// document is not signed (OP-154 m.3 (v)).
    ///
    /// # Errors
    /// [`PrmError::Member`] when the key has no JOSE algorithm or does not sign.
    pub fn signed(&self, key: &impl ProofKey) -> Result<String, PrmError> {
        let (_, alg) = jwk(key.public_key()).map_err(|_| PrmError::Member)?;
        let kid = b64url_encode(&access_kernel::verify::key_scope::thumbprint(
            key.public_key(),
        ));
        let mut header = String::from("{\"alg\":");
        text(&mut header, alg);
        header.push_str(",\"kid\":");
        text(&mut header, &kid);
        header.push('}');
        let mut claims = self.members(None);
        claims.pop();
        claims.push_str(",\"iss\":");
        text(&mut claims, &self.resource);
        claims.push('}');
        let mut jws = b64url_encode(header.as_bytes());
        jws.push('.');
        jws.push_str(&b64url_encode(claims.as_bytes()));
        let signature = key.sign(jws.as_bytes()).ok_or(PrmError::Member)?;
        jws.push('.');
        jws.push_str(&b64url_encode(&signature));
        Ok(self.members(Some(&jws)))
    }

    fn members(&self, signed: Option<&str>) -> String {
        let mut out = String::from("{\"resource\":");
        text(&mut out, &self.resource);
        out.push_str(",\"authorization_servers\":");
        list(&mut out, &self.authorization_servers);
        out.push_str(",\"scopes_supported\":");
        list(&mut out, &self.scopes_supported);
        out.push_str(",\"bearer_methods_supported\":[\"header\"]");
        match &self.binding {
            Binding::Dpop(algs) => {
                out.push_str(",\"dpop_bound_access_tokens_required\":true");
                out.push_str(",\"dpop_signing_alg_values_supported\":");
                list(&mut out, algs);
            }
            Binding::Mtls => out.push_str(",\"tls_client_certificate_bound_access_tokens\":true"),
        }
        if !self.authorization_details_types.is_empty() {
            out.push_str(",\"authorization_details_types_supported\":");
            list(&mut out, &self.authorization_details_types);
        }
        for n in &self.names {
            out.push(',');
            let mut key = String::from("resource_name");
            if let Some(l) = &n.language {
                key.push('#');
                key.push_str(l);
            }
            text(&mut out, &key);
            out.push(':');
            text(&mut out, &n.text);
        }
        for (k, v) in [
            ("resource_documentation", &self.documentation),
            ("resource_policy_uri", &self.policy_uri),
            ("resource_tos_uri", &self.tos_uri),
            ("jwks_uri", &self.jwks_uri),
        ] {
            if let Some(v) = v {
                out.push(',');
                text(&mut out, k);
                out.push(':');
                text(&mut out, v);
            }
        }
        if let Some(jws) = signed {
            out.push_str(",\"signed_metadata\":");
            text(&mut out, jws);
        }
        out.push('}');
        out
    }
}

fn list(out: &mut String, items: &[String]) {
    out.push('[');
    for (n, i) in items.iter().enumerate() {
        if n > 0 {
            out.push(',');
        }
        text(out, i);
    }
    out.push(']');
}

/// `(scheme://authority, path)` of an absolute URI.
pub(crate) fn split(uri: &str) -> (&str, &str) {
    let after = uri.find("://").map_or(0, |i| i.saturating_add(3));
    match uri.get(after..).and_then(|rest| rest.find('/')) {
        Some(i) => uri.split_at(after.saturating_add(i)),
        None => (uri, ""),
    }
}
