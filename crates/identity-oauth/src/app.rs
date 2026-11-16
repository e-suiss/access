//! Use cases over the domain and its ports (OP-63): a request's `Host` selects the environment, the
//! documents carry the issuer stored on the environment's row, never one built from the request
//! (§17.9.6, TN-10), and the start-up checks of the identity plane (OP-138).

pub mod backchannel;
pub mod dpop;
pub mod oauth;
pub mod oidf;

use crate::domain::issuer::{EnvironmentBase, IssuerStyle, PATH_PREFIX, check_slug};
use crate::domain::metadata::{self, Document, SERVED, Served};
use crate::domain::suiss;
use crate::ports::{Directory, EnvironmentEntry, Keys, Unavailable};

/// A key set that publishes nothing (CR-27: an environment always publishes a key).
const EMPTY_JWKS: &str = r#"{"keys":[]}"#;

/// What the surface answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// A JSON metadata document.
    Metadata(String),
    /// The environment's JWKS (CR-25).
    Jwks(String),
    /// The environment's Suiss discovery document (OP-149 m.3).
    Suiss(String),
    /// No environment here; the answer names none (§17.9.6).
    NotFound,
    /// The directory or the signer did not answer (fail-closed).
    Unavailable,
}

/// Why the identity plane refuses to start (OP-138, §17.9.7).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StartupError {
    /// The identity signer did not answer (CMP-22b).
    #[error("identity signer unreachable")]
    Signer,
    /// The environment directory could not be read.
    #[error("environment directory unreadable")]
    Directory,
    /// An environment's stored issuer is not one the configured environment base forms (§17.9.6).
    #[error("issuer of environment {0} does not match the configured environment base")]
    Issuer(String),
    /// An environment's JWKS could not be loaded.
    #[error("JWKS of environment {0} could not be loaded")]
    Jwks(String),
}

/// The environment discovery and key publication service.
pub struct Discovery<D, K> {
    directory: D,
    keys: K,
    served: Served,
    suiss: Option<suiss::Settings>,
    mtls_port: Option<u16>,
}

/// The lower-case host of a request authority, without its port; `None` for anything that
/// cannot be an environment hostname.
fn host_of(authority: &str) -> Option<String> {
    let host = match authority.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) => h,
        Some(_) => return None,
        None => authority,
    };
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.');
    ok.then(|| host.to_ascii_lowercase())
}

/// The environment a request reached: `Host` selects it, through its hostname or, for a path
/// issuer, its slug; the environment's stored issuer must name the origin and path the request
/// used, or there is no environment here (§17.9.6).
///
/// # Errors
/// [`Unavailable`].
pub async fn resolve<D: Directory>(
    directory: &D,
    authority: &str,
    slug: Option<&str>,
) -> Result<Option<EnvironmentEntry>, Unavailable> {
    let Some(host) = host_of(authority) else {
        return Ok(None);
    };
    let entry = match slug {
        None => match directory.by_host(&host).await? {
            Some(e) => Some(e),
            // OP-156 m.3 (i)
            None => directory.by_custom_host(&host).await?,
        },
        Some(s) if check_slug(s).is_ok() => directory.by_slug(s).await?,
        Some(_) => None,
    };
    Ok(entry.filter(|e| {
        let path = e.issuer.path();
        e.issuer.serves(authority)
            && slug.map_or(path.is_empty(), |s| {
                path.strip_prefix(PATH_PREFIX).is_some_and(|p| p == s)
            })
    }))
}

/// The environment a hosted surface reached (the Frontend API, hosted sign-in and the account pages,
/// OP-156 m.3 (i)): the environment [`resolve`] finds, or the environment a verified custom domain serves
/// at its root. `Host` still only selects the environment; the issuer stays the one on its row
/// (§17.9.6, TN-16).
///
/// # Errors
/// [`Unavailable`].
pub async fn resolve_hosted<D: Directory>(
    directory: &D,
    authority: &str,
    slug: Option<&str>,
) -> Result<Option<EnvironmentEntry>, Unavailable> {
    if let Some(e) = resolve(directory, authority, slug).await? {
        return Ok(Some(e));
    }
    let (None, Some(host)) = (slug, host_of(authority)) else {
        return Ok(None);
    };
    directory.by_custom_host(&host).await
}

impl<D: Directory, K: Keys> Discovery<D, K> {
    /// A service declaring what [`SERVED`] lists.
    pub const fn new(directory: D, keys: K) -> Self {
        Self {
            directory,
            keys,
            served: SERVED,
            suiss: None,
            mtls_port: None,
        }
    }

    /// Also serves the Suiss discovery document from `settings` (OP-149 m.3); without them it
    /// is not found.
    #[must_use]
    pub fn with_suiss(mut self, settings: suiss::Settings) -> Self {
        self.suiss = Some(settings);
        self
    }

    /// The environment a request reached: `Host` selects it, through its hostname or, for a path
    /// issuer, its slug; the environment's stored issuer must name the origin and path the request
    /// used, or there is no environment here.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn resolve(
        &self,
        authority: &str,
        slug: Option<&str>,
    ) -> Result<Option<EnvironmentEntry>, Unavailable> {
        resolve(&self.directory, authority, slug).await
    }

    /// The environment a hosted surface reached: as [`Self::resolve`], or through a verified custom
    /// domain (OP-156 m.3 (i)).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn resolve_hosted(
        &self,
        authority: &str,
        slug: Option<&str>,
    ) -> Result<Option<EnvironmentEntry>, Unavailable> {
        resolve_hosted(&self.directory, authority, slug).await
    }

    /// Also names the mTLS listener reached on `port` in the metadata of the environments that
    /// publish their aliases (RFC 8705 §5, OP-155 m.3 (m)).
    #[must_use]
    pub const fn with_mtls(mut self, port: u16) -> Self {
        self.mtls_port = Some(port);
        self
    }

    /// Serves `doc` for a request to `authority`, with `slug` from a path-issuer route.
    pub async fn serve(&self, doc: Document, authority: &str, slug: Option<&str>) -> Reply {
        let environment = match self.resolve(authority, slug).await {
            Ok(Some(environment)) => environment,
            Ok(None) => return Reply::NotFound,
            Err(Unavailable) => return Reply::Unavailable,
        };
        match doc {
            Document::OpenIdConfiguration | Document::AuthorizationServer => {
                let Ok(facts) = self.directory.facts(&environment).await else {
                    return Reply::Unavailable;
                };
                // §9.15.1 k.2, P60
                let domain_metadata = self.suiss.as_ref().zip(facts.domain).map(|(s, d)| {
                    format!(
                        "{}/.well-known/access-domain-metadata/sha-256:{}",
                        s.api_base,
                        access_kernel::json::b64url_encode(&d)
                    )
                });
                let facts = metadata::EnvironmentFacts {
                    public_sub: facts.public_sub_clients > 0,
                    domain_metadata,
                    cimd: facts.cimd,
                    dcr: facts.dcr,
                    device_code: facts.device_code,
                    ciba: facts.ciba,
                    mtls_port: self.mtls_port.filter(|_| facts.mtls_aliases),
                    frontchannel: facts.frontchannel,
                    secret_post: facts.secret_post,
                    secret_jwt: facts.secret_jwt,
                    pq_alg: facts.signing_profile.map(access_crypto::jose::JwsAlg::name),
                };
                Reply::Metadata(metadata::authorization_server_of(
                    &environment.issuer,
                    &self.served,
                    &facts,
                ))
            }
            Document::ProtectedResource => Reply::Metadata(metadata::protected_resource(
                &environment.issuer,
                &self.served,
            )),
            Document::Jwks => self
                .keys
                .jwks(environment.environment)
                .await
                .map_or(Reply::Unavailable, Reply::Jwks),
            Document::SuissConfiguration => {
                let Some(s) = self.suiss.as_ref() else {
                    return Reply::NotFound;
                };
                // OP-156 m.3 (t)
                let Ok(coordinator) = self.directory.coordinator(&environment).await else {
                    return Reply::Unavailable;
                };
                Reply::Suiss(suiss::document_with(
                    &environment.issuer,
                    s,
                    suiss::SERVED,
                    coordinator.as_deref(),
                ))
            }
        }
    }

    /// The start-up checks: the signer answers, every live environment's stored issuer is one the
    /// configured `base` forms for its slug, and every live environment's JWKS loads; returns the
    /// number of environments checked (OP-138, §17.9.6, §17.9.7).
    ///
    /// # Errors
    /// [`StartupError`].
    pub async fn check(&self, base: &EnvironmentBase) -> Result<usize, StartupError> {
        self.keys.ping().await.map_err(|_| StartupError::Signer)?;
        let environments = self
            .directory
            .all()
            .await
            .map_err(|_| StartupError::Directory)?;
        for r in &environments {
            let fixed = [IssuerStyle::Subdomain, IssuerStyle::Path]
                .into_iter()
                .any(|style| base.issuer(&r.slug, style).is_ok_and(|i| i == r.issuer));
            if !fixed {
                return Err(StartupError::Issuer(r.slug.clone()));
            }
            let jwks = self
                .keys
                .jwks(r.environment)
                .await
                .map_err(|_| StartupError::Jwks(r.slug.clone()))?;
            if jwks == EMPTY_JWKS {
                return Err(StartupError::Jwks(r.slug.clone()));
            }
        }
        Ok(environments.len())
    }
}

#[cfg(test)]
mod tests;
