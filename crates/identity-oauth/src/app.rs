//! Use cases over the domain and its ports (OP-63): a request's `Host` selects the realm, the
//! documents carry the issuer stored on the realm's row, never one built from the request
//! (§17.9.6, TN-10), and the start-up checks of the identity plane (OP-138).

pub mod backchannel;
pub mod dpop;
pub mod oauth;

use crate::domain::issuer::{IssuerStyle, PATH_PREFIX, RealmBase, check_slug};
use crate::domain::metadata::{self, Document, SERVED, Served};
use crate::domain::suiss;
use crate::ports::{Directory, Keys, RealmEntry, Unavailable};

/// A key set that publishes nothing (CR-27: a realm always publishes a key).
const EMPTY_JWKS: &str = r#"{"keys":[]}"#;

/// What the surface answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// A JSON metadata document.
    Metadata(String),
    /// The realm's JWKS (CR-25).
    Jwks(String),
    /// The realm's Suiss discovery document (OP-149 m.3).
    Suiss(String),
    /// No realm here; the answer names none (§17.9.6).
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
    /// The realm directory could not be read.
    #[error("realm directory unreadable")]
    Directory,
    /// A realm's stored issuer is not one the configured realm base forms (§17.9.6).
    #[error("issuer of realm {0} does not match the configured realm base")]
    Issuer(String),
    /// A realm's JWKS could not be loaded.
    #[error("JWKS of realm {0} could not be loaded")]
    Jwks(String),
}

/// The realm discovery and key publication service.
pub struct Discovery<D, K> {
    directory: D,
    keys: K,
    served: Served,
    suiss: Option<suiss::Settings>,
}

/// The lower-case host of a request authority, without its port; `None` for anything that
/// cannot be a realm hostname.
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

/// The realm a request reached: `Host` selects it, through its hostname or, for a path
/// issuer, its slug; the realm's stored issuer must name the origin and path the request
/// used, or there is no realm here (§17.9.6).
///
/// # Errors
/// [`Unavailable`].
pub async fn resolve<D: Directory>(
    directory: &D,
    authority: &str,
    slug: Option<&str>,
) -> Result<Option<RealmEntry>, Unavailable> {
    let Some(host) = host_of(authority) else {
        return Ok(None);
    };
    let entry = match slug {
        None => directory.by_host(&host).await?,
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

impl<D: Directory, K: Keys> Discovery<D, K> {
    /// A service declaring what [`SERVED`] lists.
    pub const fn new(directory: D, keys: K) -> Self {
        Self {
            directory,
            keys,
            served: SERVED,
            suiss: None,
        }
    }

    /// Also serves the Suiss discovery document from `settings` (OP-149 m.3); without them it
    /// is not found.
    #[must_use]
    pub fn with_suiss(mut self, settings: suiss::Settings) -> Self {
        self.suiss = Some(settings);
        self
    }

    /// The realm a request reached: `Host` selects it, through its hostname or, for a path
    /// issuer, its slug; the realm's stored issuer must name the origin and path the request
    /// used, or there is no realm here.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn resolve(
        &self,
        authority: &str,
        slug: Option<&str>,
    ) -> Result<Option<RealmEntry>, Unavailable> {
        resolve(&self.directory, authority, slug).await
    }

    /// Serves `doc` for a request to `authority`, with `slug` from a path-issuer route.
    pub async fn serve(&self, doc: Document, authority: &str, slug: Option<&str>) -> Reply {
        let realm = match self.resolve(authority, slug).await {
            Ok(Some(realm)) => realm,
            Ok(None) => return Reply::NotFound,
            Err(Unavailable) => return Reply::Unavailable,
        };
        match doc {
            Document::OpenIdConfiguration | Document::AuthorizationServer => {
                let Ok(facts) = self.directory.facts(&realm).await else {
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
                let facts = metadata::RealmFacts {
                    public_sub: facts.public_sub_clients > 0,
                    domain_metadata,
                    cimd: facts.cimd,
                };
                Reply::Metadata(metadata::authorization_server_of(
                    &realm.issuer,
                    &self.served,
                    &facts,
                ))
            }
            Document::ProtectedResource => {
                Reply::Metadata(metadata::protected_resource(&realm.issuer, &self.served))
            }
            Document::Jwks => self
                .keys
                .jwks(realm.realm)
                .await
                .map_or(Reply::Unavailable, Reply::Jwks),
            Document::SuissConfiguration => self.suiss.as_ref().map_or(Reply::NotFound, |s| {
                Reply::Suiss(suiss::document(&realm.issuer, s, suiss::SERVED))
            }),
        }
    }

    /// The start-up checks: the signer answers, every live realm's stored issuer is one the
    /// configured `base` forms for its slug, and every live realm's JWKS loads; returns the
    /// number of realms checked (OP-138, §17.9.6, §17.9.7).
    ///
    /// # Errors
    /// [`StartupError`].
    pub async fn check(&self, base: &RealmBase) -> Result<usize, StartupError> {
        self.keys.ping().await.map_err(|_| StartupError::Signer)?;
        let realms = self
            .directory
            .all()
            .await
            .map_err(|_| StartupError::Directory)?;
        for r in &realms {
            let fixed = [IssuerStyle::Subdomain, IssuerStyle::Path]
                .into_iter()
                .any(|style| base.issuer(&r.slug, style).is_ok_and(|i| i == r.issuer));
            if !fixed {
                return Err(StartupError::Issuer(r.slug.clone()));
            }
            let jwks = self
                .keys
                .jwks(r.realm)
                .await
                .map_err(|_| StartupError::Jwks(r.slug.clone()))?;
            if jwks == EMPTY_JWKS {
                return Err(StartupError::Jwks(r.slug.clone()));
            }
        }
        Ok(realms.len())
    }
}

#[cfg(test)]
mod tests;
