//! Use cases over the domain and its ports (OP-63): a request's `Host` selects the realm, the
//! documents carry the issuer stored on the realm's row, never one built from the request
//! (§17.9.6, TN-10), and the start-up checks of the identity plane (OP-138).

pub mod dpop;

use crate::domain::issuer::{IssuerStyle, PATH_PREFIX, RealmBase, check_slug};
use crate::domain::metadata::{self, Document, SERVED, Served};
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

impl<D: Directory, K: Keys> Discovery<D, K> {
    /// A service declaring what [`SERVED`] lists.
    pub const fn new(directory: D, keys: K) -> Self {
        Self {
            directory,
            keys,
            served: SERVED,
        }
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
        let Some(host) = host_of(authority) else {
            return Ok(None);
        };
        let entry = match slug {
            None => self.directory.by_host(&host).await?,
            Some(s) if check_slug(s).is_ok() => self.directory.by_slug(s).await?,
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

    /// Serves `doc` for a request to `authority`, with `slug` from a path-issuer route.
    pub async fn serve(&self, doc: Document, authority: &str, slug: Option<&str>) -> Reply {
        let realm = match self.resolve(authority, slug).await {
            Ok(Some(realm)) => realm,
            Ok(None) => return Reply::NotFound,
            Err(Unavailable) => return Reply::Unavailable,
        };
        match doc {
            Document::OpenIdConfiguration | Document::AuthorizationServer => {
                Reply::Metadata(metadata::authorization_server(&realm.issuer, &self.served))
            }
            Document::ProtectedResource => {
                Reply::Metadata(metadata::protected_resource(&realm.issuer, &self.served))
            }
            Document::Jwks => self
                .keys
                .jwks(realm.realm)
                .await
                .map_or(Reply::Unavailable, Reply::Jwks),
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
