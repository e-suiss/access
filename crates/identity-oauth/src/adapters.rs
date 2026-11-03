//! Adapters of the realm ports: the router role's view of the realm rows (OP-132 m.3) and the
//! identity signer over its Unix socket (CMP-22b).

pub mod dpop;

use std::path::PathBuf;

use access_crypto::jose::JwsAlg;
use access_identity_signer::adapters::call;
use access_identity_signer::protocol::{Realm, Request, Response};
use access_identity_signer::service::UNKNOWN_REALM;
use access_store::Pool;
use access_store::identity::RealmId;
use access_store::tenancy::{self, RealmRoute};

use crate::domain::issuer::Issuer;
use crate::ports::{Directory, Keys, RealmEntry, Unavailable};

/// The realm rows as the `access_router` role reads them.
pub struct PgDirectory {
    router: Pool,
}

impl PgDirectory {
    /// A directory over a pool of the router role.
    #[must_use]
    pub const fn new(router: Pool) -> Self {
        Self { router }
    }
}

/// A row whose stored issuer does not parse is not routed (fail-closed).
fn entry(r: RealmRoute) -> Option<RealmEntry> {
    Some(RealmEntry {
        issuer: Issuer::parse(&r.issuer).ok()?,
        realm: r.realm,
        slug: r.slug,
    })
}

impl Directory for PgDirectory {
    async fn by_host(&self, host: &str) -> Result<Option<RealmEntry>, Unavailable> {
        tenancy::route_by_host(&self.router, host)
            .await
            .map(|r| r.and_then(entry))
            .map_err(|_| Unavailable)
    }

    async fn by_slug(&self, slug: &str) -> Result<Option<RealmEntry>, Unavailable> {
        tenancy::route_by_slug(&self.router, slug)
            .await
            .map(|r| r.and_then(entry))
            .map_err(|_| Unavailable)
    }

    async fn all(&self) -> Result<Vec<RealmEntry>, Unavailable> {
        tenancy::routes(&self.router)
            .await
            .map(|rows| rows.into_iter().filter_map(entry).collect())
            .map_err(|_| Unavailable)
    }
}

/// The identity signer at a Unix socket; a realm's key set is opened with `alg` on first use.
pub struct SignerKeys {
    socket: PathBuf,
    alg: JwsAlg,
}

impl SignerKeys {
    /// The signer at `socket`, opening realms with ES256 (CR-2, MD-3).
    #[must_use]
    pub const fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            alg: JwsAlg::Es256,
        }
    }

    async fn ask(&self, request: &Request) -> Result<Response, Unavailable> {
        call(&self.socket, request).await.map_err(|_| Unavailable)
    }
}

impl Keys for SignerKeys {
    async fn ping(&self) -> Result<(), Unavailable> {
        match self.ask(&Request::Ping).await? {
            Response::Pong => Ok(()),
            _ => Err(Unavailable),
        }
    }

    async fn jwks(&self, realm: RealmId) -> Result<String, Unavailable> {
        let realm = Realm(*realm.as_bytes());
        match self.ask(&Request::Jwks(realm)).await? {
            Response::Jwks(doc) => return Ok(doc),
            Response::Error(code) if code == UNKNOWN_REALM => {}
            _ => return Err(Unavailable),
        }
        let open = Request::Open {
            realm,
            alg: self.alg,
        };
        if self.ask(&open).await? != Response::Opened {
            return Err(Unavailable);
        }
        match self.ask(&Request::Jwks(realm)).await? {
            Response::Jwks(doc) => Ok(doc),
            _ => Err(Unavailable),
        }
    }
}
