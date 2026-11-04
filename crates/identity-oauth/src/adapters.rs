//! Adapters of the realm ports: the router role's view of the realm rows (OP-132 m.3) and the
//! identity signer over its Unix socket (CMP-22b).

pub mod clients;
pub mod dpop;
pub mod oauth;
pub mod outbound;

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
        tenant: r.tenant,
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

    /// Opens the key set of `realm` with `alg`, or makes its next keys use `alg` (OP-146
    /// m.16 (m), m.8 (e)).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn open(&self, realm: RealmId, alg: JwsAlg) -> Result<(), Unavailable> {
        let open = Request::Open {
            realm: Realm(*realm.as_bytes()),
            alg,
        };
        match self.ask(&open).await? {
            Response::Opened => Ok(()),
            _ => Err(Unavailable),
        }
    }

    /// Signs deterministic CBOR as a tagged `COSE_Sign1` of `content_type` with the key that
    /// signs the realm's tokens, opening the realm's key set on first use (OP-149 m.8).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn sign_cose(
        &self,
        realm: RealmId,
        content_type: &str,
        payload: &[u8],
        at_ms: u64,
    ) -> Result<Vec<u8>, Unavailable> {
        let r = Realm(*realm.as_bytes());
        let request = Request::SignCose {
            realm: r,
            content_type: String::from(content_type),
            payload: payload.to_vec(),
            at: at_ms,
        };
        match self.ask(&request).await? {
            Response::SignedCose { sign1, .. } => return Ok(sign1),
            Response::Error(code) if code == UNKNOWN_REALM => {}
            _ => return Err(Unavailable),
        }
        let open = Request::Open {
            realm: r,
            alg: self.alg,
        };
        if self.ask(&open).await? != Response::Opened {
            return Err(Unavailable);
        }
        match self.ask(&request).await? {
            Response::SignedCose { sign1, .. } => Ok(sign1),
            _ => Err(Unavailable),
        }
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
