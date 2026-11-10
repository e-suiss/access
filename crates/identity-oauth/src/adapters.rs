//! Adapters of the realm ports: the router role's view of the realm rows (OP-132 m.3) and the
//! identity signer over its Unix socket (CMP-22b).

pub mod bundles;
pub mod certificates;
pub mod cimd;
pub mod clients;
pub mod dpop;
pub mod hooks;
pub mod oauth;
pub mod oidf;
pub mod outbound;

use std::path::PathBuf;

use access_crypto::jose::JwsAlg;
use access_identity_signer::adapters::call;
use access_identity_signer::protocol::{Realm, Request, Response};
use access_identity_signer::service::UNKNOWN_REALM;
use access_store::Pool;
use access_store::identity::{RealmId, TenantTx};
use access_store::idp;
use access_store::tenancy::{self, RealmRoute};

use crate::domain::issuer::Issuer;
use crate::ports::{Directory, Facts, Keys, RealmEntry, Unavailable};

/// The realm rows as the `access_router` role reads them; with the `access_app` pool, also
/// each realm's discovery facts in its own scope (TN-113).
pub struct PgDirectory {
    router: Pool,
    app: Option<Pool>,
}

impl PgDirectory {
    /// A directory over a pool of the router role.
    #[must_use]
    pub const fn new(router: Pool) -> Self {
        Self { router, app: None }
    }

    /// Also reads each realm's discovery facts through `app` (MD-10, §9.15.1 k.2).
    #[must_use]
    pub fn with_facts(mut self, app: Pool) -> Self {
        self.app = Some(app);
        self
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

    async fn by_custom_host(&self, host: &str) -> Result<Option<RealmEntry>, Unavailable> {
        access_store::custom_domains::route_by_custom_host(&self.router, host)
            .await
            .map(|r| r.and_then(|c| entry(c.route)))
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

    async fn facts(&self, realm: &RealmEntry) -> Result<Facts, Unavailable> {
        let Some(app) = &self.app else {
            return Ok(Facts::default());
        };
        let mut t = TenantTx::begin(app, realm.tenant, realm.realm)
            .await
            .map_err(|_| Unavailable)?;
        let public_sub_clients = idp::public_sub_clients(&mut t)
            .await
            .map_err(|_| Unavailable)?;
        let domain = idp::governance(&mut t)
            .await
            .map_err(|_| Unavailable)?
            .map(|g| *g.domain.as_bytes());
        let cimd = idp::settings(&mut t)
            .await
            .map_err(|_| Unavailable)?
            .is_some_and(|s| s.cimd_enabled);
        let dcr = t.dcr_policy().await.map_err(|_| Unavailable)?.enabled;
        let device_code = t.device_code_enabled().await.map_err(|_| Unavailable)?;
        let ciba = t.ciba_settings().await.map_err(|_| Unavailable)?.enabled;
        let mtls_aliases = t.mtls_aliases().await.map_err(|_| Unavailable)?;
        // IDP-24, OP-155 m.3 (k)
        let frontchannel = access_store::client_profiles::frontchannel_enabled(&mut t)
            .await
            .map_err(|_| Unavailable)?;
        let legacy = access_store::client_profiles::legacy_methods(&mut t)
            .await
            .map_err(|_| Unavailable)?;
        t.commit().await.map_err(|_| Unavailable)?;
        Ok(Facts {
            public_sub_clients,
            domain,
            cimd,
            dcr,
            device_code,
            ciba,
            mtls_aliases,
            frontchannel,
            secret_post: legacy.iter().any(|m| m == "client_secret_post"),
            secret_jwt: legacy.iter().any(|m| m == "client_secret_jwt"),
        })
    }

    async fn coordinator(&self, realm: &RealmEntry) -> Result<Option<String>, Unavailable> {
        let Some(app) = &self.app else {
            return Ok(None);
        };
        let mut t = TenantTx::begin(app, realm.tenant, realm.realm)
            .await
            .map_err(|_| Unavailable)?;
        let url = t.coordinator().await.map_err(|_| Unavailable)?;
        t.commit().await.map_err(|_| Unavailable)?;
        Ok(url)
    }

    async fn federation(
        &self,
        realm: &RealmEntry,
    ) -> Result<Option<access_store::oidf::FederationSettingsRow>, Unavailable> {
        oidf::settings(self.app.as_ref(), realm).await
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

    /// The identity signer's socket, for the requests of other identity plane surfaces (SAML,
    /// OP-155 m.3 (d)).
    #[must_use]
    pub fn socket(&self) -> &std::path::Path {
        &self.socket
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

    async fn rekey(&self, request: &Request) -> Result<(), Unavailable> {
        match self.ask(request).await? {
            Response::Rekeyed(_) => Ok(()),
            _ => Err(Unavailable),
        }
    }

    /// Rotates the realm's active key `retire` out now (TN-118).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn rotate(&self, realm: RealmId, retire: [u8; 32]) -> Result<(), Unavailable> {
        self.rekey(&Request::Rotate {
            realm: Realm(*realm.as_bytes()),
            retire,
        })
        .await
    }

    /// Drops the realm key `kid` at once (§13.2).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn drop_key(&self, realm: RealmId, kid: [u8; 32]) -> Result<(), Unavailable> {
        self.rekey(&Request::DropKey {
            realm: Realm(*realm.as_bytes()),
            kid,
        })
        .await
    }

    /// Replaces the realm's key rotation policy (TN-118).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn set_policy(
        &self,
        realm: RealmId,
        policy: suiss_crypto::rotation::Policy,
    ) -> Result<(), Unavailable> {
        self.rekey(&Request::SetPolicy {
            realm: Realm(*realm.as_bytes()),
            policy,
        })
        .await
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

impl SignerKeys {
    /// Opens the realm's Claim issuer key for its issuer Party `party`: its Ed25519 public key
    /// (§10.1.7).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn open_issuer(
        &self,
        realm: RealmId,
        party: [u8; 16],
    ) -> Result<[u8; 32], Unavailable> {
        let request = Request::OpenIssuer {
            realm: Realm(*realm.as_bytes()),
            party,
        };
        match self.ask(&request).await? {
            Response::Issuer { key, party: p, .. } if p == party => Ok(key),
            _ => Err(Unavailable),
        }
    }

    /// The AIS of one self-signed registration Exercise of the realm's issuer Party (OP-149
    /// m.16 (a)).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn sign_issuer_registration(
        &self,
        realm: RealmId,
        registration: access_identity_signer::issuer::Registration,
    ) -> Result<Vec<u8>, Unavailable> {
        let request = Request::SignIssuerRegistration {
            realm: Realm(*realm.as_bytes()),
            registration,
        };
        match self.ask(&request).await? {
            Response::SignedCose { sign1, .. } => Ok(sign1),
            _ => Err(Unavailable),
        }
    }
}

/// The realm issuer's Claims are signed by the realm's Claim issuer key (L2-CLM-1, §10.1.7).
impl access_identity_account::app::claims::ClaimSigner for SignerKeys {
    async fn sign(
        &self,
        realm: RealmId,
        payload: Vec<u8>,
        at: u64,
    ) -> Result<Vec<u8>, access_internal_api::idp::Unavailable> {
        let request = Request::SignClaim {
            realm: Realm(*realm.as_bytes()),
            payload,
            at,
        };
        match self.ask(&request).await {
            Ok(Response::SignedCose { sign1, .. }) => Ok(sign1),
            Ok(Response::Error(code)) => Err(access_internal_api::idp::Unavailable(code)),
            _ => Err(access_internal_api::idp::Unavailable(String::from(
                "identity-signer",
            ))),
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

    async fn federation_jwks(&self, realm: RealmId) -> Result<String, Unavailable> {
        match self
            .ask(&Request::FederationJwks(Realm(*realm.as_bytes())))
            .await?
        {
            Response::Jwks(doc) => Ok(doc),
            _ => Err(Unavailable),
        }
    }

    async fn sign_federation(
        &self,
        realm: RealmId,
        typ: &str,
        payload: &[u8],
        at: u64,
    ) -> Result<String, Unavailable> {
        let request = Request::SignFederation {
            realm: Realm(*realm.as_bytes()),
            typ: String::from(typ),
            payload: payload.to_vec(),
            at,
        };
        match self.ask(&request).await? {
            Response::Signed { token, .. } => Ok(token),
            _ => Err(Unavailable),
        }
    }
}
