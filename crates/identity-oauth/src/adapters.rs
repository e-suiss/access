//! Adapters of the environment ports: the router role's view of the environment rows (OP-132 m.3) and the
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
use access_identity_account::app::claims::NotSigned;
use access_identity_signer::adapters::call;
use access_identity_signer::protocol::{Environment, Request, Response};
use access_identity_signer::service::UNKNOWN_ENVIRONMENT;
use access_store::Pool;
use access_store::identity::{EnvironmentId, TenantTx};
use access_store::idp;
use access_store::tenancy::{self, EnvironmentRoute};

use crate::domain::issuer::Issuer;
use crate::ports::{Directory, EnvironmentEntry, Facts, Keys, Unavailable};

/// The environment rows as the `access_router` role reads them; with the `access_app` pool, also
/// each environment's discovery facts in its own scope (TN-113).
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

    /// Also reads each environment's discovery facts through `app` (MD-10, §9.15.1 k.2).
    #[must_use]
    pub fn with_facts(mut self, app: Pool) -> Self {
        self.app = Some(app);
        self
    }
}

/// A row whose stored issuer does not parse is not routed (fail-closed).
fn entry(r: EnvironmentRoute) -> Option<EnvironmentEntry> {
    Some(EnvironmentEntry {
        issuer: Issuer::parse(&r.issuer).ok()?,
        tenant: r.tenant,
        environment: r.environment,
        slug: r.slug,
    })
}

impl Directory for PgDirectory {
    async fn by_host(&self, host: &str) -> Result<Option<EnvironmentEntry>, Unavailable> {
        tenancy::route_by_host(&self.router, host)
            .await
            .map(|r| r.and_then(entry))
            .map_err(|_| Unavailable)
    }

    async fn by_custom_host(&self, host: &str) -> Result<Option<EnvironmentEntry>, Unavailable> {
        access_store::custom_domains::route_by_custom_host(&self.router, host)
            .await
            .map(|r| r.and_then(|c| entry(c.route)))
            .map_err(|_| Unavailable)
    }

    async fn by_slug(&self, slug: &str) -> Result<Option<EnvironmentEntry>, Unavailable> {
        tenancy::route_by_slug(&self.router, slug)
            .await
            .map(|r| r.and_then(entry))
            .map_err(|_| Unavailable)
    }

    async fn all(&self) -> Result<Vec<EnvironmentEntry>, Unavailable> {
        tenancy::routes(&self.router)
            .await
            .map(|rows| rows.into_iter().filter_map(entry).collect())
            .map_err(|_| Unavailable)
    }

    async fn facts(&self, environment: &EnvironmentEntry) -> Result<Facts, Unavailable> {
        let Some(app) = &self.app else {
            return Ok(Facts::default());
        };
        let mut t = TenantTx::begin(app, environment.tenant, environment.environment)
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
        // OP-159 m.3 (o)
        let signing_profile = t
            .environment_signing()
            .await
            .map_err(|_| Unavailable)?
            .profile
            .as_deref()
            .and_then(oauth::profile_alg);
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
            signing_profile,
        })
    }

    async fn coordinator(
        &self,
        environment: &EnvironmentEntry,
    ) -> Result<Option<String>, Unavailable> {
        let Some(app) = &self.app else {
            return Ok(None);
        };
        let mut t = TenantTx::begin(app, environment.tenant, environment.environment)
            .await
            .map_err(|_| Unavailable)?;
        let url = t.coordinator().await.map_err(|_| Unavailable)?;
        t.commit().await.map_err(|_| Unavailable)?;
        Ok(url)
    }

    async fn federation(
        &self,
        environment: &EnvironmentEntry,
    ) -> Result<Option<access_store::oidf::FederationSettingsRow>, Unavailable> {
        oidf::settings(self.app.as_ref(), environment).await
    }
}

/// The identity signer at a Unix socket; an environment's key set is opened with `alg` on first use.
pub struct SignerKeys {
    socket: PathBuf,
    alg: JwsAlg,
}

impl SignerKeys {
    /// The signer at `socket`, opening environments with ES256 (CR-2, MD-3).
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

    /// Opens the key set of `environment` with `alg`, or makes its next keys use `alg` (OP-146
    /// m.16 (m), m.8 (e)).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn open(&self, environment: EnvironmentId, alg: JwsAlg) -> Result<(), Unavailable> {
        let open = Request::Open {
            environment: Environment(*environment.as_bytes()),
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

    /// Rotates the environment's active key `retire` out now (TN-118).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn rotate(
        &self,
        environment: EnvironmentId,
        retire: [u8; 32],
    ) -> Result<(), Unavailable> {
        self.rekey(&Request::Rotate {
            environment: Environment(*environment.as_bytes()),
            retire,
        })
        .await
    }

    /// Drops the environment key `kid` at once (§13.2).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn drop_key(
        &self,
        environment: EnvironmentId,
        kid: [u8; 32],
    ) -> Result<(), Unavailable> {
        self.rekey(&Request::DropKey {
            environment: Environment(*environment.as_bytes()),
            kid,
        })
        .await
    }

    /// Replaces the environment's key rotation policy (TN-118).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn set_policy(
        &self,
        environment: EnvironmentId,
        policy: suiss_crypto::rotation::Policy,
    ) -> Result<(), Unavailable> {
        self.rekey(&Request::SetPolicy {
            environment: Environment(*environment.as_bytes()),
            policy,
        })
        .await
    }

    /// Signs deterministic CBOR as a tagged `COSE_Sign1` of `content_type` with the key that
    /// signs the environment's tokens, opening the environment's key set on first use (OP-149 m.8).
    ///
    /// # Errors
    /// [`Unavailable`].
    pub async fn sign_cose(
        &self,
        environment: EnvironmentId,
        content_type: &str,
        payload: &[u8],
        at_ms: u64,
    ) -> Result<Vec<u8>, Unavailable> {
        let r = Environment(*environment.as_bytes());
        let request = Request::SignCose {
            environment: r,
            content_type: String::from(content_type),
            payload: payload.to_vec(),
            at: at_ms,
        };
        match self.ask(&request).await? {
            Response::SignedCose { sign1, .. } => return Ok(sign1),
            Response::Error(code) if code == UNKNOWN_ENVIRONMENT => {}
            _ => return Err(Unavailable),
        }
        let open = Request::Open {
            environment: r,
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
    /// Whether the identity signer can hold an ML-DSA key of `alg` (OP-159 m.3 (d)).
    ///
    /// # Errors
    /// [`Unavailable`] when the signer does not answer.
    pub async fn pq_ready(&self, alg: JwsAlg) -> Result<bool, Unavailable> {
        let request = Request::Pq(access_identity_signer::pq::PqRequest::Ready { alg });
        match self.ask(&request).await? {
            Response::Opened => Ok(true),
            Response::Error(code) if code == access_identity_signer::pq::PQ_KEY_UNAVAILABLE => {
                Ok(false)
            }
            _ => Err(Unavailable),
        }
    }

    /// Opens the environment's post-quantum key set with `alg` (OP-159 m.3 (o)).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn pq_open(
        &self,
        environment: EnvironmentId,
        alg: JwsAlg,
    ) -> Result<(), Unavailable> {
        let request = Request::Pq(access_identity_signer::pq::PqRequest::Open {
            environment: Environment(*environment.as_bytes()),
            alg,
        });
        match self.ask(&request).await? {
            Response::Opened => Ok(()),
            _ => Err(Unavailable),
        }
    }

    /// Drops every key of the environment's post-quantum key set (OP-159 m.3 (a)).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn pq_close(&self, environment: EnvironmentId) -> Result<(), Unavailable> {
        let request = Request::Pq(access_identity_signer::pq::PqRequest::Close {
            environment: Environment(*environment.as_bytes()),
        });
        match self.ask(&request).await? {
            Response::Opened => Ok(()),
            _ => Err(Unavailable),
        }
    }
}

impl SignerKeys {
    /// Opens the environment's Claim issuer key for its issuer Party `party`: its Ed25519 public key
    /// (§10.1.7).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn open_issuer(
        &self,
        environment: EnvironmentId,
        party: [u8; 16],
    ) -> Result<[u8; 32], Unavailable> {
        let request = Request::OpenIssuer {
            environment: Environment(*environment.as_bytes()),
            party,
        };
        match self.ask(&request).await? {
            Response::Issuer { key, party: p, .. } if p == party => Ok(key),
            _ => Err(Unavailable),
        }
    }

    /// The AIS of one self-signed registration Exercise of the environment's issuer Party (OP-149
    /// m.16 (a)).
    ///
    /// # Errors
    /// [`Unavailable`], also when the signer refuses.
    pub async fn sign_issuer_registration(
        &self,
        environment: EnvironmentId,
        registration: access_identity_signer::issuer::Registration,
    ) -> Result<Vec<u8>, Unavailable> {
        let request = Request::SignIssuerRegistration {
            environment: Environment(*environment.as_bytes()),
            registration,
        };
        match self.ask(&request).await? {
            Response::SignedCose { sign1, .. } => Ok(sign1),
            _ => Err(Unavailable),
        }
    }
}

/// The environment issuer's Claims are signed by the environment's Claim issuer key (L2-CLM-1, §10.1.7); a
/// statement the key may not sign is refused, not an outage.
impl access_identity_account::app::claims::ClaimSigner for SignerKeys {
    async fn sign(
        &self,
        environment: EnvironmentId,
        payload: Vec<u8>,
        at: u64,
    ) -> Result<Vec<u8>, NotSigned> {
        let request = Request::SignClaim {
            environment: Environment(*environment.as_bytes()),
            payload,
            at,
        };
        let refused = access_identity_signer::SignerError::Payload.code();
        match self.ask(&request).await {
            Ok(Response::SignedCose { sign1, .. }) => Ok(sign1),
            Ok(Response::Error(code)) if code == refused => Err(NotSigned::Refused(refused)),
            Ok(Response::Error(code)) => Err(access_internal_api::idp::Unavailable(code).into()),
            _ => Err(access_internal_api::idp::Unavailable(String::from("identity-signer")).into()),
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

    async fn jwks(&self, environment: EnvironmentId) -> Result<String, Unavailable> {
        let environment = Environment(*environment.as_bytes());
        match self.ask(&Request::Jwks(environment)).await? {
            Response::Jwks(doc) => return Ok(doc),
            Response::Error(code) if code == UNKNOWN_ENVIRONMENT => {}
            _ => return Err(Unavailable),
        }
        let open = Request::Open {
            environment,
            alg: self.alg,
        };
        if self.ask(&open).await? != Response::Opened {
            return Err(Unavailable);
        }
        match self.ask(&Request::Jwks(environment)).await? {
            Response::Jwks(doc) => Ok(doc),
            _ => Err(Unavailable),
        }
    }

    async fn federation_jwks(&self, environment: EnvironmentId) -> Result<String, Unavailable> {
        match self
            .ask(&Request::FederationJwks(Environment(
                *environment.as_bytes(),
            )))
            .await?
        {
            Response::Jwks(doc) => Ok(doc),
            _ => Err(Unavailable),
        }
    }

    async fn sign_federation(
        &self,
        environment: EnvironmentId,
        typ: &str,
        payload: &[u8],
        at: u64,
    ) -> Result<String, Unavailable> {
        let request = Request::SignFederation {
            environment: Environment(*environment.as_bytes()),
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
