//! What the domain needs from the outside world (OP-63): the environment directory the router role
//! reads (OP-132 m.3), and the environment keys the identity signer publishes (CMP-22b).

pub mod dpop;
pub mod oauth;
pub mod profile;

use std::future::Future;

use access_store::identity::{EnvironmentId, TenantId};

use crate::domain::issuer::Issuer;

/// A live environment as the router sees it.
#[derive(Clone)]
pub struct EnvironmentEntry {
    /// The tenant that owns it (routing context only, TN-1).
    pub tenant: TenantId,
    /// The environment.
    pub environment: EnvironmentId,
    /// Its immutable slug (TN-16).
    pub slug: String,
    /// The issuer stored on its row (§17.9.6).
    pub issuer: Issuer,
}

/// The backing store could not answer; the caller answers 503 (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unavailable")]
pub struct Unavailable;

/// The live environments, read across tenants by the router role (OP-132 m.3).
pub trait Directory: Send + Sync {
    /// The live environment with an issuer whose hostname is `host` (lower-cased, no port).
    fn by_host(
        &self,
        host: &str,
    ) -> impl Future<Output = Result<Option<EnvironmentEntry>, Unavailable>> + Send;

    /// The live environment with an issuer whose slug is `slug`.
    fn by_slug(
        &self,
        slug: &str,
    ) -> impl Future<Output = Result<Option<EnvironmentEntry>, Unavailable>> + Send;

    /// The live environment a verified custom domain `host` (lower-cased, no port) serves (OP-156
    /// m.3 (i)). A directory that cannot tell knows of none.
    fn by_custom_host(
        &self,
        host: &str,
    ) -> impl Future<Output = Result<Option<EnvironmentEntry>, Unavailable>> + Send {
        let _ = host;
        async { Ok(None) }
    }

    /// Every live environment with an issuer, for the start-up JWKS check (§17.9.7).
    fn all(&self) -> impl Future<Output = Result<Vec<EnvironmentEntry>, Unavailable>> + Send;

    /// What the environment's discovery documents say about it: whether a client opted in to the
    /// public `sub` (MD-10) and its governing domain (§9.15.1 k.2). A directory that cannot tell
    /// knows nothing: pairwise only, no Domain Metadata reference.
    fn facts(
        &self,
        environment: &EnvironmentEntry,
    ) -> impl Future<Output = Result<Facts, Unavailable>> + Send {
        let _ = environment;
        async { Ok(Facts::default()) }
    }

    /// The coordinator Needs Attention endpoint the environment names (`idp.environment.coordinator`,
    /// OP-156 m.3 (t)); a directory that cannot tell knows of none.
    fn coordinator(
        &self,
        environment: &EnvironmentEntry,
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send {
        let _ = environment;
        async { Ok(None) }
    }

    /// The environment's OpenID Federation settings (OP-155 m.3 (j)); `None` while it is not a leaf. A
    /// directory that cannot tell knows of none.
    fn federation(
        &self,
        environment: &EnvironmentEntry,
    ) -> impl Future<Output = Result<Option<access_store::oidf::FederationSettingsRow>, Unavailable>>
    + Send {
        let _ = environment;
        async { Ok(None) }
    }
}

/// What a directory knows of an environment beyond its route.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one environment decision the metadata declares"
)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Active clients that read the environment's public `sub` (MD-10).
    pub public_sub_clients: u64,
    /// The environment's governing `DomainID` (PI-7).
    pub domain: Option<[u8; 32]>,
    /// Whether the environment accepts CIMD clients (`idp.client.cimd_policy`, AG-3).
    pub cimd: bool,
    /// Whether the environment's DCR profile is open (`idp.client.dcr_policy`, OP-154 m.3 (j)).
    pub dcr: bool,
    /// Whether the environment offers the device authorization grant (`idp.environment.device_code`).
    pub device_code: bool,
    /// Whether the environment offers CIBA (`idp.environment.ciba`, OP-155 m.3 (l)).
    pub ciba: bool,
    /// Whether the environment publishes `mtls_endpoint_aliases` (`idp.environment.mtls_aliases`, OP-155
    /// m.3 (m)).
    pub mtls_aliases: bool,
    /// Whether the environment lets its clients opt in to front-channel logout (IDP-24).
    pub frontchannel: bool,
    /// Whether an active client opted in to `client_secret_post` (OP-155 m.3 (k)).
    pub secret_post: bool,
    /// Whether an active client opted in to `client_secret_jwt` (OP-155 m.3 (k)).
    pub secret_jwt: bool,
    /// The ML-DSA parameter set of the environment's open post-quantum signing profile (OP-159 m.3
    /// (o)).
    pub signing_profile: Option<access_crypto::jose::JwsAlg>,
}

/// The environment keys the identity signer holds (CMP-22b, OP-143 m.9).
pub trait Keys: Send + Sync {
    /// The signer answers.
    fn ping(&self) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// The current JWKS of `environment`, opening its key set on first use.
    fn jwks(
        &self,
        environment: EnvironmentId,
    ) -> impl Future<Output = Result<String, Unavailable>> + Send;

    /// The environment's OpenID Federation JWKS, its `federation` key set made on first use
    /// (OP-155 m.3 (j)). A signer without one is unavailable.
    fn federation_jwks(
        &self,
        environment: EnvironmentId,
    ) -> impl Future<Output = Result<String, Unavailable>> + Send {
        let _ = environment;
        async { Err(Unavailable) }
    }

    /// Signs `payload` as a compact JWS of the federation type `typ` with the environment's
    /// `federation` key (OP-155 m.3 (j)).
    fn sign_federation(
        &self,
        environment: EnvironmentId,
        typ: &str,
        payload: &[u8],
        at: u64,
    ) -> impl Future<Output = Result<String, Unavailable>> + Send {
        let _ = (environment, typ, payload, at);
        async { Err(Unavailable) }
    }
}
