//! The management API's ports in this process (OP-151 m.3 (b)-(d)): system time and randomness,
//! the in-process rate limiter, cursors under a key derived in the HSM, `Idempotency-Key` answers
//! in PostgreSQL, the environment surfaces and resources over the identity plane ([`environment`]), and the
//! read tokens the environments issue ([`tokens`], TN-130); the platform surface is [`platform`].

// OP-157 m.3 (v)
pub(crate) mod environment;
pub(crate) mod offboarding;
pub(crate) mod platform;
pub(crate) mod tenant;
pub(crate) mod tokens;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use access_crypto::Secret;
use access_http::Limits;
use access_http::api::Api;
use access_http::api::adapters::{MemoryLimiter, SivCursors};
use access_http::api::domain::idempotency::{LEASE_MS, RETENTION_MS};
use access_http::api::ports::{
    Begun, Clock, CursorSeal, Entropy, Env, EnvironmentResources, IdempotencyStore,
    PlatformResources, RateLimiter, Unavailable,
};
use access_http::console::Console;
use access_http::login::Assets;
use access_identity_admin::ports::{Decider, Governance, Instances};
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::domain::dpop::DpopProfile;
use access_store::Pool;
use access_store::api_idempotency;
use suiss_crypto::pkcs11::KeyStore;

use crate::console::ServerConsole;
use crate::login::ID_KEY_ROOT;

/// The derivation context of the cursor key under the cell's id-key root.
const CURSOR_CONTEXT: &[u8] = b"access/admin-cursor/v1";

/// Wall-clock time.
pub(crate) struct WallClock;

impl WallClock {
    /// Unix milliseconds; 0 before the epoch.
    pub(crate) fn now() -> u64 {
        Self.now_ms().unwrap_or(0)
    }
}

/// Wall-clock time now, Unix milliseconds.
///
/// # Errors
/// [`Unavailable`].
pub(crate) fn now_ms() -> Result<u64, Unavailable> {
    WallClock.now_ms()
}

impl Clock for WallClock {
    fn now_ms(&self) -> Result<u64, Unavailable> {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Unavailable)?;
        u64::try_from(d.as_millis()).map_err(|_| Unavailable)
    }
}

/// The operating system's random source through aws-lc-rs.
pub(crate) struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        for chunk in out.chunks_mut(32) {
            let bytes = access_crypto::random::bytes::<32>().map_err(|_| Unavailable)?;
            for (d, s) in chunk.iter_mut().zip(bytes) {
                *d = s;
            }
        }
        Ok(())
    }
}

/// `Idempotency-Key` answers in `access_ops.api_idempotency` (TN-126).
pub(crate) struct PgIdempotency(Pool);

impl IdempotencyStore for PgIdempotency {
    async fn begin(
        &self,
        scope: [u8; 32],
        request: [u8; 32],
        now_ms: u64,
    ) -> Result<Begun, Unavailable> {
        let begun =
            api_idempotency::begin(&self.0, &scope, &request, now_ms, LEASE_MS, RETENTION_MS)
                .await
                .map_err(|e| {
                    tracing::warn!(event = "api.idempotency.unavailable", outcome = "error", error = %e, "idempotency store failed");
                    Unavailable
                })?;
        Ok(match begun {
            api_idempotency::Begun::Run => Begun::Run,
            api_idempotency::Begun::Replay(a) => Begun::Replay(a),
            api_idempotency::Begun::Reused => Begun::Reused,
            api_idempotency::Begun::Running => Begun::Running,
        })
    }

    async fn finish(
        &self,
        scope: [u8; 32],
        request: [u8; 32],
        answer: Option<Vec<u8>>,
    ) -> Result<(), Unavailable> {
        api_idempotency::finish(&self.0, &scope, &request, answer.as_deref())
            .await
            .map_err(|_| Unavailable)
    }
}

/// The management API's ports in this process.
pub(crate) struct ServerApi<P> {
    limiter: MemoryLimiter,
    cursors: SivCursors,
    idempotency: PgIdempotency,
    origin: String,
    environments: environment::Environments<P>,
    tokens: Arc<tokens::ManagementTokens<P>>,
}

impl<P> ServerApi<P> {
    /// The ports over the app pool, with the cursor key derived in `keys`, the management
    /// origin from configuration (§17.9.6: never from a request), the environments behind it and the
    /// read token verifier.
    pub(crate) fn new(
        app: Pool,
        keys: &KeyStore,
        origin: String,
        environments: environment::Environments<P>,
        tokens: Arc<tokens::ManagementTokens<P>>,
    ) -> Result<Self, String> {
        let key = keys
            .mac(ID_KEY_ROOT)
            .and_then(|m| m.mac(CURSOR_CONTEXT))
            .map_err(|e| e.to_string())?;
        Ok(Self {
            limiter: MemoryLimiter::default(),
            cursors: SivCursors::new(Secret::new(key)),
            idempotency: PgIdempotency(app),
            origin,
            environments,
            tokens,
        })
    }
}

/// What the environment surface and the console need of the identity plane.
pub(crate) trait EnvironmentPlane:
    Decider
    + Governance
    + Instances
    + environment::LiveKeys
    + access_identity_ui::ports::DeviceInstances
    + access_http::console::ports::AcceptedActions
    + Clone
    + Send
    + Sync
    + 'static
{
}

impl<P> EnvironmentPlane for P where
    P: Decider
        + Governance
        + Instances
        + environment::LiveKeys
        + access_identity_ui::ports::DeviceInstances
        + access_http::console::ports::AcceptedActions
        + Clone
        + Send
        + Sync
        + 'static
{
}

/// The public listener's routes the management process calls in process: the environments'
/// authorization servers for the console's sign-in, and ADP for its forwarded reads.
pub(crate) struct InProcessRoutes {
    /// The environment authorization servers.
    pub(crate) oauth: axum::Router,
    /// ADP.
    pub(crate) adp: axum::Router,
}

/// The management router over this process's ports, with the console's BFF under
/// `/console/*` (TN-128); its origin is the configured `suiss.management_api` (§17.9.6: never
/// derived from `Host`).
pub(crate) fn router<P: EnvironmentPlane>(
    (origin, identity_signer): (String, std::path::PathBuf),
    keys: &Arc<KeyStore>,
    environments: environment::Environments<P>,
    routes: InProcessRoutes,
    console_assets: Option<Assets>,
) -> Result<axum::Router, String> {
    let signer = || SignerKeys::new(identity_signer.clone());
    let router_pool = environments.router.clone();
    let directory = || PgDirectory::new(router_pool.clone());
    // OP-151 m.12 (b)
    crate::console::sign_in::client_key(keys)?;
    let tokens = Arc::new(tokens::ManagementTokens {
        directory: directory(),
        signer: signer(),
        app: environments.app.clone(),
        plane: environments.plane.clone(),
        dpop: DpopProfile::default(),
        platform: environments.platform.clone(),
    });
    let (app, ids, plane) = (
        environments.app.clone(),
        environments.ids.clone(),
        environments.plane.clone(),
    );
    let ips = Arc::clone(&environments.ips);
    let api = Api::new(
        ServerApi::new(
            app.clone(),
            keys,
            origin.clone(),
            environments,
            Arc::clone(&tokens),
        )?,
        Limits::default(),
    );
    let admin = access_http::api::router(&api).map_err(|e| e.to_string())?;
    let parts = crate::console::Parts {
        admin: admin.clone(),
        adp: routes.adp,
        sessions: crate::console::sessions::PgConsoleSessions {
            app: app.clone(),
            directory: directory(),
            ids: Arc::clone(&ids),
        },
        network: crate::console::sessions::EnvironmentBinding {
            app: app.clone(),
            directory: directory(),
        },
        sign_in: crate::console::sign_in::EnvironmentSignIn {
            public: routes.oauth,
            directory: directory(),
            app: app.clone(),
            keys: Arc::clone(keys),
            ids,
            signer: signer(),
            origin: origin.clone(),
        },
        accepted: plane.clone(),
        devices: crate::console::devices::ConsoleDevices {
            app,
            instances: plane,
            ips,
        },
        grants: tokens::ConsoleGrants(tokens),
    };
    let console = Console::new(
        ServerConsole::new(parts, origin),
        Limits::default(),
        console_assets,
    );
    Ok(access_http::console::router(&console).merge(admin))
}

impl<P: EnvironmentPlane> Env for ServerApi<P> {
    type Tokens = tokens::ManagementTokens<P>;
    type Surfaces = environment::Environments<P>;
    type Idempotency = PgIdempotency;

    fn clock(&self) -> &dyn Clock {
        &WallClock
    }

    fn entropy(&self) -> &dyn Entropy {
        &OsEntropy
    }

    fn limiter(&self) -> &dyn RateLimiter {
        &self.limiter
    }

    fn cursors(&self) -> &dyn CursorSeal {
        &self.cursors
    }

    fn tokens(&self) -> &tokens::ManagementTokens<P> {
        &self.tokens
    }

    fn surfaces(&self) -> &environment::Environments<P> {
        &self.environments
    }

    fn idempotency(&self) -> &PgIdempotency {
        &self.idempotency
    }

    fn origin(&self) -> &str {
        &self.origin
    }

    fn environment(&self) -> &dyn EnvironmentResources {
        &self.environments
    }

    fn platform(&self) -> &dyn PlatformResources {
        &self.environments
    }

    fn jobs(&self) -> &dyn access_http::api::ports::Jobs {
        &self.environments
    }
}
