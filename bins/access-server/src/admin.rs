//! The management API's ports in this process (OP-151 m.3 (b)-(d)): system time and randomness,
//! the in-process rate limiter, cursors under a key derived in the HSM, `Idempotency-Key` answers
//! in PostgreSQL, the realm surfaces and resources over the identity plane ([`realm`]), and the
//! read token verifier and the platform's write path, which stay fail-closed until their lanes
//! wire them: no read token verifies and no platform write is proposed.

pub(crate) mod platform;
pub(crate) mod realm;

use std::time::{SystemTime, UNIX_EPOCH};

use access_crypto::Secret;
use access_http::Limits;
use access_http::api::Api;
use access_http::api::adapters::{MemoryLimiter, NoProposals, NoReadTokens, SivCursors};
use access_http::api::domain::idempotency::{LEASE_MS, RETENTION_MS};
use access_http::api::ports::{
    Begun, Clock, CursorSeal, Entropy, Env, IdempotencyStore, PlatformResources, RateLimiter,
    RealmResources, Unavailable,
};
use access_http::console::Console;
use access_http::login::Assets;
use access_identity_admin::ports::{Decider, Governance, Instances};
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
    realms: realm::Realms<P>,
}

impl<P> ServerApi<P> {
    /// The ports over the app pool, with the cursor key derived in `keys`, the management
    /// origin from configuration (§17.9.6: never from a request) and the realms behind it.
    pub(crate) fn new(
        app: Pool,
        keys: &KeyStore,
        origin: String,
        realms: realm::Realms<P>,
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
            realms,
        })
    }
}

/// What the realm surface needs of the identity plane.
pub(crate) trait RealmPlane:
    Decider + Governance + Instances + realm::LiveKeys + Clone + Send + Sync + 'static
{
}

impl<P: Decider + Governance + Instances + realm::LiveKeys + Clone + Send + Sync + 'static>
    RealmPlane for P
{
}

/// The management router over this process's ports, with the console's BFF under
/// `/console/*` (TN-128); its origin is the configured `suiss.management_api` (§17.9.6: never
/// derived from `Host`).
pub(crate) fn router<P: RealmPlane>(
    config: &crate::config::Config,
    app: Pool,
    keys: &KeyStore,
    realms: realm::Realms<P>,
    console_assets: Option<Assets>,
) -> Result<axum::Router, String> {
    let origin = config
        .suiss
        .as_ref()
        .map(|s| s.management_api.clone())
        .ok_or("no suiss section")?;
    let api = Api::new(
        ServerApi::new(app, keys, origin.clone(), realms)?,
        Limits::default(),
    );
    let admin = access_http::api::router(&api).map_err(|e| e.to_string())?;
    let console = Console::new(
        ServerConsole::new(admin.clone(), origin),
        Limits::default(),
        console_assets,
    );
    Ok(access_http::console::router(&console).merge(admin))
}

impl<P: RealmPlane> Env for ServerApi<P> {
    type Tokens = NoReadTokens;
    type Surfaces = realm::Realms<P>;
    type Proposals = NoProposals;
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

    fn tokens(&self) -> &NoReadTokens {
        &NoReadTokens
    }

    fn surfaces(&self) -> &realm::Realms<P> {
        &self.realms
    }

    fn proposals(&self) -> &NoProposals {
        &NoProposals
    }

    fn idempotency(&self) -> &PgIdempotency {
        &self.idempotency
    }

    fn origin(&self) -> &str {
        &self.origin
    }

    fn realm(&self) -> &dyn RealmResources {
        &self.realms
    }

    fn platform(&self) -> &dyn PlatformResources {
        &self.realms
    }

    fn jobs(&self) -> &dyn access_http::api::ports::Jobs {
        &self.realms
    }
}
