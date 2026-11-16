//! What the SCIM service needs from outside: the environments' PII vault keys and time.

use access_identity_account::app::vault::Vault;
use access_store::identity::{EnvironmentId, TenantId};

/// The environments' PII vault keys (OP-153 m.3 (aa)): a User is read and written only through them.
pub trait Vaults: Send + Sync {
    /// The environment's vault keys; `None` when the token refuses them (fail closed, TI-9).
    fn vault(&self, tenant: TenantId, environment: EnvironmentId) -> Option<Vault>;
}

/// Trusted time, Unix milliseconds.
pub trait Clock: Send + Sync {
    /// Now.
    fn now_ms(&self) -> u64;
}

/// The operating system's clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}
