//! What the edge service needs from outside: the gateway registry and the realms' vault keys.

use std::future::Future;

use access_identity_account::app::vault::Vault;
use access_internal_api::edge::GatewayUri;
use access_store::identity::{RealmId, TenantId};

use crate::EdgeError;
use crate::domain::Gateway;

/// Finds the live gateway a certificate names.
pub trait Registry: Send + Sync {
    /// The one live gateway `uri` whose certificate has SHA-256 `cert`; `None` when none or more
    /// than one match.
    fn gateway(
        &self,
        uri: &GatewayUri,
        cert: &[u8; 32],
    ) -> impl Future<Output = Result<Option<Gateway>, EdgeError>> + Send;
}

/// The realms' PII vault keys (OP-153 m.3 (aa)): an identifier is read only through them.
pub trait Vaults: Send + Sync {
    /// The realm's vault keys; `None` when the token refuses them (fail closed, TI-9).
    fn vault(&self, tenant: TenantId, realm: RealmId) -> Option<Vault>;
}
