//! Use cases (OP-63): producing identity events in the business transaction, the fan-out from
//! the outboxes into per-subscription deliveries, the push courier, and stream management with
//! RFC 8936 poll.

pub mod courier;
pub mod fanout;
pub mod ssf;
pub mod streams;

use access_crypto::jose::JwsAlg;
use access_identity_oauth::domain::issuer::Issuer;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::{Pool, StoreError, idp};

use crate::domain::Invalid;
use crate::domain::catalog::IdentityEvent;
use crate::ports::Unavailable;

/// Queues `event` in the caller's transaction (OP-10, OP-63): it is delivered only if the
/// transaction commits.
///
/// # Errors
/// [`StoreError`]; the caller rolls its transaction back.
pub async fn emit(tx: &mut TenantTx, event: &IdentityEvent) -> Result<(), StoreError> {
    let bytes = event.to_outbox().map_err(|_: Invalid| StoreError::Range)?;
    tx.outbox(event.kind.outbox_kind(), &bytes).await
}

/// The pools delivery uses: `access_app` for realm-scoped rows and the authority outbox,
/// `access_outbox_reader` for the identity outbox and the due queue (OP-131).
#[derive(Clone)]
pub struct Db {
    /// `access_app`.
    pub app: Pool,
    /// `access_outbox_reader`.
    pub reader: Pool,
}

pub(crate) fn down<E>(_: E) -> Unavailable {
    Unavailable
}

/// A realm's issuer and JOSE algorithm, when the realm is active and has an issuer.
pub(crate) async fn realm_signing(
    app: &Pool,
    tenant: TenantId,
    realm: RealmId,
) -> Result<Option<(Issuer, JwsAlg)>, Unavailable> {
    let mut t = TenantTx::begin(app, tenant, realm).await.map_err(down)?;
    let issuer = idp::governance(&mut t)
        .await
        .map_err(down)?
        .and_then(|g| g.issuer)
        .and_then(|i| Issuer::parse(&i).ok());
    let alg = match idp::settings(&mut t).await.map_err(down)?.as_ref() {
        Some(s) if s.jose_alg == "Ed25519" => JwsAlg::Ed25519,
        _ => JwsAlg::Es256,
    };
    t.commit().await.map_err(down)?;
    Ok(issuer.map(|i| (i, alg)))
}
