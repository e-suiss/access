//! Organization events and use cases of the identity plane (TN-5, TN-89, TN-90, OP-153 m.3 (b),
//! (o), (p)): what a committed `idp.org.*` Exercise writes besides its rows.

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_events::app::emit;
use access_identity_events::domain::catalog::{IdentityEvent, IdentityKind, TENANT_PREFIX};
use access_store::identity::TenantTx;

use crate::AdminError;

/// Queues `organization.created` or `organization.updated` of `org` in `t` (OP-149 m.4).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn organization_event(
    t: &mut TenantTx,
    ids: &IdKey,
    kind: IdentityKind,
    org: [u8; 16],
    at: u64,
) -> Result<(), AdminError> {
    let id = access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?;
    let tenant = ids.encode(TENANT_PREFIX, *t.tenant().as_bytes())?;
    emit(t, &IdentityEvent::organization(kind, id, &tenant, &org, at)).await?;
    Ok(())
}

/// Queues `membership.added` or `membership.removed` of `subject` in `org` in `t` (OP-151 m.3
/// (i), OP-153 m.4).
///
/// # Errors
/// [`AdminError`].
pub(crate) async fn membership_event(
    t: &mut TenantTx,
    ids: &IdKey,
    kind: IdentityKind,
    (subject, org): ([u8; 16], [u8; 16]),
    at: u64,
) -> Result<(), AdminError> {
    let realm = t.realm().ok_or(AdminError::NoRealm)?;
    let id = access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?;
    let account = ids.encode(SUBJECT_PREFIX, subject)?;
    let event = IdentityEvent::membership(kind, id, realm.as_bytes(), &account, &org, at);
    emit(t, &event).await?;
    Ok(())
}
