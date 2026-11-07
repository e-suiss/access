//! The identity plane signals a configuration change queues in its own transaction (TN-41,
//! CR-27): a dropped realm key is a `credential-compromise` of the realm with back-channel
//! logout for every client that registered an endpoint; a claim mapper change is a
//! `token-claims-change` for every subject with a live grant.

use access_identity_account::domain::signal::{Signal, realm_key_compromise};
use access_store::identity::TenantTx;

use crate::AdminError;
use crate::domain::Change;

async fn queue(t: &mut TenantTx, s: &Signal) -> Result<(), AdminError> {
    let bytes = s.to_outbox().map_err(|_| AdminError::Encode)?;
    Ok(t.outbox(&s.kind.outbox_kind(), &bytes).await?)
}

fn id() -> Result<[u8; 32], AdminError> {
    access_identity_account::app::signal::fresh_id().map_err(|_| AdminError::Encode)
}

/// Queues the signals of `change`, applied at `at`, in `t`.
///
/// # Errors
/// [`AdminError`]; the caller rolls its transaction back.
pub(crate) async fn queue_for(
    t: &mut TenantTx,
    change: &Change,
    at: u64,
) -> Result<(), AdminError> {
    match change {
        // CR-27, §13.2
        Change::KeyDrop { .. } => {
            queue(t, &realm_key_compromise(id()?, at)).await?;
            let grants = t.backchannel_grants().await?;
            t.queue_backchannel_logout(&grants).await?;
        }
        // TN-41
        Change::MapperSet { claim, .. } => {
            for subject in t.granted_subjects().await? {
                let s = Signal::token_claims_change(id()?, subject, &[claim.as_str()], at);
                queue(t, &s).await?;
            }
        }
        _ => {}
    }
    Ok(())
}
