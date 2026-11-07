//! Queuing identity plane signals (TN-41, OP-10): a signal is written to the identity outbox in
//! the transaction of the change it reports, so it exists exactly when the change does.

use std::future::Future;

use access_store::identity::TenantTx;

use crate::AccountError;
use crate::domain::signal::{RiskLevel, Signal};
use crate::ports::AccountTx;

/// A fresh signal id: 32 random bytes, never derived from the subject (TI-RT10).
///
/// # Errors
/// [`AccountError::Random`].
pub fn fresh_id() -> Result<[u8; 32], AccountError> {
    access_crypto::random::bytes::<32>().map_err(|_| AccountError::Random)
}

/// Queues `signal` in `tx`.
///
/// # Errors
/// [`AccountError::Corrupt`] when it cannot be encoded; [`AccountError`].
pub async fn emit<T: AccountTx>(tx: &mut T, signal: &Signal) -> Result<(), AccountError> {
    let bytes = signal.to_outbox().map_err(|_| AccountError::Corrupt)?;
    tx.outbox(&signal.kind.outbox_kind(), &bytes).await
}

/// Queues `signal` in a realm transaction of the store.
///
/// # Errors
/// [`AccountError`].
pub async fn emit_tenant(tx: &mut TenantTx, signal: &Signal) -> Result<(), AccountError> {
    let bytes = signal.to_outbox().map_err(|_| AccountError::Corrupt)?;
    Ok(tx.outbox(&signal.kind.outbox_kind(), &bytes).await?)
}

/// Where SL2 risk scoring reports a level change of an account (§12.2.4, TN-41): the CAEP
/// `risk-level-change` port. A report only signals; the decision stays with the ADP and a
/// failing engine never turns into an allow (MD-8, CI-2).
pub trait RiskLevels: Send + Sync {
    /// Reports that `subject`'s level moved from `previous` to `current` at `at`, in `tx`.
    fn changed(
        &self,
        tx: &mut TenantTx,
        subject: [u8; 16],
        current: RiskLevel,
        previous: Option<RiskLevel>,
        at: u64,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
}

/// [`RiskLevels`] over the identity outbox.
#[derive(Clone, Copy, Debug, Default)]
pub struct OutboxRiskLevels;

impl RiskLevels for OutboxRiskLevels {
    async fn changed(
        &self,
        tx: &mut TenantTx,
        subject: [u8; 16],
        current: RiskLevel,
        previous: Option<RiskLevel>,
        at: u64,
    ) -> Result<(), AccountError> {
        if previous == Some(current) {
            return Ok(());
        }
        let s = Signal::risk_level(fresh_id()?, subject, current, previous, at);
        emit_tenant(tx, &s).await
    }
}
