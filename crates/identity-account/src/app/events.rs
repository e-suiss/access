//! Queues identity events in the business transaction (OP-151 m.3 (i), TI-7): an event is
//! delivered only if the change commits, and the change never waits for its delivery (INV-24).

use crate::AccountError;
use crate::app::Realm;
use crate::domain::events::{AccountEvent, CredentialChange, EventOrder};
use crate::domain::status::AccountStatus;
use crate::ports::AccountTx;

/// A fresh event id.
///
/// # Errors
/// [`AccountError::Random`].
pub fn new_id() -> Result<[u8; 32], AccountError> {
    access_crypto::random::bytes::<32>().map_err(|_| AccountError::Random)
}

/// Queues `order` in the caller's transaction.
///
/// # Errors
/// [`AccountError`]; the caller rolls its transaction back.
pub async fn emit<T: AccountTx>(tx: &mut T, order: &EventOrder) -> Result<(), AccountError> {
    let bytes = order.to_outbox().map_err(|_| AccountError::Corrupt)?;
    tx.outbox(order.kind.outbox_kind(), &bytes).await
}

/// Queues `account.created`.
///
/// # Errors
/// [`AccountError`].
pub async fn created<T: AccountTx>(
    tx: &mut T,
    realm: &Realm<'_>,
    subject: [u8; 16],
) -> Result<(), AccountError> {
    let at = tx.server_time().await?;
    let order = EventOrder::created(
        new_id()?,
        realm.realm.as_bytes(),
        &realm.external(subject)?,
        at,
    );
    emit(tx, &order).await
}

/// Queues the event of a status move, if it names one.
///
/// # Errors
/// [`AccountError`].
pub async fn status<T: AccountTx>(
    tx: &mut T,
    realm: &Realm<'_>,
    subject: [u8; 16],
    from: AccountStatus,
    to: AccountStatus,
) -> Result<(), AccountError> {
    let Some(kind) = AccountEvent::of_status(from, to) else {
        return Ok(());
    };
    let at = tx.server_time().await?;
    let order = EventOrder::status(
        kind,
        new_id()?,
        realm.realm.as_bytes(),
        &realm.external(subject)?,
        to,
        at,
    );
    emit(tx, &order).await
}

/// Queues `session.revoked` at the new epoch `rev`.
///
/// # Errors
/// [`AccountError`].
pub async fn sessions_ended<T: AccountTx>(
    tx: &mut T,
    realm: &Realm<'_>,
    subject: [u8; 16],
    rev: i64,
) -> Result<(), AccountError> {
    let at = tx.server_time().await?;
    let order = EventOrder::session_revoked(
        new_id()?,
        realm.realm.as_bytes(),
        &realm.external(subject)?,
        rev,
        at,
    );
    emit(tx, &order).await
}

/// Queues `credential.changed`.
///
/// # Errors
/// [`AccountError`].
pub async fn credential<T: AccountTx>(
    tx: &mut T,
    realm: &Realm<'_>,
    subject: [u8; 16],
    kind: &str,
    change: CredentialChange,
) -> Result<(), AccountError> {
    let at = tx.server_time().await?;
    let order = EventOrder::credential(
        new_id()?,
        realm.realm.as_bytes(),
        &realm.external(subject)?,
        kind,
        change,
        at,
    );
    emit(tx, &order).await
}
