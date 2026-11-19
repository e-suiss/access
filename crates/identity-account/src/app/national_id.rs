//! An account's national identity number (TN-158): sealed among its profile fields, and held by
//! one account per environment through its environment-keyed blind index.

use crate::AccountError;
use crate::adapters::pg::PgTx;
use crate::app::vault::{self, Vault};

fn index(tx: &PgTx, vault: &Vault, scheme: &str, number: &str) -> Result<[u8; 32], AccountError> {
    let environment = tx.0.environment().ok_or(AccountError::Corrupt)?;
    vault.index_of(
        tx.0.tenant().as_bytes(),
        environment.as_bytes(),
        &format!("national-id:{scheme}:{number}"),
    )
}

/// The account that holds `number` of `scheme` in the transaction's environment.
///
/// # Errors
/// [`AccountError`].
pub async fn holder(
    tx: &mut PgTx,
    vault: &Vault,
    scheme: &str,
    number: &str,
) -> Result<Option<[u8; 16]>, AccountError> {
    let i = index(tx, vault, scheme, number)?;
    Ok(tx.0.national_id_holder(scheme, &i).await?)
}

/// Keeps `number` of `scheme`, normalized by its scheme, as `subject`'s; `false` when another
/// account holds it or the subject has a number already.
///
/// # Errors
/// [`AccountError`].
pub async fn keep(
    tx: &mut PgTx,
    vault: &Vault,
    subject: [u8; 16],
    (scheme, number): (&str, &str),
) -> Result<bool, AccountError> {
    let i = index(tx, vault, scheme, number)?;
    if !tx.0.insert_national_id(subject, scheme, &i).await? {
        return Ok(false);
    }
    vault::set_profile(&mut tx.0, vault, subject, "national_id", number).await?;
    vault::set_profile(&mut tx.0, vault, subject, "national_id_scheme", scheme).await?;
    Ok(true)
}
