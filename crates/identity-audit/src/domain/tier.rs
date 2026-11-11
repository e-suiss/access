//! The cold tier of the identity audit log (OP-40, OP-73 m.4, OP-158 m.3 (w)): where a
//! partition's copy lives and what makes the copy the partition's.

use access_store::audit::AuditRow;
use suiss_ledger::Hash;
use suiss_ledger::merkle::Frontier;

use crate::AuditError;
use crate::domain::leaf;

/// The prefix of every cold object of the identity audit log.
pub const PREFIX: &str = "identity-audit";

/// The cold object of `partition` of `month` (year, month).
#[must_use]
pub fn object_key(partition: &str, (year, month): (i32, u32)) -> String {
    format!("{PREFIX}/{year:04}/{month:02}/{partition}.parquet")
}

/// The RFC 9162 root of `rows`' leaves in their order: the partition root its copy is checked
/// against (OP-158 m.3 (w)).
///
/// # Errors
/// [`AuditError`].
pub fn root(rows: &[AuditRow]) -> Result<Hash, AuditError> {
    let mut frontier = Frontier::default();
    for row in rows {
        frontier.push(leaf(row)?)?;
    }
    Ok(frontier.root())
}

/// Whether `copy` is `rows`: as many rows, the same root. Returns the root.
///
/// # Errors
/// [`AuditError::ColdMismatch`] otherwise.
pub fn check_copy(rows: &[AuditRow], copy: &[AuditRow]) -> Result<Hash, AuditError> {
    let want = root(rows)?;
    if copy.len() != rows.len() || root(copy)? != want {
        return Err(AuditError::ColdMismatch);
    }
    Ok(want)
}

#[cfg(test)]
mod tests;
