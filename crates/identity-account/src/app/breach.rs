//! The breached-password check on set and change (IDP-3, OP-146 m.4 (e), G50). Login never
//! checks. When the check cannot run, the password is not accepted: `503 + Retry-After`.

use crate::AccountError;
use crate::domain::breach::RangeQuery;
use crate::domain::password::{Password, PasswordRejected};
use crate::ports::BreachRanges;

/// Refuses a breached password.
///
/// # Errors
/// [`AccountError::Password`] with [`PasswordRejected::Breached`];
/// [`AccountError::BreachUnavailable`] when the range cannot be read.
pub async fn check<B: BreachRanges>(ranges: &B, password: &Password) -> Result<(), AccountError> {
    let q = RangeQuery::of(password);
    let body = ranges
        .range(q.prefix())
        .await
        .map_err(|_| AccountError::BreachUnavailable)?;
    match q.listed_in(&body) {
        Ok(false) => Ok(()),
        Ok(true) => Err(AccountError::Password(PasswordRejected::Breached)),
        Err(_) => Err(AccountError::BreachUnavailable),
    }
}
