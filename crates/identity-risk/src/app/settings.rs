//! The realm's protection mode and canary accounts as configuration (MD-14, EI-25, OP-151 m.3
//! (o)). Both are `idp.*` domain actions: the management surface compiles a change to an
//! Exercise carrying the caller's AIS, and the write below happens only under the committed ALLOW
//! bound in the same transaction; the database refuses any other write (TN-110).
//!
//! | Action | Tier |
//! |---|---|
//! | `idp.realm.protection_mode` | CT1 when it only tightens (monitor → enforce, a later SL2 stage, more denied ASNs); CT2 when anything loosens |
//! | `idp.account.canary` | CT2: a canary account is a credential the realm plants |

use access_store::identity::TenantTx;
use access_store::idp::Bound;
use access_store::risk::ProtectionRow;

use crate::RiskError;
use crate::domain::mode::{InvalidMode, ProtectionMode, Tier, tier};

/// The `idp.*` label of making an account a canary (§4.4).
pub const CANARY_ACTION: &str = "idp.account.canary";

/// The tier of `idp.account.canary`.
pub const CANARY_TIER: Tier = Tier::Ct2;

fn row_of(m: &ProtectionMode) -> ProtectionRow {
    ProtectionRow {
        bot: m.bot.name().to_owned(),
        suspicious_ip: m.suspicious_ip.name().to_owned(),
        breached_password: m.breached_password.name().to_owned(),
        sl2: m.sl2.name().to_owned(),
        denied_asns: m.denied_asns.iter().copied().collect(),
    }
}

fn mode_of(r: &ProtectionRow) -> Result<ProtectionMode, InvalidMode> {
    ProtectionMode::parse(
        &[
            ("bot", r.bot.as_str()),
            ("suspicious_ip", r.suspicious_ip.as_str()),
            ("breached_password", r.breached_password.as_str()),
        ],
        &r.sl2,
        &r.denied_asns,
    )
}

/// The canonical text of a mode, whose digest an intent binds.
#[must_use]
pub fn canonical(m: &ProtectionMode) -> String {
    let asns: Vec<String> = m.denied_asns.iter().map(u32::to_string).collect();
    format!(
        "bot={};suspicious_ip={};breached_password={};brute_force=enforce;sl2={};denied_asns={}",
        m.bot.name(),
        m.suspicious_ip.name(),
        m.breached_password.name(),
        m.sl2.name(),
        asns.join(",")
    )
}

/// The realm's mode; the defaults when none was decided.
///
/// # Errors
/// [`RiskError::Corrupt`] for a stored value outside the model; [`RiskError`].
pub async fn mode(tx: &mut TenantTx) -> Result<ProtectionMode, RiskError> {
    match tx.protection().await? {
        Some(r) => mode_of(&r).map_err(|_| RiskError::Corrupt),
        None => Ok(ProtectionMode::default()),
    }
}

/// The tier of changing the realm's mode to `next`.
///
/// # Errors
/// [`RiskError`].
pub async fn change_tier(tx: &mut TenantTx, next: &ProtectionMode) -> Result<Tier, RiskError> {
    let current = mode(tx).await?;
    Ok(tier(&current, next))
}

/// Writes `next` under `bound`, a committed `idp.realm.protection_mode` ALLOW of this
/// transaction.
///
/// # Errors
/// [`RiskError`]; an unbound decision fails in the database.
pub async fn apply_mode(
    tx: &mut TenantTx,
    bound: &Bound,
    next: &ProtectionMode,
) -> Result<(), RiskError> {
    tx.set_protection(bound, &row_of(next)).await?;
    tracing::info!(
        event = "risk.protection_mode.changed",
        sl2 = next.sl2.name(),
        suspicious_ip = next.suspicious_ip.name(),
        breached_password = next.breached_password.name(),
        bot = next.bot.name(),
        "realm protection mode changed"
    );
    Ok(())
}

/// Makes `subject` a canary account under `bound`, a committed `idp.account.canary` ALLOW of
/// this transaction; false when it already is one.
///
/// # Errors
/// [`RiskError`]; an unbound decision fails in the database.
pub async fn mark_canary(
    tx: &mut TenantTx,
    bound: &Bound,
    subject: [u8; 16],
) -> Result<bool, RiskError> {
    Ok(tx.mark_canary(bound, subject).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-151 m.3 (o): the stored form reads back to the same mode
    #[test]
    fn rows_round_trip() {
        let m = ProtectionMode::parse(&[("suspicious_ip", "enforce")], "stepup", &[7, 3]).unwrap();
        assert_eq!(mode_of(&row_of(&m)).unwrap(), m);
        assert_eq!(
            canonical(&m),
            "bot=monitor;suspicious_ip=enforce;breached_password=monitor;brute_force=enforce;\
             sl2=stepup;denied_asns=3,7"
        );
    }
}
