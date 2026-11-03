//! Account use cases (TN-49, TN-50, TN-68, §12.3.1): each runs in one transaction with its
//! audit row (OPI-6). Accounts are found by identifier only; nothing is linked, merged or
//! authorized by an e-mail address (§12.3.3, E27).

use access_store::accounts::{NewCredential, Revoke};
use access_store::audit::AuditEvent;

use crate::AccountError;
use crate::app::hasher::Hasher;
use crate::app::sealing::{new_subject_key, seal, subject_key};
use crate::app::{Actor, Realm, breach};
use crate::domain::identifier::Identifier;
use crate::domain::password::{ALGORITHM, Password};
use crate::domain::status::{AccountStatus, Deactivation};
use crate::ports::{AccountDb, AccountTx, BreachRanges, Entropy};

/// The password credential kind.
pub const PASSWORD: &str = "password";

/// The stored status, typed.
fn status_of(raw: &str) -> Result<AccountStatus, AccountError> {
    AccountStatus::parse(raw).ok_or(AccountError::Corrupt)
}

async fn audit<T: AccountTx>(
    tx: &mut T,
    event_type: &str,
    who: &Actor<'_>,
    target: &str,
) -> Result<(), AccountError> {
    tx.audit(&AuditEvent {
        event_type,
        actor: who.actor,
        target,
        correlation: who.correlation,
    })
    .await
}

/// Creates a `staged` account with its identifiers and its own DEK under the realm KEK.
///
/// # Errors
/// [`AccountError::IdentifierTaken`] (nothing is created); [`AccountError`].
pub async fn create<D: AccountDb>(
    db: &D,
    realm: &Realm<'_>,
    identifiers: &[Identifier],
    who: &Actor<'_>,
) -> Result<[u8; 16], AccountError> {
    let wrapped = new_subject_key(realm)?;
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let subject = tx
        .insert_subject(AccountStatus::Staged, realm.kek.id(), &wrapped)
        .await?;
    for id in identifiers {
        if !tx.add_identifier(subject, id).await? {
            return Err(AccountError::IdentifierTaken);
        }
    }
    audit(&mut tx, "account.created", who, &realm.external(subject)?).await?;
    tx.commit().await?;
    Ok(subject)
}

/// Moves an account along TN-49. Leaving `active` for `locked` or `suspended` ends its
/// sessions in the same transaction. Deactivation has its own use case.
///
/// # Errors
/// [`AccountError::Transition`], [`AccountError::NotFound`], [`AccountError`].
pub async fn change_status<D: AccountDb>(
    db: &D,
    realm: &Realm<'_>,
    subject: [u8; 16],
    to: AccountStatus,
    who: &Actor<'_>,
) -> Result<(), AccountError> {
    if to == AccountStatus::Deactivated {
        return deactivate(db, realm, subject, who).await.map(drop);
    }
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let row = tx
        .subject(subject, true)
        .await?
        .ok_or(AccountError::NotFound)?;
    let from = status_of(&row.status)?;
    from.transition(to)?;
    if !tx.set_status(subject, from, to).await? {
        return Err(AccountError::Corrupt);
    }
    if from.can_authenticate() && !to.can_authenticate() {
        tx.end_sessions(subject).await?;
    }
    let event = format!("account.{}", to.name());
    audit(&mut tx, &event, who, &realm.external(subject)?).await?;
    tx.commit().await
}

/// What deactivation did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deactivated {
    /// Deactivated now; sessions and refresh families end at this epoch.
    Done {
        /// The new session epoch.
        session_epoch: i64,
    },
    /// The account was already deprovisioned; nothing changed.
    AlreadyDone,
}

/// Deactivates an account (TN-50): status, sessions, refresh families and `session_epoch`
/// change in one transaction with the audit row. Idempotent (§12.3.1). Authority narrowing
/// comes from the `account.status` Claim, not from here; offline projections stay valid for
/// their declared window.
///
/// # Errors
/// [`AccountError::NotFound`], [`AccountError`].
pub async fn deactivate<D: AccountDb>(
    db: &D,
    realm: &Realm<'_>,
    subject: [u8; 16],
    who: &Actor<'_>,
) -> Result<Deactivated, AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let row = tx
        .subject(subject, true)
        .await?
        .ok_or(AccountError::NotFound)?;
    let from = status_of(&row.status)?;
    if from.deactivation() == Deactivation::AlreadyDone {
        tx.commit().await?;
        return Ok(Deactivated::AlreadyDone);
    }
    if !tx
        .set_status(subject, from, AccountStatus::Deactivated)
        .await?
    {
        return Err(AccountError::Corrupt);
    }
    let session_epoch = tx
        .end_sessions(subject)
        .await?
        .ok_or(AccountError::Corrupt)?;
    audit(
        &mut tx,
        "account.deactivated",
        who,
        &realm.external(subject)?,
    )
    .await?;
    tx.commit().await?;
    Ok(Deactivated::Done { session_epoch })
}

/// The policy services a password change needs.
pub struct PasswordServices<'a, B, E> {
    /// The Argon2id service.
    pub hasher: &'a Hasher,
    /// The breach corpus.
    pub ranges: &'a B,
    /// Salts.
    pub entropy: &'a E,
}

/// Sets the account's password (§10.2.1): policy after NFKC, the mandatory breach check,
/// Argon2id, sealed under the subject's DEK. The new credential is stored before the old one
/// is revoked, so the account always keeps a method (TN-68).
///
/// # Errors
/// [`AccountError::Password`]; [`AccountError::BreachUnavailable`] or
/// [`AccountError::Busy`] (`503 + Retry-After`); [`AccountError`].
pub async fn set_password<D: AccountDb, B: BreachRanges, E: Entropy>(
    db: &D,
    realm: &Realm<'_>,
    services: &PasswordServices<'_, B, E>,
    subject: [u8; 16],
    raw: &str,
    who: &Actor<'_>,
) -> Result<[u8; 16], AccountError> {
    let password = Password::new(raw)?;
    breach::check(services.ranges, &password).await?;
    let phc = services
        .hasher
        .hash(&password, services.entropy.salt()?)
        .await?;
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let row = tx
        .subject(subject, true)
        .await?
        .ok_or(AccountError::NotFound)?;
    if matches!(
        status_of(&row.status)?,
        AccountStatus::Tombstone | AccountStatus::Purging
    ) {
        return Err(AccountError::NotFound);
    }
    let dek = subject_key(realm, &row)?;
    let sealed = seal(realm, &dek, &subject, PASSWORD, phc.expose().as_bytes())?;
    let old = tx.credentials(subject, PASSWORD).await?;
    let id = tx
        .insert_credential(&NewCredential {
            subject,
            kind: PASSWORD,
            algorithm: ALGORITHM,
            sealed: &sealed,
        })
        .await?;
    for c in old {
        if tx.revoke(subject, c.id).await? != Revoke::Done {
            return Err(AccountError::Corrupt);
        }
    }
    audit(
        &mut tx,
        "credential.password.set",
        who,
        &realm.external(subject)?,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Removes one credential unless it is the account's last method (TN-68).
///
/// # Errors
/// [`AccountError::LastMethod`], [`AccountError::NotFound`], [`AccountError`].
pub async fn remove_credential<D: AccountDb>(
    db: &D,
    realm: &Realm<'_>,
    subject: [u8; 16],
    credential: [u8; 16],
    who: &Actor<'_>,
) -> Result<(), AccountError> {
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    match tx.revoke(subject, credential).await? {
        Revoke::Done => {}
        Revoke::Missing => return Err(AccountError::NotFound),
        Revoke::LastMethod => return Err(AccountError::LastMethod),
    }
    audit(
        &mut tx,
        "credential.removed",
        who,
        &realm.external(subject)?,
    )
    .await?;
    tx.commit().await
}
