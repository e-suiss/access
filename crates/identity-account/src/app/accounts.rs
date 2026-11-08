//! Account use cases (TN-49, TN-50, TN-68, §12.3.1): each runs in one transaction with its
//! audit row (OPI-6). Accounts are found by identifier only; nothing is linked, merged or
//! authorized by an e-mail address (§12.3.3, E27).

use access_kernel::claim::body::AuthenticatorKind;
use access_store::accounts::{NewCredential, Revoke};
use access_store::audit::AuditEvent;

use crate::AccountError;
use crate::app::events;
use crate::app::hasher::Hasher;
use crate::app::sealing::{new_subject_key, seal_password, subject_key};
use crate::app::signal::{emit as signal, fresh_id};
use crate::app::{Actor, Naming, Realm, breach};
use crate::domain::events::CredentialChange;
use crate::domain::identifier::{Identifier, IdentifierKind};
use crate::domain::password::{ALGORITHM, Password};
use crate::domain::signal::{ChangeType, CredentialType, Initiator, Signal};
use crate::domain::status::{AccountStatus, Deactivation};
use crate::ports::{AccountDb, AccountTx, BreachRanges, Entropy};

/// The password credential kind.
pub const PASSWORD: &str = "password";

/// The credential kind of a TOTP seed.
pub const TOTP: &str = "totp";

/// The credential kind of a passkey's identity credential row.
pub const PASSKEY: &str = "webauthn";

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

/// TN-41, TN-43: the CAEP `session-revoked` of ending the subject's sessions and, when the
/// account can no longer sign in, the RISC `account-disabled`, in the change's transaction.
async fn ended_signals<T: AccountTx>(
    tx: &mut T,
    subject: [u8; 16],
    disabled: bool,
) -> Result<(), AccountError> {
    let at = tx.server_time().await?;
    signal(
        tx,
        &Signal::session_revoked(fresh_id()?, subject, Initiator::Admin, at),
    )
    .await?;
    if disabled {
        signal(tx, &Signal::account_disabled(fresh_id()?, subject, at)).await?;
    }
    Ok(())
}

/// TN-41: the CAEP `credential-change` of a credential change, in its transaction.
async fn credential_signal<T: AccountTx>(
    tx: &mut T,
    subject: [u8; 16],
    credential: CredentialType,
    change: ChangeType,
) -> Result<(), AccountError> {
    let at = tx.server_time().await?;
    let s = Signal::credential_change(fresh_id()?, subject, credential, change, at);
    signal(tx, &s).await
}

/// Queues the realm issuer's `account_status` Claim of a status change in the same transaction
/// (TN-49, §12.3.1, OP-150 L2): authority narrowing comes from this Claim, never from the
/// identity plane writing authority state.
///
/// # Errors
/// [`AccountError`].
pub async fn status_claim<T: AccountTx>(
    tx: &mut T,
    subject: [u8; 16],
    to: AccountStatus,
) -> Result<(), AccountError> {
    if !access_kernel::claim::body::ACCOUNT_STATUSES.contains(&to.name()) {
        return Ok(());
    }
    let at = tx.server_time().await?;
    crate::app::claims::emit(
        tx,
        &crate::domain::claims::account_status(subject, to.name(), at),
    )
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
    // OP-151 m.3 (i)
    events::created(&mut tx, realm, subject).await?;
    tx.commit().await?;
    Ok(subject)
}

/// Self-service registration (TN-135, OP-151 m.3 (j)): the realm's `pre_registration` hook is
/// asked first and may only refuse; any failure to answer refuses (MD-8). Then [`create`].
///
/// # Errors
/// [`AccountError`]; a refusal is [`Registered::Refused`], not an error.
pub async fn register<D: AccountDb>(
    db: &D,
    realm: &Realm<'_>,
    identifiers: &[Identifier],
    who: &Actor<'_>,
    hooks: &(dyn access_identity_hooks::ports::HookCaller + Sync),
) -> Result<Registered, AccountError> {
    use access_identity_hooks::domain::{Call, Outcome, PreRegistration};
    let email = identifiers
        .iter()
        .find(|i| i.kind() == IdentifierKind::Email)
        .map(|i| String::from(i.value()));
    let call = Call::PreRegistration(PreRegistration {
        identifier_kinds: identifiers.iter().map(|i| i.kind().name()).collect(),
        email,
    });
    match hooks.call(realm.tenant, realm.realm, call).await {
        Outcome::Proceed { .. } => Ok(Registered::Created(
            create(db, realm, identifiers, who).await?,
        )),
        Outcome::Refused(reason) => Ok(Registered::Refused(reason)),
    }
}

/// What registration did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Registered {
    /// The new `staged` subject.
    Created([u8; 16]),
    /// The `pre_registration` hook refused or did not answer (TN-135, MD-8).
    Refused(access_identity_hooks::domain::Refusal),
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
    status_moved(&mut tx, realm, subject, (from, to), who).await?;
    tx.commit().await
}

/// What follows a status move of `subject` in its transaction, once the status is written
/// (TN-49, TN-41, OP-150 L2, OP-151 m.3 (i)): leaving the states that sign in ends the
/// subject's sessions with their signals and event, and every move queues the realm issuer's
/// `account_status` Claim, its event and its audit row. An `idp.account.*` decision writes the
/// status bound to the decision and then this (TN-110).
///
/// # Errors
/// [`AccountError`]; the caller rolls its transaction back.
pub async fn status_moved<T: AccountTx>(
    tx: &mut T,
    realm: &impl Naming,
    subject: [u8; 16],
    (from, to): (AccountStatus, AccountStatus),
    who: &Actor<'_>,
) -> Result<(), AccountError> {
    if from.can_authenticate() && !to.can_authenticate() {
        let rev = tx.end_sessions(subject).await?;
        ended_signals(tx, subject, true).await?;
        // OP-151 m.3 (i)
        if let Some(rev) = rev {
            events::sessions_ended(tx, realm, subject, rev).await?;
        }
    }
    status_claim(tx, subject, to).await?;
    events::status(tx, realm, subject, from, to).await?;
    let event = format!("account.{}", to.name());
    audit(tx, &event, who, &realm.external(subject)?).await
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
    ended_signals(&mut tx, subject, true).await?;
    status_claim(&mut tx, subject, AccountStatus::Deactivated).await?;
    // OP-151 m.3 (i)
    events::sessions_ended(&mut tx, realm, subject, session_epoch).await?;
    events::status(&mut tx, realm, subject, from, AccountStatus::Deactivated).await?;
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
    let id = store_password(&mut tx, realm, subject, phc.expose(), who).await?;
    tx.commit().await?;
    Ok(id)
}

/// Stores the hashed password `phc` of `subject` in `tx`, as [`set_password`] does after its
/// policy and breach checks: the new credential before the old ones are revoked (TN-68), with
/// their Claims, signal, event and audit row. A recovery's rebind uses it inside the
/// transaction that consumes its evidence (TN-54).
///
/// # Errors
/// [`AccountError::NotFound`] for a deleted account; [`AccountError`].
pub async fn store_password<T: AccountTx>(
    tx: &mut T,
    realm: &Realm<'_>,
    subject: [u8; 16],
    phc: &str,
    who: &Actor<'_>,
) -> Result<[u8; 16], AccountError> {
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
    let sealed = seal_password(realm, &dek, &subject, phc.as_bytes())?;
    let old = tx.credentials(subject, PASSWORD).await?;
    let replaced = if old.is_empty() {
        CredentialChange::Added
    } else {
        CredentialChange::Replaced
    };
    let id = tx
        .insert_credential(&NewCredential {
            subject,
            kind: PASSWORD,
            algorithm: ALGORITHM,
            sealed: &sealed,
        })
        .await?;
    let change = if old.is_empty() {
        ChangeType::Create
    } else {
        ChangeType::Update
    };
    let at = tx.server_time().await?;
    for c in old {
        if tx.revoke(subject, c.id).await? != Revoke::Done {
            return Err(AccountError::Corrupt);
        }
        // §10.1.3, OP-150 m.12 (j)
        crate::app::claims::emit(
            tx,
            &crate::domain::claims::authenticator_removed(
                subject,
                AuthenticatorKind::Password,
                &c.id,
                at,
            ),
        )
        .await?;
    }
    // §10.1.3, OP-150 m.12 (j)
    crate::app::claims::emit(
        tx,
        &crate::domain::claims::secret_binding(subject, AuthenticatorKind::Password, &id, at),
    )
    .await?;
    credential_signal(tx, subject, CredentialType::Password, change).await?;
    // OP-151 m.3 (i)
    events::credential(tx, realm, subject, PASSWORD, replaced).await?;
    audit(
        tx,
        "credential.password.set",
        who,
        &realm.external(subject)?,
    )
    .await?;
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
    let passkey = tx
        .credentials(subject, PASSKEY)
        .await?
        .iter()
        .any(|c| c.id == credential);
    let kind = if passkey {
        PASSKEY
    } else {
        credential_kind(&mut tx, subject, credential).await?
    };
    let signal_kind = match kind {
        PASSKEY => CredentialType::Fido2,
        PASSWORD => CredentialType::Password,
        _ => CredentialType::App,
    };
    match tx.revoke(subject, credential).await? {
        Revoke::Done => {}
        Revoke::Missing => return Err(AccountError::NotFound),
        Revoke::LastMethod => return Err(AccountError::LastMethod),
    }
    credential_signal(&mut tx, subject, signal_kind, ChangeType::Revoke).await?;
    // IDP-2, OP-150 L2, OP-150 m.12 (j)
    let bound = match kind {
        PASSKEY => Some(AuthenticatorKind::Passkey),
        PASSWORD => Some(AuthenticatorKind::Password),
        TOTP => Some(AuthenticatorKind::Totp),
        _ => None,
    };
    if let Some(bound) = bound {
        let at = tx.server_time().await?;
        crate::app::claims::emit(
            &mut tx,
            &crate::domain::claims::authenticator_removed(subject, bound, &credential, at),
        )
        .await?;
    }
    // OP-151 m.3 (i)
    events::credential(&mut tx, realm, subject, kind, CredentialChange::Removed).await?;
    audit(
        &mut tx,
        "credential.removed",
        who,
        &realm.external(subject)?,
    )
    .await?;
    tx.commit().await
}

/// The kind of a live credential other than a passkey, before it is revoked.
async fn credential_kind<T: AccountTx>(
    tx: &mut T,
    subject: [u8; 16],
    credential: [u8; 16],
) -> Result<&'static str, AccountError> {
    for kind in [PASSWORD, TOTP, "recovery_code"] {
        if tx
            .credentials(subject, kind)
            .await?
            .iter()
            .any(|c| c.id == credential)
        {
            return Ok(kind);
        }
    }
    Ok("other")
}
