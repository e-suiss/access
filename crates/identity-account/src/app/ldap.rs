//! The LDAP credential class (§10.6.3, IDP-16, OP-155 m.3 (n)): a separate secret per application,
//! issued on the account surface (S11), kept as Argon2id and shown once. Only these bind on the
//! LDAP gateway: the primary password never does. RFC 3062 replaces one in place under the §12
//! rules (the current credential authenticates, the person is told, `session_epoch` moves, the
//! new `authenticator-binding` Claim starts SEC18 cooling). Revoking never deletes (OP-73).
//!
//! A credential reads `<id>.<secret>`, both base64url: the id names the row, so a bind costs one
//! Argon2id verification.

use access_crypto::Secret;
use access_kernel::claim::body::AuthenticatorKind;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_store::audit::AuditEvent;
use access_store::ldap::LdapCredentialRow;

use crate::AccountError;
use crate::adapters::pg::PgTx;
use crate::app::claims::emit;
use crate::app::hasher::Hasher;
use crate::domain::claims::{authenticator_removed, secret_binding};
use crate::domain::password::Password;
use crate::domain::status::AccountStatus;
use crate::notify::message::{Address, AppPasswordChange, Body, Message};
use crate::notify::ports::Notifier;
use crate::ports::{AccountTx as _, Entropy};

/// Most active LDAP credentials one person holds.
pub const MAX_PER_SUBJECT: usize = 25;

/// Longest application name, in characters.
pub const MAX_APPLICATION: usize = 200;

/// Length of a credential as text: 22 + 1 + 43.
pub const TOKEN_LEN: usize = 66;

/// A new or replaced LDAP credential, shown to its holder once.
pub struct Issued {
    /// Its id.
    pub id: [u8; 16],
    /// The whole credential, `<id>.<secret>`.
    pub token: Secret<String>,
}

impl core::fmt::Debug for Issued {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Issued").finish_non_exhaustive()
    }
}

/// Why an LDAP credential was not issued; a decision, not a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The application name is empty, too long or holds control characters.
    Application,
    /// The person already holds [`MAX_PER_SUBJECT`] credentials.
    TooMany,
    /// No such active credential of this person.
    Missing,
    /// The account cannot authenticate.
    Inactive,
}

/// A bind that checked out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound {
    /// The subject.
    pub subject: [u8; 16],
    /// The LDAP credential.
    pub credential: [u8; 16],
}

/// The id and the secret part of a presented credential; `None` when it is not one.
#[must_use]
pub fn parse(token: &str) -> Option<([u8; 16], &str)> {
    if token.len() != TOKEN_LEN {
        return None;
    }
    let (id, secret) = token.split_once('.')?;
    let id = <[u8; 16]>::try_from(b64url_decode(id).ok()?).ok()?;
    let raw = b64url_decode(secret).ok()?;
    (raw.len() == 32).then_some((id, secret))
}

fn application(name: &str) -> Option<&str> {
    let name = name.trim();
    let n = name.chars().count();
    ((1..=MAX_APPLICATION).contains(&n) && !name.chars().any(char::is_control)).then_some(name)
}

/// The line and material of an LDAP credential's binding: kind `password`, named by the
/// credential's own id so that it never supersedes the primary password's line.
fn line_of(id: &[u8; 16]) -> Vec<u8> {
    let mut c = b"ldap-credential:".to_vec();
    c.extend_from_slice(id);
    c
}

fn secret<E: Entropy + ?Sized>(entropy: &E) -> Result<(String, [u8; 16]), AccountError> {
    let mut raw = [0_u8; 32];
    let (a, b) = raw.split_at_mut(16);
    a.copy_from_slice(&entropy.salt()?);
    b.copy_from_slice(&entropy.salt()?);
    Ok((b64url_encode(&raw), entropy.salt()?))
}

async fn tell<N: Notifier + Sync>(
    tx: &mut PgTx,
    notifier: &N,
    subject: [u8; 16],
    change: AppPasswordChange,
    application: &str,
    at_ms: u64,
) -> Result<(), AccountError> {
    let Some((kind, stored)) = tx.0.contact(subject).await? else {
        return Ok(());
    };
    let Some(value) = tx.reveal(subject, &stored).await? else {
        return Ok(());
    };
    let (to, valid_since_ms) = if kind == "email" {
        let since = tx.0.mailbox_since(subject).await?;
        (
            Address::Email(value),
            Some(
                since
                    .and_then(|v| u64::try_from(v).ok())
                    .unwrap_or(1)
                    .max(1),
            ),
        )
    } else {
        (Address::Phone(value), None)
    };
    let message = Message {
        subject,
        to,
        locale: None,
        valid_since_ms,
        body: Body::LdapCredentialChanged {
            change,
            application: application.chars().take(MAX_APPLICATION).collect(),
            at_ms,
        },
    };
    notifier
        .notify(&mut tx.0, &message)
        .await
        .map_err(|_| AccountError::Corrupt)?;
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{x:02x}"));
        s
    })
}

async fn audit(
    tx: &mut PgTx,
    event_type: &'static str,
    actor: &str,
    credential: &[u8; 16],
    correlation: &str,
) -> Result<(), AccountError> {
    let target = hex(credential);
    tx.audit(&AuditEvent {
        event_type,
        actor,
        target: &target,
        correlation,
    })
    .await
}

async fn live(tx: &mut PgTx, subject: [u8; 16]) -> Result<bool, AccountError> {
    Ok(tx
        .subject(subject, false)
        .await?
        .and_then(|s| AccountStatus::parse(&s.status))
        .is_some_and(AccountStatus::can_authenticate))
}

/// Who acts and under which correlation id, for the audit row.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// The audit actor.
    pub actor: &'a str,
    /// The request's correlation id.
    pub correlation: &'a str,
    /// Trusted now, Unix ms.
    pub at_ms: u64,
}

/// Issues a new LDAP credential to `subject` for `application_name`, with its binding Claim, the
/// notice and the audit row, in the caller's transaction.
///
/// # Errors
/// [`AccountError`]; a refusal is `Ok(Err(_))`.
pub async fn issue<E: Entropy + ?Sized, N: Notifier + Sync>(
    tx: &mut PgTx,
    hasher: &Hasher,
    entropy: &E,
    notifier: &N,
    subject: [u8; 16],
    application_name: &str,
    cx: Context<'_>,
) -> Result<Result<Issued, Refused>, AccountError> {
    let Some(name) = application(application_name) else {
        return Ok(Err(Refused::Application));
    };
    if !live(tx, subject).await? {
        return Ok(Err(Refused::Inactive));
    }
    if tx.0.ldap_credentials(subject).await?.len() >= MAX_PER_SUBJECT {
        return Ok(Err(Refused::TooMany));
    }
    let id = entropy.salt()?;
    let (raw, salt) = secret(entropy)?;
    let phc = hasher
        .hash(
            &Password::presented(&raw).ok_or(AccountError::Corrupt)?,
            salt,
        )
        .await?;
    tx.0.insert_ldap_credential(id, subject, name, phc.expose())
        .await?;
    emit(
        tx,
        &secret_binding(
            subject,
            AuthenticatorKind::Password,
            &line_of(&id),
            cx.at_ms,
        ),
    )
    .await?;
    tell(
        tx,
        notifier,
        subject,
        AppPasswordChange::Created,
        name,
        cx.at_ms,
    )
    .await?;
    audit(tx, "credential.ldap.issued", cx.actor, &id, cx.correlation).await?;
    Ok(Ok(Issued {
        id,
        token: Secret::new(format!("{}.{raw}", b64url_encode(&id))),
    }))
}

/// The person's active LDAP credentials; never a secret.
///
/// # Errors
/// [`AccountError`].
pub async fn list(
    tx: &mut PgTx,
    subject: [u8; 16],
) -> Result<Vec<LdapCredentialRow>, AccountError> {
    Ok(tx.0.ldap_credentials(subject).await?)
}

/// Revokes the person's LDAP credential `id`: its binding line ends, the person is told, nothing
/// is deleted (OP-73).
///
/// # Errors
/// [`AccountError`]; a refusal is `Ok(Err(_))`.
pub async fn revoke<N: Notifier + Sync>(
    tx: &mut PgTx,
    notifier: &N,
    subject: [u8; 16],
    id: [u8; 16],
    cx: Context<'_>,
) -> Result<Result<(), Refused>, AccountError> {
    let Some(name) = tx.0.revoke_ldap_credential(subject, id).await? else {
        return Ok(Err(Refused::Missing));
    };
    emit(
        tx,
        &authenticator_removed(
            subject,
            AuthenticatorKind::Password,
            &line_of(&id),
            cx.at_ms,
        ),
    )
    .await?;
    tell(
        tx,
        notifier,
        subject,
        AppPasswordChange::Revoked,
        &name,
        cx.at_ms,
    )
    .await?;
    audit(tx, "credential.ldap.revoked", cx.actor, &id, cx.correlation).await?;
    Ok(Ok(()))
}

/// Checks a presented LDAP credential; `None` for anything but an active credential of an
/// active account with the right secret. Only the LDAP credential class is ever consulted: a
/// primary password never binds (IDP-16).
///
/// # Errors
/// [`AccountError`].
pub async fn verify(
    tx: &mut PgTx,
    hasher: &Hasher,
    token: &str,
) -> Result<Option<Bound>, AccountError> {
    let Some((id, raw)) = parse(token) else {
        return Ok(None);
    };
    let Some(v) = tx.0.ldap_verifier(id).await? else {
        return Ok(None);
    };
    let presented = Password::presented(raw).ok_or(AccountError::Corrupt)?;
    if !hasher.verify(&presented, Secret::new(v.phc)).await?.matched {
        return Ok(None);
    }
    if !live(tx, v.subject).await? {
        return Ok(None);
    }
    tx.0.ldap_credential_used(id).await?;
    Ok(Some(Bound {
        subject: v.subject,
        credential: id,
    }))
}

/// RFC 3062 on the LDAP credential `bound` just authenticated with: a new secret replaces the
/// old, the person's sessions end (`session_epoch`), the person is told and a new binding Claim
/// starts SEC18 cooling. Nothing else of the account changes.
///
/// # Errors
/// [`AccountError`]; a refusal is `Ok(Err(_))`.
pub async fn rotate<E: Entropy + ?Sized, N: Notifier + Sync>(
    tx: &mut PgTx,
    hasher: &Hasher,
    entropy: &E,
    notifier: &N,
    bound: Bound,
    cx: Context<'_>,
) -> Result<Result<Issued, Refused>, AccountError> {
    let Some(v) = tx.0.ldap_verifier(bound.credential).await? else {
        return Ok(Err(Refused::Missing));
    };
    if v.subject != bound.subject {
        return Ok(Err(Refused::Missing));
    }
    let (raw, salt) = secret(entropy)?;
    let phc = hasher
        .hash(
            &Password::presented(&raw).ok_or(AccountError::Corrupt)?,
            salt,
        )
        .await?;
    if !tx
        .0
        .rotate_ldap_credential(bound.credential, phc.expose())
        .await?
    {
        return Ok(Err(Refused::Missing));
    }
    tx.end_sessions(bound.subject).await?;
    emit(
        tx,
        &secret_binding(
            bound.subject,
            AuthenticatorKind::Password,
            &line_of(&bound.credential),
            cx.at_ms,
        ),
    )
    .await?;
    tell(
        tx,
        notifier,
        bound.subject,
        AppPasswordChange::Changed,
        &v.application,
        cx.at_ms,
    )
    .await?;
    audit(
        tx,
        "credential.ldap.rotated",
        cx.actor,
        &bound.credential,
        cx.correlation,
    )
    .await?;
    Ok(Ok(Issued {
        id: bound.credential,
        token: Secret::new(format!("{}.{raw}", b64url_encode(&bound.credential))),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-155 m.3 (n)
    #[test]
    fn a_credential_names_its_row() {
        let id = [7_u8; 16];
        let mut raw = [0_u8; 32];
        raw[0] = 1;
        let token = format!("{}.{}", b64url_encode(&id), b64url_encode(&raw));
        assert_eq!(token.len(), TOKEN_LEN);
        let (got, secret) = parse(&token).unwrap_or(([0; 16], ""));
        assert_eq!(got, id);
        assert_eq!(secret.len(), 43);
        assert!(parse("dn=token").is_none());
        assert!(parse(&token.replace('.', "-")).is_none());
        assert!(application("  ").is_none());
        assert!(application("mail\u{7}").is_none());
        assert_eq!(application(" Thunderbird "), Some("Thunderbird"));
    }
}
