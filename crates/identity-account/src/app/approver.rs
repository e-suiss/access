//! Approvers (OP-156 m.3 (d), §10.1.3, IDP-4): an app that embeds the public SDK's approver
//! module registers its app-bound P-256 key on the account surface after a recent sign-in. The
//! key's possession is proven by its signature, the registration makes an `authenticator_binding`
//! Claim (its SEC18 cooling starts with it), a CAEP credential change and a notice to the person.
//! No approver is privileged; retiring one ends its binding line and deletes nothing (OP-73).

use access_kernel::claim::body::{
    AuthenticatorBinding, AuthenticatorKind, Body as ClaimBody, Class,
};
use access_store::audit::AuditEvent;
use access_store::push::{DeviceKeyRow, NewDeviceKey};
use std::collections::{BTreeMap, BTreeSet};

use crate::AccountError;
use crate::adapters::pg::PgTx;
use crate::app::claims::emit;
use crate::app::signal::{emit as signal, fresh_id};
use crate::domain::approver::{self, PUBLIC_KEY_LEN};
use crate::domain::claims::{
    BINDING_TTL_MS, Bind, ClaimOrder, Content, authenticator_line, authenticator_removed, material,
};
use crate::domain::signal::{ChangeType, CredentialType, Signal};
use crate::domain::status::AccountStatus;
use crate::notify::message::{Address, Body, Message, Notice};
use crate::notify::ports::Notifier;
use crate::ports::{AccountTx as _, Entropy};

/// Most active approvers one person holds (PD).
pub const MAX_PER_SUBJECT: usize = 10;

/// Longest approver name, in characters.
pub const MAX_NAME: usize = 200;

/// COSE ES256.
pub const ES256: i64 = -7;

/// Why an approver was not registered or retired; a decision, not a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The name is empty, too long or holds control characters.
    Name,
    /// The public key is not an uncompressed P-256 point.
    Key,
    /// The signature does not prove possession of the key.
    Proof,
    /// The key is registered already, on this account or another.
    Known,
    /// The person already holds [`MAX_PER_SUBJECT`] approvers.
    TooMany,
    /// No such active approver of this person.
    Missing,
    /// The account cannot authenticate.
    Inactive,
}

/// A registration request.
#[derive(Clone, Copy)]
pub struct Registration<'a> {
    /// The name the person gives it.
    pub name: &'a str,
    /// The uncompressed SEC1 P-256 public key.
    pub public_key: &'a [u8],
    /// Its ES256 signature over [`approver::registration_message`].
    pub proof: &'a [u8],
    /// The realm issuer the proof names.
    pub issuer: &'a str,
}

impl core::fmt::Debug for Registration<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registration").finish_non_exhaustive()
    }
}

/// A registered approver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registered {
    /// Its id.
    pub id: [u8; 16],
    /// Its key's RFC 7638 thumbprint, the Relay address of its pushes.
    pub thumbprint: [u8; 32],
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

fn name_of(name: &str) -> Option<&str> {
    let name = name.trim();
    let n = name.chars().count();
    ((1..=MAX_NAME).contains(&n) && !name.chars().any(char::is_control)).then_some(name)
}

/// The binding line of an approver: kind `device-key`, named by the approver's id.
fn line_name(id: &[u8; 16]) -> Vec<u8> {
    let mut c = b"approver:".to_vec();
    c.extend_from_slice(id);
    c
}

fn binding(subject: [u8; 16], id: &[u8; 16], public_key: &[u8], at: u64) -> ClaimOrder {
    let name = line_name(id);
    ClaimOrder {
        subject,
        class: Class::AuthenticatorBinding.name(),
        at,
        ttl_ms: BINDING_TTL_MS,
        content: Content::Body {
            body: ClaimBody::AuthenticatorBinding(AuthenticatorBinding {
                kind: AuthenticatorKind::DeviceKey,
                material: material(AuthenticatorKind::DeviceKey, &name, public_key),
                alg: Some(ES256),
                attestation: None,
                aaguid: None,
                be: false,
                transports: BTreeSet::new(),
            }),
            disclose: true,
        },
        assurance: BTreeMap::new(),
        bind: Bind::None,
        line: Some(authenticator_line(AuthenticatorKind::DeviceKey, &name)),
        retract: false,
    }
}

async fn live(tx: &mut PgTx, subject: [u8; 16]) -> Result<bool, AccountError> {
    Ok(tx
        .subject(subject, false)
        .await?
        .and_then(|s| AccountStatus::parse(&s.status))
        .is_some_and(AccountStatus::can_authenticate))
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
    cx: Context<'_>,
    id: &[u8; 16],
) -> Result<(), AccountError> {
    let target = hex(id);
    tx.audit(&AuditEvent {
        event_type,
        actor: cx.actor,
        target: &target,
        correlation: cx.correlation,
    })
    .await
}

/// Tells the person about a new sign-in method on their registered address (SEC18).
async fn tell<N: Notifier + Sync>(
    tx: &mut PgTx,
    notifier: &N,
    subject: [u8; 16],
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
    notifier
        .notify(
            &mut tx.0,
            &Message {
                subject,
                to,
                locale: None,
                valid_since_ms,
                body: Body::Notice {
                    notice: Notice::NewMethod,
                    at_ms,
                    until_ms: None,
                },
            },
        )
        .await
        .map_err(|_| AccountError::Corrupt)?;
    Ok(())
}

/// Registers an approver for `subject` in the caller's transaction: the key, its binding Claim,
/// the CAEP credential change, the notice and the audit row.
///
/// # Errors
/// [`AccountError`]; a refusal is `Ok(Err(_))`.
pub async fn register<E: Entropy + ?Sized, N: Notifier + Sync>(
    tx: &mut PgTx,
    entropy: &E,
    notifier: &N,
    subject: [u8; 16],
    r: &Registration<'_>,
    cx: Context<'_>,
) -> Result<Result<Registered, Refused>, AccountError> {
    let Some(name) = name_of(r.name) else {
        return Ok(Err(Refused::Name));
    };
    if r.public_key.len() != PUBLIC_KEY_LEN {
        return Ok(Err(Refused::Key));
    }
    let Some(thumbprint) = approver::thumbprint(r.public_key) else {
        return Ok(Err(Refused::Key));
    };
    // OP-156 m.3 (d)
    if !approver::verify(
        r.public_key,
        &approver::registration_message(r.issuer, &thumbprint),
        r.proof,
    ) {
        return Ok(Err(Refused::Proof));
    }
    if !live(tx, subject).await? {
        return Ok(Err(Refused::Inactive));
    }
    if tx.0.device_keys(subject).await?.len() >= MAX_PER_SUBJECT {
        return Ok(Err(Refused::TooMany));
    }
    let id = entropy.salt()?;
    if !tx
        .0
        .insert_device_key(&NewDeviceKey {
            id,
            subject,
            thumbprint,
            public_key: r.public_key,
            name,
        })
        .await?
    {
        return Ok(Err(Refused::Known));
    }
    // §10.1.3, SEC18
    emit(tx, &binding(subject, &id, r.public_key, cx.at_ms)).await?;
    // TN-41
    let s = Signal::credential_change(
        fresh_id()?,
        subject,
        CredentialType::Key,
        ChangeType::Create,
        cx.at_ms,
    );
    signal(tx, &s).await?;
    tell(tx, notifier, subject, cx.at_ms).await?;
    audit(tx, "approver.registered", cx, &id).await?;
    Ok(Ok(Registered { id, thumbprint }))
}

/// The person's active approvers; never a key.
///
/// # Errors
/// [`AccountError`].
pub async fn list(tx: &mut PgTx, subject: [u8; 16]) -> Result<Vec<DeviceKeyRow>, AccountError> {
    Ok(tx.0.device_keys(subject).await?)
}

/// Retires the person's approver `id`: its binding line ends and its pushes stop; nothing is
/// deleted (OP-73).
///
/// # Errors
/// [`AccountError`]; a refusal is `Ok(Err(_))`.
pub async fn retire(
    tx: &mut PgTx,
    subject: [u8; 16],
    id: [u8; 16],
    cx: Context<'_>,
) -> Result<Result<(), Refused>, AccountError> {
    if tx.0.retire_device_key(subject, id).await?.is_none() {
        return Ok(Err(Refused::Missing));
    }
    emit(
        tx,
        &authenticator_removed(
            subject,
            AuthenticatorKind::DeviceKey,
            &line_name(&id),
            cx.at_ms,
        ),
    )
    .await?;
    let s = Signal::credential_change(
        fresh_id()?,
        subject,
        CredentialType::Key,
        ChangeType::Revoke,
        cx.at_ms,
    );
    signal(tx, &s).await?;
    audit(tx, "approver.retired", cx, &id).await?;
    Ok(Ok(()))
}
