//! What the identity plane writes about a device Instance, in the caller's transaction (OP-149
//! m.16 (a), m.32, OP-150 m.12 (b), (d)): the subject's Party binding with its
//! `identity_binding_person` Claim, the device key with its `authenticator_binding` Claim, and a
//! later session's binding to a known key's Instance with that session's `authentication`
//! Claim. `POST /v1/me/instances`, `POST /v1/me/instances/bindings` and the local bootstrap's
//! test user go through these (OP-149 m.28 (b)).

use std::collections::BTreeMap;

use access_identity_account::AccountError;
use access_identity_account::adapters::pg::PgTx;
use access_identity_account::app::claims::emit;
use access_identity_account::domain::claims::{
    AuthFacts, Bind, authentication, device_key_binding, identity_binding,
};
use access_identity_account::ports::AccountTx as _;
use access_kernel::claim::body::{AuthMethod, BindingKind};
use access_kernel::verify::cose::PublicKey;
use access_store::idp;
use access_store::issuer::{
    NewDeviceKey, NewSessionInstance, bind_session_instance, insert_device_key, known_device,
    session_instance,
};

/// Records that `subject`'s device Instances belong to `party` and queues the
/// `identity_binding_person` Claim that binds the subject to it (§10.1.3 IDP-2, §10.1.5):
/// `proof` is the Party's own self-signed `party_register` AIS, which enters by digest only.
/// `false` when the subject or the Party was bound already; nothing is queued then.
///
/// # Errors
/// [`AccountError`].
pub async fn bind_party(
    tx: &mut PgTx,
    subject: &[u8; 16],
    party: &[u8; 16],
    proof: &[u8],
) -> Result<bool, AccountError> {
    if !idp::bind_subject_party(&mut tx.0, subject, party).await? {
        return Ok(false);
    }
    let at = tx.server_time().await?;
    emit(
        tx,
        &identity_binding(*subject, BindingKind::Person, proof, at),
    )
    .await?;
    Ok(true)
}

/// The raw public material the key row keeps (32 bytes for Ed25519, SEC1 for P-256), its
/// `key_type`, `algorithm` and COSE algorithm; an ML-DSA key is not a device key (OP-149 m.14
/// (a)).
fn raw(key: &PublicKey) -> Result<(Vec<u8>, &'static str, &'static str, i64), AccountError> {
    match key {
        PublicKey::Ed25519(k) => Ok((k.to_vec(), "OKP", "Ed25519", -8)),
        PublicKey::P256(k) => Ok((k.clone(), "EC2", "ES256", -7)),
        PublicKey::MlDsa(..) => Err(AccountError::Corrupt),
    }
}

/// A device key as the identity plane records it (§10.1.3 "Cihaz anahtarı kaydı").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKey {
    /// The subject.
    pub subject: [u8; 16],
    /// The key the Instance holds.
    pub key: PublicKey,
    /// The Instance.
    pub instance: [u8; 16],
    /// The session that proved the key, when one did.
    pub session: Option<[u8; 16]>,
}

/// Records `device` and queues the `authenticator_binding` Claim of its key, bound to its
/// Instance (§10.1.5, OP-150 L2). The server time of the record when the key is new; `None`
/// when the Instance's key was recorded before, and nothing is queued.
///
/// # Errors
/// [`AccountError`]; an ML-DSA key is not a device key (OP-149 m.14 (a)) and is
/// [`AccountError::Corrupt`].
pub async fn record_device_key(
    tx: &mut PgTx,
    device: &DeviceKey,
) -> Result<Option<u64>, AccountError> {
    let (key, kty, alg, cose) = raw(&device.key)?;
    let row = NewDeviceKey {
        subject: device.subject,
        public_key: &key,
        key_type: kty,
        algorithm: alg,
        instance: device.instance,
        session: device.session,
    };
    if insert_device_key(&mut tx.0, &row).await?.is_none() {
        return Ok(None);
    }
    let at = tx.server_time().await?;
    emit(
        tx,
        &device_key_binding(device.subject, &key, cose, device.instance, at),
    )
    .await?;
    Ok(Some(at))
}

/// Why a session was not bound to a known device's Instance; a decision, not an error (OP-64).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotBound {
    /// No active device key of the subject has this public material: never registered,
    /// retired, or another subject's. The three are not told apart.
    UnknownKey,
    /// The session already binds an active Instance (INV-13, OP-150 m.14 (f)).
    SessionBound,
}

/// A known device key a session proved (OP-149 m.32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenDevice<'a> {
    /// The session's subject.
    pub subject: [u8; 16],
    /// The session.
    pub session: [u8; 16],
    /// The key.
    pub key: &'a PublicKey,
    /// When the session authenticated.
    pub auth_time: u64,
    /// The session's assurance as Claim levels (§10.1.6).
    pub assurance: BTreeMap<String, u64>,
}

/// Binds the session to the Instance of the subject's active device key with this public
/// material (OP-149 m.32, INV-13, §5.1 eki): no new Instance, the key row untouched, one new
/// binding row (OP-73); and queues the session's `authentication` Claim bound to that Instance,
/// as a registration does (OP-150 m.12 (f)). The Instance when bound.
///
/// # Errors
/// [`AccountError`]; an ML-DSA key is not a device key and is [`AccountError::Corrupt`].
pub async fn bind_known_device(
    tx: &mut PgTx,
    p: &ProvenDevice<'_>,
) -> Result<Result<[u8; 16], NotBound>, AccountError> {
    let (key, _, _, _) = raw(p.key)?;
    let Some(known) = known_device(&mut tx.0, &p.subject, &key).await? else {
        return Ok(Err(NotBound::UnknownKey));
    };
    if session_instance(&mut tx.0, &p.session).await?.is_some() {
        return Ok(Err(NotBound::SessionBound));
    }
    let row = NewSessionInstance {
        session: p.session,
        subject: p.subject,
        device: known.device,
        instance: known.instance,
    };
    if !bind_session_instance(&mut tx.0, &row).await? {
        return Ok(Err(NotBound::SessionBound));
    }
    let login = authentication(AuthFacts {
        subject: p.subject,
        method: AuthMethod::DeviceKey,
        auth_time: p.auth_time,
        assurance: p.assurance.clone(),
        webauthn: None,
        evidence: None,
        bind: Bind::Instance(known.instance),
    });
    emit(tx, &login).await?;
    Ok(Ok(known.instance))
}
