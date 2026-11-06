//! What the identity plane writes about a registered device Instance, in the caller's
//! transaction (OP-149 m.16 (a), OP-150 m.12 (b), (d)): the subject's Party binding with its
//! `identity_binding_person` Claim, and the device key with its `authenticator_binding` Claim.
//! `POST /v1/me/instances` and the local bootstrap's test user go through these (OP-149 m.28 (b)).

use access_identity_account::AccountError;
use access_identity_account::adapters::pg::PgTx;
use access_identity_account::app::claims::emit;
use access_identity_account::domain::claims::{device_key_binding, identity_binding};
use access_identity_account::ports::AccountTx as _;
use access_kernel::claim::body::BindingKind;
use access_kernel::verify::cose::PublicKey;
use access_store::idp;
use access_store::issuer::{NewDeviceKey, insert_device_key};

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
    let (key, kty, alg, cose) = match &device.key {
        PublicKey::Ed25519(k) => (k.to_vec(), "OKP", "Ed25519", -8),
        PublicKey::P256(k) => (k.clone(), "EC2", "ES256", -7),
        PublicKey::MlDsa(..) => return Err(AccountError::Corrupt),
    };
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
