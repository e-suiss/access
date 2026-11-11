//! A sink's secret sealed under the realm KEK (OP-156 m.3 (s), CR-32): its own DEK, bound to the
//! tenant, realm and sink. It is opened only to send a batch and never written anywhere else.

use access_store::events::SealedKey;
use access_store::identity::{RealmId, TenantId};
use suiss_crypto::envelope::{Dek, Kek, Sealed, open_body, seal_body};

use super::sink::SinkSecret;

const CONTEXT: &[u8] = b"access/export-secret/v1\0";

fn context(tenant: TenantId, realm: RealmId, sink: &[u8; 16]) -> Vec<u8> {
    let mut c = CONTEXT.to_vec();
    c.extend_from_slice(tenant.as_bytes());
    c.extend_from_slice(realm.as_bytes());
    c.extend_from_slice(sink);
    c
}

/// Sealing or opening failed: no KEK, another KEK version, or a broken envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("sink secret envelope")]
pub struct Unsealed;

/// Seals `secret` of sink `sink` under `kek`.
///
/// # Errors
/// [`Unsealed`].
pub fn seal(
    kek: &dyn Kek,
    (tenant, realm): (TenantId, RealmId),
    sink: &[u8; 16],
    secret: &SinkSecret,
) -> Result<SealedKey, Unsealed> {
    let dek = Dek::generate().map_err(|_| Unsealed)?;
    let wrapped_dek = kek.wrap(&dek).map_err(|_| Unsealed)?;
    let s = seal_body(
        dek,
        &context(tenant, realm, sink),
        secret.expose().as_bytes(),
    )
    .map_err(|_| Unsealed)?;
    Ok(SealedKey {
        kek_id: String::from(kek.id()),
        wrapped_dek,
        nonce: s.nonce,
        ciphertext: s.ciphertext,
    })
}

/// Opens the sealed secret of sink `sink`.
///
/// # Errors
/// [`Unsealed`].
pub fn open(
    kek: &dyn Kek,
    (tenant, realm): (TenantId, RealmId),
    sink: &[u8; 16],
    sealed: &SealedKey,
) -> Result<SinkSecret, Unsealed> {
    if !kek.opens(&sealed.kek_id) {
        return Err(Unsealed);
    }
    let dek = kek.unwrap(&sealed.wrapped_dek).map_err(|_| Unsealed)?;
    let plain = open_body(
        &dek,
        &context(tenant, realm, sink),
        &Sealed {
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext.clone(),
        },
    )
    .map_err(|_| Unsealed)?;
    let text = core::str::from_utf8(&plain).map_err(|_| Unsealed)?;
    Ok(SinkSecret::new(text))
}
