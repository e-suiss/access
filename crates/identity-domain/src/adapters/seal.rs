//! Certificate keys sealed under the realm KEK (OP-156 m.3 (i), CR-32): each key under its own
//! DEK, bound to the tenant, realm and certificate id.

use std::sync::Arc;

use access_store::events::SealedKey;
use access_store::identity::{RealmId, TenantId};
use suiss_crypto::envelope::{Dek, Kek, Sealed, open_body, seal_body};
use zeroize::Zeroizing;

use crate::ports::Unavailable;

/// The realm KEKs this process holds.
pub trait RealmKek: Send + Sync {
    /// The realm's current KEK.
    fn kek(&self, tenant: TenantId, realm: RealmId) -> Option<Arc<dyn Kek + Send + Sync>>;
}

const CONTEXT: &[u8] = b"access/domain-key/v1\0";

fn context(tenant: TenantId, realm: RealmId, id: &[u8; 16]) -> Vec<u8> {
    let mut c = CONTEXT.to_vec();
    c.extend_from_slice(tenant.as_bytes());
    c.extend_from_slice(realm.as_bytes());
    c.extend_from_slice(id);
    c
}

fn down(what: &str) -> Unavailable {
    Unavailable(format!("realm kek: {what}"))
}

/// Seals and opens certificate keys under the realm KEK.
pub struct KeySeal<K>(pub K);

impl<K: RealmKek> KeySeal<K> {
    /// Seals the PKCS#8 `plain` of certificate `id`.
    ///
    /// # Errors
    /// [`Unavailable`] without the realm's KEK or when sealing fails.
    pub fn seal(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        plain: &[u8],
    ) -> Result<SealedKey, Unavailable> {
        let kek = self.0.kek(tenant, realm).ok_or_else(|| down("none"))?;
        let dek = Dek::generate().map_err(|_| down("dek"))?;
        let wrapped_dek = kek.wrap(&dek).map_err(|_| down("wrap"))?;
        let s = seal_body(dek, &context(tenant, realm, id), plain).map_err(|_| down("seal"))?;
        Ok(SealedKey {
            kek_id: String::from(kek.id()),
            wrapped_dek,
            nonce: s.nonce,
            ciphertext: s.ciphertext,
        })
    }

    /// Opens the sealed key of certificate `id`.
    ///
    /// # Errors
    /// [`Unavailable`].
    pub fn open(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        sealed: &SealedKey,
    ) -> Result<Zeroizing<Vec<u8>>, Unavailable> {
        let kek = self.0.kek(tenant, realm).ok_or_else(|| down("none"))?;
        if kek.id() != sealed.kek_id {
            return Err(down("version"));
        }
        let dek = kek
            .unwrap(&sealed.wrapped_dek)
            .map_err(|_| down("unwrap"))?;
        let plain = open_body(
            &dek,
            &context(tenant, realm, id),
            &Sealed {
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext.clone(),
            },
        )
        .map_err(|_| down("open"))?;
        Ok(Zeroizing::new(plain.to_vec()))
    }
}
