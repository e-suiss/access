//! Adapters: PostgreSQL through `access-store`, the SSRF-guarded HTTPS client, and the realm
//! KEK envelope for webhook secrets.

use std::sync::Arc;

use access_identity_oauth::adapters::outbound::{Outbound, OutboundError};
use access_store::events::SealedKey;
use access_store::identity::{RealmId, TenantId};
use suiss_crypto::envelope::{Dek, Kek, Sealed, open_body, seal_body};
use zeroize::Zeroizing;

use crate::ports::{PollClient, PostError, Reply, Sealer, Transport, Unavailable};

/// Pushes through the identity plane's outbound client: `https` on 443 to public addresses
/// only, no redirects, one deadline (§14.3).
#[derive(Clone)]
pub struct OutboundTransport(pub Outbound);

impl Transport for OutboundTransport {
    async fn post(
        &self,
        url: &str,
        content_type: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> Result<Reply, PostError> {
        match self.0.post(url, content_type, headers, body).await {
            Ok(a) => Ok(Reply {
                status: a.status,
                retry_after_ms: a.retry_after_s.and_then(|s| s.checked_mul(1000)),
            }),
            Err(OutboundError::Url | OutboundError::Blocked) => Err(PostError::Refused),
            Err(OutboundError::Unreachable | OutboundError::Malformed) => {
                Err(PostError::Unreachable)
            }
        }
    }
}

impl PollClient for OutboundTransport {
    async fn poll(
        &self,
        url: &str,
        bearer: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), PostError> {
        let auth = [("authorization", format!("Bearer {bearer}"))];
        match self.0.post(url, "application/json", &auth, body).await {
            Ok(a) => Ok((a.status, a.body)),
            Err(OutboundError::Url | OutboundError::Blocked) => Err(PostError::Refused),
            Err(OutboundError::Unreachable | OutboundError::Malformed) => {
                Err(PostError::Unreachable)
            }
        }
    }
}

/// The realm KEK of a tenant's realm (OP-42, OP-135).
pub trait RealmKek: Send + Sync {
    /// The realm's current KEK, when this process holds it.
    fn kek(&self, tenant: TenantId, realm: RealmId) -> Option<Arc<dyn Kek + Send + Sync>>;
}

const CONTEXT: &[u8] = b"access/webhook-secret/v1\0";

fn context(tenant: TenantId, realm: RealmId, id: &[u8; 16]) -> Vec<u8> {
    let mut c = CONTEXT.to_vec();
    c.extend_from_slice(tenant.as_bytes());
    c.extend_from_slice(realm.as_bytes());
    c.extend_from_slice(id);
    c
}

/// Seals a webhook secret under its own DEK wrapped by the realm KEK, bound to the tenant,
/// realm and subscription.
pub struct KekSealer<K>(pub K);

impl<K: RealmKek> Sealer for KekSealer<K> {
    fn seal(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        plain: &[u8],
    ) -> Result<SealedKey, Unavailable> {
        let kek = self.0.kek(tenant, realm).ok_or(Unavailable)?;
        let dek = Dek::generate().map_err(|_| Unavailable)?;
        let wrapped_dek = kek.wrap(&dek).map_err(|_| Unavailable)?;
        let s = seal_body(dek, &context(tenant, realm, id), plain).map_err(|_| Unavailable)?;
        Ok(SealedKey {
            kek_id: String::from(kek.id()),
            wrapped_dek,
            nonce: s.nonce,
            ciphertext: s.ciphertext,
        })
    }

    fn open(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        sealed: &SealedKey,
    ) -> Result<Zeroizing<Vec<u8>>, Unavailable> {
        let kek = self.0.kek(tenant, realm).ok_or(Unavailable)?;
        if kek.id() != sealed.kek_id {
            return Err(Unavailable);
        }
        let dek = kek.unwrap(&sealed.wrapped_dek).map_err(|_| Unavailable)?;
        let plain = open_body(
            &dek,
            &context(tenant, realm, id),
            &Sealed {
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext.clone(),
            },
        )
        .map_err(|_| Unavailable)?;
        Ok(Zeroizing::new(plain.to_vec()))
    }
}

/// The same envelope seals hook and webhook keys (TN-135, TN-136), each bound to its own
/// registration or key id.
impl<K: RealmKek> access_identity_hooks::ports::KeyVault for KekSealer<K> {
    fn seal(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        plain: &[u8],
    ) -> Result<SealedKey, access_identity_hooks::ports::Unavailable> {
        Sealer::seal(self, tenant, realm, id, plain)
            .map_err(|Unavailable| access_identity_hooks::ports::Unavailable)
    }

    fn open(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        sealed: &SealedKey,
    ) -> Result<Zeroizing<Vec<u8>>, access_identity_hooks::ports::Unavailable> {
        Sealer::open(self, tenant, realm, id, sealed)
            .map_err(|Unavailable| access_identity_hooks::ports::Unavailable)
    }
}
