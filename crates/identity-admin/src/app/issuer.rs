//! The realm's identity Claim issuer (§10.1.4 rule 3, §10.1.7, OP-150 L2): a system Party fixed
//! when the realm is created and named in its Genesis, so the governing domain is born accepting
//! it for `actor-binding`; its Instance is the realm's Claim issuer key, opened by the key's own
//! self-signed `party_register` and `instance_create` (OP-149 m.16 (a)).

use access_identity_signer::issuer::{Registration as Ais, Step};
use access_internal_api::instances::{
    Registrant, Registration, RegistrationVerdict, SelfSigned, register_nonce,
};
use access_kernel::digest::Digest;
use access_kernel::model::{Id, Window};
use access_kernel::verify::key_scope::thumbprint;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::issuer as store;
use access_store::scope::DomainId;
use suiss_crypto::digest::context_digest;

use super::Admin;
use crate::AdminError;
use crate::ports::{Decider, Governance, Instances, RealmKeys};

/// Digest context of the issuer Instance's `instance_create` nonce.
pub const NONCE_CONTEXT: &str = "access/claim-issuer-instance/v1";

/// How long the registration Exercises' intents hold (PD).
pub const VALIDITY_MS: u64 = 600_000;

/// How far back the intents' windows start, for clock skew (PD).
pub const SKEW_MS: u64 = 60_000;

/// A fresh issuer Party id.
///
/// # Errors
/// [`AdminError::Encode`] when the random source fails.
pub fn new_party() -> Result<[u8; 16], AdminError> {
    access_crypto::random::bytes::<16>().map_err(|_| AdminError::Encode)
}

/// The `instance_create` nonce of the issuer key `kid` in `domain` at `from`.
#[must_use]
pub fn nonce(domain: &Digest, kid: &[u8; 32], from: u64) -> Vec<u8> {
    let mut m = domain.0.to_vec();
    m.extend_from_slice(kid);
    m.extend_from_slice(&from.to_be_bytes());
    context_digest(NONCE_CONTEXT, &m).0.to_vec()
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// Opens the realm's Claim issuer key and its Instance in the governing domain, unless the
    /// key already holds one there. A realm without an issuer Party has nothing to open.
    ///
    /// # Errors
    /// [`AdminError::Refused`] when the domain refuses the registration; [`AdminError`].
    pub async fn register_issuer(
        &self,
        tenant: TenantId,
        realm: RealmId,
    ) -> Result<Option<[u8; 16]>, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let party = store::realm_issuer(&mut t).await?;
        let g = access_store::idp::governance(&mut t).await?;
        t.commit().await?;
        let (Some(party), Some(g)) = (party, g) else {
            return Ok(None);
        };
        let key = self
            .keys
            .open_issuer(realm, party)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let kid = thumbprint(&key);
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let known = store::issuer_instance(&mut t, &g.domain, &kid).await?;
        let registered = store::has_issuer_instance(&mut t, &g.domain).await?;
        t.commit().await?;
        if let Some(instance) = known {
            return Ok(Some(instance));
        }
        let now = Instances::now(self.governance)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let domain = Digest(*g.domain.as_bytes());
        let validity = Window {
            from: now.saturating_sub(SKEW_MS),
            until: now.saturating_add(VALIDITY_MS),
        };
        let create = nonce(&domain, &kid, validity.from);
        let sign = |nonce: Vec<u8>, step| Ais {
            domain: domain.0,
            nonce,
            validity: (validity.from, validity.until),
            iat: now,
            pep: String::from(self.pep),
            step,
        };
        let register = if registered {
            None
        } else {
            let n = register_nonce(&create);
            let ais = self
                .keys
                .sign_issuer_registration(realm, sign(n.clone(), Step::Register))
                .await
                .map_err(|e| AdminError::Unavailable(e.0))?;
            Some(SelfSigned {
                nonce: n,
                validity,
                ais,
            })
        };
        let ais = self
            .keys
            .sign_issuer_registration(realm, sign(create.clone(), Step::Create))
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let verdict = self
            .governance
            .register(Registration {
                tenant: *tenant.as_bytes(),
                domain,
                registrant: Registrant::ClaimIssuer {
                    realm: *realm.as_bytes(),
                },
                party: Id(party),
                key,
                register,
                create: SelfSigned {
                    nonce: create,
                    validity,
                    ais,
                },
                pep: String::from(self.pep),
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let instance = match verdict {
            RegistrationVerdict::Registered(r) => r.instance.0,
            RegistrationVerdict::Refused { code } => return Err(AdminError::Refused(code)),
        };
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        store::record_issuer_instance(&mut t, &DomainId::from_bytes(domain.0), &kid, &instance)
            .await?;
        t.commit().await?;
        Ok(Some(instance))
    }
}
