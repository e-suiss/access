//! The token vault's reads of the authority plane in this process (G59, U66, OP-154 m.3 (t)):
//! an allowed Exercise's kept receipt and what the head says of it, and the operating system's
//! randomness.

use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_identity_vault::domain::release::Allowed;
use access_identity_vault::ports::{Exercises, Random, Unavailable};
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;

use super::Plane;

impl<K, B, S, C> Exercises for Plane<K, B, S, C>
where
    K: Keys + Send + Sync + 'static,
    B: Binding + Clone + Send + Sync + 'static,
    S: Salts + Clone + Send + Sync + 'static,
    C: Clock + Clone + Send + Sync + 'static,
{
    async fn allowed(
        &self,
        domain: [u8; 32],
        exercise: [u8; 32],
        intent: &IntentEnvelope,
    ) -> Result<Option<Allowed>, Unavailable> {
        let basis = self
            .domains
            .release_basis(Digest(domain), Digest(exercise), intent)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "vault release read failed");
                Unavailable
            })?;
        Ok(basis.map(|b| Allowed {
            pep: b.pep,
            principal: b.principal.map(|p| p.0),
            actor: b.actor.map(|p| p.0),
            tier: b.tier,
            basis_live: b.basis_live,
            position: b.position,
        }))
    }
}

/// A refresh reads no Exercise; this answers none.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoExercises;

impl Exercises for NoExercises {
    fn allowed(
        &self,
        _: [u8; 32],
        _: [u8; 32],
        _: &IntentEnvelope,
    ) -> impl Future<Output = Result<Option<Allowed>, Unavailable>> + Send {
        std::future::ready(Err(Unavailable))
    }
}

/// How often due tokens are looked for (PD).
pub(crate) const REFRESH_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// Most connections one realm refreshes per round (PD).
const REFRESH_BATCH: u32 = 100;

/// Refreshes, every [`REFRESH_EVERY`] until aborted, each realm's tokens that expire within
/// five minutes, each under its connection's lease (OP-154 m.3 (t)).
pub(crate) async fn refresh_run<H, S>(
    app: access_store::Pool,
    router: access_store::Pool,
    keks: crate::login::RealmKeks,
    ids: std::sync::Arc<crate::ids::CellIds>,
    vault: access_identity_vault::app::Vault<H, S, NoExercises, OsRandom>,
) where
    H: access_identity_vault::ports::ProviderHttp,
    S: access_identity_vault::ports::SocialSecrets,
{
    let mut every = tokio::time::interval(REFRESH_EVERY);
    loop {
        every.tick().await;
        let Some(now) = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
        else {
            continue;
        };
        let (Ok(realms), Some(id_key)) = (access_store::tenancy::routes(&router).await, ids.key())
        else {
            tracing::warn!("vault refresh round not run");
            continue;
        };
        for r in realms {
            let Some(v) = keks.vault(r.realm) else {
                continue;
            };
            let realm_keys = access_identity_vault::app::Keys {
                tenant: r.tenant,
                realm: r.realm,
                kek: &*v.kek,
                ids: &id_key,
                issuer: &r.issuer,
            };
            if let Err(error) = vault
                .refresh_due(&app, &realm_keys, now, REFRESH_BATCH)
                .await
            {
                tracing::warn!(%error, "vault refresh round failed for a realm");
            }
        }
    }
}

/// The operating system's randomness.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        for chunk in out.chunks_mut(32) {
            let b: [u8; 32] = access_crypto::random::bytes().map_err(|_| Unavailable)?;
            let n = chunk.len();
            chunk.copy_from_slice(b.get(..n).ok_or(Unavailable)?);
        }
        Ok(())
    }
}
