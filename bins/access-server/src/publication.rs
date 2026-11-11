//! The publication of the identity audit log (OP-37, OP-38, U52, OP-158 m.3 (w)): each tick of
//! the audit checkpointer hands every target, the cold tier's write-once store and the declared
//! HTTPS hooks, the latest checkpoint it does not have; then the tree's full tiles are written
//! and every ended year is frozen as static tiles in the cold tier.

use access_identity_audit::adapters::{PgAudit, PgPublications};
use access_identity_audit::app::publish::{Published, publish_latest};
use access_identity_audit::app::tiles::{extend, freeze_due};
use access_identity_export::adapters::OutboundWire;
use access_identity_export::adapters::cold_file::FileCold;
use access_identity_export::adapters::publish::{HookNotes, StoreNotes};
use access_identity_oauth::adapters::outbound::Outbound;
use access_store::Pool;

use crate::config::Config;

/// The targets this process publishes to.
#[derive(Default)]
pub(crate) struct Targets {
    /// The cold tier's store, when there is one.
    pub(crate) store: Option<StoreNotes<FileCold>>,
    /// The declared hooks.
    pub(crate) hooks: Vec<HookNotes<OutboundWire>>,
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 63
        && name != "object-store"
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'.' | b'_' | b'-')
        })
}

impl Targets {
    /// The targets `config` declares.
    ///
    /// # Errors
    /// A hook whose name or URL is malformed (OP-52 fail-fast).
    pub(crate) fn from_config(config: &Config, outbound: &Outbound) -> Result<Self, String> {
        let mut hooks = Vec::new();
        for hook in &config.audit_publication.hooks {
            if !valid_name(&hook.name) || !hook.url.starts_with("https://") {
                return Err(format!(
                    "audit publication hook `{}` is malformed",
                    hook.name
                ));
            }
            hooks.push(HookNotes {
                name: hook.name.clone(),
                url: hook.url.clone(),
                wire: OutboundWire(outbound.clone()),
            });
        }
        Ok(Self {
            store: config.audit_cold.as_ref().map(|c| StoreNotes {
                store: FileCold {
                    root: c.dir.clone(),
                },
            }),
            hooks,
        })
    }
}

fn report(published: &Published) {
    for (sink, error) in &published.failed {
        tracing::warn!(%error, %sink, "audit checkpoint not published; retried next tick");
    }
}

/// Publishes the latest checkpoint to every target that lacks it; returns how many took one.
pub(crate) async fn tick(checkpointer: &Pool, targets: &Targets) -> usize {
    let store = PgPublications(checkpointer.clone());
    let mut n = 0_usize;
    if let Some(s) = &targets.store {
        let p = publish_latest(&store, std::slice::from_ref(s)).await;
        report(&p);
        n = n.saturating_add(p.done.len());
    }
    let p = publish_latest(&store, &targets.hooks).await;
    report(&p);
    tiles(checkpointer, targets).await;
    n.saturating_add(p.done.len())
}

/// Writes the full tiles behind the latest checkpoint and, with a cold tier, freezes every ended
/// year (OP-37).
async fn tiles(checkpointer: &Pool, targets: &Targets) {
    let log = PgAudit(checkpointer.clone());
    match access_store::audit::last_checkpoint(checkpointer).await {
        Ok(Some(cp)) => {
            if let Err(error) = extend(&log, &cp).await {
                tracing::warn!(%error, "audit tiles not written; they catch up later");
            }
        }
        Ok(None) => {}
        Err(error) => tracing::warn!(%error, "audit checkpoint not read"),
    }
    if let Some(s) = &targets.store {
        match freeze_due(&log, &s.store).await {
            Ok(frozen) => {
                for shard in frozen {
                    tracing::info!(
                        event = "audit.tiles.frozen",
                        year = shard.year,
                        size = shard.size,
                        tiles = shard.tiles,
                        "identity audit year frozen as static tiles (OP-37)"
                    );
                }
            }
            Err(error) => tracing::warn!(%error, "audit shard not frozen; tried again"),
        }
    }
}

#[cfg(test)]
mod tests;
