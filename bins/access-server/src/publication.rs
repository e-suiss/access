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
use access_store::operational::{OperationalEvent, record_operational};

use crate::config::Config;

/// The targets this process publishes to.
#[derive(Default)]
pub(crate) struct Targets {
    /// `access_app`, for the operational audit stream (OP-44).
    pub(crate) app: Option<Pool>,
    /// Targets whose last publication failed; their next success is audited.
    pub(crate) failing: std::sync::Mutex<std::collections::BTreeSet<String>>,
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
    pub(crate) fn from_config(
        config: &Config,
        outbound: &Outbound,
        app: Pool,
    ) -> Result<Self, String> {
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
            app: Some(app),
            failing: std::sync::Mutex::default(),
            store: config.audit_cold.as_ref().map(|c| StoreNotes {
                store: FileCold {
                    root: c.dir.clone(),
                },
            }),
            hooks,
        })
    }
}

async fn audit(targets: &Targets, event_type: &str, target: &str) {
    let Some(app) = &targets.app else { return };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0);
    let e = OperationalEvent {
        occurred_at_ms: now,
        tenant: None,
        domain: None,
        event_type,
        actor: "checkpointer",
        target,
        reason: "",
        correlation: "identity-audit",
    };
    if let Err(error) = record_operational(app, &e).await {
        tracing::error!(%error, event_type, "operational audit event not recorded");
    }
}

/// Audits a target's first publication and its first after a failure; a steady stream of
/// publications is visible in the publication records, not as one event each (OP-38).
async fn report(targets: &Targets, published: &Published, first: &[String]) {
    let (recovered, failed) = {
        let Ok(mut failing) = targets.failing.lock() else {
            return;
        };
        let recovered: Vec<(String, u64)> = published
            .done
            .iter()
            .filter(|(sink, _)| failing.remove(sink) || first.contains(sink))
            .cloned()
            .collect();
        for (sink, _) in &published.failed {
            failing.insert(sink.clone());
        }
        (recovered, published.failed.len())
    };
    for (sink, error) in &published.failed {
        tracing::warn!(%error, %sink, failed, "audit checkpoint not published; retried next tick");
    }
    for (sink, size) in recovered {
        audit(targets, "checkpoint.published", &format!("{sink}:{size}")).await;
    }
}

async fn fresh(checkpointer: &Pool, names: impl Iterator<Item = String>) -> Vec<String> {
    let mut out = Vec::new();
    for name in names {
        if access_store::audit_publication::published_through(checkpointer, &name)
            .await
            .is_ok_and(|n| n == 0)
        {
            out.push(name);
        }
    }
    out
}

/// Publishes the latest checkpoint to every target that lacks it; returns how many took one.
pub(crate) async fn tick(checkpointer: &Pool, targets: &Targets) -> usize {
    use access_identity_audit::ports::Publisher as _;
    let store = PgPublications(checkpointer.clone());
    let mut n = 0_usize;
    if let Some(s) = &targets.store {
        let first = fresh(checkpointer, std::iter::once(s.name().to_owned())).await;
        let p = publish_latest(&store, std::slice::from_ref(s)).await;
        report(targets, &p, &first).await;
        n = n.saturating_add(p.done.len());
    }
    let first = fresh(
        checkpointer,
        targets.hooks.iter().map(|h| h.name().to_owned()),
    )
    .await;
    let p = publish_latest(&store, &targets.hooks).await;
    report(targets, &p, &first).await;
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
                    let target = format!("shard:{}:{}", shard.year, shard.size);
                    audit(targets, "audit.shard_frozen", &target).await;
                }
            }
            Err(error) => tracing::warn!(%error, "audit shard not frozen; tried again"),
        }
    }
}

#[cfg(test)]
mod tests;
