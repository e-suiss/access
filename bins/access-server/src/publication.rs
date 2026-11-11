//! The publication targets of the identity audit log's checkpoints (OP-37, OP-38, U52,
//! OP-158 m.3 (w)): the cold tier's write-once store and the declared HTTPS hooks. Each tick of
//! the audit checkpointer hands every target the latest checkpoint it does not have.

use access_identity_audit::adapters::PgPublications;
use access_identity_audit::app::publish::{Published, publish_latest};
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
    n.saturating_add(p.done.len())
}

#[cfg(test)]
mod tests;
