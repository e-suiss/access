//! The checkpointers of this process. The identity audit log and the authority plane's
//! operational stream are integrated into their trees and signed by the identity signer's cell
//! `audit-checkpoint` key (OP-38, OP-44, OP-150 m.3 (h)); every domain this process leads has
//! its committed head signed by the authority signer at the cadence, a quiet one included
//! (CMP-6, T16, OP-143 m.10), and the note is appended with its key excerpt. A signer that is
//! down leaves nothing behind and the next tick retries (CR-23, G42).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use access_authority_sequencer::adapters::{PgHeads, SocketSigner, SourcesClock};
use access_authority_sequencer::checkpoint::{CheckpointError, checkpoint};
use access_authority_sequencer::ports::{Clock as _, Heads, NoteSigner as DomainSigner};
use access_identity_audit::AuditError;
use access_identity_audit::adapters::{Held, PgAudit, PgOperational, SignerNotes};
use access_identity_audit::app::step;
use access_identity_audit::ports::{AuditLog, NoteSigner};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::record::RecordEnvelope;
use access_kernel::verify::key_scope::SpecVersions;
use access_store::Pool;
use access_store::audit_lease::{AuditChain, acquire_audit_lease};
use access_store::authority_checkpoint::{AuthorityCheckpoint, append};
use access_store::scope::DomainId;

/// How often the audit chains are integrated (PD; Ek B "periodic ~1 s").
pub(crate) const AUDIT_INTERVAL: Duration = Duration::from_secs(1);

/// The domain checkpoint cadence (T16 POLICY DEFAULT 60 s).
pub(crate) const DOMAIN_INTERVAL: Duration = Duration::from_secs(60);

/// How long a replica's lease on a cell audit chain lasts unless renewed (PD; OP-152 m.5 (k)).
pub(crate) const AUDIT_LEASE: Duration = Duration::from_secs(10);

/// Most checkpoints one chain appends per tick.
const STEPS: u32 = 16;

/// What one [`audit_tick`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuditTick {
    /// Identity audit checkpoints appended.
    pub(crate) identity: u32,
    /// Operational stream checkpoints appended.
    pub(crate) operational: u32,
    /// Chains whose step failed.
    pub(crate) failed: u32,
    /// Chains whose lease another replica holds (OP-152 m.5 (k)).
    pub(crate) standby: u32,
}

async fn drain<L: AuditLog + Sync, S: NoteSigner + Sync>(
    log: &L,
    signer: &S,
    now: u64,
) -> Result<u32, AuditError> {
    let mut n = 0_u32;
    while n < STEPS && step(log, signer, now).await?.is_some() {
        n = n.saturating_add(1);
    }
    Ok(n)
}

/// Integrates and signs what ended on both audit chains since their last checkpoints, at `now`,
/// on each chain whose lease `holder` takes or renews; another replica's live lease leaves that
/// chain to it (OP-152 m.5 (k)).
pub(crate) async fn audit_tick<S: NoteSigner + Sync>(
    checkpointer: &Pool,
    holder: &str,
    signer: &S,
    now: u64,
) -> AuditTick {
    let mut out = AuditTick::default();
    match acquire_audit_lease(checkpointer, AuditChain::Identity, holder, AUDIT_LEASE).await {
        Ok(true) => {
            let log = Held {
                log: PgAudit(checkpointer.clone()),
                holder: holder.to_owned(),
            };
            match drain(&log, signer, now).await {
                Ok(n) => out.identity = n,
                Err(error) => {
                    out.failed = out.failed.saturating_add(1);
                    tracing::warn!(%error, chain = "identity-audit", "audit checkpoint not appended");
                }
            }
        }
        Ok(false) => out.standby = out.standby.saturating_add(1),
        Err(error) => {
            out.failed = out.failed.saturating_add(1);
            tracing::warn!(%error, chain = "identity-audit", "audit checkpoint lease not taken");
        }
    }
    match acquire_audit_lease(checkpointer, AuditChain::Operational, holder, AUDIT_LEASE).await {
        Ok(true) => {
            let log = Held {
                log: PgOperational(checkpointer.clone()),
                holder: holder.to_owned(),
            };
            match drain(&log, signer, now).await {
                Ok(n) => out.operational = n,
                Err(error) => {
                    out.failed = out.failed.saturating_add(1);
                    tracing::warn!(%error, chain = "authority-operational", "audit checkpoint not appended");
                }
            }
        }
        Ok(false) => out.standby = out.standby.saturating_add(1),
        Err(error) => {
            out.failed = out.failed.saturating_add(1);
            tracing::warn!(%error, chain = "authority-operational", "audit checkpoint lease not taken");
        }
    }
    out
}

/// The `SpecVersions` `domain` adopted at Genesis (§16.4.4 m.17).
async fn versions(app: &Pool, domain: Digest) -> Result<SpecVersions, CheckpointError> {
    let unreadable = || CheckpointError::Extension;
    let genesis = access_store::authority::read_log(app, &DomainId::from_bytes(domain.0), 0, 0)
        .await
        .map_err(|e| CheckpointError::Store(e.into()))?;
    let record = genesis.first().ok_or_else(unreadable)?;
    let envelope = RecordEnvelope::from_bytes(&record.envelope).map_err(|_| unreadable())?;
    let field = envelope.fields.get("versions").ok_or_else(unreadable)?;
    SpecVersions::from_value(&field.value).map_err(|_| unreadable())
}

/// Signs and appends the checkpoint of one domain's committed head at `now`.
pub(crate) async fn domain_checkpoint<H: Heads + Sync, S: DomainSigner + Sync>(
    (heads, signer): (&H, &S),
    (app, sequencer): (&Pool, &Pool),
    domain: Digest,
    now: u64,
) -> Result<AuthorityCheckpoint, CheckpointError> {
    let versions = versions(app, domain).await?;
    let noted = checkpoint(heads, signer, domain, &versions, now).await?;
    let row = AuthorityCheckpoint {
        issued_at: now,
        size: noted.checkpoint.size,
        root: noted.checkpoint.root,
        note: noted.note,
        excerpt: noted.excerpt,
    };
    append(sequencer, &DomainId::from_bytes(domain.0), &row)
        .await
        .map_err(|e| CheckpointError::Store(e.into()))?;
    Ok(row)
}

fn wall_ms() -> u64 {
    use access_identity_account::ports::Clock as _;
    access_identity_account::adapters::system::SystemClock.now_ms()
}

/// The running checkpointers; [`Checkpointers::stop`] ends them.
pub(crate) struct Checkpointers {
    audit: tokio::task::JoinHandle<()>,
    domains: tokio::task::JoinHandle<()>,
}

/// Where the checkpointers read and write, and the two signers.
pub(crate) struct Inputs {
    /// `access_checkpointer`: both audit chains and their checkpoints.
    pub(crate) checkpointer: Pool,
    /// `access_app`: committed heads and Genesis records.
    pub(crate) app: Pool,
    /// `access_sequencer`: domain checkpoints are appended as the sequencer.
    pub(crate) sequencer: Pool,
    /// The identity signer's socket (cell `audit-checkpoint` key).
    pub(crate) identity_signer: PathBuf,
    /// The authority signer's socket (operational keys, usage `checkpoint`).
    pub(crate) authority_signer: PathBuf,
    /// This process's lease holder name for the cell audit chains (OP-152 m.5 (k)).
    pub(crate) holder: String,
}

impl Checkpointers {
    /// Starts both loops; `led` names the domains this process leads.
    pub(crate) fn start<F>(inputs: Inputs, led: F) -> Self
    where
        F: Fn() -> Vec<Digest> + Send + Sync + 'static,
    {
        let Inputs {
            checkpointer,
            app,
            sequencer,
            identity_signer,
            authority_signer,
            holder,
        } = inputs;
        let audit = tokio::spawn(async move {
            let signer = SignerNotes(identity_signer);
            let mut every = tokio::time::interval(AUDIT_INTERVAL);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                every.tick().await;
                audit_tick(&checkpointer, &holder, &signer, wall_ms()).await;
            }
        });
        let led = Arc::new(led);
        let domains = tokio::spawn(async move {
            let heads = PgHeads(app.clone());
            let signer = SocketSigner::new(authority_signer);
            let mut clock = SourcesClock::new(sequencer.clone());
            let mut every = tokio::time::interval(DOMAIN_INTERVAL);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                every.tick().await;
                let Ok(now) = clock.now().await else {
                    tracing::warn!("no trusted time; domain checkpoints not signed");
                    continue;
                };
                for domain in led() {
                    if let Err(error) =
                        domain_checkpoint((&heads, &signer), (&app, &sequencer), domain, now).await
                    {
                        tracing::warn!(%error, "domain checkpoint not appended");
                    }
                }
            }
        });
        Self { audit, domains }
    }

    /// Stops both loops between ticks.
    pub(crate) fn stop(self) {
        self.audit.abort();
        self.domains.abort();
    }
}

#[cfg(test)]
mod tests;
