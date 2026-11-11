//! The checkpointers of this process. The identity audit log and the authority plane's
//! operational stream are integrated into their trees and signed by the identity signer's cell
//! `audit-checkpoint` key (OP-38, OP-44, OP-150 m.3 (h)); every domain this process leads has
//! its committed head signed by the authority signer at the cadence, a quiet one included
//! (CMP-6, T16, OP-143 m.10), and the note is appended with its key excerpt. A signer that is
//! down leaves nothing behind and the next tick retries (CR-23, G42). A domain checkpoint is
//! due every 60 s or 1 000 records, whichever comes first, as a heartbeat when nothing changed,
//! and out of cycle when a commit waits for its cosignature (coalesced, OP-38, OP-158 m.3 (c));
//! each is sent to the declared witnesses and compared with what they hold (§16.6).

mod mirrored;
pub(crate) mod publish;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use access_authority_sequencer::adapters::{PgHeads, SocketSigner, SourcesClock};
use access_authority_sequencer::checkpoint::{CheckpointError, SignedCheckpoint, checkpoint};
use access_authority_sequencer::ports::{Heads, NoteSigner as DomainSigner};
use access_authority_sequencer::witness::board;
use access_identity_audit::AuditError;
use access_identity_audit::adapters::{Held, PgAudit, PgOperational, SignerNotes};
use access_identity_audit::app::{identity_step, step};
use access_identity_audit::ports::{AuditLog, NoteSigner};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::record::RecordEnvelope;
use access_kernel::verify::key_scope::SpecVersions;
use access_store::Pool;
use access_store::audit_lease::{AuditChain, acquire_audit_lease};
use access_store::authority_checkpoint::{AuthorityCheckpoint, append, latest};
use access_store::scope::DomainId;
use suiss_ledger::checkpoint::cadence::Cadence;

/// How often the audit chains are integrated and published: half the identity MMD of 1 s, so a
/// row is in a published checkpoint within it (PD; U52, OP-38, OP-158 m.3 (w)).
pub(crate) const AUDIT_INTERVAL: Duration = Duration::from_millis(500);

/// How often the domain cadences are looked at; the cadence itself is T16's 60 s or 1 000
/// records (`suiss_ledger::checkpoint::cadence`).
pub(crate) const DOMAIN_TICK: Duration = Duration::from_secs(1);

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

/// [`drain`] on the identity audit log, each step followed by the tree checkpoints of the realms
/// it touched (OP-152 m.7 (d)).
async fn drain_identity<S: NoteSigner + Sync>(
    log: &Held<PgAudit>,
    signer: &S,
    now: u64,
) -> Result<u32, AuditError> {
    let mut n = 0_u32;
    while n < STEPS {
        let Some(done) = identity_step(log, signer, now).await? else {
            break;
        };
        if done.realms_failed > 0 {
            tracing::warn!(
                failed = done.realms_failed,
                "realm audit checkpoints not appended; they catch up later"
            );
        }
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
            match drain_identity(&log, signer, now).await {
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
#[cfg(test)]
pub(crate) async fn domain_checkpoint<H: Heads + Sync, S: DomainSigner + Sync>(
    (heads, signer): (&H, &S),
    (app, sequencer): (&Pool, &Pool),
    domain: Digest,
    now: u64,
) -> Result<AuthorityCheckpoint, CheckpointError> {
    signed_checkpoint((heads, signer), (app, sequencer), domain, now)
        .await
        .map(|(row, _)| row)
}

/// [`domain_checkpoint`] with the signed checkpoint the witnesses get.
pub(crate) async fn signed_checkpoint<H: Heads + Sync, S: DomainSigner + Sync>(
    (heads, signer): (&H, &S),
    (app, sequencer): (&Pool, &Pool),
    domain: Digest,
    now: u64,
) -> Result<(AuthorityCheckpoint, SignedCheckpoint), CheckpointError> {
    let versions = versions(app, domain).await?;
    let noted = checkpoint(heads, signer, domain, &versions, now).await?;
    let row = AuthorityCheckpoint {
        issued_at: now,
        size: noted.checkpoint.size,
        root: noted.checkpoint.root,
        note: noted.note.clone(),
        excerpt: noted.excerpt.clone(),
    };
    append(sequencer, &DomainId::from_bytes(domain.0), &row)
        .await
        .map_err(|e| CheckpointError::Store(e.into()))?;
    Ok((row, noted))
}

/// The declarations of the binding-signed Domain Metadata `signed`; nothing declared when it
/// cannot be read (OP-158 m.6 (e): an absent declaration grants nothing).
fn declarations(signed: &[u8]) -> access_kernel::verify::key_scope::Declarations {
    use access_kernel::codec::Canonical as _;
    suiss_crypto::cose::parse_sign1(signed)
        .ok()
        .and_then(|s| s.payload)
        .and_then(|p| access_kernel::verify::key_scope::DomainMetadata::from_bytes(&p).ok())
        .map(|m| m.declared)
        .unwrap_or_default()
}

/// One cadence step of `domain` at `now`: the checkpoint when one is due, published.
pub(crate) async fn domain_step<H: Heads + Sync, S: DomainSigner + Sync>(
    (heads, keys, witnesses): (&H, &S, &publish::Publisher),
    (app, sequencer): (&Pool, &Pool),
    (domain, cadence): (Digest, &mut Cadence),
    now: u64,
) -> Result<Option<(AuthorityCheckpoint, publish::Published)>, CheckpointError> {
    let id = DomainId::from_bytes(domain.0);
    if cadence.last().is_none()
        && let Some(last) = latest(app, &id)
            .await
            .map_err(|e| CheckpointError::Store(e.into()))?
    {
        *cadence = cadence.resume(last.size, last.issued_at);
    }
    if let Some(wanted) = board().wanted(&domain) {
        cadence.want(wanted);
    }
    let head = heads.committed(&domain).await?;
    let size = head.pos.saturating_add(1);
    let Some(due) = cadence.due(size, now) else {
        return Ok(None);
    };
    if due == suiss_ledger::checkpoint::cadence::Due::OutOfCycle {
        tracing::debug!(
            event = "checkpoint.coalesced",
            waiters = 1_u32,
            "an out-of-cycle checkpoint serves every waiting commit"
        );
    }
    let (row, noted) = signed_checkpoint((heads, keys), (app, sequencer), domain, now).await?;
    cadence.issued(row.size, now);
    let target_text = row.size.to_string();
    let published = access_store::operational::record_operational(
        app,
        &access_store::operational::OperationalEvent {
            event_type: "checkpoint.published",
            occurred_at_ms: now,
            tenant: None,
            domain: Some(domain.0),
            actor: "provider",
            target: &target_text,
            reason: "",
            correlation: "",
        },
    )
    .await;
    if let Err(error) = published {
        tracing::warn!(%error, "checkpoint audit row not kept");
    }
    let recorded_at =
        access_authority_sequencer::checkpoint::extensions(&noted.checkpoint)?.recorded_at;
    // OP-158 m.6 (e)
    let declared = declarations(&noted.metadata);
    if let Some(m) = declared.mmd {
        *cadence = cadence.within(m.authority_ms);
    }
    let witnesses = publish::Publisher {
        targets: access_authority_sequencer::witness::declared(&witnesses.targets, &declared),
        sinks: witnesses.sinks.clone(),
    };
    // T21, TI-13, OP-158 m.3 (f)
    let witnesses = mirrored::first(app, domain, &declared, row.size, witnesses).await;
    let outcome = publish::publish(
        &witnesses,
        (app, sequencer),
        domain,
        (&row, &noted, recorded_at),
    )
    .await;
    if !witnesses.targets.is_empty() {
        publish::gossip(&witnesses, (app, sequencer), domain, now).await;
    }
    Ok(Some((row, outcome)))
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
    /// Where the identity audit checkpoints are published (OP-37, U52).
    pub(crate) publication: crate::publication::Targets,
    /// The witnesses and sinks of the led domains' checkpoints (OP-158 m.3 (d)).
    pub(crate) publisher: publish::Publisher,
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
            publication,
            publisher,
        } = inputs;
        let audit = tokio::spawn(async move {
            let signer = SignerNotes(identity_signer);
            let mut every = tokio::time::interval(AUDIT_INTERVAL);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                every.tick().await;
                audit_tick(&checkpointer, &holder, &signer, wall_ms()).await;
                crate::publication::tick(&checkpointer, &publication).await;
            }
        });
        let led = Arc::new(led);
        let domains = tokio::spawn(async move {
            let heads = PgHeads(app.clone());
            let signer = SocketSigner::new(authority_signer);
            let mut clock = SourcesClock::new(sequencer.clone());
            let mut cadences: std::collections::HashMap<Digest, Cadence> =
                std::collections::HashMap::new();
            let mut every = tokio::time::interval(DOMAIN_TICK);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = every.tick() => {}
                    () = board().woken() => {}
                }
                // TI-RT2
                let Ok(now) = clock.sources().await else {
                    tracing::warn!("no trusted time; domain checkpoints not signed");
                    continue;
                };
                for domain in led() {
                    let cadence = cadences.entry(domain).or_default();
                    if let Err(error) = domain_step(
                        (&heads, &signer, &publisher),
                        (&app, &sequencer),
                        (domain, cadence),
                        now,
                    )
                    .await
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
