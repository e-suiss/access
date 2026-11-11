//! The decision point's side of the Replica Mirror and the streamed Record Export (§16.6.1,
//! T21, TI-13, AP-14, G28, OP-158 m.3 (e), (f), (g)): a run starts only from an allowed
//! `access.audit_export` Exercise and is written to the audit stream before anything leaves;
//! its stream is read from the store, outside the domain's commit lock, and every record is
//! checked against its stored leaf on the way out (INV-27). A replica's acknowledgement counts
//! only under its declared key and for a checkpoint the domain signed.

use std::time::Duration;

use access_authority_sequencer::ports::Clock;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::record::RecordEnvelope;
use access_store::authority::{LogRecord, domain_tenant, read_head, read_log};
use access_store::mirror::{
    ExportRun, ReplicaAckRow, RunKind, ack, checkpoint_exists, checkpoints, leaf_hashes, run,
    start_run,
};
use access_store::operational::{OperationalEvent, record_operational};
use access_store::scope::DomainId;
use suiss_crypto::sig::PureBackend;
use suiss_ledger::replica::mirror::{Frame, SignedReplicaAck};

use super::audit::{audit_text, who};
use crate::CoreError;
use crate::adapters::Domains;
use crate::app::Incoming;
use crate::app::export::Started;
use crate::app::mirror::replicas;
use crate::domain::export::{Coverage, disclosure};
use crate::ports::{Binding, Keys, Salts};

/// A Record Export or Replica Mirror stream started (OP-44, G28).
pub(crate) const AUDIT_EVENT_STREAMED: &str = "export.streamed";

/// A declared replica acknowledged a checkpoint (TI-13).
pub(crate) const AUDIT_EVENT_REPLICA_ACKED: &str = "replica.acked";

/// Most records one mirror answer carries (PD); the replica asks again from where it is.
pub(crate) const MIRROR_BATCH: u64 = 512;

/// How often a long-polled mirror answer looks for new records or checkpoints.
pub(crate) const MIRROR_POLL: Duration = Duration::from_millis(200);

fn id(domain: &Digest) -> DomainId {
    DomainId::from_bytes(domain.0)
}

fn coverage(full: bool) -> Coverage {
    if full {
        Coverage::Full
    } else {
        Coverage::Digest
    }
}

impl<K: Keys, B: Binding + Clone, S: Salts + Clone, C: Clock + Clone> Domains<K, B, S, C> {
    async fn now(&self) -> Result<u64, CoreError> {
        let mut clock = self.setup.clock.clone();
        clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))
    }

    async fn start_led(&self, inc: &Incoming) -> Result<(Started, u64), CoreError> {
        let mut guard = self.leading(inc.request.domain).await?;
        let Some(led) = guard.as_mut() else {
            return Err(CoreError::Unavailable("leader"));
        };
        let now = led
            .clock
            .now()
            .await
            .map_err(|_| CoreError::Unavailable("time"))?;
        let result = led.core.start_export(inc, now).await;
        if matches!(result, Err(CoreError::Sequencer(_) | CoreError::Store(_))) {
            *guard = None;
        }
        result.map(|s| (s, now))
    }

    /// Starts the run of the allowed `access.audit_export` Exercise `inc` names: a package of
    /// a fixed range, or with `stream: "mirror"` the open-ended Replica Mirror (OP-158 m.3
    /// (f), (g)). The run is kept and written to the audit stream before its stream is read
    /// (U53, OP-44, G28); the same Exercise sent again names the same run. No rate class,
    /// quota or plan state counts it (anti-hostage k.2, B3).
    ///
    /// # Errors
    /// As [`crate::app::Authority::start_export`]; [`CoreError::Unavailable`] `audit` when the
    /// run cannot be audited.
    pub async fn start_export(&self, inc: &Incoming) -> Result<ExportRun, CoreError> {
        let result = self.start_led(inc).await;
        let (started, now) = self.audited(inc, "export", result).await?;
        let domain = id(&inc.request.domain);
        let fresh = ExportRun {
            export: started.exercise.0,
            kind: if started.mirror {
                RunKind::Mirror
            } else {
                RunKind::Package
            },
            party: started.party.0,
            instance: started.instance.0,
            pep: inc.pep.clone(),
            from: started.from,
            to: started.to,
            full: started.coverage == Coverage::Full,
            started_at: now,
        };
        if !start_run(&self.setup.app, &domain, &fresh).await? {
            return run(&self.setup.app, &domain, &fresh.export)
                .await?
                .filter(|r| r.pep == fresh.pep)
                .ok_or(CoreError::Protocol("export-run"));
        }
        let target = match fresh.to {
            Some(to) => format!("records:{}-{to}", fresh.from),
            None => format!("mirror:{}", fresh.from),
        };
        self.operational(
            inc,
            (
                AUDIT_EVENT_STREAMED,
                &who(inc, Some(&started.instance)),
                &target,
                started.coverage.word(),
            ),
        )
        .await?;
        Ok(fresh)
    }

    /// The run `export` of `domain` for the PEP `pep`: only the PEP that committed its Exercise
    /// reads it, and a mirror only while its Party still audits the domain (G28, OP-141 m.38
    /// (d)).
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `export-run` for no such run or another PEP, `export-scope`
    /// when the Party no longer audits; [`CoreError::Store`].
    pub async fn export_run(
        &self,
        domain: Digest,
        export: &[u8; 32],
        pep: &str,
    ) -> Result<ExportRun, CoreError> {
        let r = run(&self.setup.app, &id(&domain), export)
            .await?
            .filter(|r| r.pep == pep)
            .ok_or(CoreError::Protocol("export-run"))?;
        if r.kind == RunKind::Mirror {
            let mut guard = self.leading(domain).await?;
            let Some(led) = guard.as_mut() else {
                return Err(CoreError::Unavailable("leader"));
            };
            let now = led
                .clock
                .now()
                .await
                .map_err(|_| CoreError::Unavailable("time"))?;
            let party = access_kernel::model::Id(r.party);
            if !led.core.still_audits(&party, now).await? {
                return Err(CoreError::Protocol("export-scope"));
            }
        }
        Ok(r)
    }

    /// The leaf hashes of `domain`'s records before `from`: the frontier a package streamed
    /// from `from` starts with.
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn leaves_before(
        &self,
        domain: Digest,
        from: u64,
    ) -> Result<Vec<[u8; 32]>, CoreError> {
        Ok(leaf_hashes(&self.setup.app, &id(&domain), 0, from).await?)
    }

    /// `domain`'s stored records `from..=to`.
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn records(
        &self,
        domain: Digest,
        from: u64,
        to: u64,
    ) -> Result<Vec<LogRecord>, CoreError> {
        Ok(read_log(&self.setup.app, &id(&domain), from, to).await?)
    }

    /// The signed checkpoints of `domain` with size in `(after, upto]`: size, root, note.
    ///
    /// # Errors
    /// [`CoreError::Store`].
    pub async fn checkpoints_in(
        &self,
        domain: Digest,
        after: u64,
        upto: u64,
    ) -> Result<Vec<(u64, [u8; 32], String)>, CoreError> {
        Ok(checkpoints(&self.setup.app, &id(&domain), after, upto)
            .await?
            .into_iter()
            .map(|c| (c.size, c.root, c.note))
            .collect())
    }

    async fn mirror_batch(
        &self,
        r: &ExportRun,
        domain: Digest,
        (from, checkpoint): (u64, u64),
    ) -> Result<(Vec<Frame>, u64), CoreError> {
        let head = read_head(&self.setup.app, &id(&domain)).await?.pos;
        let size = head.saturating_add(1);
        let mut frames = Vec::new();
        let mut end = from.min(size);
        if from < size {
            let last = from
                .saturating_add(MIRROR_BATCH)
                .saturating_sub(1)
                .min(head);
            for rec in self.records(domain, from, last).await? {
                let env = RecordEnvelope::from_bytes(&rec.envelope)
                    .map_err(|_| CoreError::Unavailable("mirror"))?;
                let d = disclosure(&env, coverage(r.full))
                    .map_err(|_| CoreError::Unavailable("mirror"))?;
                // INV-27
                if d.leaf_hash().ok() != Some(rec.leaf_hash) || d.header.pos != rec.pos {
                    return Err(CoreError::Unavailable("mirror"));
                }
                frames.push(Frame::Record {
                    position: rec.pos,
                    envelope: d.to_bytes().map_err(|_| CoreError::Unavailable("mirror"))?,
                    body: None,
                });
            }
            end = last.saturating_add(1);
        }
        for c in checkpoints(&self.setup.app, &id(&domain), checkpoint, end).await? {
            frames.push(Frame::Checkpoint {
                note: c.note,
                cosignatures: Vec::new(),
                excerpt: Some(c.excerpt),
            });
        }
        Ok((frames, size))
    }

    /// The next mirror answer of run `r` for a replica holding `from` records whose last
    /// accepted checkpoint has size `checkpoint`: up to [`MIRROR_BATCH`] records and the
    /// checkpoints they complete, or, when nothing new comes within `wait`, a heartbeat
    /// (long poll, T21).
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `export-run` for a run that is not a mirror;
    /// [`CoreError::Unavailable`] `mirror` when a stored record does not match its leaf.
    pub async fn mirror(
        &self,
        r: &ExportRun,
        domain: Digest,
        (from, checkpoint): (u64, u64),
        wait: Duration,
    ) -> Result<Vec<Frame>, CoreError> {
        if r.kind != RunKind::Mirror || from < r.from {
            return Err(CoreError::Protocol("export-run"));
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(wait)
            .unwrap_or_else(tokio::time::Instant::now);
        loop {
            let (frames, size) = self.mirror_batch(r, domain, (from, checkpoint)).await?;
            if !frames.is_empty() {
                return Ok(frames);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(vec![Frame::Heartbeat {
                    size,
                    at: self.now().await?,
                }]);
            }
            tokio::time::sleep(MIRROR_POLL).await;
        }
    }

    /// Takes a replica's signed acknowledgement (TI-13, SEC23): it counts only when the replica
    /// is declared for the domain, the signature verifies under its declared key and the size
    /// and root are a checkpoint the domain signed. `true` when it is new.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `replica-unknown`, `replica-ack-signature` or
    /// `replica-ack-checkpoint`; [`CoreError::Store`].
    pub async fn replica_ack(&self, signed: &SignedReplicaAck) -> Result<bool, CoreError> {
        let domain = Digest(signed.ack.domain);
        let replica = replicas()
            .named(&domain, &signed.ack.replica)
            .ok_or(CoreError::Protocol("replica-unknown"))?;
        signed
            .verify(&PureBackend, &replica.key)
            .map_err(|_| CoreError::Protocol("replica-ack-signature"))?;
        let scope = id(&domain);
        if !checkpoint_exists(&self.setup.app, &scope, signed.ack.size, &signed.ack.root).await? {
            return Err(CoreError::Protocol("replica-ack-checkpoint"));
        }
        let fresh = ack(
            &self.setup.sequencer,
            &scope,
            &ReplicaAckRow {
                replica: replica.name.clone(),
                size: signed.ack.size,
                root: signed.ack.root,
                acked_at: signed.ack.at,
                signature: signed.sig,
            },
        )
        .await?;
        replicas().set_acked(domain, signed.ack.size);
        if fresh {
            let now = self.now().await?;
            let tenant = domain_tenant(&self.setup.sequencer, &scope).await?;
            record_operational(
                &self.setup.app,
                &OperationalEvent {
                    occurred_at_ms: now,
                    tenant,
                    domain: tenant.map(|_| domain.0),
                    event_type: AUDIT_EVENT_REPLICA_ACKED,
                    actor: &audit_text(&format!("replica:{}", replica.name)),
                    target: &format!("size:{}", signed.ack.size),
                    reason: "",
                    correlation: &audit_text(&b64url_encode(&signed.sig)),
                },
            )
            .await
            .map_err(|_| CoreError::Unavailable("audit"))?;
        }
        Ok(fresh)
    }
}
