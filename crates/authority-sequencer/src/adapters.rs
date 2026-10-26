//! PostgreSQL adapter of the [`DomainLog`] port, domain creation and chain verification.

use std::collections::BTreeMap;
use std::time::Duration;

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::model::TrustedTime;
use access_kernel::record::{Header, Opened, RecordEnvelope, RecordKind, check_link};
use access_store::Pool;
use access_store::authority::{
    CommitBatch, HeadRow, Lease, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
    find_nonce, read_log, release_lease, renew_lease,
};
use access_store::scope::DomainId;

use crate::SequencerError;
use crate::ports::DomainLog;

/// One domain's log in PostgreSQL, used as `holder`.
pub struct PgLog {
    pool: Pool,
    domain: DomainId,
    tenant: [u8; 16],
    holder: String,
    ttl: Duration,
}

impl PgLog {
    /// The log of `domain`, written as `holder` with leases of `ttl` (OP-130 m.6).
    #[must_use]
    pub fn new(
        pool: Pool,
        domain: Digest,
        tenant: [u8; 16],
        holder: String,
        ttl: Duration,
    ) -> Self {
        Self {
            pool,
            domain: DomainId::from_bytes(domain.0),
            tenant,
            holder,
            ttl,
        }
    }
}

impl DomainLog for PgLog {
    async fn acquire(&self) -> Result<(Lease, HeadRow), SequencerError> {
        Ok(acquire_lease(&self.pool, &self.domain, &self.holder, self.ttl).await?)
    }

    async fn renew(&self, lease: Lease) -> Result<(), SequencerError> {
        Ok(renew_lease(&self.pool, &self.domain, &self.holder, lease, self.ttl).await?)
    }

    async fn release(&self, lease: Lease) -> Result<(), SequencerError> {
        Ok(release_lease(&self.pool, &self.domain, &self.holder, lease).await?)
    }

    async fn record(&self, pos: u64) -> Result<Option<LogRecord>, SequencerError> {
        Ok(read_log(&self.pool, &self.domain, pos, pos)
            .await?
            .into_iter()
            .next())
    }

    async fn nonce(&self, nonce: &[u8]) -> Result<Option<NonceRow>, SequencerError> {
        Ok(find_nonce(&self.pool, &self.domain, nonce).await?)
    }

    async fn commit(&self, batch: &CommitBatch) -> Result<(), SequencerError> {
        Ok(commit_batch(&self.pool, &self.domain, self.tenant, batch).await?)
    }
}

/// Writes the Genesis record at position 0 and returns the new domain's id, the digest of
/// the Genesis envelope (§5.2, L0-ENC-25, INV-2).
///
/// # Errors
/// [`SequencerError`]; a second Genesis for the same domain fails in the store.
pub async fn create_genesis(
    sequencer: &Pool,
    tenant: [u8; 16],
    fields: BTreeMap<String, Opened>,
    recorded_at: TrustedTime,
) -> Result<Digest, SequencerError> {
    // OP-106 m.10, m.11
    let envelope = RecordEnvelope {
        header: Header {
            domain: None,
            pos: 0,
            kind: RecordKind::Genesis,
            recorded_at,
            prev: None,
        },
        fields,
    };
    let domain = envelope.domain()?;
    let record = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at,
        leaf_hash: envelope.leaf_hash()?,
        envelope: envelope
            .to_bytes()
            .map_err(access_kernel::record::RecordError::from)?,
    };
    create_domain(sequencer, &DomainId::from_bytes(domain.0), tenant, &record).await?;
    Ok(domain)
}

/// Checks that stored records `from..=to` chain to each other (TI-19, L0-ENC-27).
///
/// # Errors
/// [`SequencerError`].
pub async fn verify_chain(
    pool: &Pool,
    domain: Digest,
    from: u64,
    to: u64,
) -> Result<(), SequencerError> {
    let records = read_log(pool, &DomainId::from_bytes(domain.0), from, to).await?;
    let mut previous = None;
    for r in &records {
        let core = RecordEnvelope::from_bytes(&r.envelope)
            .map_err(|_| SequencerError::Diverged)?
            .leaf_core()?;
        if core.leaf_hash()? != r.leaf_hash {
            return Err(SequencerError::Diverged);
        }
        if let Some(prev) = &previous {
            check_link(prev, &core, &domain)?;
        }
        previous = Some(core);
    }
    Ok(())
}
