//! PostgreSQL adapters of the [`DomainLog`], [`Clock`] and [`Heads`] ports, the signer socket
//! as the [`NoteSigner`] port, domain creation and chain verification.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use access_authority_signer::adapters::call;
use access_authority_signer::app::Noted;
use access_authority_signer::domain::default_template;
use access_authority_signer::protocol::{Request, Response};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::model::TrustedTime;
use access_kernel::record::{Header, Opened, RecordEnvelope, RecordKind, check_link};
use access_store::Pool;
use access_store::authority::{
    CommitBatch, HeadRow, Lease, LogRecord, NonceRow, Renewal, acquire_lease, commit_batch,
    create_domain, find_nonce, read_head, read_log, release_lease, renew_lease, server_time,
};
use access_store::scope::DomainId;
use suiss_ledger::time::{Sample, TimeError, TrustedClock};

use crate::SequencerError;
use crate::ports::{Clock, DomainLog, Heads, NoteSigner};

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

    async fn renew(&self, lease: Lease) -> Result<Renewal, SequencerError> {
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

/// Committed heads read from PostgreSQL.
pub struct PgHeads(pub Pool);

impl Heads for PgHeads {
    async fn committed(&self, domain: &Digest) -> Result<HeadRow, SequencerError> {
        Ok(read_head(&self.0, &DomainId::from_bytes(domain.0)).await?)
    }
}

/// The authority signer behind its Unix domain socket; a domain it does not know yet is
/// opened with the default template first (OP-143 m.5).
pub struct SocketSigner {
    path: std::path::PathBuf,
}

impl SocketSigner {
    /// The signer listening at `path`.
    #[must_use]
    pub const fn new(path: std::path::PathBuf) -> Self {
        Self { path }
    }
}

impl NoteSigner for SocketSigner {
    async fn sign_note(&self, domain: Digest, body: String, at: u64) -> Result<Noted, String> {
        let request = Request::SignNote { domain, body, at };
        let mut answer = call(&self.path, &request).await;
        if matches!(&answer, Ok(Response::Error(code)) if code == "signer-unknown-domain") {
            let open = Request::Open(Box::new(default_template(domain)));
            if !matches!(call(&self.path, &open).await, Ok(Response::Opened)) {
                return Err(String::from("signer-unknown-domain"));
            }
            answer = call(&self.path, &request).await;
        }
        match answer {
            Ok(Response::Noted { line, excerpt }) => Ok(Noted { line, excerpt }),
            Ok(Response::Error(code)) => Err(code),
            Ok(_) => Err(String::from("signer-frame")),
            Err(_) => Err(String::from("signer-unreachable")),
        }
    }

    async fn metadata(&self, domain: Digest) -> Result<Vec<u8>, String> {
        let request = Request::Metadata(domain);
        let mut answer = call(&self.path, &request).await;
        if matches!(&answer, Ok(Response::Error(code)) if code == "signer-unknown-domain") {
            let open = Request::Open(Box::new(default_template(domain)));
            if !matches!(call(&self.path, &open).await, Ok(Response::Opened)) {
                return Err(String::from("signer-unknown-domain"));
            }
            answer = call(&self.path, &request).await;
        }
        match answer {
            Ok(Response::Metadata(bytes)) => Ok(bytes),
            Ok(Response::Error(code)) => Err(code),
            Ok(_) => Err(String::from("signer-frame")),
            Err(_) => Err(String::from("signer-unreachable")),
        }
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
    // L0-META-7
    let state = access_kernel::fold::genesis(&envelope)?
        .into_iter()
        .filter_map(|(k, e)| e.value.map(|v| (k, v)))
        .map(|(k, v)| {
            suiss_crypto::dcbor::encode(&v, suiss_crypto::dcbor::Limits::CEILING)
                .map(|v| (k, v))
                .map_err(access_kernel::record::RecordError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let record = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at,
        leaf_hash: envelope.leaf_hash()?,
        envelope: envelope
            .to_bytes()
            .map_err(access_kernel::record::RecordError::from)?,
    };
    create_domain(
        sequencer,
        &DomainId::from_bytes(domain.0),
        tenant,
        &record,
        &state,
    )
    .await?;
    Ok(domain)
}

/// The arbiter (§16.5, TI-16, L2-REC-3): folds the log from Genesis up to the head and
/// compares the result with the stored state, key by key.
///
/// # Errors
/// [`SequencerError::FoldDiverged`] when they differ; [`SequencerError`] otherwise.
pub async fn fold_check(pool: &Pool, domain: Digest) -> Result<(), SequencerError> {
    let id = DomainId::from_bytes(domain.0);
    let head = access_store::authority::read_head(pool, &id).await?;
    let mut folded = None;
    for r in read_log(pool, &id, 0, head.pos).await? {
        let record =
            RecordEnvelope::from_bytes(&r.envelope).map_err(|_| SequencerError::Diverged)?;
        match folded.as_mut() {
            None => folded = Some(access_kernel::fold::genesis(&record)?),
            Some(state) => access_kernel::fold::apply(state, &record)?,
        }
    }
    let folded = folded.ok_or(SequencerError::Diverged)?;
    let stored = access_store::authority::state(pool, &id).await?;
    let mut same = folded.len() == stored.len();
    for ((key, entry), row) in folded.iter().zip(&stored) {
        let value = entry
            .value
            .as_ref()
            .map(|v| suiss_crypto::dcbor::encode(v, suiss_crypto::dcbor::Limits::CEILING))
            .transpose()
            .map_err(access_kernel::record::RecordError::from)?;
        same &= *key == row.key && entry.version == row.version && value == row.value;
    }
    if same {
        Ok(())
    } else {
        Err(SequencerError::FoldDiverged)
    }
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

/// Trusted time from the process clock, the canonical server's clock (OP-129 m.1 (a), (b))
/// and the latest Roughtime reading when one is fresh (OP-158 m.3 (k)), bounded by a
/// monotonic clock; refused while a witness cross-check failed. A clone keeps its own last reading.
#[derive(Clone)]
pub struct SourcesClock {
    pool: Pool,
    started: Instant,
    combiner: TrustedClock,
}

impl SourcesClock {
    /// Reads the system clock and `pool`'s server.
    #[must_use]
    pub fn new(pool: Pool) -> Self {
        Self {
            pool,
            started: Instant::now(),
            combiner: TrustedClock::default(),
        }
    }
}

impl SourcesClock {
    /// How many sources the last reading left out (TI-RT2: one of three may deviate).
    #[must_use]
    pub const fn deviating(&self) -> usize {
        self.combiner.deviating()
    }

    /// The sources' trusted time without the witness gate: the checkpointer keeps signing
    /// while the gate is closed, so that a later cosignature can reopen it (TI-RT2).
    ///
    /// # Errors
    /// [`SequencerError::Time`] or the server clock's store error.
    pub async fn sources(&mut self) -> Result<u64, SequencerError> {
        let server = server_time(&self.pool).await?;
        let system = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .ok_or(TimeError::TooFewSources)?;
        let mono =
            u64::try_from(self.started.elapsed().as_millis()).map_err(|_| TimeError::Monotonic)?;
        let mut samples = vec![Sample::exact(system), Sample::exact(server)];
        samples.extend(crate::witness::roughtime().current());
        Ok(self.combiner.read_samples(&samples, mono)?)
    }
}

impl Clock for SourcesClock {
    async fn now(&mut self) -> Result<u64, SequencerError> {
        // TI-RT2, OP-158 m.3 (k)
        crate::witness::time_check()?;
        self.sources().await
    }
}
