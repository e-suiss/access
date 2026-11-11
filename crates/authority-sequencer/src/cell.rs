//! Moving a domain between cells (§17.4.1, TI-2, EI-20, FA-2, FA-13, T28, OP-158 m.3 (n)).
//!
//! - Planned: the source seals its head at (q, e) under the lease; the target takes the whole
//!   image, replays it (chain, Merkle root, fold from Genesis) and accepts it at (q, e + 1).
//!   Positions are never reused and the source never appends again.
//! - Unplanned: only with a fence proof of the lost cell and the image covering the lost cell's
//!   last committed head and its highest witnessed checkpoint. Anything less is refused, is a
//!   sev-1 signal, and leaves the domain closed for `domain.recover`; an async copy is never
//!   promoted into the lineage by itself.

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::record::{RecordEnvelope, check_link};
use access_store::Pool;
use access_store::authority::{StateRow, acquire_lease};
use access_store::cells::{
    Acceptance, Image, accept as accept_image, continue_in_place, image, seal as seal_head,
};
use access_store::operational::{OperationalEvent, record_operational};
use access_store::scope::DomainId;
use suiss_ledger::merkle::Frontier;

use crate::SequencerError;

/// Why a cell move was refused.
#[derive(Debug, thiserror::Error)]
pub enum MoveError {
    /// The source head is not sealed: a planned acceptance needs the seal.
    #[error("the source is not sealed")]
    NotSealed,
    /// The image does not replay to its own head (chain, root or fold).
    #[error("the image does not replay: {0}")]
    Diverged(&'static str),
    /// No fence proof of the lost cell (OP-54-RL12, FA-13).
    #[error("no fence proof: the lost cell may still write")]
    Unfenced,
    /// The image does not cover the lost cell's last head or its witnessed checkpoint
    /// (§17.4.1 item 2 (ii)); the path is `domain.recover`.
    #[error("the copy does not cover {0}")]
    Uncovered(&'static str),
    /// The store or sequencer refused.
    #[error("{0}")]
    Sequencer(#[from] SequencerError),
}

impl From<access_store::StoreError> for MoveError {
    fn from(e: access_store::StoreError) -> Self {
        Self::Sequencer(SequencerError::Store(e))
    }
}

/// A head position and its leaf hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    /// Position.
    pub pos: u64,
    /// Leaf hash of the record there.
    pub leaf: [u8; 32],
}

/// A checkpoint the witnesses co-signed: tree size and root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Witnessed {
    /// Tree size.
    pub size: u64,
    /// Root.
    pub root: [u8; 32],
}

/// The operator's fence proof for an unplanned continuation (§17.4.1 item 2 (i)): the lost
/// cell's storage is fenced, by a readable seal or by out-of-band STONITH named in `evidence`,
/// and its last committed head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fence {
    /// What fenced the lost cell's store, as the operator records it; never empty.
    pub evidence: String,
    /// The lost cell's last committed head.
    pub last: Point,
}

impl Fence {
    /// The digest text recorded with the acceptance.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut bytes = self.evidence.as_bytes().to_vec();
        bytes.extend_from_slice(&self.last.pos.to_be_bytes());
        bytes.extend_from_slice(&self.last.leaf);
        access_kernel::json::b64url_encode(&suiss_crypto::digest::sha256(&bytes))
    }
}

/// What a replayed image proves: its Merkle root and the root at every earlier size asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replayed {
    /// Root of the whole image.
    pub root: [u8; 32],
    /// The root at the witnessed size, when one was asked for and the image reaches it.
    pub witnessed_root: Option<[u8; 32]>,
}

fn state_equal(
    folded: &access_kernel::fold::State,
    stored: &[StateRow],
) -> Result<bool, MoveError> {
    if folded.len() != stored.len() {
        return Ok(false);
    }
    for ((key, entry), row) in folded.iter().zip(stored) {
        let value = entry
            .value
            .as_ref()
            .map(|v| suiss_crypto::dcbor::encode(v, suiss_crypto::dcbor::Limits::CEILING))
            .transpose()
            .map_err(|_| MoveError::Diverged("state"))?;
        if *key != row.key || entry.version != row.version || value != row.value {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Replays `image` for `domain` (§17.4.1 item 1, TI-16): every leaf hash from its record, every
/// record chained to the previous one, the Merkle frontier equal to the head's, and the fold
/// from Genesis equal to the stored state.
///
/// # Errors
/// [`MoveError::Diverged`] naming the first check that failed.
pub fn replay(
    domain: Digest,
    image: &Image,
    witnessed: Option<Witnessed>,
) -> Result<Replayed, MoveError> {
    let mut frontier = Frontier::default();
    let mut previous = None;
    let mut folded = None;
    let mut witnessed_root = None;
    for (i, r) in image.records.iter().enumerate() {
        if u64::try_from(i).ok() != Some(r.pos) {
            return Err(MoveError::Diverged("positions"));
        }
        let record =
            RecordEnvelope::from_bytes(&r.envelope).map_err(|_| MoveError::Diverged("record"))?;
        let core = record
            .leaf_core()
            .map_err(|_| MoveError::Diverged("record"))?;
        if core.leaf_hash().map_err(|_| MoveError::Diverged("leaf"))? != r.leaf_hash {
            return Err(MoveError::Diverged("leaf"));
        }
        if let Some(prev) = &previous {
            check_link(prev, &core, &domain).map_err(|_| MoveError::Diverged("chain"))?;
        }
        previous = Some(core);
        frontier
            .push(r.leaf_hash)
            .map_err(|_| MoveError::Diverged("frontier"))?;
        if witnessed.is_some_and(|w| w.size == frontier.size()) {
            witnessed_root = Some(frontier.root());
        }
        match folded.as_mut() {
            None => {
                folded = Some(
                    access_kernel::fold::genesis(&record)
                        .map_err(|_| MoveError::Diverged("genesis"))?,
                );
            }
            Some(state) => access_kernel::fold::apply(state, &record)
                .map_err(|_| MoveError::Diverged("fold"))?,
        }
    }
    let head = &image.head.head;
    if image.records.last().map(|r| (r.pos, r.leaf_hash)) != Some((head.pos, head.leaf_hash))
        || frontier.nodes() != head.frontier.as_slice()
    {
        return Err(MoveError::Diverged("head"));
    }
    let folded = folded.ok_or(MoveError::Diverged("genesis"))?;
    if !state_equal(&folded, &image.state)? {
        return Err(MoveError::Diverged("fold"));
    }
    Ok(Replayed {
        root: frontier.root(),
        witnessed_root,
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

async fn audit(
    app: &Pool,
    image_tenant: Option<[u8; 16]>,
    domain: Digest,
    event_type: &'static str,
    reason: &str,
) -> Result<(), MoveError> {
    let target = format!("domain:{}", access_kernel::json::b64url_encode(&domain.0));
    record_operational(
        app,
        &OperationalEvent {
            occurred_at_ms: now_ms(),
            tenant: image_tenant,
            domain: None,
            event_type,
            actor: "cell-move",
            target: &target,
            reason,
            correlation: "cell-move",
        },
    )
    .await?;
    Ok(())
}

/// Seals `domain` on the source cell (§17.4.1 item 1): the lease is taken under a new epoch,
/// so no other leader writes meanwhile, and the head is sealed at that epoch. Returns the sealed
/// head position and its epoch.
///
/// # Errors
/// [`MoveError`]; `Store(LeaseHeld)` while another leader holds the domain.
pub async fn seal(
    sequencer: &Pool,
    app: &Pool,
    domain: Digest,
    holder: &str,
) -> Result<(u64, u64), MoveError> {
    let id = DomainId::from_bytes(domain.0);
    let (lease, head) = acquire_lease(sequencer, &id, holder, crate::LEASE_TTL).await?;
    let frontier = Frontier::from_parts(
        head.pos.checked_add(1).ok_or(MoveError::Diverged("head"))?,
        head.frontier.clone(),
    )
    .map_err(|_| MoveError::Diverged("frontier"))?;
    let sealed = seal_head(sequencer, &id, lease.epoch, frontier.root()).await?;
    audit(app, None, domain, "domain.sealed", "").await?;
    Ok((sealed.pos, sealed.epoch))
}

/// Accepts a sealed domain on the target cell (§17.4.1 item 1): the source image is replayed
/// and written here at (q, e + 1). Returns the accepted epoch.
///
/// # Errors
/// [`MoveError::NotSealed`] when the source is not sealed; [`MoveError`] otherwise.
pub async fn accept(
    source: &Pool,
    target: &Pool,
    target_app: &Pool,
    domain: Digest,
) -> Result<u64, MoveError> {
    let id = DomainId::from_bytes(domain.0);
    let img = image(source, &id).await?;
    if img.head.sealed_at != Some(img.head.head.pos) {
        return Err(MoveError::NotSealed);
    }
    let replayed = replay(domain, &img, None)?;
    let epoch = img
        .head
        .head
        .epoch
        .checked_add(1)
        .ok_or(MoveError::Diverged("epoch"))?;
    accept_image(target, &id, &img, epoch, replayed.root, Acceptance::Planned).await?;
    audit(target_app, Some(img.tenant), domain, "domain.accepted", "").await?;
    Ok(epoch)
}

/// The sev-1 refusal of a continuation without a fence proof or without coverage
/// (OP-54-RL12, §17.4.4).
async fn refused(app: &Pool, domain: Digest, why: &MoveError) -> MoveError {
    let reason = match why {
        MoveError::Unfenced => "no-fence-proof",
        MoveError::Uncovered(_) => "head-not-covered",
        _ => "diverged",
    };
    // §17.8.2, OP-158 m.3 (n)
    access_telemetry::signals::INTEGRITY_ALARMS.incr(["unfenced_promote"]);
    tracing::error!(
        event = "failover.fence.missing",
        reason,
        "an unplanned continuation was refused; the domain stays closed (FA-13)"
    );
    let _ = audit(app, None, domain, "failover.unfenced_attempt", reason).await;
    match why {
        MoveError::Unfenced => MoveError::Unfenced,
        MoveError::Uncovered(w) => MoveError::Uncovered(w),
        MoveError::Diverged(w) => MoveError::Diverged(w),
        _ => MoveError::Diverged("refused"),
    }
}

/// Checks an image against the fence proof and the witnessed checkpoint (§17.4.1 item 2).
///
/// # Errors
/// [`MoveError`].
pub fn covered(
    domain: Digest,
    img: &Image,
    fence: Option<&Fence>,
    witnessed: Option<Witnessed>,
) -> Result<Replayed, MoveError> {
    let fence = fence
        .filter(|f| !f.evidence.trim().is_empty())
        .ok_or(MoveError::Unfenced)?;
    let replayed = replay(domain, img, witnessed)?;
    let last = usize::try_from(fence.last.pos)
        .ok()
        .and_then(|p| img.records.get(p));
    if last.is_none_or(|r| r.leaf_hash != fence.last.leaf) {
        return Err(MoveError::Uncovered("the last committed head"));
    }
    if let Some(w) = witnessed
        && replayed.witnessed_root != Some(w.root)
    {
        return Err(MoveError::Uncovered("the witnessed checkpoint"));
    }
    Ok(replayed)
}

/// Accepts a domain of a lost cell from a copy's `img` (§17.4.1 item 2): only under a fence proof
/// and with the lost head and the witnessed checkpoint covered. Returns the accepted epoch.
///
/// # Errors
/// [`MoveError::Unfenced`], [`MoveError::Uncovered`] or [`MoveError::Diverged`], each a sev-1
/// signal with nothing written but the audit row.
pub async fn accept_unplanned(
    target: &Pool,
    target_app: &Pool,
    domain: Digest,
    img: &Image,
    fence: Option<&Fence>,
    witnessed: Option<Witnessed>,
) -> Result<u64, MoveError> {
    let replayed = match covered(domain, img, fence, witnessed) {
        Ok(r) => r,
        Err(e) => return Err(refused(target_app, domain, &e).await),
    };
    let fence = fence.ok_or(MoveError::Unfenced)?;
    let epoch = img
        .head
        .head
        .epoch
        .checked_add(1)
        .ok_or(MoveError::Diverged("epoch"))?;
    accept_image(
        target,
        &DomainId::from_bytes(domain.0),
        img,
        epoch,
        replayed.root,
        Acceptance::Unplanned(&fence.digest()),
    )
    .await?;
    audit(
        target_app,
        Some(img.tenant),
        domain,
        "failover.promoted",
        "",
    )
    .await?;
    Ok(epoch)
}

/// Continues a domain of a cell promoted from an async copy (OP-29, §17.4.1 item 2): the same
/// checks as [`accept_unplanned`], in place, under a new epoch. Returns that epoch.
///
/// # Errors
/// As [`accept_unplanned`].
pub async fn continue_promoted(
    sequencer: &Pool,
    app: &Pool,
    domain: Digest,
    fence: Option<&Fence>,
    witnessed: Option<Witnessed>,
) -> Result<u64, MoveError> {
    let id = DomainId::from_bytes(domain.0);
    let img = image(sequencer, &id).await?;
    let replayed = match covered(domain, &img, fence, witnessed) {
        Ok(r) => r,
        Err(e) => return Err(refused(app, domain, &e).await),
    };
    let fence = fence.ok_or(MoveError::Unfenced)?;
    let epoch = img
        .head
        .head
        .epoch
        .checked_add(1)
        .ok_or(MoveError::Diverged("epoch"))?;
    continue_in_place(
        sequencer,
        &id,
        (img.head.head.pos, img.head.head.leaf_hash),
        epoch,
        replayed.root,
        &fence.digest(),
    )
    .await?;
    audit(app, Some(img.tenant), domain, "failover.promoted", "").await?;
    Ok(epoch)
}
