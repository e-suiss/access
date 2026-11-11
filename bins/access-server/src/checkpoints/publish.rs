//! Sends each signed domain checkpoint to the declared witnesses and keeps their verified
//! cosignatures (§16.6 witness protocol, CMP-6, T17, SEC23, OP-158 m.3 (c), (d)), copies the
//! cosigned note to the declared sinks (§9.16, P32), cross-checks the log clock against each
//! cosignature (TI-RT2), and compares what every witness holds with what this provider signed
//! (gossip; U9, HL-7).

use std::path::PathBuf;

use access_authority_sequencer::checkpoint::SignedCheckpoint;
use access_authority_sequencer::witness::{
    Target, WitnessError, add_checkpoint, board, cross_check, latest,
};
use access_kernel::digest::Digest;
use access_store::Pool;
use access_store::authority_checkpoint::AuthorityCheckpoint;
use access_store::scope::DomainId;
use access_store::witness::{
    Cosign, Equivocation, checkpoint_of_size, leaf_hashes, record_cosign, record_equivocation,
    witness_base,
};
use suiss_crypto::note::{Checkpoint, parse_note};
use suiss_ledger::checkpoint::proof::consistency;
use suiss_ledger::checkpoint::witness::equivocates;

/// The declared witnesses and sinks.
#[derive(Clone, Debug, Default)]
pub(crate) struct Publisher {
    /// Witnesses every led domain's checkpoints go to.
    pub(crate) targets: Vec<Target>,
    /// Sink directories.
    pub(crate) sinks: Vec<PathBuf>,
}

/// What one checkpoint's publication got.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Published {
    /// Verified cosignatures kept.
    pub(crate) cosigned: usize,
    /// Of them, from independent witnesses.
    pub(crate) independent: usize,
    /// Witnesses that gave none, with why.
    pub(crate) failed: Vec<(String, WitnessError)>,
}

async fn proof(
    app: &Pool,
    domain: &DomainId,
    leaves: &mut Option<Vec<[u8; 32]>>,
    old: u64,
    size: u64,
) -> Result<Vec<[u8; 32]>, WitnessError> {
    if old == 0 || old >= size {
        return Ok(Vec::new());
    }
    if leaves.is_none() {
        *leaves = Some(
            leaf_hashes(app, domain, 0, size)
                .await
                .map_err(|_| WitnessError::Unreachable)?,
        );
    }
    let all = leaves.as_deref().unwrap_or_default();
    consistency(all, old, size).map_err(|_| WitnessError::Conflict(old))
}

async fn one(
    target: &Target,
    app: &Pool,
    domain: &DomainId,
    signed: &SignedCheckpoint,
) -> Result<(String, u64), WitnessError> {
    let size = signed.checkpoint.size;
    let mut leaves = None;
    let mut old = witness_base(app, domain, &target.vkey)
        .await
        .map_err(|_| WitnessError::Unreachable)?;
    for _ in 0..2 {
        let p = proof(app, domain, &mut leaves, old, size).await?;
        match add_checkpoint(
            target,
            (old, &p),
            &signed.note,
            &signed.excerpt,
            &signed.metadata,
        )
        .await
        {
            Err(WitnessError::Conflict(n)) if n != old && n <= size => old = n,
            other => return other,
        }
    }
    Err(WitnessError::Conflict(old))
}

/// Publishes `signed`, appended as `row`, of `domain` whose newest record is `recorded_at`.
pub(crate) async fn publish(
    p: &Publisher,
    (app, sequencer): (&Pool, &Pool),
    domain: Digest,
    (row, signed, recorded_at): (&AuthorityCheckpoint, &SignedCheckpoint, u64),
) -> Published {
    let id = DomainId::from_bytes(domain.0);
    let mut set = tokio::task::JoinSet::new();
    for target in p.targets.clone() {
        let (app, signed) = (app.clone(), signed.clone());
        set.spawn(async move {
            let got = one(&target, &app, &id, &signed).await;
            (target, got)
        });
    }
    let mut out = Published::default();
    while let Some(joined) = set.join_next().await {
        let Ok((target, got)) = joined else {
            continue;
        };
        let (line, time) = match got {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(witness = %target.url, error = %e, "checkpoint not cosigned");
                out.failed.push((target.url.clone(), e));
                continue;
            }
        };
        // TI-RT2, OP-158 m.3 (k)
        let _ = cross_check(recorded_at, time);
        let cosign = Cosign {
            issued_at: row.issued_at,
            size: row.size,
            witness: target.vkey.clone(),
            independent: target.independent,
            cosigned_at: time,
            line: line.clone(),
        };
        if let Err(error) = record_cosign(sequencer, &id, &cosign).await {
            tracing::warn!(%error, "cosignature not kept");
            out.failed
                .push((target.url.clone(), WitnessError::Unreachable));
            continue;
        }
        out.cosigned = out.cosigned.saturating_add(1);
        if target.independent {
            out.independent = out.independent.saturating_add(1);
        }
        sink(&p.sinks, &domain, row, &line);
    }
    // SEC23, SI-12
    if out.independent > 0 {
        board().set_witnessed(domain, row.size);
    }
    out
}

fn sink(sinks: &[PathBuf], domain: &Digest, row: &AuthorityCheckpoint, line: &str) {
    use std::io::Write as _;
    let name = access_kernel::json::b64url_encode(&domain.0);
    let digest = suiss_crypto::digest::sha256(line.as_bytes());
    let witness = access_kernel::json::b64url_encode(digest.get(..8).unwrap_or_default());
    for dir in sinks {
        let dir = dir.join(&name);
        let file = dir.join(format!("{}-{}-{witness}.note", row.size, row.issued_at));
        let written = std::fs::create_dir_all(&dir).and_then(|()| {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&file)?;
            f.write_all(row.note.as_bytes())?;
            f.write_all(line.as_bytes())?;
            f.sync_all()
        });
        if let Err(error) = written
            && error.kind() != std::io::ErrorKind::AlreadyExists
        {
            tracing::warn!(sink = %dir.display(), %error, "checkpoint not copied to its sink");
        }
    }
}

fn body(note: &str) -> Option<Checkpoint> {
    Checkpoint::parse(&parse_note(note).ok()?.body).ok()
}

/// Compares every witness's latest cosigned note of `domain` with the checkpoint this
/// provider signed at that size and with each other; contradictions are kept as evidence and
/// raised (U9, HL-7). The number found.
pub(crate) async fn gossip(
    p: &Publisher,
    (app, sequencer): (&Pool, &Pool),
    domain: Digest,
    now: u64,
) -> u32 {
    let id = DomainId::from_bytes(domain.0);
    let mut seen: Vec<(String, Checkpoint, String)> = Vec::new();
    for t in &p.targets {
        match latest(t, &domain).await {
            Ok(note) => {
                if let Some(cp) = body(&note) {
                    seen.push((t.url.clone(), cp, note));
                }
            }
            Err(error) => tracing::warn!(witness = %t.url, %error, "witness not compared"),
        }
    }
    let mut pairs: Vec<(String, Checkpoint, String, Checkpoint, String)> = Vec::new();
    for (url, cp, note) in &seen {
        if let Ok(Some(own)) = checkpoint_of_size(app, &id, cp.size).await
            && let Some(own_cp) = body(&own.note)
            && equivocates(&own_cp, cp)
        {
            pairs.push((url.clone(), own_cp, own.note, cp.clone(), note.clone()));
        }
    }
    for (i, (ua, a, na)) in seen.iter().enumerate() {
        for (ub, b, nb) in seen.iter().skip(i.saturating_add(1)) {
            if equivocates(a, b) {
                pairs.push((
                    format!("{ua} {ub}"),
                    a.clone(),
                    na.clone(),
                    b.clone(),
                    nb.clone(),
                ));
            }
        }
    }
    let mut found = 0_u32;
    for (source, a, na, b, nb) in pairs {
        let evidence = Equivocation {
            size: a.size,
            a: (a.root, na),
            b: (b.root, nb),
            source,
            detected_at: now,
        };
        // U9, HL-7: sev-1
        tracing::error!(
            size = evidence.size,
            source = %evidence.source,
            "equivocation: two cosigned checkpoints of one size with different roots"
        );
        match record_equivocation(sequencer, &id, &evidence).await {
            Ok(_) => found = found.saturating_add(1),
            Err(error) => tracing::error!(%error, "equivocation evidence not kept"),
        }
    }
    found
}
