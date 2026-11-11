//! Sends each signed domain checkpoint to the declared witnesses and keeps their verified
//! cosignatures (§16.6 witness protocol, CMP-6, T17, SEC23, OP-158 m.3 (c), (d)), copies the
//! cosigned note to the declared sinks (§9.16, P32), cross-checks the log clock against each
//! cosignature (TI-RT2), and compares what every witness holds with what this provider signed
//! (gossip; U9, HL-7).

use std::path::PathBuf;

use access_authority_sequencer::checkpoint::SignedCheckpoint;
use access_authority_sequencer::witness::{
    Base, Target, WitnessError, add_checkpoint, board, cross_check, latest,
};
use access_kernel::digest::Digest;
use access_store::Pool;
use access_store::authority_checkpoint::AuthorityCheckpoint;
use access_store::operational::{OperationalEvent, record_operational};
use access_store::scope::DomainId;
use access_store::witness::{
    Cosign, Equivocation, checkpoint_of_size, leaf_hashes, record_cosign, record_equivocation,
    witness_base,
};
use suiss_crypto::note::{Checkpoint, parse_note};
use suiss_ledger::checkpoint::proof::consistency;
use suiss_ledger::checkpoint::witness::{Cosignature, Refused, equivocates};

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

async fn leaves_of(
    app: &Pool,
    domain: &DomainId,
    leaves: &mut Option<Vec<[u8; 32]>>,
    size: u64,
) -> Result<(), WitnessError> {
    if leaves.is_none() {
        *leaves = Some(
            leaf_hashes(app, domain, 0, size)
                .await
                .map_err(|_| WitnessError::Unreachable)?,
        );
    }
    Ok(())
}

/// The base `old` of the tree of `size` and the consistency proof from it.
async fn base_and_proof(
    app: &Pool,
    domain: &DomainId,
    leaves: &mut Option<Vec<[u8; 32]>>,
    old: u64,
    size: u64,
) -> Result<(Option<Base>, Vec<[u8; 32]>), WitnessError> {
    if old == 0 {
        return Ok((None, Vec::new()));
    }
    if old > size {
        return Err(WitnessError::Conflict(old));
    }
    leaves_of(app, domain, leaves, size).await?;
    let all = leaves.as_deref().unwrap_or_default();
    let root = suiss_ledger::checkpoint::proof::Leaves::subtree(all, 0, old)
        .map_err(|_| WitnessError::Conflict(old))?;
    let p = consistency(all, old, size).map_err(|_| WitnessError::Conflict(old))?;
    Ok((Some((old, root)), p))
}

async fn one(
    target: &Target,
    app: &Pool,
    domain: (&Digest, &DomainId),
    signed: &SignedCheckpoint,
) -> Result<(String, u64), WitnessError> {
    let (d, id) = domain;
    let size = signed.checkpoint.size;
    let mut leaves = None;
    let mut old = witness_base(app, id, &target.vkey)
        .await
        .map_err(|_| WitnessError::Unreachable)?;
    for _ in 0..2 {
        let (base, p) = base_and_proof(app, id, &mut leaves, old, size).await?;
        match add_checkpoint(target, d, (base, &p), &signed.note, &signed.excerpt).await {
            Err(WitnessError::Said(Refused::Inconsistent, _)) => {
                // §16.6
                let held = match latest(target, d).await {
                    Ok((entry, _)) => entry.size,
                    Err(WitnessError::Refused(404)) => 0,
                    Err(e) => return Err(e),
                };
                if held == old || held > size {
                    return Err(WitnessError::Said(Refused::Inconsistent, 409));
                }
                old = held;
            }
            other => return other,
        }
    }
    Err(WitnessError::Said(Refused::Inconsistent, 409))
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
            let got = one(&target, &app, (&domain, &id), &signed).await;
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
                tracing::warn!(
                    event = "witness.unreachable",
                    witness = %target.url,
                    error = %e,
                    "checkpoint not cosigned"
                );
                out.failed.push((target.url.clone(), e));
                continue;
            }
        };
        // TI-RT2, OP-158 m.3 (k)
        let _ = cross_check(recorded_at, time);
        let Ok((parsed, _)) = Cosignature::from_line(&line) else {
            out.failed
                .push((target.url.clone(), WitnessError::Cosignature));
            continue;
        };
        let cosign = Cosign {
            size: row.size,
            root: row.root,
            witness: parsed.name,
            vkey: target.vkey.clone(),
            independent: target.independent,
            cosigned_at: time,
            signature: parsed.signature,
        };
        if let Err(error) = record_cosign(sequencer, &id, &cosign).await {
            tracing::warn!(%error, "cosignature not kept");
            out.failed
                .push((target.url.clone(), WitnessError::Unreachable));
            continue;
        }
        out.cosigned = out.cosigned.saturating_add(1);
        let target_text = row.size.to_string();
        let kept = record_operational(
            app,
            &OperationalEvent {
                event_type: "checkpoint.cosigned",
                occurred_at_ms: row.issued_at,
                tenant: None,
                domain: Some(domain.0),
                actor: &target.vkey,
                target: &target_text,
                reason: "",
                correlation: "",
            },
        )
        .await;
        if let Err(error) = kept {
            tracing::warn!(%error, "cosignature audit row not kept");
        }
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
            Ok((_, note)) => {
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
        // U9, HL-7
        tracing::error!(
            event = "witness.equivocation.detected",
            witness = %evidence.source,
            size = evidence.size,
            "equivocation: two cosigned checkpoints of one size with different roots"
        );
        let target_text = evidence.size.to_string();
        let raised = record_operational(
            app,
            &OperationalEvent {
                event_type: "witness.equivocation",
                occurred_at_ms: now,
                tenant: None,
                domain: Some(domain.0),
                actor: &evidence.source,
                target: &target_text,
                reason: "equivocation",
                correlation: "",
            },
        )
        .await;
        if let Err(error) = raised {
            tracing::error!(%error, "equivocation audit row not kept");
        }
        match record_equivocation(sequencer, &id, &evidence).await {
            Ok(_) => found = found.saturating_add(1),
            Err(error) => tracing::error!(%error, "equivocation evidence not kept"),
        }
    }
    found
}
