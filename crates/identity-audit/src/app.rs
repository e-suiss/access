//! One checkpoint step (OP-38): integrate what has ended since the last checkpoint and have the
//! cell's `audit-checkpoint` key sign it (OP-150 m.3 (h)). On the identity audit log, each realm
//! the step touched then gets its own tree checkpoint under the realm's origin (OP-152 m.7 (d)).

pub mod publish;
pub mod tier;

use access_crypto::AwsLcBackend;
use access_identity_signer::cell::{OPERATIONAL_CHAIN, operational_origin, realm_origin};
use access_store::audit::{AuditRow, CheckpointRow};
use access_store::audit_realm::RealmCheckpointRow;
use suiss_crypto::note::NoteError;
use suiss_ledger::merkle::Frontier;

use crate::AuditError;
use crate::domain::{Leaf, body, leaf, next, realm, verify};
use crate::ports::{AuditLog, NoteSigner, RealmTrees};

/// Most rows one step integrates.
pub const STEP_ROWS: u32 = 10_000;

/// What one step integrated and appended.
struct Integrated<R> {
    checkpoint: CheckpointRow,
    rows: Vec<R>,
    body: String,
    origin: String,
}

async fn integrate<L: AuditLog, S: NoteSigner>(
    log: &L,
    signer: &S,
    now: u64,
) -> Result<Option<Integrated<L::Row>>, AuditError> {
    let last = log.last().await?;
    let after = last.as_ref().map(|c| c.cursor).unwrap_or_default();
    let rows = log.pending(after, STEP_ROWS).await?;
    let Some(mut checkpoint) = next(last.as_ref(), &rows)? else {
        return Ok(None);
    };
    let (identity, vkey) = signer.key().await?;
    // OP-44
    let origin = match log.chain() {
        None => identity,
        Some(OPERATIONAL_CHAIN) => {
            operational_origin(&identity).ok_or(AuditError::Note(NoteError::Checkpoint))?
        }
        Some(_) => return Err(AuditError::Note(NoteError::Checkpoint)),
    };
    let text = body(&origin, &checkpoint, now)?;
    let line = signer.sign(text.clone()).await?;
    checkpoint.note = Some(format!("{text}\n{line}"));
    verify(&AwsLcBackend, &checkpoint, &origin, &vkey)?;
    log.append(&checkpoint).await?;
    Ok(Some(Integrated {
        checkpoint,
        rows,
        body: text,
        origin,
    }))
}

/// Integrates up to [`STEP_ROWS`] rows after the latest checkpoint, has `signer` sign it at
/// `now` and appends it with its note. Returns it, or `None` when nothing new ended.
///
/// # Errors
/// [`AuditError::Unsigned`] when the signer cannot sign: nothing is appended and the next step
/// retries (CR-23, G42); [`AuditError::Note`] when the note does not verify under the cell key;
/// [`AuditError`] otherwise. A concurrent checkpointer's same-size checkpoint makes this one
/// fail, and the next step continues from whichever was stored.
pub async fn step<L: AuditLog, S: NoteSigner>(
    log: &L,
    signer: &S,
    now: u64,
) -> Result<Option<CheckpointRow>, AuditError> {
    Ok(integrate(log, signer, now).await?.map(|i| i.checkpoint))
}

/// What one identity step appended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityStep {
    /// The cell checkpoint.
    pub checkpoint: CheckpointRow,
    /// Realm tree checkpoints appended.
    pub realms: u32,
    /// Realms whose tree checkpoint failed; each catches up later.
    pub realms_failed: u32,
}

/// [`step`] on the identity audit log, then a tree checkpoint of every realm the step touched
/// (OP-152 m.7 (d)). A realm whose tree checkpoint fails catches up the next time one of its
/// rows is integrated; the cell checkpoint stands either way.
///
/// # Errors
/// As [`step`].
pub async fn identity_step<L, S>(
    log: &L,
    signer: &S,
    now: u64,
) -> Result<Option<IdentityStep>, AuditError>
where
    L: AuditLog<Row = AuditRow> + RealmTrees,
    S: NoteSigner,
{
    let Some(done) = integrate(log, signer, now).await? else {
        return Ok(None);
    };
    let mut scopes: Vec<([u8; 16], [u8; 16])> =
        done.rows.iter().map(|r| (r.tenant, r.realm)).collect();
    scopes.sort_unstable();
    scopes.dedup();
    let (mut realms, mut realms_failed) = (0_u32, 0_u32);
    for scope in scopes {
        match realm_tree(log, signer, (&done, scope), now).await {
            Ok(Some(_)) => realms = realms.saturating_add(1),
            Ok(None) => {}
            Err(_) => realms_failed = realms_failed.saturating_add(1),
        }
    }
    Ok(Some(IdentityStep {
        checkpoint: done.checkpoint,
        realms,
        realms_failed,
    }))
}

/// The next checkpoint of one realm's tree, after the cell checkpoint `done`.
async fn realm_tree<L: RealmTrees, S: NoteSigner>(
    log: &L,
    signer: &S,
    (done, scope): (&Integrated<AuditRow>, ([u8; 16], [u8; 16])),
    now: u64,
) -> Result<Option<RealmCheckpointRow>, AuditError> {
    let last = log.realm_last(scope).await?;
    let after = last.as_ref().map(|c| c.cursor).unwrap_or_default();
    let rows = log
        .realm_pending(scope, after, done.checkpoint.cursor, STEP_ROWS)
        .await?;
    let Some(final_row) = rows.last() else {
        return Ok(None);
    };
    let mut frontier = match &last {
        Some(c) => Frontier::from_parts(c.size, c.frontier.clone())?,
        None => Frontier::default(),
    };
    for row in &rows {
        frontier.push(leaf(row)?)?;
    }
    let origin = realm_origin(&done.origin, &scope.1);
    let text = realm::body(&origin, (frontier.size(), frontier.root()), &done.body, now)?;
    let line = signer.sign(text.clone()).await?;
    let checkpoint = RealmCheckpointRow {
        tenant: scope.0,
        realm: scope.1,
        size: frontier.size(),
        root: frontier.root(),
        frontier: frontier.nodes().to_vec(),
        cursor: final_row.cursor(),
        cell_size: done.checkpoint.size,
        note: format!("{text}\n{line}"),
    };
    log.realm_append(&checkpoint).await?;
    Ok(Some(checkpoint))
}
