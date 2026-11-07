//! One checkpoint step (OP-38): integrate what has ended since the last checkpoint and have the
//! cell's `audit-checkpoint` key sign it (OP-150 m.3 (h)).

use access_crypto::AwsLcBackend;
use access_identity_signer::cell::{OPERATIONAL_CHAIN, operational_origin};
use access_store::audit::CheckpointRow;
use suiss_crypto::note::NoteError;

use crate::AuditError;
use crate::domain::{body, next, verify};
use crate::ports::{AuditLog, NoteSigner};

/// Most rows one step integrates.
pub const STEP_ROWS: u32 = 10_000;

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
    let last = log.last().await?;
    let after = last.as_ref().map(|c| c.cursor).unwrap_or_default();
    let rows = log.pending(after, STEP_ROWS).await?;
    let Some(mut checkpoint) = next(last.as_ref(), &rows)? else {
        return Ok(None);
    };
    let (identity, vkey) = signer.key().await?;
    // OP-44: a separate chain carries its own origin under the same cell key
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
    Ok(Some(checkpoint))
}
