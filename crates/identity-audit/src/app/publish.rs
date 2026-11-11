//! Publication of the identity audit log's checkpoints (OP-37, OP-38, U52, OP-158 m.3 (w)):
//! each declared target gets the latest signed checkpoint it does not have yet. A newer
//! checkpoint covers every older one, so a target that was down catches up with one publication
//! (coalescing, OP-38). A target that refuses keeps its place and is tried on the next tick.

use crate::AuditError;
use crate::ports::{Publications, Publisher};

/// What one tick published.
#[derive(Debug, Default)]
pub struct Published {
    /// (target, size) pairs now published.
    pub done: Vec<(String, u64)>,
    /// Targets that refused, with why.
    pub failed: Vec<(String, AuditError)>,
}

async fn one<S: Publications, P: Publisher>(
    store: &S,
    sink: &P,
) -> Result<Option<u64>, AuditError> {
    let after = store.published_through(sink.name()).await?;
    let Some(checkpoint) = store.latest_after(after).await? else {
        return Ok(None);
    };
    let note = checkpoint
        .note
        .as_deref()
        .ok_or(AuditError::Note(suiss_crypto::note::NoteError::Unverified))?;
    sink.publish(checkpoint.size, note).await?;
    store.record(sink.name(), checkpoint.size).await?;
    Ok(Some(checkpoint.size))
}

/// Publishes the latest checkpoint to every target that does not have it.
pub async fn publish_latest<S: Publications, P: Publisher>(store: &S, sinks: &[P]) -> Published {
    let mut out = Published::default();
    for sink in sinks {
        match one(store, sink).await {
            Ok(Some(size)) => out.done.push((sink.name().to_owned(), size)),
            Ok(None) => {}
            Err(e) => out.failed.push((sink.name().to_owned(), e)),
        }
    }
    out
}
