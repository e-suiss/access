//! Publication targets of the identity audit log's checkpoints (OP-37, U52, OP-158 m.3 (w)):
//! the cold tier's write-once store, and declared HTTPS hooks that take the signed note.

use access_identity_audit::AuditError;
use access_identity_audit::ports::{ColdStore, Publisher};

use crate::domain::collector::Request;
use crate::ports::Wire;

/// The key of the note of the checkpoint of `size` in the log `origin`.
#[must_use]
pub fn note_key(origin: &str, size: u64) -> String {
    let log: String = origin
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("checkpoints/{log}/{size:020}.note")
}

/// The write-once object store as a target: each note under its own key, never overwritten.
pub struct StoreNotes<S> {
    /// The store.
    pub store: S,
}

impl<S: ColdStore + Sync> Publisher for StoreNotes<S> {
    fn name(&self) -> &'static str {
        "object-store"
    }

    async fn publish(&self, size: u64, note: &str) -> Result<(), AuditError> {
        let origin = note.lines().next().unwrap_or_default();
        self.store
            .put(&note_key(origin, size), note.as_bytes())
            .await
    }
}

/// Most bytes read of a hook's answer.
const HOOK_ANSWER: usize = 4096;

/// A declared HTTPS hook: the note is `POST`ed as `text/plain`; any 2xx is taken.
pub struct HookNotes<W> {
    /// The target's name.
    pub name: String,
    /// The URL.
    pub url: String,
    /// The guarded transport.
    pub wire: W,
}

impl<W: Wire> Publisher for HookNotes<W> {
    fn name(&self) -> &str {
        &self.name
    }

    async fn publish(&self, _size: u64, note: &str) -> Result<(), AuditError> {
        let request = Request {
            method: "POST",
            url: self.url.clone(),
            content_type: "text/plain; charset=utf-8",
            headers: Vec::new(),
            body: note.as_bytes().to_vec(),
        };
        match self.wire.http(&request, HOOK_ANSWER).await {
            Ok((status, _)) if (200..300).contains(&status) => Ok(()),
            Ok((status, _)) => Err(AuditError::Unpublished(format!("hook answered {status}"))),
            Err(down) => Err(AuditError::Unpublished(down.0)),
        }
    }
}

#[cfg(test)]
mod tests;
