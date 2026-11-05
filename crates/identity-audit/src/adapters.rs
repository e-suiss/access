//! PostgreSQL adapter of the [`AuditLog`] port, as `access_checkpointer`, and the identity
//! signer adapter of the [`NoteSigner`] port over its Unix socket (CMP-22b).

use std::path::PathBuf;

use access_identity_signer::adapters::call;
use access_identity_signer::protocol::{Request, Response};

use access_store::Pool;
use access_store::audit::{AuditRow, CheckpointRow, append_checkpoint, last_checkpoint, pending};
use access_store::identity::Cursor;

use crate::AuditError;
use crate::ports::{AuditLog, NoteSigner};

/// The audit log in PostgreSQL.
pub struct PgAudit(pub Pool);

impl AuditLog for PgAudit {
    async fn last(&self) -> Result<Option<CheckpointRow>, AuditError> {
        Ok(last_checkpoint(&self.0).await?)
    }

    async fn pending(&self, after: Cursor, limit: u32) -> Result<Vec<AuditRow>, AuditError> {
        Ok(pending(&self.0, after, limit).await?)
    }

    async fn append(&self, checkpoint: &CheckpointRow) -> Result<(), AuditError> {
        Ok(append_checkpoint(&self.0, checkpoint).await?)
    }
}

/// The identity signer at a Unix socket path.
pub struct SignerNotes(pub PathBuf);

fn refused(r: Response) -> AuditError {
    AuditError::Unsigned(match r {
        Response::Error(code) => code,
        _ => String::from("signer-answer"),
    })
}

impl NoteSigner for SignerNotes {
    async fn key(&self) -> Result<(String, String), AuditError> {
        match call(&self.0, &Request::CellKey).await {
            Ok(Response::CellKey { origin, vkey }) => Ok((origin, vkey)),
            Ok(other) => Err(refused(other)),
            Err(e) => Err(AuditError::Unsigned(e.to_string())),
        }
    }

    async fn sign(&self, body: String) -> Result<String, AuditError> {
        match call(&self.0, &Request::SignCheckpoint { body }).await {
            Ok(Response::Noted { line }) => Ok(line),
            Ok(other) => Err(refused(other)),
            Err(e) => Err(AuditError::Unsigned(e.to_string())),
        }
    }
}
