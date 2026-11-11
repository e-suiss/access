//! PostgreSQL adapter of the [`AuditLog`] port, as `access_checkpointer`, and the identity
//! signer adapter of the [`NoteSigner`] port over its Unix socket (CMP-22b).

use std::path::PathBuf;

use access_identity_signer::adapters::call;
use access_identity_signer::protocol::{Request, Response};

use access_store::Pool;
use access_store::audit::{AuditRow, CheckpointRow, append_checkpoint, last_checkpoint, pending};
use access_store::audit_lease::{AuditChain, append_held_checkpoint};
use access_store::audit_realm::{
    RealmCheckpointRow, append_realm_checkpoint, last_realm_checkpoint, realm_pending,
};
use access_store::identity::Cursor;
use access_store::operational::{
    OperationalRow, append_operational_checkpoint, last_operational_checkpoint, pending_operational,
};

use crate::AuditError;
use crate::ports::{AuditLog, NoteSigner, RealmTrees};

pub mod cef;
pub mod ocsf;
pub mod set;

/// The audit log in PostgreSQL.
pub struct PgAudit(pub Pool);

/// The authority plane's operational audit stream in PostgreSQL (OP-39, OP-44).
pub struct PgOperational(pub Pool);

impl AuditLog for PgOperational {
    type Row = OperationalRow;

    fn chain(&self) -> Option<&'static str> {
        Some(access_identity_signer::cell::OPERATIONAL_CHAIN)
    }

    async fn last(&self) -> Result<Option<CheckpointRow>, AuditError> {
        Ok(last_operational_checkpoint(&self.0).await?)
    }

    async fn pending(&self, after: Cursor, limit: u32) -> Result<Vec<OperationalRow>, AuditError> {
        Ok(pending_operational(&self.0, after, limit).await?)
    }

    async fn append(&self, checkpoint: &CheckpointRow) -> Result<(), AuditError> {
        Ok(append_operational_checkpoint(&self.0, checkpoint).await?)
    }
}

impl AuditLog for PgAudit {
    type Row = AuditRow;

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

impl RealmTrees for PgAudit {
    async fn realm_last(
        &self,
        (tenant, realm): ([u8; 16], [u8; 16]),
    ) -> Result<Option<RealmCheckpointRow>, AuditError> {
        Ok(last_realm_checkpoint(&self.0, tenant, realm).await?)
    }

    async fn realm_pending(
        &self,
        scope: ([u8; 16], [u8; 16]),
        after: Cursor,
        upto: Cursor,
        limit: u32,
    ) -> Result<Vec<AuditRow>, AuditError> {
        Ok(realm_pending(&self.0, scope, after, upto, limit).await?)
    }

    async fn realm_append(&self, checkpoint: &RealmCheckpointRow) -> Result<(), AuditError> {
        Ok(append_realm_checkpoint(&self.0, checkpoint).await?)
    }
}

impl RealmTrees for Held<PgAudit> {
    async fn realm_last(
        &self,
        scope: ([u8; 16], [u8; 16]),
    ) -> Result<Option<RealmCheckpointRow>, AuditError> {
        self.log.realm_last(scope).await
    }

    async fn realm_pending(
        &self,
        scope: ([u8; 16], [u8; 16]),
        after: Cursor,
        upto: Cursor,
        limit: u32,
    ) -> Result<Vec<AuditRow>, AuditError> {
        self.log.realm_pending(scope, after, upto, limit).await
    }

    async fn realm_append(&self, checkpoint: &RealmCheckpointRow) -> Result<(), AuditError> {
        self.log.realm_append(checkpoint).await
    }
}

/// A chain whose checkpoints are appended only while `holder` holds its lease, so one replica
/// writes each cell chain (OP-152 m.5 (k)).
pub struct Held<L> {
    /// The chain.
    pub log: L,
    /// This process's lease holder name.
    pub holder: String,
}

impl AuditLog for Held<PgAudit> {
    type Row = AuditRow;

    async fn last(&self) -> Result<Option<CheckpointRow>, AuditError> {
        self.log.last().await
    }

    async fn pending(&self, after: Cursor, limit: u32) -> Result<Vec<AuditRow>, AuditError> {
        self.log.pending(after, limit).await
    }

    async fn append(&self, checkpoint: &CheckpointRow) -> Result<(), AuditError> {
        Ok(
            append_held_checkpoint(&self.log.0, AuditChain::Identity, &self.holder, checkpoint)
                .await?,
        )
    }
}

impl AuditLog for Held<PgOperational> {
    type Row = OperationalRow;

    fn chain(&self) -> Option<&'static str> {
        self.log.chain()
    }

    async fn last(&self) -> Result<Option<CheckpointRow>, AuditError> {
        self.log.last().await
    }

    async fn pending(&self, after: Cursor, limit: u32) -> Result<Vec<OperationalRow>, AuditError> {
        self.log.pending(after, limit).await
    }

    async fn append(&self, checkpoint: &CheckpointRow) -> Result<(), AuditError> {
        Ok(append_held_checkpoint(
            &self.log.0,
            AuditChain::Operational,
            &self.holder,
            checkpoint,
        )
        .await?)
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

/// The archive role's view of the audit partitions (OP-73 m.4).
pub struct PgTiers(pub Pool);

impl crate::ports::Tiers for PgTiers {
    async fn due(&self) -> Result<Vec<access_store::audit_tier::Due>, AuditError> {
        Ok(access_store::audit_tier::due(&self.0).await?)
    }

    async fn rows(
        &self,
        partition: &str,
        after: Cursor,
        limit: u32,
    ) -> Result<Vec<AuditRow>, AuditError> {
        Ok(access_store::audit_tier::rows(&self.0, partition, after, limit).await?)
    }

    async fn detach(&self, moved: &access_store::audit_tier::Moved) -> Result<(), AuditError> {
        Ok(access_store::audit_tier::detach(&self.0, moved).await?)
    }
}

/// The publication records in PostgreSQL, as `access_checkpointer`.
pub struct PgPublications(pub Pool);

impl crate::ports::Publications for PgPublications {
    async fn published_through(&self, sink: &str) -> Result<u64, AuditError> {
        Ok(access_store::audit_publication::published_through(&self.0, sink).await?)
    }

    async fn record(&self, sink: &str, size: u64) -> Result<(), AuditError> {
        Ok(access_store::audit_publication::record_published(&self.0, sink, size).await?)
    }

    async fn latest_after(&self, after: u64) -> Result<Option<CheckpointRow>, AuditError> {
        Ok(access_store::audit_publication::latest_after(&self.0, after).await?)
    }
}
