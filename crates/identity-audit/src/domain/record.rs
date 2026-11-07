//! The audit record both publication channels render (OP-41, §17.6.8): one shape for the
//! identity log's rows and the authority plane's operational stream, carrying the common `txn`
//! and the three first-class timestamps (occurred, recorded, checkpointed). A rendering is a copy,
//! never the record (X22).

use std::fmt::Write as _;

use access_identity_signer::cell::{IDENTITY_CHAIN, OPERATIONAL_CHAIN};
use access_kernel::json::b64url_encode;
use access_store::audit::AuditRow;
use access_store::operational::OperationalRow;

use crate::AuditError;

/// What the event is scoped to below its tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// A realm of the identity plane.
    Realm([u8; 16]),
    /// An authority domain.
    Domain([u8; 32]),
    /// Nothing known: a rejection before any domain was named.
    None,
}

impl Scope {
    /// `realm:<uuid>`, `domain:<base64url>` or `none`.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::Realm(r) => format!("realm:{}", uuid_text(r)),
            Self::Domain(d) => format!("domain:{}", b64url_encode(d)),
            Self::None => String::from("none"),
        }
    }
}

/// One audit event as channel B publishes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Stable id within its chain: `<chain>:<row id>`.
    pub id: String,
    /// Event name, from the taxonomy.
    pub event: String,
    /// The common transaction id of both channels (OP-41): the request's correlation id.
    pub txn: String,
    /// When it happened, Unix milliseconds.
    pub occurred_at_ms: u64,
    /// When it was written, Unix milliseconds.
    pub recorded_at_ms: u64,
    /// When a signed checkpoint first covered it, Unix milliseconds; `None` before that.
    pub checkpoint_at_ms: Option<u64>,
    /// The tenant, when known.
    pub tenant: Option<[u8; 16]>,
    /// The realm or domain.
    pub scope: Scope,
    /// Who acted.
    pub actor: String,
    /// What it acted on.
    pub target: String,
    /// The stable reason code, if any.
    pub reason: Option<String>,
}

fn ms(v: i64) -> Result<u64, AuditError> {
    u64::try_from(v).map_err(|_| AuditError::Encode)
}

impl AuditRecord {
    /// An identity audit row: written in the business transaction, so it occurred when it was
    /// recorded (§9.16.3).
    ///
    /// # Errors
    /// [`AuditError::Encode`] for a row time before the epoch.
    pub fn identity(row: &AuditRow, checkpoint_at_ms: Option<u64>) -> Result<Self, AuditError> {
        let at = ms(row.at_ms)?;
        Ok(Self {
            id: format!("{IDENTITY_CHAIN}:{}", row.id),
            event: row.event_type.clone(),
            txn: row.correlation.clone(),
            occurred_at_ms: at,
            recorded_at_ms: at,
            checkpoint_at_ms,
            tenant: Some(row.tenant),
            scope: Scope::Realm(row.realm),
            actor: row.actor.clone(),
            target: row.target.clone(),
            reason: None,
        })
    }

    /// An operational stream row (OP-39, OP-44): it occurred at the decision point's trusted
    /// time and was recorded when written.
    ///
    /// # Errors
    /// [`AuditError::Encode`] for a row time before the epoch.
    pub fn operational(
        row: &OperationalRow,
        checkpoint_at_ms: Option<u64>,
    ) -> Result<Self, AuditError> {
        Ok(Self {
            id: format!("{OPERATIONAL_CHAIN}:{}", row.id),
            event: row.event_type.clone(),
            txn: row.correlation.clone(),
            occurred_at_ms: row.occurred_at_ms,
            recorded_at_ms: ms(row.at_ms)?,
            checkpoint_at_ms,
            tenant: row.tenant,
            scope: row.domain.map_or(Scope::None, Scope::Domain),
            actor: row.actor.clone(),
            target: row.target.clone(),
            reason: (!row.reason.is_empty()).then(|| row.reason.clone()),
        })
    }
}

/// A 16-byte id as a hyphenated lowercase UUID.
#[must_use]
pub fn uuid_text(b: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}
