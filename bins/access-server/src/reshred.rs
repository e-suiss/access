//! Re-shred after a restore (OP-42, OP-57 item 7, OP-158 m.3 (r)). Every destroyed subject is
//! also written to the shred journal in the cold tier, outside the database, so a restore to a
//! time before the destruction cannot bring the keys back unnoticed:
//!
//! - at start, a restore generation above the latest re-shred, or a journal entry whose keys the
//!   database still holds, keeps the server closed: it does not serve;
//! - `access-server reshred` applies every journal entry again, records the re-shred and opens.

use std::path::PathBuf;
use std::sync::OnceLock;

use access_identity_audit::ports::ColdStore as _;
use access_identity_export::adapters::cold_file::FileCold;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::restore::{Shredded, mark_reshredded, mark_restored, pending_reshred};
use access_store::tenancy::RealmRoute;

/// The journal's prefix in the cold tier.
pub(crate) const JOURNAL: &str = "shred-journal";

static COLD: OnceLock<FileCold> = OnceLock::new();

/// Names the cold tier the journal lives in; set once at start.
pub(crate) fn use_cold(dir: Option<PathBuf>) {
    if let Some(root) = dir {
        let _ = COLD.set(FileCold { root });
    }
}

fn hex(b: &[u8; 16]) -> String {
    format!("{:032x}", u128::from_be_bytes(*b))
}

fn bytes(text: &str) -> Option<[u8; 16]> {
    u128::from_str_radix(text, 16).ok().map(u128::to_be_bytes)
}

fn key(tenant: &[u8; 16], realm: &[u8; 16], subject: &[u8; 16]) -> String {
    format!("{JOURNAL}/{}/{}/{}", hex(tenant), hex(realm), hex(subject))
}

/// One journal entry: the subject of a realm whose keys were destroyed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) tenant: [u8; 16],
    pub(crate) realm: [u8; 16],
    pub(crate) subject: [u8; 16],
}

fn entry_of(key: &str) -> Option<Entry> {
    let mut parts = key
        .strip_prefix(JOURNAL)?
        .trim_start_matches('/')
        .split('/');
    let e = Entry {
        tenant: bytes(parts.next()?)?,
        realm: bytes(parts.next()?)?,
        subject: bytes(parts.next()?)?,
    };
    parts.next().is_none().then_some(e)
}

/// Writes the destroyed subjects of `route` to `cold`'s journal (write-once).
///
/// # Errors
/// The cold tier's refusal.
pub(crate) async fn journal_to(
    cold: &FileCold,
    route: &RealmRoute,
    subjects: &[[u8; 16]],
) -> Result<(), String> {
    for s in subjects {
        let k = key(route.tenant.as_bytes(), route.realm.as_bytes(), s);
        cold.put(&k, b"destroyed")
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// [`journal_to`] the cold tier named at start; without one nothing is journaled.
pub(crate) async fn journal(route: &RealmRoute, subjects: &[[u8; 16]]) {
    if let Some(cold) = COLD.get()
        && let Err(error) = journal_to(cold, route, subjects).await
    {
        tracing::error!(%error, "shred journal not written; a restore could not apply these again");
    }
}

/// Every journal entry.
///
/// # Errors
/// The cold tier's refusal.
pub(crate) async fn entries(cold: &FileCold) -> Result<Vec<Entry>, String> {
    Ok(cold
        .list(JOURNAL)
        .await
        .map_err(|e| e.to_string())?
        .iter()
        .filter_map(|k| entry_of(k))
        .collect())
}

async fn behind(app: &Pool, entries: &[Entry]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    for e in entries {
        let mut tx = TenantTx::begin(
            app,
            TenantId::from_bytes(e.tenant),
            RealmId::from_bytes(e.realm),
        )
        .await
        .map_err(|x| x.to_string())?;
        let s = tx
            .subject_shredded(e.subject)
            .await
            .map_err(|x| x.to_string())?;
        tx.commit().await.map_err(|x| x.to_string())?;
        if s == Shredded::No {
            out.push(*e);
        }
    }
    Ok(out)
}

/// The start check: `Err` keeps the server closed. A journal entry the database is behind on
/// shows a restore that was not recorded; it is recorded now.
///
/// # Errors
/// Why the server stays closed.
pub(crate) async fn gate(app: &Pool, cold: Option<&FileCold>) -> Result<(), String> {
    let closed = |g: u64| {
        format!(
            "{}: restore generation {g} is not re-shredded; run `access-server reshred` before serving (OP-42)",
            access_http::problem::type_uri(
                access_http::problem::codes::durability::RESTORE_RESHRED_PENDING.code
            )
        )
    };
    if let Some(g) = pending_reshred(app).await.map_err(|e| e.to_string())? {
        tracing::error!(
            event = "restore.reshred.pending",
            generation = g,
            "server stays closed"
        );
        return Err(closed(g));
    }
    let Some(cold) = cold else {
        return Ok(());
    };
    if behind(app, &entries(cold).await?).await?.is_empty() {
        return Ok(());
    }
    let g = mark_restored(app).await.map_err(|e| e.to_string())?;
    tracing::error!(
        event = "restore.reshred.pending",
        generation = g,
        "server stays closed"
    );
    Err(closed(g))
}

/// What a re-shred did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Reshred {
    /// Journal entries applied.
    pub(crate) entries: u32,
    /// Keys destroyed again.
    pub(crate) keys: u64,
    /// The restore generation now re-shredded, if one was pending.
    pub(crate) generation: Option<u64>,
}

/// Applies every journal entry again and records the re-shred of the pending restore.
///
/// # Errors
/// Why the re-shred stopped; nothing is recorded then and the server stays closed.
pub(crate) async fn reshred(app: &Pool, cold: &FileCold) -> Result<Reshred, String> {
    let all = entries(cold).await?;
    if !behind(app, &all).await?.is_empty()
        && pending_reshred(app)
            .await
            .map_err(|e| e.to_string())?
            .is_none()
    {
        mark_restored(app).await.map_err(|e| e.to_string())?;
    }
    let mut out = Reshred::default();
    for e in &all {
        let mut tx = TenantTx::begin(
            app,
            TenantId::from_bytes(e.tenant),
            RealmId::from_bytes(e.realm),
        )
        .await
        .map_err(|x| x.to_string())?;
        let n = tx
            .reshred_subject(e.subject)
            .await
            .map_err(|x| x.to_string())?;
        tx.commit().await.map_err(|x| x.to_string())?;
        out.entries = out.entries.saturating_add(1);
        out.keys = out.keys.saturating_add(n);
    }
    if !behind(app, &all).await?.is_empty() {
        return Err(String::from("keys of the shred list are still readable"));
    }
    if let Some(g) = pending_reshred(app).await.map_err(|e| e.to_string())? {
        mark_reshredded(app, g).await.map_err(|e| e.to_string())?;
        let target = format!("restore:{g}");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .unwrap_or(0);
        access_store::operational::record_operational(
            app,
            &access_store::operational::OperationalEvent {
                occurred_at_ms: now,
                tenant: None,
                domain: None,
                event_type: "restore.reshredded",
                actor: "reshred",
                target: &target,
                reason: "",
                correlation: "restore",
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        out.generation = Some(g);
    }
    Ok(out)
}
