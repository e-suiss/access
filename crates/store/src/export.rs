//! A realm's export sinks and their cursors (OP-156 m.3 (s), OP-41, X22). A sink is a versioned
//! row written under a committed `idp.export.*` ALLOW; its sealed secret is shredded when a newer
//! version supersedes it. The cursor names the last audit row the sink accepted and moves only
//! forward, only after the sink accepted a batch.

use sqlx::types::Uuid;

use crate::StoreError;
use crate::audit::AuditRow;
use crate::events::SealedKey;
use crate::identity::{Cursor, TenantTx};
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// A new version of a sink.
pub struct NewSink<'a> {
    /// Its stable id, the same for every version.
    pub id: [u8; 16],
    /// Its name in the realm.
    pub name: &'a str,
    /// `live` or `retired`.
    pub state: &'a str,
    /// `s3_parquet`, `otlp`, `collector` or `syslog`.
    pub adapter: &'a str,
    /// The collector's preset.
    pub preset: Option<&'a str>,
    /// The syslog message format.
    pub format: Option<&'a str>,
    /// Where the copy goes.
    pub endpoint: &'a str,
    /// The adapter's settings without the secret, a JSON object's text.
    pub settings: &'a str,
    /// The sealed secret.
    pub secret: Option<&'a SealedKey>,
}

/// A sink's newest version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkRow {
    /// Its stable id.
    pub id: [u8; 16],
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: u64,
    /// `live` or `retired`.
    pub state: String,
    /// The adapter.
    pub adapter: String,
    /// The collector's preset.
    pub preset: Option<String>,
    /// The syslog message format.
    pub format: Option<String>,
    /// Where the copy goes.
    pub endpoint: String,
    /// The adapter's settings, a JSON object's text.
    pub settings: String,
    /// The sealed secret, while not shredded.
    pub secret: Option<SealedKey>,
    /// The deciding position of this version.
    pub decision_pos: u64,
    /// Unix seconds of this version.
    pub changed_at: i64,
}

macro_rules! sink_row {
    ($r:expr) => {{
        let r = $r;
        let secret = match (r.kek_id, r.wrapped_dek, r.secret_nonce, r.secret_sealed) {
            (Some(kek_id), Some(wrapped_dek), Some(nonce), Some(ciphertext)) => Some(SealedKey {
                kek_id,
                wrapped_dek,
                nonce: <[u8; 12]>::try_from(nonce).map_err(|_| StoreError::Corrupt)?,
                ciphertext,
            }),
            _ => None,
        };
        SinkRow {
            id: *r.sink_uuid.as_bytes(),
            name: r.name,
            version: unsigned(r.version)?,
            state: r.state,
            adapter: r.adapter,
            preset: r.preset,
            format: r.format,
            endpoint: r.endpoint,
            settings: r.settings,
            secret,
            decision_pos: unsigned(r.decision_pos)?,
            changed_at: r.changed_s,
        }
    }};
}

/// Writes the next version of sink `s` under `bound`, and shreds the secret of every earlier
/// version (OP-73).
///
/// # Errors
/// [`StoreError`]; a version that is not bound to its committed ALLOW fails its trigger.
pub async fn write(t: &mut TenantTx, bound: &Bound, s: &NewSink<'_>) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let version: i64 = sqlx::query_scalar!(
        r#"SELECT COALESCE(max(version), 0) + 1 AS "v!" FROM access.export_sinks
            WHERE tenant_id = $1 AND realm_id = $2 AND name = $3"#,
        tenant,
        realm,
        s.name,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    sqlx::query!(
        "INSERT INTO access.export_sinks (tenant_id, realm_id, name, version, sink_uuid, state,
                adapter, preset, format, endpoint, settings, kek_id, wrapped_dek, secret_nonce,
                secret_sealed, domain_id, decision_pos)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::jsonb, $12, $13, $14, $15, $16, $17)",
        tenant,
        realm,
        s.name,
        version,
        Uuid::from_bytes(s.id),
        s.state,
        s.adapter,
        s.preset,
        s.format,
        s.endpoint,
        s.settings,
        s.secret.map(|k| k.kek_id.as_str()),
        s.secret.map(|k| k.wrapped_dek.as_slice()),
        s.secret.map(|k| k.nonce.as_slice()),
        s.secret.map(|k| k.ciphertext.as_slice()),
        bound.domain().as_bytes().as_slice(),
        bound.raw_position(),
    )
    .execute(&mut *t.tx)
    .await?;
    sqlx::query!(
        "UPDATE access.export_sinks
            SET kek_id = NULL, wrapped_dek = NULL, secret_nonce = NULL, secret_sealed = NULL
          WHERE tenant_id = $1 AND realm_id = $2 AND name = $3 AND version < $4
            AND secret_sealed IS NOT NULL",
        tenant,
        realm,
        s.name,
        version,
    )
    .execute(&mut *t.tx)
    .await?;
    sqlx::query!(
        "INSERT INTO access.export_cursors (tenant_id, realm_id, sink_uuid)
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        tenant,
        realm,
        Uuid::from_bytes(s.id),
    )
    .execute(&mut *t.tx)
    .await?;
    unsigned(version)
}

/// The newest version of every sink of the realm, by name.
///
/// # Errors
/// [`StoreError`].
pub async fn sinks(t: &mut TenantTx) -> Result<Vec<SinkRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        r#"SELECT DISTINCT ON (name) name, version, sink_uuid, state, adapter, preset, format,
                endpoint, settings::text AS "settings!", kek_id, wrapped_dek, secret_nonce, secret_sealed, decision_pos,
                extract(epoch FROM created_at)::bigint AS "changed_s!"
           FROM access.export_sinks WHERE tenant_id = $1 AND realm_id = $2
          ORDER BY name, version DESC"#,
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter().map(|r| Ok(sink_row!(r))).collect()
}

/// The newest version of sink `name`.
///
/// # Errors
/// [`StoreError`].
pub async fn sink(t: &mut TenantTx, name: &str) -> Result<Option<SinkRow>, StoreError> {
    Ok(sinks(t).await?.into_iter().find(|s| s.name == name))
}

/// A sink's cursor and delivery state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CursorRow {
    /// The last audit row the sink accepted.
    pub after: Cursor,
    /// How many rows it accepted.
    pub sent: u64,
    /// Failed attempts since the last accepted batch.
    pub failures: u32,
    /// Unix milliseconds of the first of them.
    pub failed_since_ms: Option<u64>,
    /// The last failure's code.
    pub last_error: Option<String>,
    /// Whether `export.sink_failed` went out for this failure.
    pub notified: bool,
    /// Unix milliseconds of the last accepted batch.
    pub sent_at_ms: Option<u64>,
}

/// The cursor of sink `id`; `None` before the sink was registered.
///
/// # Errors
/// [`StoreError`].
pub async fn cursor(t: &mut TenantTx, id: [u8; 16]) -> Result<Option<CursorRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let r = sqlx::query!(
        r#"SELECT after_xid, after_id, sent, failures, last_error, notified_at IS NOT NULL AS "notified!",
                (extract(epoch FROM failed_since) * 1000)::bigint AS failed_ms,
                (extract(epoch FROM sent_at) * 1000)::bigint AS sent_ms
           FROM access.export_cursors WHERE tenant_id = $1 AND realm_id = $2 AND sink_uuid = $3"#,
        tenant,
        realm,
        Uuid::from_bytes(id),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    r.map(|r| {
        Ok(CursorRow {
            after: Cursor {
                xid: unsigned(r.after_xid)?,
                id: r.after_id,
            },
            sent: unsigned(r.sent)?,
            failures: u32::try_from(r.failures).map_err(|_| StoreError::Corrupt)?,
            failed_since_ms: r.failed_ms.map(unsigned).transpose()?,
            last_error: r.last_error,
            notified: r.notified,
            sent_at_ms: r.sent_ms.map(unsigned).transpose()?,
        })
    })
    .transpose()
}

/// Moves sink `id`'s cursor from `from` to `to` after it accepted `n` rows, and clears its
/// failure. `false` when the cursor is no longer at `from` (another node moved it).
///
/// # Errors
/// [`StoreError`].
pub async fn advance(
    t: &mut TenantTx,
    id: [u8; 16],
    (from, to): (Cursor, Cursor),
    n: u64,
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.export_cursors
            SET after_xid = $4, after_id = $5, sent = sent + $6, failures = 0, failed_since = NULL,
                last_error = NULL, notified_at = NULL, attempted_at = clock_timestamp(),
                sent_at = clock_timestamp()
          WHERE tenant_id = $1 AND realm_id = $2 AND sink_uuid = $3
            AND after_xid = $7 AND after_id = $8",
        tenant,
        realm,
        Uuid::from_bytes(id),
        signed(to.xid)?,
        to.id,
        signed(n)?,
        signed(from.xid)?,
        from.id,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// Records a refused batch of sink `id` with `error`; the cursor stays. Returns the failure count.
///
/// # Errors
/// [`StoreError`].
pub async fn failed(t: &mut TenantTx, id: [u8; 16], error: &str) -> Result<u32, StoreError> {
    let (tenant, realm) = scope(t)?;
    let n: i32 = sqlx::query_scalar!(
        "UPDATE access.export_cursors
            SET failures = failures + 1, failed_since = COALESCE(failed_since, clock_timestamp()),
                last_error = $4, attempted_at = clock_timestamp()
          WHERE tenant_id = $1 AND realm_id = $2 AND sink_uuid = $3
         RETURNING failures",
        tenant,
        realm,
        Uuid::from_bytes(id),
        error,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    u32::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// Marks that `export.sink_failed` went out for sink `id`'s current failure; `false` when it
/// already had.
///
/// # Errors
/// [`StoreError`].
pub async fn notified(t: &mut TenantTx, id: [u8; 16]) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let done = sqlx::query!(
        "UPDATE access.export_cursors SET notified_at = clock_timestamp()
          WHERE tenant_id = $1 AND realm_id = $2 AND sink_uuid = $3
            AND failed_since IS NOT NULL AND notified_at IS NULL",
        tenant,
        realm,
        Uuid::from_bytes(id),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// The realm's audit rows after `after` whose transactions have ended, in integration order,
/// at most `limit` (OP-41, OP-44: every row, none sampled). A row is returned only below every
/// transaction still open at the snapshot that could write one: an open transaction counts
/// unless it is a session of another database, which cannot write this table, so another
/// database's long transaction does not hold the export back.
///
/// # Errors
/// [`StoreError`].
pub async fn audit_after(
    t: &mut TenantTx,
    after: Cursor,
    limit: u32,
) -> Result<Vec<AuditRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        r#"WITH elsewhere AS (
                  SELECT backend_xid::text::bigint AS x FROM pg_stat_activity
                   WHERE backend_xid IS NOT NULL
                     AND datid IS DISTINCT FROM (SELECT oid FROM pg_database
                                                  WHERE datname = current_database())),
                horizon AS (
                  SELECT COALESCE(min(p.x), pg_snapshot_xmax(pg_current_snapshot())) AS h
                    FROM pg_snapshot_xip(pg_current_snapshot()) AS p(x)
                   WHERE (p.x::text::bigint % 4294967296) NOT IN (SELECT x FROM elsewhere))
           SELECT tenant_id, realm_id, (extract(epoch FROM at) * 1000)::bigint AS "at_ms!", id,
                  xid::text::bigint AS "xid!", event_type, actor, target, correlation
             FROM access.identity_audit
            WHERE tenant_id = $1 AND realm_id = $2
              AND xid < (SELECT h FROM horizon)
              AND (xid, id) > ($3::bigint::text::xid8, $4)
            ORDER BY xid, id
            LIMIT $5"#,
        tenant,
        realm,
        signed(after.xid)?,
        after.id,
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(AuditRow {
                tenant: *r.tenant_id.as_bytes(),
                realm: *r.realm_id.as_bytes(),
                at_ms: r.at_ms,
                id: r.id,
                xid: unsigned(r.xid)?,
                event_type: r.event_type,
                actor: r.actor,
                target: r.target,
                correlation: r.correlation,
            })
        })
        .collect()
}
