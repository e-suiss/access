//! The export pass (OP-41, OP-44, OP-156 m.3 (s), X22): for each live sink of a realm, the audit
//! rows after its cursor go out in batches, in integration order, every row and none sampled.
//! The cursor moves only after the sink accepted the batch; a refused batch leaves it where it
//! was and is sent again on the next pass, so nothing is lost. A sink that keeps refusing raises
//! `export.sink_failed` once per failure.

use access_identity_audit::domain::record::AuditRecord;
use access_identity_events::domain::catalog::IdentityEvent;
use access_store::audit::{AuditEvent, AuditRow};
use access_store::export::{self as store, SinkRow};
use access_store::identity::{Cursor, RealmId, TenantId, TenantTx};
use access_store::{Pool, StoreError};
use serde_json::{Map, Value};

use crate::domain::collector::{self, Request};
use crate::domain::secret;
use crate::domain::sink::{Adapter, Format, Preset, SinkSecret, SinkSpec, host_port};
use crate::domain::{otlp, parquet, s3, syslog};
use crate::ports::{Down, RealmKek, Wire};

/// Rows per batch (PD).
pub const BATCH: u32 = 500;

/// Batches one sink sends in one pass at most (PD).
pub const MAX_BATCHES: u32 = 20;

/// Refused batches in a row before `export.sink_failed` (PD).
pub const NOTIFY_AFTER: u32 = 3;

/// A cursor this far behind the oldest unsent row is reported as lag (PD).
pub const LAG_WARN_MS: u64 = 300_000;

/// The actor of the exporter's own audit events.
pub const ACTOR: &str = "export";

/// The audit event of an accepted batch.
pub const BATCH_SENT: &str = "export.batch_sent";

/// The audit event of a sink that keeps refusing.
pub const SINK_FAILED: &str = "export.sink_failed";

const MAX_ANSWER: usize = 64 * 1024;

/// What one pass over a realm did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Rows the sinks accepted.
    pub sent: u64,
    /// Batches the sinks accepted.
    pub batches: u32,
    /// Batches the sinks refused.
    pub refused: u32,
    /// `export.sink_failed` events raised.
    pub notified: u32,
}

/// The pass's database, transports and keys.
pub struct Pass<'a, W, K> {
    /// `access_app`.
    pub app: &'a Pool,
    /// The sinks' transports.
    pub wire: &'a W,
    /// The realm KEKs.
    pub keys: &'a K,
}

/// A sink row's declaration.
///
/// # Errors
/// [`Down`] `stored` when the row does not read back as a declaration.
pub fn spec_of(s: &SinkRow) -> Result<SinkSpec, Down> {
    let stored = || Down(String::from("stored"));
    let settings: Map<String, Value> = serde_json::from_str(&s.settings).map_err(|_| stored())?;
    Ok(SinkSpec {
        adapter: Adapter::parse(&s.adapter).ok_or_else(stored)?,
        preset: s
            .preset
            .as_deref()
            .map(Preset::parse)
            .transpose_none(stored)?,
        format: s
            .format
            .as_deref()
            .map(Format::parse)
            .transpose_none(stored)?,
        endpoint: s.endpoint.clone(),
        settings,
    })
}

trait TransposeNone<T> {
    fn transpose_none(self, e: impl Fn() -> Down) -> Result<Option<T>, Down>;
}

impl<T> TransposeNone<T> for Option<Option<T>> {
    fn transpose_none(self, e: impl Fn() -> Down) -> Result<Option<T>, Down> {
        match self {
            None => Ok(None),
            Some(Some(v)) => Ok(Some(v)),
            Some(None) => Err(e()),
        }
    }
}

fn settled(row: &AuditRow) -> Cursor {
    Cursor {
        xid: row.xid,
        id: row.id,
    }
}

fn uuid(b: &[u8; 16]) -> String {
    access_identity_audit::domain::record::uuid_text(b)
}

impl<W: Wire, K: RealmKek> Pass<'_, W, K> {
    /// Sends every live sink of the realm what it has not accepted yet, at `now_ms`.
    ///
    /// # Errors
    /// [`StoreError`]; what was committed stays.
    pub async fn realm(
        &self,
        (tenant, realm): (TenantId, RealmId),
        now_ms: u64,
    ) -> Result<Outcome, StoreError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let sinks = store::sinks(&mut t).await?;
        t.commit().await?;
        let mut out = Outcome::default();
        for s in sinks.iter().filter(|s| s.state == "live") {
            self.sink((tenant, realm), s, now_ms, &mut out).await?;
        }
        Ok(out)
    }

    async fn sink(
        &self,
        scope: (TenantId, RealmId),
        s: &SinkRow,
        now_ms: u64,
        out: &mut Outcome,
    ) -> Result<(), StoreError> {
        let opened = self.opened(scope, s);
        for _ in 0..MAX_BATCHES {
            let mut t = TenantTx::begin(self.app, scope.0, scope.1).await?;
            let Some(c) = store::cursor(&mut t, s.id).await? else {
                t.rollback().await?;
                return Ok(());
            };
            let rows = store::audit_after(&mut t, c.after, BATCH).await?;
            t.commit().await?;
            let (Some(first), Some(last)) = (rows.first(), rows.last()) else {
                return Ok(());
            };
            let sent = match &opened {
                Ok((spec, secret)) => {
                    self.send(scope, (s, spec, secret.as_ref()), &rows, now_ms)
                        .await
                }
                Err(e) => Err(e.clone()),
            };
            let mut t = TenantTx::begin(self.app, scope.0, scope.1).await?;
            match sent {
                Ok(()) => {
                    let n = u64::try_from(rows.len()).unwrap_or(u64::MAX);
                    if store::advance(&mut t, s.id, (c.after, settled(last)), n).await? {
                        // OP-44
                        if rows.iter().any(|r| r.event_type != BATCH_SENT) {
                            t.audit(&AuditEvent {
                                event_type: BATCH_SENT,
                                actor: ACTOR,
                                target: &s.name,
                                correlation: "-",
                            })
                            .await?;
                        }
                        out.sent = out.sent.saturating_add(n);
                        out.batches = out.batches.saturating_add(1);
                    }
                    t.commit().await?;
                    if rows.len() < usize::try_from(BATCH).unwrap_or(usize::MAX) {
                        return Ok(());
                    }
                }
                Err(Down(code)) => {
                    let failures = store::failed(&mut t, s.id, &code).await?;
                    out.refused = out.refused.saturating_add(1);
                    if failures >= NOTIFY_AFTER && store::notified(&mut t, s.id).await? {
                        self.raise(
                            &mut t,
                            scope,
                            s,
                            c.failed_since_ms.unwrap_or(now_ms),
                            now_ms,
                        )
                        .await?;
                        out.notified = out.notified.saturating_add(1);
                    }
                    t.commit().await?;
                    tracing::warn!(
                        event = "export.sink.failed",
                        adapter = %s.adapter,
                        status = %code,
                        "an export sink refused a batch; its cursor stays (X22)"
                    );
                    let lag = u64::try_from(first.at_ms)
                        .ok()
                        .map_or(0, |at| now_ms.saturating_sub(at));
                    if lag > LAG_WARN_MS {
                        tracing::warn!(
                            event = "export.cursor.lag",
                            adapter = %s.adapter,
                            lag_s = lag / 1000,
                            "an export sink is behind the audit log"
                        );
                    }
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    async fn raise(
        &self,
        t: &mut TenantTx,
        (_, realm): (TenantId, RealmId),
        s: &SinkRow,
        since_ms: u64,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        // OP-41
        t.audit(&AuditEvent {
            event_type: SINK_FAILED,
            actor: ACTOR,
            target: &s.name,
            correlation: "-",
        })
        .await?;
        let id = access_crypto::random::bytes::<32>().map_err(|_| StoreError::Range)?;
        let event = IdentityEvent::export_sink_failed(
            id,
            realm.as_bytes(),
            (&s.name, &s.adapter),
            since_ms,
            now_ms,
        );
        access_identity_events::app::emit(t, &event).await
    }

    fn opened(
        &self,
        scope: (TenantId, RealmId),
        s: &SinkRow,
    ) -> Result<(SinkSpec, Option<SinkSecret>), Down> {
        let spec = spec_of(s)?;
        let secret = match &s.secret {
            None => None,
            Some(sealed) => {
                let kek = self
                    .keys
                    .kek(scope.0, scope.1)
                    .ok_or_else(|| Down(String::from("kek")))?;
                Some(
                    secret::open(&*kek, scope, &s.id, sealed)
                        .map_err(|_| Down(String::from("secret")))?,
                )
            }
        };
        Ok((spec, secret))
    }

    async fn send(
        &self,
        (_, realm): (TenantId, RealmId),
        (s, spec, secret): (&SinkRow, &SinkSpec, Option<&SinkSecret>),
        rows: &[AuditRow],
        now_ms: u64,
    ) -> Result<(), Down> {
        let render = |_| Down(String::from("render"));
        let records = rows
            .iter()
            .map(|r| AuditRecord::identity(r, None))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Down(String::from("render")))?;
        let request = match spec.adapter {
            Adapter::Syslog => {
                let format = spec.format.ok_or_else(|| Down(String::from("stored")))?;
                let (host, port) =
                    host_port(&spec.endpoint).ok_or_else(|| Down(String::from("stored")))?;
                let text = |k| {
                    spec.settings
                        .get(k)
                        .and_then(Value::as_str)
                        .unwrap_or("access")
                };
                let mut frames = Vec::new();
                for r in &records {
                    let m = syslog::message(r, format, (text("hostname"), text("app_name")))
                        .map_err(render)?;
                    frames.extend_from_slice(&syslog::frame(&m));
                }
                return self.wire.syslog((host, port), &frames).await;
            }
            Adapter::S3Parquet => {
                let first = rows.first().ok_or_else(|| Down(String::from("render")))?;
                let file = parquet::file(&records).map_err(|_| Down(String::from("render")))?;
                let key = s3::key(
                    spec,
                    &uuid(realm.as_bytes()),
                    (first.xid, first.id),
                    u64::try_from(first.at_ms).unwrap_or(0),
                );
                let secret = secret.ok_or_else(|| Down(String::from("secret")))?;
                s3::put(spec, secret, &key, file, now_ms)
                    .ok_or_else(|| Down(String::from("stored")))?
            }
            Adapter::Otlp => {
                let mut r = collector::request(
                    &SinkSpec {
                        preset: None,
                        ..spec.clone()
                    },
                    secret,
                    None,
                    &records,
                )
                .map_err(render)?;
                r.body = otlp::body(&records).map_err(render)?;
                r
            }
            Adapter::Collector => {
                let bearer = match (spec.preset, secret) {
                    (Some(Preset::Sentinel), Some(secret)) => {
                        Some(self.sentinel_token(spec, secret).await?)
                    }
                    _ => None,
                };
                collector::request(spec, secret, bearer.as_deref(), &records).map_err(render)?
            }
        };
        let (status, body) = self.wire.http(&request, MAX_ANSWER).await?;
        if collector::accepted(
            spec.preset.filter(|_| s.adapter == "collector"),
            status,
            &body,
        ) {
            Ok(())
        } else {
            Err(Down(format!("status-{status}")))
        }
    }

    async fn sentinel_token(&self, spec: &SinkSpec, secret: &SinkSecret) -> Result<String, Down> {
        let (url, form) = collector::sentinel_token(spec, secret);
        let request = Request {
            method: "POST",
            url,
            content_type: "application/x-www-form-urlencoded",
            headers: Vec::new(),
            body: form.into_bytes(),
        };
        let (status, body) = self.wire.http(&request, MAX_ANSWER).await?;
        if !(200..300).contains(&status) {
            return Err(Down(format!("token-{status}")));
        }
        serde_json::from_slice::<Value>(&body)
            .ok()
            .and_then(|v| {
                v.get("access_token")
                    .and_then(Value::as_str)
                    .map(String::from)
            })
            .ok_or_else(|| Down(String::from("token")))
    }
}
