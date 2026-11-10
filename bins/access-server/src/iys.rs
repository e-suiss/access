//! Relay's İYS reports kept beside their records (OP-156 m.3 (c), IDP-37 (4), B23): the tenant
//! named by its external id, the realm scoped by row-level security, the report audited.
//! Nothing here changes a preference or an authority.

use std::sync::Arc;

use access_http::relay_callback::{IysReports, Kept, Report, Status, Unavailable};
use access_identity_events::ports::TenantIds;
use access_store::Pool;
use access_store::audit::AuditEvent;
use access_store::identity::{RealmId, TenantId, TenantTx};

/// The reports, in each realm's own rows.
pub(crate) struct PgIysReports {
    pub(crate) app: Pool,
    pub(crate) ids: Arc<dyn TenantIds>,
}

fn uuid(b: &[u8; 16]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(36);
    for (i, x) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{x:02x}");
    }
    s
}

impl IysReports for PgIysReports {
    async fn keep(&self, r: &Report) -> Result<Kept, Unavailable> {
        let Some(tenant) = self.ids.internal(&r.tenant) else {
            return Ok(Kept::NoRecord);
        };
        let down = |_| Unavailable;
        let mut t = TenantTx::begin(
            &self.app,
            TenantId::from_bytes(tenant),
            RealmId::from_bytes(r.realm),
        )
        .await
        .map_err(down)?;
        if !t
            .insert_iys_status(r.record, r.status.name(), r.reason.as_deref(), r.at_ms)
            .await
            .map_err(down)?
        {
            return Ok(Kept::NoRecord);
        }
        let record = uuid(&r.record);
        t.audit(&AuditEvent {
            event_type: match r.status {
                Status::Recorded => "iys.recorded",
                Status::Failed => "iys.failed",
            },
            actor: RELAY,
            target: &record,
            correlation: &record,
        })
        .await
        .map_err(down)?;
        t.commit().await.map_err(down)?;
        if r.status == Status::Failed {
            tracing::warn!(event = "iys.status.failed", status = "failed");
        }
        Ok(Kept::Kept)
    }
}

/// The actor audit rows name for Relay's reports.
pub(crate) const RELAY: &str = "relay";
