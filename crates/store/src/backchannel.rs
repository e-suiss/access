//! Back-channel logout notices (OIDC Back-Channel Logout 1.0, §10.4.6). A session that ends,
//! by sign-out or by a `session_epoch` step, revokes its grants in the same transaction and
//! queues one outbox event naming the grants whose clients have a back-channel endpoint
//! (G57, TN-50). The courier signs and posts the logout tokens; what it cannot deliver is
//! recorded here and the outbox row stays (OP-73).

use core::fmt::Write as _;

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{Cursor, TenantTx};

/// The outbox kind of a logout notice.
pub const LOGOUT_KIND: &str = "oauth.backchannel_logout";

/// Most grants one notice names; a longer list is split.
pub const MAX_GRANTS: usize = 64;

fn hex(b: &[u8; 16], out: &mut String) {
    for x in b {
        let _ = write!(out, "{x:02x}");
    }
}

fn unhex(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2)?;
        *o = u8::from_str_radix(s.get(at..at.checked_add(2)?)?, 16).ok()?;
    }
    Some(out)
}

/// The payload of a notice: `{"grants":["<hex>",…]}`.
#[must_use]
pub fn logout_payload(grants: &[[u8; 16]]) -> Vec<u8> {
    let mut out = String::from("{\"grants\":[");
    for (i, g) in grants.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        hex(g, &mut out);
        out.push('"');
    }
    out.push_str("]}");
    out.into_bytes()
}

/// The grants a notice names; `None` when the payload is not one.
#[must_use]
pub fn logout_grants(payload: &[u8]) -> Option<Vec<[u8; 16]>> {
    let text = core::str::from_utf8(payload).ok()?;
    let inner = text.strip_prefix("{\"grants\":[")?.strip_suffix("]}")?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        out.push(unhex(item.strip_prefix('"')?.strip_suffix('"')?)?);
        if out.len() > MAX_GRANTS {
            return None;
        }
    }
    Some(out)
}

/// One grant the courier passed without delivering.
pub struct LogoutUndelivered {
    /// The grant.
    pub grant: [u8; 16],
    /// Where its notice sits in the outbox.
    pub at: Cursor,
    /// `rejected`, `refused`, `unreachable` or `missing`.
    pub reason: &'static str,
    /// The client's HTTP status, for `rejected`.
    pub client_status: Option<u16>,
}

/// A recorded undelivered notice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogoutUndeliveredRow {
    /// The grant.
    pub grant: [u8; 16],
    /// Reason code.
    pub reason: String,
    /// The client's HTTP status.
    pub client_status: Option<u16>,
}

impl TenantTx {
    /// Queues a notice for `grants` in this transaction; nothing when the list is empty.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn queue_backchannel_logout(&mut self, grants: &[Uuid]) -> Result<(), StoreError> {
        let ids: Vec<[u8; 16]> = grants.iter().map(|g| g.into_bytes()).collect();
        for chunk in ids.chunks(MAX_GRANTS) {
            self.outbox(LOGOUT_KIND, &logout_payload(chunk)).await?;
        }
        Ok(())
    }

    /// Records `u` once; a second record of the same grant is a no-op (redelivery).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn backchannel_undelivered(
        &mut self,
        u: &LogoutUndelivered,
    ) -> Result<(), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let xid = i64::try_from(u.at.xid).map_err(|_| StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO access.backchannel_undelivered
                (tenant_id, realm_id, grant_id, outbox_xid, outbox_id, reason, client_status)
             VALUES ($1, $2, $3, $4::bigint::text::xid8, $5, $6, $7)
             ON CONFLICT (tenant_id, realm_id, grant_id) DO NOTHING",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(u.grant),
            xid,
            u.at.id,
            u.reason,
            u.client_status.map(i32::from),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The realm's undelivered notices, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn list_backchannel_undelivered(
        &mut self,
        limit: u32,
    ) -> Result<Vec<LogoutUndeliveredRow>, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let rows = sqlx::query!(
            "SELECT grant_id, reason, client_status FROM access.backchannel_undelivered
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY outbox_xid, outbox_id, grant_id LIMIT $3",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(LogoutUndeliveredRow {
                    grant: r.grant_id.into_bytes(),
                    reason: r.reason,
                    client_status: r
                        .client_status
                        .map(u16::try_from)
                        .transpose()
                        .map_err(|_| StoreError::Corrupt)?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // §10.4.6: a notice names its grants and reads back exactly
    #[test]
    fn payload_round_trips() {
        let grants = [[1_u8; 16], [0xab; 16]];
        let p = logout_payload(&grants);
        assert_eq!(logout_grants(&p).unwrap(), grants.to_vec());
        assert_eq!(logout_grants(b"{\"grants\":[]}").unwrap().len(), 0);
        assert!(logout_grants(b"{\"grants\":[\"zz\"]}").is_none());
        assert!(logout_grants(b"{}").is_none());
    }
}
