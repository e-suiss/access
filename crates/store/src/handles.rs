//! Handles of a realm (E56, OP-156 m.4 Q20): the claim of each, naming the Party and the DID it
//! must point at, and its verification and retirement as rows of their own. A handle is claimed
//! once per realm and never handed to anyone else. Nothing is deleted (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

/// A handle as the realm keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleRow {
    /// Its id.
    pub id: [u8; 16],
    /// The person.
    pub subject: [u8; 16],
    /// Their Party.
    pub party: [u8; 16],
    /// The handle.
    pub handle: String,
    /// The DID it must point at.
    pub did: String,
    /// `suiss` or `own`.
    pub kind: String,
    /// Whether it was verified.
    pub verified: bool,
    /// Whether it was retired.
    pub retired: bool,
}

impl TenantTx {
    /// Claims `handle` for `subject`'s `party`; the id, or `None` when the realm has seen the
    /// handle before.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn claim_handle(
        &mut self,
        (subject, party): ([u8; 16], [u8; 16]),
        handle: &str,
        did: &str,
        kind: &str,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.handles (tenant_id, realm_id, subject_id, party, handle, did, kind)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT DO NOTHING
             RETURNING handle_id",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            party.as_slice(),
            handle,
            did,
            kind,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(id.map(|u| *u.as_bytes()))
    }

    /// Records `event` (`verified` or `retired`) of `subject`'s handle `id`; `false` when it is
    /// not theirs or was recorded already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn handle_event(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
        event: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.handle_events (tenant_id, realm_id, handle_id, event, handle, kind)
             SELECT h.tenant_id, h.realm_id, h.handle_id, $5, h.handle, h.kind
               FROM access.handles h
              WHERE h.tenant_id = $1 AND h.realm_id = $2 AND h.handle_id = $3
                AND h.subject_id = $4
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(id),
            Uuid::from_bytes(subject),
            event,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The handles of `subject`, or of the person bound to `party` when `subject` is `None`,
    /// oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn handles(
        &mut self,
        subject: Option<[u8; 16]>,
        party: Option<[u8; 16]>,
    ) -> Result<Vec<HandleRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            r#"SELECT h.handle_id, h.subject_id, h.party, h.handle, h.did, h.kind,
                      EXISTS (SELECT 1 FROM access.handle_events e
                               WHERE e.tenant_id = h.tenant_id AND e.realm_id = h.realm_id
                                 AND e.handle_id = h.handle_id AND e.event = 'verified') AS "verified!",
                      EXISTS (SELECT 1 FROM access.handle_events e
                               WHERE e.tenant_id = h.tenant_id AND e.realm_id = h.realm_id
                                 AND e.handle_id = h.handle_id AND e.event = 'retired') AS "retired!"
                 FROM access.handles h
                WHERE h.tenant_id = $1 AND h.realm_id = $2
                  AND ($3::uuid IS NULL OR h.subject_id = $3)
                  AND ($4::bytea IS NULL OR h.party = $4)
                ORDER BY h.handle_id
                LIMIT 32"#,
            tenant,
            realm,
            subject.map(Uuid::from_bytes),
            party.as_ref().map(<[u8; 16]>::as_slice),
        )
        .fetch_all(&mut *self.tx)
        .await?
        .into_iter()
        .map(|r| {
            Ok(HandleRow {
                id: *r.handle_id.as_bytes(),
                subject: *r.subject_id.as_bytes(),
                party: <[u8; 16]>::try_from(r.party).map_err(|_| StoreError::Corrupt)?,
                handle: r.handle,
                did: r.did,
                kind: r.kind,
                verified: r.verified,
                retired: r.retired,
            })
        })
        .collect()
    }
}

/// The DID a verified, not retired Suiss handle `host` points at, read as the router
/// (`/.well-known/access-handle`, E56 (2)).
///
/// # Errors
/// [`StoreError`].
pub async fn suiss_handle_did(router: &PgPool, host: &str) -> Result<Option<String>, StoreError> {
    Ok(sqlx::query_scalar!(
        "SELECT h.did FROM access.handles h
          WHERE h.handle = $1 AND h.kind = 'suiss'
            AND EXISTS (SELECT 1 FROM access.handle_events e
                         WHERE e.tenant_id = h.tenant_id AND e.realm_id = h.realm_id
                           AND e.handle_id = h.handle_id AND e.event = 'verified')
            AND NOT EXISTS (SELECT 1 FROM access.handle_events e
                             WHERE e.tenant_id = h.tenant_id AND e.realm_id = h.realm_id
                               AND e.handle_id = h.handle_id AND e.event = 'retired')",
        host,
    )
    .fetch_optional(router)
    .await?)
}
