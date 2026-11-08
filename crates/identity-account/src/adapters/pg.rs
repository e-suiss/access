//! PostgreSQL adapter of [`AccountDb`], as `access_app` under the realm's scope (OP-12, OP-66).
//! Identifiers go through the realm's PII vault (OP-153 m.3 (aa)): a transaction without the
//! vault's keys reads and writes no identifier (TI-9).

use access_store::Pool;
use access_store::accounts::{CredentialRow, NewCredential, Revoke, SealedSecret, SubjectRow};
use access_store::audit::AuditEvent;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::throttle::ThrottleRow;

use crate::AccountError;
use crate::app::vault::{self, Vault, folded};
use crate::domain::identifier::Identifier;
use crate::domain::status::AccountStatus;
use crate::ports::{AccountDb, AccountTx};

/// The account tables in PostgreSQL, with the realm's vault keys when identifiers are touched.
pub struct PgAccounts(pub Pool, pub Option<Vault>);

impl PgAccounts {
    /// The account tables without the vault: no identifier is read or written.
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self(pool, None)
    }

    /// The account tables with the realm's vault keys.
    #[must_use]
    pub const fn sealed(pool: Pool, vault: Vault) -> Self {
        Self(pool, Some(vault))
    }
}

/// One scoped transaction, with the realm's vault keys when it has them; the inner
/// transaction is open to other identity adapters that add tables to the same unit of work
/// (OP-63).
pub struct PgTx(pub TenantTx, pub Option<Vault>);

impl PgTx {
    /// A transaction without the vault.
    #[must_use]
    pub const fn new(tx: TenantTx) -> Self {
        Self(tx, None)
    }

    /// The vault's keys.
    ///
    /// # Errors
    /// [`AccountError::Vault`] when this transaction has none.
    pub fn vault(&self) -> Result<&Vault, AccountError> {
        self.1.as_ref().ok_or(AccountError::Vault)
    }

    /// The readable stored identifier `stored` of `subject`; `None` once its key is shredded.
    ///
    /// # Errors
    /// [`AccountError`].
    pub async fn reveal(
        &mut self,
        subject: [u8; 16],
        stored: &access_store::accounts::StoredValue,
    ) -> Result<Option<String>, AccountError> {
        let v = self.vault()?.clone();
        vault::reveal(&mut self.0, &v, subject, stored).await
    }
}

impl AccountDb for PgAccounts {
    type Tx = PgTx;

    async fn begin(&self, tenant: TenantId, realm: RealmId) -> Result<PgTx, AccountError> {
        Ok(PgTx(
            TenantTx::begin(&self.0, tenant, realm).await?,
            self.1.clone(),
        ))
    }
}

impl AccountTx for PgTx {
    async fn insert_subject(
        &mut self,
        status: AccountStatus,
        kek_id: &str,
        wrapped_dek: &[u8],
    ) -> Result<[u8; 16], AccountError> {
        Ok(self
            .0
            .insert_subject(status.name(), kek_id, wrapped_dek)
            .await?)
    }

    async fn subject(
        &mut self,
        id: [u8; 16],
        lock: bool,
    ) -> Result<Option<SubjectRow>, AccountError> {
        Ok(self.0.subject(id, lock).await?)
    }

    async fn set_status(
        &mut self,
        id: [u8; 16],
        from: AccountStatus,
        to: AccountStatus,
    ) -> Result<bool, AccountError> {
        Ok(self
            .0
            .set_subject_status(id, from.name(), to.name())
            .await?)
    }

    async fn end_sessions(&mut self, id: [u8; 16]) -> Result<Option<i64>, AccountError> {
        Ok(self.0.end_sessions(id).await?)
    }

    async fn end_sessions_because(
        &mut self,
        id: [u8; 16],
        reason: &'static str,
    ) -> Result<Option<i64>, AccountError> {
        Ok(self.0.end_sessions_because(id, reason).await?)
    }

    async fn add_identifier(
        &mut self,
        subject: [u8; 16],
        identifier: &Identifier,
    ) -> Result<bool, AccountError> {
        let v = self.vault()?.clone();
        if self
            .subject_by_identifier(identifier.value())
            .await?
            .is_some()
        {
            return Ok(false);
        }
        let sealed = vault::seal_identifier(
            &mut self.0,
            &v,
            subject,
            identifier.kind(),
            identifier.value(),
        )
        .await?;
        Ok(self
            .0
            .add_identifier(subject, identifier.kind().name(), &sealed)
            .await?)
    }

    async fn subject_by_identifier(
        &mut self,
        value: &str,
    ) -> Result<Option<[u8; 16]>, AccountError> {
        let realm = self.0.realm().ok_or(AccountError::Corrupt)?;
        let index = self
            .vault()?
            .index_of(self.0.tenant().as_bytes(), realm.as_bytes(), value)?;
        Ok(self.0.subject_by_identifier(&index, &folded(value)).await?)
    }

    async fn insert_credential(
        &mut self,
        credential: &NewCredential<'_>,
    ) -> Result<[u8; 16], AccountError> {
        Ok(self.0.insert_credential(credential).await?)
    }

    async fn credentials(
        &mut self,
        subject: [u8; 16],
        kind: &str,
    ) -> Result<Vec<CredentialRow>, AccountError> {
        Ok(self.0.credentials(subject, kind).await?)
    }

    async fn reseal(
        &mut self,
        id: [u8; 16],
        algorithm: &str,
        sealed: &SealedSecret,
    ) -> Result<bool, AccountError> {
        Ok(self.0.reseal_credential(id, algorithm, sealed).await?)
    }

    async fn revoke(&mut self, subject: [u8; 16], id: [u8; 16]) -> Result<Revoke, AccountError> {
        Ok(self.0.revoke_credential(subject, id).await?)
    }

    async fn credential_used(&mut self, id: [u8; 16]) -> Result<(), AccountError> {
        Ok(self.0.credential_used(id).await?)
    }

    async fn throttle(
        &mut self,
        key: &[u8; 32],
        day: i32,
        horizon_days: i32,
    ) -> Result<ThrottleRow, AccountError> {
        Ok(self.0.throttle(key, day, horizon_days).await?)
    }

    async fn put_throttle(
        &mut self,
        key: &[u8; 32],
        day: i32,
        row: &ThrottleRow,
    ) -> Result<(), AccountError> {
        Ok(self.0.put_throttle(key, day, row).await?)
    }

    async fn server_time(&mut self) -> Result<u64, AccountError> {
        Ok(self.0.server_time().await?)
    }

    async fn outbox(&mut self, kind: &str, payload: &[u8]) -> Result<(), AccountError> {
        // OP-67 m.1
        let trace = access_telemetry::trace::current_header();
        Ok(self
            .0
            .outbox_traced(kind, payload, trace.as_deref())
            .await?)
    }

    async fn audit(&mut self, event: &AuditEvent<'_>) -> Result<(), AccountError> {
        Ok(self.0.audit(event).await?)
    }

    async fn commit(self) -> Result<(), AccountError> {
        Ok(self.0.commit().await?)
    }
}
