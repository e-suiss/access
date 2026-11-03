//! The passkey registry (CMP-15.7, OP-146 m.9): realm-scoped public material, a random
//! 64-byte `user.id` per subject (§12.3.6 invariant 10), soft delete only (OP-73). Each
//! credential's life cycle is its sibling `identity_credentials` row, so the last-method rule
//! (TN-68) covers passkeys.

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

/// A passkey row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyRow {
    /// WebAuthn credential ID.
    pub raw_id: Vec<u8>,
    /// The sibling `identity_credentials` row.
    pub credential: [u8; 16],
    /// The owner's `user.id`.
    pub user_handle: Vec<u8>,
    /// `COSE_Key` bytes.
    pub public_key: Vec<u8>,
    /// COSE algorithm number.
    pub alg: i32,
    /// Last accepted counter.
    pub sign_count: i64,
    /// BE at registration.
    pub backup_eligible: bool,
    /// Last seen BS.
    pub backup_state: bool,
    /// UV at registration.
    pub user_verified: bool,
    /// AAGUID.
    pub aaguid: Vec<u8>,
    /// Transport hints.
    pub transports: Vec<String>,
    /// `none`, `verified` or `unverified:<fmt>`.
    pub attestation: String,
    /// `credProtect` level.
    pub cred_protect: Option<i16>,
    /// `credProps.rk`.
    pub discoverable: Option<bool>,
    /// `prf.enabled`.
    pub prf_enabled: Option<bool>,
    /// Current PRF salt.
    pub prf_first: Option<Vec<u8>>,
    /// Next PRF salt during a rotation.
    pub prf_second: Option<Vec<u8>>,
    /// Registration, Unix seconds.
    pub created_s: i64,
    /// Last use, Unix seconds.
    pub last_used_s: Option<i64>,
    /// Soft delete, Unix seconds.
    pub deleted_s: Option<i64>,
}

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

struct PasskeyRecord {
    raw_id: Vec<u8>,
    credential_id: Uuid,
    user_handle: Vec<u8>,
    public_key: Vec<u8>,
    alg: i32,
    sign_count: i64,
    backup_eligible: bool,
    backup_state: bool,
    user_verified: bool,
    aaguid: Vec<u8>,
    transports: Vec<String>,
    attestation: String,
    cred_protect: Option<i16>,
    discoverable: Option<bool>,
    prf_enabled: Option<bool>,
    prf_first: Option<Vec<u8>>,
    prf_second: Option<Vec<u8>>,
    created_s: i64,
    last_used_s: Option<i64>,
    deleted_s: Option<i64>,
}

impl PasskeyRecord {
    fn into_row(self) -> PasskeyRow {
        PasskeyRow {
            raw_id: self.raw_id,
            credential: *self.credential_id.as_bytes(),
            user_handle: self.user_handle,
            public_key: self.public_key,
            alg: self.alg,
            sign_count: self.sign_count,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            user_verified: self.user_verified,
            aaguid: self.aaguid,
            transports: self.transports,
            attestation: self.attestation,
            cred_protect: self.cred_protect,
            discoverable: self.discoverable,
            prf_enabled: self.prf_enabled,
            prf_first: self.prf_first,
            prf_second: self.prf_second,
            created_s: self.created_s,
            last_used_s: self.last_used_s,
            deleted_s: self.deleted_s,
        }
    }
}

impl TenantTx {
    fn passkey_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((uuid(*self.tenant.as_bytes()), uuid(*realm.as_bytes())))
    }

    /// Gives the subject its `user.id`; false when it has one.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_user_handle(
        &mut self,
        subject: [u8; 16],
        handle: &[u8; 64],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.passkey_scope()?;
        let n = sqlx::query!(
            "INSERT INTO access.webauthn_users (tenant_id, realm_id, subject_id, user_handle)
             VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, realm_id, subject_id) DO NOTHING",
            tenant,
            realm,
            uuid(subject),
            handle.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The subject's `user.id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn user_handle(&mut self, subject: [u8; 16]) -> Result<Option<[u8; 64]>, StoreError> {
        let (tenant, realm) = self.passkey_scope()?;
        let h = sqlx::query_scalar!(
            "SELECT user_handle FROM access.webauthn_users
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3",
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        h.map(|v| <[u8; 64]>::try_from(v).map_err(|_| StoreError::Corrupt))
            .transpose()
    }

    /// The subject a `user.id` belongs to.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn subject_by_user_handle(
        &mut self,
        handle: &[u8],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.passkey_scope()?;
        let id = sqlx::query_scalar!(
            "SELECT subject_id FROM access.webauthn_users
              WHERE tenant_id = $1 AND realm_id = $2 AND user_handle = $3",
            tenant,
            realm,
            handle,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(id.map(|u| *u.as_bytes()))
    }

    /// Stores a passkey; false when the realm has the credential ID, deleted ones included.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_passkey(&mut self, p: &PasskeyRow) -> Result<bool, StoreError> {
        let (tenant, realm) = self.passkey_scope()?;
        let n = sqlx::query!(
            "INSERT INTO access.webauthn_credentials
               (tenant_id, realm_id, raw_id, credential_id, user_handle, public_key, alg, sign_count,
                backup_eligible, backup_state, user_verified, aaguid, transports, attestation,
                cred_protect, discoverable, prf_enabled, prf_first, prf_second, created_s)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
                     $19, $20)
             ON CONFLICT (tenant_id, realm_id, raw_id) DO NOTHING",
            tenant,
            realm,
            p.raw_id,
            uuid(p.credential),
            p.user_handle,
            p.public_key,
            p.alg,
            p.sign_count,
            p.backup_eligible,
            p.backup_state,
            p.user_verified,
            p.aaguid,
            &p.transports,
            p.attestation,
            p.cred_protect,
            p.discoverable,
            p.prf_enabled,
            p.prf_first,
            p.prf_second,
            p.created_s,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Whether the realm has the credential ID, deleted ones included.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn passkey_exists(&mut self, raw_id: &[u8]) -> Result<bool, StoreError> {
        let (tenant, realm) = self.passkey_scope()?;
        Ok(sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM access.webauthn_credentials
                WHERE tenant_id = $1 AND realm_id = $2 AND raw_id = $3) AS "e!""#,
            tenant,
            realm,
            raw_id,
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// A passkey by credential ID, deleted ones included.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn passkey(&mut self, raw_id: &[u8]) -> Result<Option<PasskeyRow>, StoreError> {
        let (tenant, realm) = self.passkey_scope()?;
        Ok(sqlx::query_as!(
            PasskeyRecord,
            "SELECT raw_id, credential_id, user_handle, public_key, alg, sign_count, backup_eligible,
                    backup_state, user_verified, aaguid, transports, attestation, cred_protect,
                    discoverable, prf_enabled, prf_first, prf_second, created_s, last_used_s, deleted_s
               FROM access.webauthn_credentials
              WHERE tenant_id = $1 AND realm_id = $2 AND raw_id = $3",
            tenant,
            realm,
            raw_id,
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .map(PasskeyRecord::into_row))
    }

    /// The live passkeys of a `user.id`, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn passkeys(&mut self, handle: &[u8]) -> Result<Vec<PasskeyRow>, StoreError> {
        let (tenant, realm) = self.passkey_scope()?;
        Ok(sqlx::query_as!(
            PasskeyRecord,
            "SELECT raw_id, credential_id, user_handle, public_key, alg, sign_count, backup_eligible,
                    backup_state, user_verified, aaguid, transports, attestation, cred_protect,
                    discoverable, prf_enabled, prf_first, prf_second, created_s, last_used_s, deleted_s
               FROM access.webauthn_credentials
              WHERE tenant_id = $1 AND realm_id = $2 AND user_handle = $3 AND deleted_s IS NULL
              ORDER BY created_s, raw_id",
            tenant,
            realm,
            handle,
        )
        .fetch_all(&mut *self.tx)
        .await?
        .into_iter()
        .map(PasskeyRecord::into_row)
        .collect())
    }

    /// Records a successful assertion: counter, BS and time.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn passkey_used(
        &mut self,
        raw_id: &[u8],
        sign_count: i64,
        backup_state: bool,
        at_s: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.passkey_scope()?;
        let n = sqlx::query!(
            "UPDATE access.webauthn_credentials
                SET sign_count = $4, backup_state = $5, last_used_s = $6
              WHERE tenant_id = $1 AND realm_id = $2 AND raw_id = $3 AND deleted_s IS NULL",
            tenant,
            realm,
            raw_id,
            sign_count,
            backup_state,
            at_s,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Marks a passkey deleted (OP-73); its sibling credential is revoked separately, under
    /// the last-method rule.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn passkey_deleted(&mut self, raw_id: &[u8], at_s: i64) -> Result<bool, StoreError> {
        let (tenant, realm) = self.passkey_scope()?;
        let n = sqlx::query!(
            "UPDATE access.webauthn_credentials SET deleted_s = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND raw_id = $3 AND deleted_s IS NULL",
            tenant,
            realm,
            raw_id,
            at_s,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }
}
