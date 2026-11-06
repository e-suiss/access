//! Platform product pairing (OP-149 m.4, m.16 (a), L0-META-7): the challenges Access hands a
//! platform client for one realm, the Instance each one opened, and the client's one Party per
//! realm (the identity plane's actor binding). Realm-scoped; nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

/// One pairing challenge of a platform client in a realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingRow {
    /// The challenge: the `instance_create` nonce.
    pub challenge: [u8; 32],
    /// The platform client.
    pub client_id: String,
    /// RFC 7638 `kid` of the service key the Exercises are signed with.
    pub kid: [u8; 32],
    /// The Party the Exercises name.
    pub party: [u8; 16],
    /// Whether the Party is new, so `party_register` comes first.
    pub register: bool,
    /// The signed intents' validity, Unix ms.
    pub valid_from_ms: u64,
    /// End of it, Unix ms.
    pub valid_until_ms: u64,
    /// The Instance the pairing opened, once it did.
    pub instance: Option<[u8; 16]>,
}

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn ms(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

struct Raw {
    challenge: Vec<u8>,
    client_id: String,
    kid: Vec<u8>,
    party_id: Vec<u8>,
    register: bool,
    valid_from_ms: i64,
    valid_until_ms: i64,
    instance_id: Option<Vec<u8>>,
}

impl Raw {
    fn row(self) -> Result<PairingRow, StoreError> {
        let fixed = |v: Vec<u8>| v.try_into().map_err(|_| StoreError::Corrupt);
        let unsigned = |v: i64| u64::try_from(v).map_err(|_| StoreError::Corrupt);
        Ok(PairingRow {
            challenge: <[u8; 32]>::try_from(self.challenge).map_err(|_| StoreError::Corrupt)?,
            client_id: self.client_id,
            kid: <[u8; 32]>::try_from(self.kid).map_err(|_| StoreError::Corrupt)?,
            party: fixed(self.party_id)?,
            register: self.register,
            valid_from_ms: unsigned(self.valid_from_ms)?,
            valid_until_ms: unsigned(self.valid_until_ms)?,
            instance: self.instance_id.map(fixed).transpose()?,
        })
    }
}

impl TenantTx {
    /// Stores a new pairing challenge in this realm.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_pairing(&mut self, p: &PairingRow) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.platform_pairing (tenant_id, realm_id, challenge, client_id, kid,
                    party_id, register, valid_from_ms, valid_until_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            tenant,
            realm,
            p.challenge.as_slice(),
            p.client_id,
            p.kid.as_slice(),
            p.party.as_slice(),
            p.register,
            ms(p.valid_from_ms)?,
            ms(p.valid_until_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The pairing whose challenge is `challenge`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn pairing(
        &mut self,
        challenge: &[u8; 32],
    ) -> Result<Option<PairingRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let raw = sqlx::query_as!(
            Raw,
            "SELECT challenge, client_id, kid, party_id, register, valid_from_ms, valid_until_ms,
                    instance_id
               FROM access.platform_pairing
              WHERE tenant_id = $1 AND realm_id = $2 AND challenge = $3",
            tenant,
            realm,
            challenge.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        raw.map(Raw::row).transpose()
    }

    /// The pairing of `client_id` with the service key `kid` that opened an Instance, else its
    /// newest challenge still valid at `now_ms`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn current_pairing(
        &mut self,
        client_id: &str,
        kid: &[u8; 32],
        now_ms: u64,
    ) -> Result<Option<PairingRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let raw = sqlx::query_as!(
            Raw,
            "SELECT challenge, client_id, kid, party_id, register, valid_from_ms, valid_until_ms,
                    instance_id
               FROM access.platform_pairing
              WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND kid = $4
                AND (instance_id IS NOT NULL OR valid_until_ms >= $5)
              ORDER BY instance_id IS NULL, valid_until_ms DESC
              LIMIT 1",
            tenant,
            realm,
            client_id,
            kid.as_slice(),
            ms(now_ms)?,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        raw.map(Raw::row).transpose()
    }

    /// Records the Instance a pairing opened; `false` when it was recorded before.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_pairing(
        &mut self,
        challenge: &[u8; 32],
        instance: &[u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "UPDATE access.platform_pairing SET instance_id = $4, paired_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND challenge = $3 AND instance_id IS NULL",
            tenant,
            realm,
            challenge.as_slice(),
            instance.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(done == 1)
    }

    /// The Party the platform client `client_id` holds in this realm (OP-149 m.16 (a)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn platform_party(
        &mut self,
        client_id: &str,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let party = sqlx::query_scalar!(
            "SELECT party_id FROM access.platform_party
              WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3",
            tenant,
            realm,
            client_id,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        party
            .map(|p| <[u8; 16]>::try_from(p).map_err(|_| StoreError::Corrupt))
            .transpose()
    }

    /// Binds the platform client's Party in this realm once its `party_register` committed;
    /// `false` when a Party was bound before.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn bind_platform_party(
        &mut self,
        client_id: &str,
        party: &[u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "INSERT INTO access.platform_party (tenant_id, realm_id, client_id, party_id)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            client_id,
            party.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(done == 1)
    }

    /// The pairwise `sub` the client `sector` reads of the platform Party `party` in this realm
    /// (OP-149 m.31 (a), MD-10): the stored one, else `candidate`, stored now; `None` when
    /// `party` is not a platform client's Party here.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn platform_party_pairwise(
        &mut self,
        party: &[u8; 16],
        sector: [u8; 16],
        candidate: &str,
    ) -> Result<Option<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.platform_party_subjects (tenant_id, realm_id, party_id, sector, value)
             SELECT $1, $2, $3, $4, $5
              WHERE EXISTS (SELECT 1 FROM access.platform_party
                             WHERE tenant_id = $1 AND realm_id = $2 AND party_id = $3)
             ON CONFLICT (tenant_id, realm_id, party_id, sector) DO NOTHING",
            tenant,
            realm,
            party.as_slice(),
            Uuid::from_bytes(sector),
            candidate,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(sqlx::query_scalar!(
            "SELECT value FROM access.platform_party_subjects
              WHERE tenant_id = $1 AND realm_id = $2 AND party_id = $3 AND sector = $4",
            tenant,
            realm,
            party.as_slice(),
            Uuid::from_bytes(sector),
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// The platform Party whose pairwise `sub` for `sector` is `value` (OP-149 m.31 (a), A11).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn platform_party_by_pairwise(
        &mut self,
        sector: [u8; 16],
        value: &str,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let party = sqlx::query_scalar!(
            "SELECT party_id FROM access.platform_party_subjects
              WHERE tenant_id = $1 AND realm_id = $2 AND sector = $3 AND value = $4",
            tenant,
            realm,
            Uuid::from_bytes(sector),
            value,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        party
            .map(|p| <[u8; 16]>::try_from(p).map_err(|_| StoreError::Corrupt))
            .transpose()
    }
}
