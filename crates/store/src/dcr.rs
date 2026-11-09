//! The dynamic client registration profile (OP-154 m.3 (j), §11.4.5 #31-35): the realm's decided
//! policy versions and the clients registered under them. Scoped to the transaction's realm by
//! row-level security; a client retires once and is never removed (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn u64_of(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// The realm's DCR policy as decided.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DcrPolicyRow {
    /// Whether `/register` is open.
    pub enabled: bool,
    /// The hosts redirect URIs may name; empty is any host.
    pub domains: Vec<String>,
    /// SHA-256 digests of the initial access tokens that open `/register`.
    pub tokens: Vec<[u8; 32]>,
}

/// A live DCR client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcrClientRow {
    /// Its internal id.
    pub client_uuid: [u8; 16],
    /// Its `client_id`.
    pub client_id: String,
    /// The metadata as registered.
    pub metadata: Vec<u8>,
    /// The issuer it was registered at.
    pub issuer: String,
    /// The initial access token digest it was registered with.
    pub token: [u8; 32],
    /// When it was registered.
    pub registered_ms: u64,
    /// When it was last used.
    pub last_used_ms: u64,
}

/// A registration to keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDcrClient<'a> {
    /// Its `client_id`.
    pub client_id: &'a str,
    /// The accepted metadata.
    pub metadata: &'a [u8],
    /// The issuer stamped on it.
    pub issuer: &'a str,
    /// The initial access token digest.
    pub token: [u8; 32],
    /// The IP prefix it came from.
    pub ip_prefix: &'a str,
    /// Now.
    pub now_ms: u64,
}

impl TenantTx {
    /// The newest decided DCR policy; the default (off) when none was ever decided.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn dcr_policy(&mut self) -> Result<DcrPolicyRow, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT enabled, domains, tokens FROM access.idp_dcr_policies
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        let Some(r) = row else {
            return Ok(DcrPolicyRow::default());
        };
        let tokens = r
            .tokens
            .iter()
            .map(|t| <[u8; 32]>::try_from(t.as_slice()).map_err(|_| StoreError::Corrupt))
            .collect::<Result<_, _>>()?;
        Ok(DcrPolicyRow {
            enabled: r.enabled,
            domains: r.domains,
            tokens,
        })
    }

    /// Writes the next DCR policy version under `bound` (`idp.client.dcr_policy`,
    /// `dcr_policy_tighten`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_dcr_policy(
        &mut self,
        bound: &Bound,
        p: &DcrPolicyRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let tokens: Vec<Vec<u8>> = p.tokens.iter().map(|t| t.to_vec()).collect();
        sqlx::query!(
            "INSERT INTO access.idp_dcr_policies
               (tenant_id, realm_id, version, enabled, domains, tokens, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_dcr_policies
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5, $6, $7",
            tenant,
            realm,
            p.enabled,
            &p.domains,
            &tokens,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Keeps a registration; its internal id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_dcr_client(
        &mut self,
        c: &NewDcrClient<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = scope(self)?;
        let now = i64_of(c.now_ms)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.oauth_dcr_clients (tenant_id, realm_id, client_id, metadata, issuer,
                    token, ip_prefix, registered_ms, last_used_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
             RETURNING client_uuid",
            tenant,
            realm,
            c.client_id,
            c.metadata,
            c.issuer,
            c.token.as_slice(),
            c.ip_prefix,
            now,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The live DCR client `client_id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn dcr_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<DcrClientRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT client_uuid, client_id, metadata, issuer, token, registered_ms, last_used_ms
               FROM access.oauth_dcr_clients
              WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            client_id,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(DcrClientRow {
                client_uuid: *r.client_uuid.as_bytes(),
                client_id: r.client_id,
                metadata: r.metadata,
                issuer: r.issuer,
                token: <[u8; 32]>::try_from(r.token.as_slice()).map_err(|_| StoreError::Corrupt)?,
                registered_ms: u64_of(r.registered_ms),
                last_used_ms: u64_of(r.last_used_ms),
            })
        })
        .transpose()
    }

    /// The live DCR client with internal id `client`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn dcr_client_by_uuid(
        &mut self,
        client: [u8; 16],
    ) -> Result<Option<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT client_id FROM access.oauth_dcr_clients
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(client),
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// Every live DCR client of the realm, for retroactive invalidation.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn dcr_clients(&mut self) -> Result<Vec<DcrClientRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT client_uuid, client_id, metadata, issuer, token, registered_ms, last_used_ms
               FROM access.oauth_dcr_clients
              WHERE tenant_id = $1 AND realm_id = $2 AND retired_ms IS NULL
              ORDER BY client_uuid",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(DcrClientRow {
                    client_uuid: *r.client_uuid.as_bytes(),
                    client_id: r.client_id,
                    metadata: r.metadata,
                    issuer: r.issuer,
                    token: <[u8; 32]>::try_from(r.token.as_slice())
                        .map_err(|_| StoreError::Corrupt)?,
                    registered_ms: u64_of(r.registered_ms),
                    last_used_ms: u64_of(r.last_used_ms),
                })
            })
            .collect()
    }

    /// How many registrations came from `ip_prefix` since `since_ms`, how many the realm took
    /// since `day_ms`, and how many of its DCR clients are live.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn dcr_counts(
        &mut self,
        ip_prefix: &str,
        since_ms: u64,
        day_ms: u64,
    ) -> Result<(u64, u64, u64), StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            r#"SELECT
                 count(*) FILTER (WHERE ip_prefix = $3 AND registered_ms >= $4) AS "ip!",
                 count(*) FILTER (WHERE registered_ms >= $5) AS "day!",
                 count(*) FILTER (WHERE retired_ms IS NULL) AS "live!"
               FROM access.oauth_dcr_clients WHERE tenant_id = $1 AND realm_id = $2"#,
            tenant,
            realm,
            ip_prefix,
            i64_of(since_ms)?,
            i64_of(day_ms)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok((u64_of(r.ip), u64_of(r.day), u64_of(r.live)))
    }

    /// Notes that DCR client `client` was used now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn touch_dcr_client(
        &mut self,
        client: [u8; 16],
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.oauth_dcr_clients SET last_used_ms = GREATEST(last_used_ms, $4)
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(client),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Retires DCR client `client` for `reason` (`unused`, `policy`): its consent records end as
    /// `client_retired` and its identity grants are revoked, so introspection answers
    /// `active: false` (§11.4.5 #35). Returns whether it was live.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn retire_dcr_client(
        &mut self,
        client: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let now = i64_of(now_ms)?;
        let n = sqlx::query!(
            "UPDATE access.oauth_dcr_clients
                SET retired_ms = GREATEST($4, registered_ms), retire_reason = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(client),
            now,
            reason,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if n != 1 {
            return Ok(false);
        }
        self.end_client_consents(client, "client_retired", now_ms)
            .await?;
        sqlx::query!(
            "UPDATE access.oauth_grants SET revoked_ms = $4, revoke_reason = 'revoked'
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND revoked_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(client),
            now,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(true)
    }
}
