//! The token vault (OP-154 m.3 (t), MD-13, E36, EI-26, AG-32, AG-39, §11.13): Resources and the
//! release mode as realm configuration bound to a committed `idp.vault.*` ALLOW, a person's
//! connections, their sealed `TokenSets` and the release records. None of it is authority
//! (AGI-2); nothing is deleted (OP-73): a `TokenSet` is superseded and shredded, a connection is
//! disconnected.

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

fn u64_of(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn key32(v: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn key16(v: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// One version of a Resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRow {
    /// The realm's name for it.
    pub name: String,
    /// Its version; the newest is the Resource.
    pub version: u64,
    /// The upstream's catalog id, or the realm's own upstream's name.
    pub upstream: String,
    /// `catalog` or `realm`.
    pub origin: String,
    /// The dCBOR definition; `None` once disabled.
    pub definition: Option<Vec<u8>>,
    /// Position of the decision that wrote it.
    pub position: u64,
}

/// A Resource version to write.
#[derive(Clone, Copy, Debug)]
pub struct NewResource<'a> {
    /// The realm's name for it.
    pub name: &'a str,
    /// The upstream.
    pub upstream: &'a str,
    /// `catalog` or `realm`.
    pub origin: &'a str,
    /// The dCBOR definition; `None` disables it.
    pub definition: Option<&'a [u8]>,
}

/// A connected account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionRow {
    /// Its id.
    pub id: [u8; 16],
    /// The person's subject.
    pub subject: [u8; 16],
    /// The person's Party.
    pub party: [u8; 16],
    /// The Resource it connects to.
    pub resource: String,
    /// The Resource version it was connected under.
    pub resource_version: u64,
    /// The agent client the person consented for.
    pub client_id: String,
    /// The upstream scopes it holds.
    pub scopes: Vec<String>,
    /// `pending`, `active`, `needs_reconnect` or `disconnected`.
    pub status: String,
    /// Unix milliseconds.
    pub created_ms: u64,
    /// When the status last changed, Unix milliseconds.
    pub status_ms: u64,
}

/// A connection to open.
#[derive(Clone, Copy, Debug)]
pub struct NewConnection<'a> {
    /// The person's subject.
    pub subject: [u8; 16],
    /// The person's Party.
    pub party: [u8; 16],
    /// The Resource.
    pub resource: &'a str,
    /// Its version.
    pub resource_version: u64,
    /// The agent client.
    pub client_id: &'a str,
    /// The upstream scopes asked for.
    pub scopes: &'a [String],
    /// Unix milliseconds.
    pub now_ms: u64,
}

/// A sealed `TokenSet`.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenSetRow {
    /// The connection.
    pub connection: [u8; 16],
    /// Its version.
    pub version: u64,
    /// The id of the key that wraps its DEK.
    pub kek_id: String,
    /// Wrapped DEK, nonce and ciphertext; `None` once shredded.
    pub sealed: Option<(Vec<u8>, [u8; 12], Vec<u8>)>,
    /// When its access token expires, Unix milliseconds, when known.
    pub access_expires_ms: Option<u64>,
    /// Whether it holds a refresh token.
    pub refreshable: bool,
    /// Unix milliseconds.
    pub created_ms: u64,
}

impl core::fmt::Debug for TokenSetRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TokenSetRow")
            .field("connection", &self.connection)
            .field("version", &self.version)
            .field("sealed", &self.sealed.as_ref().map(|_| "[sealed]"))
            .field("access_expires_ms", &self.access_expires_ms)
            .field("refreshable", &self.refreshable)
            .finish_non_exhaustive()
    }
}

/// A `TokenSet` to seal in.
#[derive(Clone, Copy)]
pub struct NewTokenSet<'a> {
    /// The id of the key that wraps its DEK.
    pub kek_id: &'a str,
    /// The wrapped DEK.
    pub wrapped_dek: &'a [u8],
    /// The nonce.
    pub nonce: &'a [u8; 12],
    /// The ciphertext.
    pub ciphertext: &'a [u8],
    /// When its access token expires, when known.
    pub access_expires_ms: Option<u64>,
    /// Whether it holds a refresh token.
    pub refreshable: bool,
    /// Unix milliseconds.
    pub now_ms: u64,
}

/// A release record (G59, EI-26).
#[derive(Clone, Copy, Debug)]
pub struct NewRelease<'a> {
    /// The domain whose Exercise it is.
    pub domain: &'a [u8; 32],
    /// The allowed Exercise.
    pub exercise: &'a [u8; 32],
    /// Position of its decision record.
    pub position: u64,
    /// The intent digest it was allowed for.
    pub intent: &'a [u8; 32],
    /// The actor Instance's Party, when the authority plane named it.
    pub actor: Option<[u8; 16]>,
    /// The connection.
    pub connection: [u8; 16],
    /// The `TokenSet` version released.
    pub token_set_version: u64,
    /// The PEP the token went to.
    pub pep: &'a str,
    /// `executor` or `agent`.
    pub path: &'a str,
    /// The Exercise's consequence tier, 0 to 3.
    pub tier: u8,
    /// Unix milliseconds the token may be used until.
    pub use_until_ms: u64,
    /// Unix milliseconds.
    pub now_ms: u64,
}

/// A release record as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseRow {
    /// The allowed Exercise.
    pub exercise: [u8; 32],
    /// The actor Instance's Party, when known.
    pub actor: Option<[u8; 16]>,
    /// The PEP the token went to.
    pub pep: String,
    /// `executor` or `agent`.
    pub path: String,
    /// The consequence tier.
    pub tier: u8,
    /// Unix milliseconds.
    pub released_ms: u64,
}

fn connection_row(
    id: &Uuid,
    subject: &Uuid,
    party: &[u8],
    (resource, version, client_id): (String, i64, String),
    scopes: Vec<String>,
    (status, created, at): (String, i64, i64),
) -> Result<ConnectionRow, StoreError> {
    Ok(ConnectionRow {
        id: *id.as_bytes(),
        subject: *subject.as_bytes(),
        party: key16(party)?,
        resource,
        resource_version: u64_of(version)?,
        client_id,
        scopes,
        status,
        created_ms: u64_of(created)?,
        status_ms: u64_of(at)?,
    })
}

impl TenantTx {
    /// The newest version of the Resource `name`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_resource(&mut self, name: &str) -> Result<Option<ResourceRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT name, version, upstream, origin, definition, decision_pos
               FROM access.vault_resources
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3
              ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
            name,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| {
            Ok(ResourceRow {
                name: r.name,
                version: u64_of(r.version)?,
                upstream: r.upstream,
                origin: r.origin,
                definition: r.definition,
                position: u64_of(r.decision_pos)?,
            })
        })
        .transpose()
    }

    /// The Resource `name` at `version`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_resource_at(
        &mut self,
        name: &str,
        version: u64,
    ) -> Result<Option<ResourceRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT name, version, upstream, origin, definition, decision_pos
               FROM access.vault_resources
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3 AND version = $4",
            tenant,
            realm,
            name,
            i64_of(version)?,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| {
            Ok(ResourceRow {
                name: r.name,
                version: u64_of(r.version)?,
                upstream: r.upstream,
                origin: r.origin,
                definition: r.definition,
                position: u64_of(r.decision_pos)?,
            })
        })
        .transpose()
    }

    /// The newest version of every Resource, by name.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_resources(&mut self) -> Result<Vec<ResourceRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (name) name, version, upstream, origin, definition, decision_pos
               FROM access.vault_resources
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY name, version DESC",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(ResourceRow {
                    name: r.name,
                    version: u64_of(r.version)?,
                    upstream: r.upstream,
                    origin: r.origin,
                    definition: r.definition,
                    position: u64_of(r.decision_pos)?,
                })
            })
            .collect()
    }

    /// Writes the next version of a Resource under `bound` (`idp.vault.resource_enable`,
    /// `resource_register`, `resource_disable`); returns its version.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_vault_resource(
        &mut self,
        bound: &Bound,
        r: &NewResource<'_>,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let state = if r.definition.is_some() {
            "enabled"
        } else {
            "disabled"
        };
        let v = sqlx::query_scalar!(
            r#"INSERT INTO access.vault_resources
                 (tenant_id, realm_id, name, version, upstream, origin, state, definition,
                  domain_id, decision_pos)
               SELECT $1, $2, $3,
                      COALESCE((SELECT max(version) FROM access.vault_resources
                                 WHERE tenant_id = $1 AND realm_id = $2 AND name = $3), 0) + 1,
                      $4, $5, $6, $7, $8, $9
               RETURNING version"#,
            tenant,
            realm,
            r.name,
            r.upstream,
            r.origin,
            state,
            r.definition,
            bound.domain.as_bytes().as_slice(),
            bound.position,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        u64_of(v)
    }

    /// Whether path (b) is open in the realm (OP-154 m.3 (t)); closed when never set.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_release_open(&mut self) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let mode = sqlx::query_scalar!(
            "SELECT mode FROM access.vault_release_modes
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(mode.as_deref() == Some("open"))
    }

    /// Writes the realm's release mode under `bound` (`idp.vault.release_mode_open`,
    /// `release_mode_close`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_vault_release_mode(
        &mut self,
        bound: &Bound,
        open: bool,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let mode = if open { "open" } else { "closed" };
        sqlx::query!(
            "INSERT INTO access.vault_release_modes
               (tenant_id, realm_id, version, mode, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.vault_release_modes
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5",
            tenant,
            realm,
            mode,
            bound.domain.as_bytes().as_slice(),
            bound.position,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Opens a pending connection; returns its id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_vault_connection(
        &mut self,
        c: &NewConnection<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = scope(self)?;
        let now = i64_of(c.now_ms)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.vault_connections
               (tenant_id, realm_id, subject_id, party, resource, resource_version, client_id,
                scopes, created_ms, status_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
             RETURNING connection_id",
            tenant,
            realm,
            Uuid::from_bytes(c.subject),
            c.party.as_slice(),
            c.resource,
            i64_of(c.resource_version)?,
            c.client_id,
            c.scopes,
            now,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The connection `id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_connection(
        &mut self,
        id: [u8; 16],
    ) -> Result<Option<ConnectionRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT connection_id, subject_id, party, resource, resource_version, client_id, scopes,
                    status, created_ms, status_ms
               FROM access.vault_connections
              WHERE tenant_id = $1 AND realm_id = $2 AND connection_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| {
            connection_row(
                &r.connection_id,
                &r.subject_id,
                &r.party,
                (r.resource, r.resource_version, r.client_id),
                r.scopes,
                (r.status, r.created_ms, r.status_ms),
            )
        })
        .transpose()
    }

    /// The person's connections that are not disconnected, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_connections_of(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<ConnectionRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT connection_id, subject_id, party, resource, resource_version, client_id, scopes,
                    status, created_ms, status_ms
               FROM access.vault_connections
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status <> 'disconnected'
              ORDER BY created_ms, connection_id",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                connection_row(
                    &r.connection_id,
                    &r.subject_id,
                    &r.party,
                    (r.resource, r.resource_version, r.client_id),
                    r.scopes,
                    (r.status, r.created_ms, r.status_ms),
                )
            })
            .collect()
    }

    /// The connections of the realm whose client is `client_id` and that are not disconnected.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_connections_for_client(
        &mut self,
        client_id: &str,
    ) -> Result<Vec<ConnectionRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT connection_id, subject_id, party, resource, resource_version, client_id, scopes,
                    status, created_ms, status_ms
               FROM access.vault_connections
              WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND status <> 'disconnected'
              ORDER BY created_ms, connection_id",
            tenant,
            realm,
            client_id,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                connection_row(
                    &r.connection_id,
                    &r.subject_id,
                    &r.party,
                    (r.resource, r.resource_version, r.client_id),
                    r.scopes,
                    (r.status, r.created_ms, r.status_ms),
                )
            })
            .collect()
    }

    /// Moves the connection `id` to `status` (and `scopes`, when given) unless it is
    /// disconnected; `false` when nothing moved.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn set_vault_connection(
        &mut self,
        id: [u8; 16],
        status: &str,
        scopes: Option<&[String]>,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "UPDATE access.vault_connections
                SET status = $4, scopes = COALESCE($5, scopes), status_ms = greatest(status_ms, $6),
                    refresh_lease_ms = NULL
              WHERE tenant_id = $1 AND realm_id = $2 AND connection_id = $3
                AND status <> 'disconnected'",
            tenant,
            realm,
            Uuid::from_bytes(id),
            status,
            scopes,
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(done == 1)
    }

    /// Takes the refresh lease of the connection `id` until `until_ms` (OP-154 m.3 (t)): `false`
    /// while another holder's lease runs, or for a connection that is not active.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn lease_vault_refresh(
        &mut self,
        id: [u8; 16],
        now_ms: u64,
        until_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "UPDATE access.vault_connections SET refresh_lease_ms = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND connection_id = $3 AND status = 'active'
                AND (refresh_lease_ms IS NULL OR refresh_lease_ms <= $4)",
            tenant,
            realm,
            Uuid::from_bytes(id),
            i64_of(now_ms)?,
            i64_of(until_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(done == 1)
    }

    /// Opens the upstream redirect attempt of a connection.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_vault_attempt(
        &mut self,
        (state_hash, device_hash): (&[u8; 32], &[u8; 32]),
        connection: [u8; 16],
        verifier: &str,
        (now_ms, expires_ms): (u64, u64),
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.vault_connect_attempts
               (tenant_id, realm_id, state_hash, device_hash, connection_id, verifier, created_ms,
                expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            tenant,
            realm,
            state_hash.as_slice(),
            device_hash.as_slice(),
            Uuid::from_bytes(connection),
            verifier,
            i64_of(now_ms)?,
            i64_of(expires_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Uses the open, unexpired attempt of `state_hash` the same browser opened; returns its
    /// connection and PKCE verifier. An attempt is used once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn take_vault_attempt(
        &mut self,
        state_hash: &[u8; 32],
        device_hash: &[u8; 32],
        now_ms: u64,
    ) -> Result<Option<([u8; 16], String)>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "UPDATE access.vault_connect_attempts SET status = 'used', used_ms = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND state_hash = $3 AND device_hash = $4
                AND status = 'open' AND expires_ms > $5
             RETURNING connection_id, verifier",
            tenant,
            realm,
            state_hash.as_slice(),
            device_hash.as_slice(),
            i64_of(now_ms)?,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(r.map(|r| (*r.connection_id.as_bytes(), r.verifier)))
    }

    /// Seals in the connection's next `TokenSet`; the live one is superseded and shredded in the
    /// same transaction (OP-73). Returns the new version.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_vault_token_set(
        &mut self,
        connection: [u8; 16],
        s: &NewTokenSet<'_>,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let now = i64_of(s.now_ms)?;
        sqlx::query!(
            "UPDATE access.vault_token_sets
                SET superseded_ms = $4, shredded_ms = $4, wrapped_dek = NULL, nonce = NULL,
                    ciphertext = NULL
              WHERE tenant_id = $1 AND realm_id = $2 AND connection_id = $3
                AND superseded_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(connection),
            now,
        )
        .execute(&mut *self.tx)
        .await?;
        let v = sqlx::query_scalar!(
            r#"INSERT INTO access.vault_token_sets
                 (tenant_id, realm_id, connection_id, version, kek_id, wrapped_dek, nonce,
                  ciphertext, access_expires_ms, refreshable, created_ms)
               SELECT $1, $2, $3,
                      COALESCE((SELECT max(version) FROM access.vault_token_sets
                                 WHERE tenant_id = $1 AND realm_id = $2 AND connection_id = $3), 0) + 1,
                      $4, $5, $6, $7, $8, $9, $10
               RETURNING version"#,
            tenant,
            realm,
            Uuid::from_bytes(connection),
            s.kek_id,
            s.wrapped_dek,
            s.nonce.as_slice(),
            s.ciphertext,
            s.access_expires_ms.map(i64_of).transpose()?,
            s.refreshable,
            now,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        u64_of(v)
    }

    /// The connection's live `TokenSet`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_token_set(
        &mut self,
        connection: [u8; 16],
    ) -> Result<Option<TokenSetRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT version, kek_id, wrapped_dek, nonce, ciphertext, access_expires_ms, refreshable,
                    created_ms
               FROM access.vault_token_sets
              WHERE tenant_id = $1 AND realm_id = $2 AND connection_id = $3
                AND superseded_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(connection),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| {
            let sealed = match (r.wrapped_dek, r.nonce, r.ciphertext) {
                (Some(w), Some(n), Some(c)) => Some((
                    w,
                    <[u8; 12]>::try_from(n).map_err(|_| StoreError::Corrupt)?,
                    c,
                )),
                (None, None, None) => None,
                _ => return Err(StoreError::Corrupt),
            };
            Ok(TokenSetRow {
                connection,
                version: u64_of(r.version)?,
                kek_id: r.kek_id,
                sealed,
                access_expires_ms: r.access_expires_ms.map(u64_of).transpose()?,
                refreshable: r.refreshable,
                created_ms: u64_of(r.created_ms)?,
            })
        })
        .transpose()
    }

    /// Supersedes and shreds every `TokenSet` of the connection (OP-73 crypto-shredding);
    /// returns how many were shredded.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn shred_vault_token_sets(
        &mut self,
        connection: [u8; 16],
        now_ms: u64,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "UPDATE access.vault_token_sets
                SET superseded_ms = COALESCE(superseded_ms, $4), shredded_ms = $4,
                    wrapped_dek = NULL, nonce = NULL, ciphertext = NULL
              WHERE tenant_id = $1 AND realm_id = $2 AND connection_id = $3
                AND shredded_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(connection),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(done)
    }

    /// Active connections whose live, refreshable `TokenSet` expires before `before_ms`, oldest
    /// expiry first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_refresh_due(
        &mut self,
        before_ms: u64,
        limit: u32,
    ) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query_scalar!(
            "SELECT s.connection_id
               FROM access.vault_token_sets s
               JOIN access.vault_connections c
                 ON c.tenant_id = s.tenant_id AND c.realm_id = s.realm_id
                AND c.connection_id = s.connection_id
              WHERE s.tenant_id = $1 AND s.realm_id = $2 AND s.superseded_ms IS NULL
                AND s.refreshable AND s.access_expires_ms < $3 AND c.status = 'active'
              ORDER BY s.access_expires_ms LIMIT $4",
            tenant,
            realm,
            i64_of(before_ms)?,
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows.into_iter().map(|u| *u.as_bytes()).collect())
    }

    /// Records a release (G59, EI-26); `false` when the Exercise was released already (one
    /// release per Exercise).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_vault_release(&mut self, r: &NewRelease<'_>) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "INSERT INTO access.vault_releases
               (tenant_id, realm_id, domain_id, exercise, decision_pos, intent_digest, actor,
                connection_id, token_set_version, pep, path, tier, use_until_ms, released_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $14, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT (tenant_id, realm_id, domain_id, exercise) DO NOTHING",
            tenant,
            realm,
            r.domain.as_slice(),
            r.exercise.as_slice(),
            i64_of(r.position)?,
            r.intent.as_slice(),
            Uuid::from_bytes(r.connection),
            i64_of(r.token_set_version)?,
            r.pep,
            r.path,
            i16::from(r.tier),
            i64_of(r.use_until_ms)?,
            i64_of(r.now_ms)?,
            r.actor.as_ref().map(<[u8; 16]>::as_slice),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(done == 1)
    }

    /// The connection's newest releases, newest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_releases_of(
        &mut self,
        connection: [u8; 16],
        limit: u32,
    ) -> Result<Vec<ReleaseRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT exercise, actor, pep, path, tier, released_ms FROM access.vault_releases
              WHERE tenant_id = $1 AND realm_id = $2 AND connection_id = $3
              ORDER BY released_ms DESC, release_id DESC LIMIT $4",
            tenant,
            realm,
            Uuid::from_bytes(connection),
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(ReleaseRow {
                    exercise: key32(&r.exercise)?,
                    actor: r.actor.as_deref().map(key16).transpose()?,
                    pep: r.pep,
                    path: r.path,
                    tier: u8::try_from(r.tier).map_err(|_| StoreError::Corrupt)?,
                    released_ms: u64_of(r.released_ms)?,
                })
            })
            .collect()
    }

    /// The connections a token was ever released for to `actor`'s Exercises, oldest release
    /// first (the agent registry's connected accounts, AG-21).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_connections_released_to(
        &mut self,
        actor: [u8; 16],
    ) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query_scalar!(
            r#"SELECT connection_id AS "connection_id!" FROM access.vault_releases
                WHERE tenant_id = $1 AND realm_id = $2 AND actor = $3
                GROUP BY connection_id ORDER BY min(released_ms), connection_id"#,
            tenant,
            realm,
            actor.as_slice(),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows.into_iter().map(|u| *u.as_bytes()).collect())
    }

    /// The Grant of the person's live consent record for the client `client_id` (registered or
    /// CIMD), newest first: the AAS the person gave that client (AS-M15, OP-154 m.8 (d)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn vault_client_consent(
        &mut self,
        subject: [u8; 16],
        client_id: &str,
    ) -> Result<Option<([u8; 32], [u8; 16])>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT r.grant_domain, r.grant_ref FROM access.oauth_consent_records r
              WHERE r.tenant_id = $1 AND r.realm_id = $2 AND r.subject_id = $3
                AND r.ended_ms IS NULL
                AND r.client_uuid IN (
                      SELECT c.client_uuid FROM access.idp_clients c
                       WHERE c.tenant_id = $1 AND c.realm_id = $2 AND c.client_id = $4
                      UNION ALL
                      SELECT m.client_uuid FROM access.oauth_cimd_clients m
                       WHERE m.tenant_id = $1 AND m.realm_id = $2 AND m.client_id = $4
                         AND m.retired_ms IS NULL)
              ORDER BY r.created_ms DESC LIMIT 1",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            client_id,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| Ok((key32(&r.grant_domain)?, key16(&r.grant_ref)?)))
            .transpose()
    }
}
