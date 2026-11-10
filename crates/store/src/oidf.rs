//! OpenID Federation (OP-155 m.3 (j), IDP-19, IDP-20, IDI-12): the realm's federation settings
//! and trust anchors as decided, the clients resolved through a trust chain, the replay keys of
//! automatic registration, and the chain state of each chain-constrained issuer per domain.
//! Realm rows are scoped by row-level security to the transaction's realm, issuer rows to the
//! transaction's domain; nothing is deleted (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;
use crate::scope::{DomainId, DomainTx};

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

/// The empty subordinate list, a JSON array.
pub const NO_SUBORDINATES: &[u8] = b"[]";

/// The realm's federation settings as decided; off when never decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationSettingsRow {
    /// Whether the realm issuer is a federation leaf.
    pub enabled: bool,
    /// The leaf's superiors.
    pub authority_hints: Vec<String>,
    /// Whether the intermediate or trust anchor role is served.
    pub ta_enabled: bool,
    /// The subordinates the role vouches for, a JSON array.
    pub subordinates: Vec<u8>,
    /// Whether OIDF client registration is open.
    pub registration_open: bool,
}

impl Default for FederationSettingsRow {
    fn default() -> Self {
        Self {
            enabled: false,
            authority_hints: Vec::new(),
            ta_enabled: false,
            subordinates: NO_SUBORDINATES.to_vec(),
            registration_open: false,
        }
    }
}

/// A trust anchor's newest version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchorRow {
    /// Its entity identifier.
    pub entity_id: String,
    /// Its pinned JWKS document.
    pub jwks: Vec<u8>,
    /// Whether it is trusted now.
    pub live: bool,
}

/// How an OIDF client came to the realm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OidfRegistration {
    /// Resolved from its `client_id` alone.
    Resolved,
    /// A request object carrying its trust chain.
    Automatic,
    /// The explicit registration endpoint.
    Explicit,
}

impl OidfRegistration {
    /// The stored word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Resolved => "resolved",
            Self::Automatic => "automatic",
            Self::Explicit => "explicit",
        }
    }

    fn of(word: &str) -> Result<Self, StoreError> {
        match word {
            "resolved" => Ok(Self::Resolved),
            "automatic" => Ok(Self::Automatic),
            "explicit" => Ok(Self::Explicit),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// A live OIDF client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidfClientRow {
    /// Its internal id.
    pub client_uuid: [u8; 16],
    /// Its entity identifier, the `client_id`.
    pub client_id: String,
    /// Its `openid_relying_party` metadata after the chain's policy, JSON.
    pub metadata: Vec<u8>,
    /// SHA-256 of `metadata`.
    pub metadata_hash: [u8; 32],
    /// The trust anchor its chain ends at.
    pub anchor: String,
    /// The types of the trust marks that verified.
    pub trust_marks: Vec<String>,
    /// How it came.
    pub registration: OidfRegistration,
    /// When the realm first saw it.
    pub first_seen_ms: u64,
    /// When its chain was last resolved.
    pub fetched_ms: u64,
    /// When its chain expires.
    pub chain_exp_ms: u64,
}

/// A resolved chain's outcome for an OIDF client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OidfSnapshot<'a> {
    /// The resolved metadata, JSON.
    pub metadata: &'a [u8],
    /// SHA-256 of `metadata`.
    pub metadata_hash: [u8; 32],
    /// The trust anchor.
    pub anchor: &'a str,
    /// The verified trust mark types.
    pub trust_marks: &'a [String],
    /// How it came.
    pub registration: OidfRegistration,
    /// Now.
    pub fetched_ms: u64,
    /// The chain's expiry.
    pub chain_exp_ms: u64,
}

fn oidf_client(
    client_uuid: Uuid,
    client_id: String,
    metadata: Vec<u8>,
    hash: &[u8],
    anchor: String,
    trust_marks: Vec<String>,
    times: (&str, i64, i64, i64),
) -> Result<OidfClientRow, StoreError> {
    let (registration, first, fetched, exp) = times;
    Ok(OidfClientRow {
        client_uuid: *client_uuid.as_bytes(),
        client_id,
        metadata,
        metadata_hash: <[u8; 32]>::try_from(hash).map_err(|_| StoreError::Corrupt)?,
        anchor,
        trust_marks,
        registration: OidfRegistration::of(registration)?,
        first_seen_ms: u64_of(first),
        fetched_ms: u64_of(fetched),
        chain_exp_ms: u64_of(exp),
    })
}

impl TenantTx {
    /// The newest decided federation settings; the default (off) when none was ever decided.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn federation_settings(&mut self) -> Result<FederationSettingsRow, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT enabled, authority_hints, ta_enabled, subordinates, registration_open
               FROM access.idp_federation_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(
            row.map_or_else(FederationSettingsRow::default, |r| FederationSettingsRow {
                enabled: r.enabled,
                authority_hints: r.authority_hints,
                ta_enabled: r.ta_enabled,
                subordinates: r.subordinates,
                registration_open: r.registration_open,
            }),
        )
    }

    /// Writes the next federation settings version under `bound` (`idp.federation.*`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_federation_settings(
        &mut self,
        bound: &Bound,
        s: &FederationSettingsRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_federation_settings
               (tenant_id, realm_id, version, enabled, authority_hints, ta_enabled, subordinates,
                registration_open, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_federation_settings
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5, $6, $7, $8, $9",
            tenant,
            realm,
            s.enabled,
            &s.authority_hints,
            s.ta_enabled,
            &s.subordinates,
            s.registration_open,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Every trust anchor the realm ever named, each at its newest version.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn trust_anchors(&mut self) -> Result<Vec<TrustAnchorRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (entity_id) entity_id, state, jwks
               FROM access.idp_federation_trust_anchors
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY entity_id, version DESC",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| TrustAnchorRow {
                entity_id: r.entity_id,
                jwks: r.jwks,
                live: r.state == "live",
            })
            .collect())
    }

    /// Writes the next version of the trust anchor `entity_id` under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_trust_anchor(
        &mut self,
        bound: &Bound,
        entity_id: &str,
        jwks: &[u8],
        live: bool,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_federation_trust_anchors
               (tenant_id, realm_id, entity_id, version, state, jwks, domain_id, decision_pos)
             SELECT $1, $2, $3,
                    COALESCE((SELECT max(version) FROM access.idp_federation_trust_anchors
                               WHERE tenant_id = $1 AND realm_id = $2 AND entity_id = $3), 0) + 1,
                    $4, $5, $6, $7",
            tenant,
            realm,
            entity_id,
            if live { "live" } else { "removed" },
            jwks,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The live OIDF client `client_id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn oidf_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<OidfClientRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT client_uuid, client_id, metadata, metadata_hash, anchor, trust_marks,
                    registration, first_seen_ms, fetched_ms, chain_exp_ms
               FROM access.oauth_oidf_clients
              WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            client_id,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            oidf_client(
                r.client_uuid,
                r.client_id,
                r.metadata,
                &r.metadata_hash,
                r.anchor,
                r.trust_marks,
                (
                    &r.registration,
                    r.first_seen_ms,
                    r.fetched_ms,
                    r.chain_exp_ms,
                ),
            )
        })
        .transpose()
    }

    /// The live OIDF client with internal id `client`, by its `client_id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn oidf_client_by_uuid(
        &mut self,
        client: [u8; 16],
    ) -> Result<Option<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT client_id FROM access.oauth_oidf_clients
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(client),
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// Keeps a newly resolved OIDF client; its internal id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_oidf_client(
        &mut self,
        client_id: &str,
        s: &OidfSnapshot<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = scope(self)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.oauth_oidf_clients (tenant_id, realm_id, client_id, metadata,
                    metadata_hash, anchor, trust_marks, registration, first_seen_ms, fetched_ms,
                    chain_exp_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10)
             RETURNING client_uuid",
            tenant,
            realm,
            client_id,
            s.metadata,
            s.metadata_hash.as_slice(),
            s.anchor,
            s.trust_marks,
            s.registration.word(),
            i64_of(s.fetched_ms)?,
            i64_of(s.chain_exp_ms)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Refreshes a live OIDF client with a newly resolved chain.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn refresh_oidf_client(
        &mut self,
        client: [u8; 16],
        s: &OidfSnapshot<'_>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.oauth_oidf_clients
                SET metadata = $4, metadata_hash = $5, anchor = $6, trust_marks = $7,
                    fetched_ms = $8, chain_exp_ms = $9
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(client),
            s.metadata,
            s.metadata_hash.as_slice(),
            s.anchor,
            s.trust_marks,
            i64_of(s.fetched_ms)?,
            i64_of(s.chain_exp_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Retires a live OIDF client, once (`chain_lost` or `disabled`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn retire_oidf_client(
        &mut self,
        client: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.oauth_oidf_clients SET retired_ms = $4, retire_reason = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(client),
            i64_of(now_ms)?,
            reason,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Records the replay key of a registration request object; `false` when it was seen.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn oidf_jti_first(
        &mut self,
        replay_key: &[u8; 32],
        exp_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "INSERT INTO access.oauth_oidf_jti (tenant_id, realm_id, replay_key, exp_ms)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            replay_key.as_slice(),
            i64_of(exp_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }
}

/// A chain-constrained issuer's chain state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainState {
    /// Tracked, never resolved yet.
    Pending,
    /// The chain resolved at `checked_ms`.
    Resolved,
    /// The chain did not resolve.
    Unresolved,
    /// The chain's metadata policies conflict.
    Conflict,
}

impl ChainState {
    /// The stored word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Resolved => "resolved",
            Self::Unresolved => "unresolved",
            Self::Conflict => "conflict",
        }
    }

    fn of(word: &str) -> Result<Self, StoreError> {
        match word {
            "pending" => Ok(Self::Pending),
            "resolved" => Ok(Self::Resolved),
            "unresolved" => Ok(Self::Unresolved),
            "conflict" => Ok(Self::Conflict),
            _ => Err(StoreError::Corrupt),
        }
    }
}

/// One tracked issuer of a domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerStateRow {
    /// Its entity identifier.
    pub entity_id: String,
    /// Its issuer Party, when known.
    pub issuer: Option<[u8; 16]>,
    /// The realm that resolves its chain.
    pub realm: ([u8; 16], [u8; 16]),
    /// The state.
    pub state: ChainState,
    /// The anchor the chain ended at.
    pub anchor: Option<String>,
    /// When the chain was last checked.
    pub checked_ms: u64,
    /// When the chain expires.
    pub chain_exp_ms: u64,
}

/// Starts tracking the issuer `entity_id` of `domain`, resolved by the realm `(tenant, realm)`:
/// pending, so the gate refuses its Claims until its chain resolves. Tracking it again changes
/// nothing.
///
/// # Errors
/// [`StoreError`].
pub async fn track_issuer(
    app: &PgPool,
    domain: &DomainId,
    realm: ([u8; 16], [u8; 16]),
    entity_id: &str,
    issuer: Option<[u8; 16]>,
    now_ms: u64,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    sqlx::query!(
        "INSERT INTO access.federation_issuer_state (domain_id, entity_id, issuer_id, tenant_id,
                realm_id, state, checked_ms, chain_exp_ms, tracked_ms)
         VALUES ($1, $2, $3, $4, $5, 'pending', 0, 0, $6) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        entity_id,
        issuer.as_ref().map(<[u8; 16]>::as_slice),
        Uuid::from_bytes(realm.0),
        Uuid::from_bytes(realm.1),
        i64_of(now_ms)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await
}

/// The tracked issuers of `domain` that are `entity_id` or the issuer Party `issuer`.
///
/// # Errors
/// [`StoreError`].
pub async fn issuer_states(
    app: &PgPool,
    domain: &DomainId,
    entity_id: Option<&str>,
    issuer: Option<[u8; 16]>,
) -> Result<Vec<IssuerStateRow>, StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    let rows = sqlx::query!(
        "SELECT entity_id, issuer_id, tenant_id, realm_id, state, anchor, checked_ms, chain_exp_ms
           FROM access.federation_issuer_state
          WHERE domain_id = $1 AND untracked_ms IS NULL
            AND (entity_id = $2 OR issuer_id = $3)",
        domain.as_bytes().as_slice(),
        entity_id,
        issuer.as_ref().map(<[u8; 16]>::as_slice),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(IssuerStateRow {
                entity_id: r.entity_id,
                issuer: r
                    .issuer_id
                    .map(|i| <[u8; 16]>::try_from(i.as_slice()).map_err(|_| StoreError::Corrupt))
                    .transpose()?,
                realm: (*r.tenant_id.as_bytes(), *r.realm_id.as_bytes()),
                state: ChainState::of(&r.state)?,
                anchor: r.anchor,
                checked_ms: u64_of(r.checked_ms),
                chain_exp_ms: u64_of(r.chain_exp_ms),
            })
        })
        .collect()
}

/// Every tracked issuer of `domain`, for the refresher and the `federation-chain` search.
///
/// # Errors
/// [`StoreError`].
pub async fn tracked_issuers(
    app: &PgPool,
    domain: &DomainId,
) -> Result<Vec<IssuerStateRow>, StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    let rows = sqlx::query!(
        "SELECT entity_id, issuer_id, tenant_id, realm_id, state, anchor, checked_ms, chain_exp_ms
           FROM access.federation_issuer_state
          WHERE domain_id = $1 AND untracked_ms IS NULL
          ORDER BY entity_id",
        domain.as_bytes().as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(IssuerStateRow {
                entity_id: r.entity_id,
                issuer: r
                    .issuer_id
                    .map(|i| <[u8; 16]>::try_from(i.as_slice()).map_err(|_| StoreError::Corrupt))
                    .transpose()?,
                realm: (*r.tenant_id.as_bytes(), *r.realm_id.as_bytes()),
                state: ChainState::of(&r.state)?,
                anchor: r.anchor,
                checked_ms: u64_of(r.checked_ms),
                chain_exp_ms: u64_of(r.chain_exp_ms),
            })
        })
        .collect()
}

/// Records the outcome of a chain check of the tracked issuer `entity_id` of `domain`.
///
/// # Errors
/// [`StoreError`].
pub async fn set_issuer_state(
    app: &PgPool,
    domain: &DomainId,
    entity_id: &str,
    state: ChainState,
    anchor: Option<&str>,
    checked_ms: u64,
    chain_exp_ms: u64,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    sqlx::query!(
        "UPDATE access.federation_issuer_state
            SET state = $3, anchor = $4, checked_ms = $5, chain_exp_ms = $6
          WHERE domain_id = $1 AND entity_id = $2 AND untracked_ms IS NULL",
        domain.as_bytes().as_slice(),
        entity_id,
        state.word(),
        anchor,
        i64_of(checked_ms)?,
        i64_of(chain_exp_ms)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await
}
