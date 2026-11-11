//! The Placement Directory and what a cell declares (OP-158 m.3 (o), (p), CMP-26, OP-30, TI-17,
//! HL-40): where a tenant, realm or domain is served, one version per move; the cell's own
//! profile; a realm's residency; and the two ends of a realm rehome (E14). The directory routes
//! requests and is never a decision input: a cell that does not lead a domain refuses it.
//! Nothing here is changed or removed (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{TenantId, TenantTx};
use crate::idp::Bound;
use crate::scope::DomainId;

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// What a placement row names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    /// A tenant, by its id.
    Tenant([u8; 16]),
    /// A realm, by its id.
    Realm([u8; 16]),
    /// An authority domain, by its id.
    Domain([u8; 32]),
}

impl Subject {
    /// The `subject_kind` column.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Tenant(_) => "tenant",
            Self::Realm(_) => "realm",
            Self::Domain(_) => "domain",
        }
    }

    /// The `subject` column.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Tenant(b) | Self::Realm(b) => b,
            Self::Domain(b) => b,
        }
    }
}

/// One placement version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placed {
    /// The cell.
    pub cell: String,
    /// Whether the cell is dedicated to the tenant (OP-12, OP-48).
    pub dedicated: bool,
    /// The version.
    pub version: u64,
}

/// Places `subject` of the transaction's tenant in `cell` from `since_ms`, as its next version.
/// Returns the version written.
///
/// # Errors
/// [`StoreError`]; a cell name outside `^[a-z0-9][a-z0-9-]{0,62}$` fails in the database.
pub async fn place(
    t: &mut TenantTx,
    subject: &Subject,
    (cell, dedicated): (&str, bool),
    since_ms: u64,
) -> Result<u64, StoreError> {
    let v = sqlx::query_scalar!(
        "INSERT INTO access.placement (tenant_id, subject_kind, subject, version, cell, dedicated, since)
         SELECT $1, $2, $3,
                COALESCE((SELECT max(version) FROM access.placement
                           WHERE tenant_id = $1 AND subject_kind = $2 AND subject = $3), 0) + 1,
                $4, $5, $6
         RETURNING version",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        subject.kind(),
        subject.bytes(),
        cell,
        dedicated,
        signed(since_ms)?,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    unsigned(v)
}

/// [`place`] in a transaction of its own over `tenant`; nothing when the tenant is not in this
/// cell's database. Returns the version written.
///
/// # Errors
/// [`StoreError`].
pub async fn place_tenant(
    app: &PgPool,
    tenant: [u8; 16],
    subject: &Subject,
    at: (&str, bool),
    since_ms: u64,
) -> Result<Option<u64>, StoreError> {
    let mut t = TenantTx::begin_tenant(app, TenantId::from_bytes(tenant)).await?;
    let here = sqlx::query_scalar!(
        "SELECT EXISTS (SELECT 1 FROM access.tenants WHERE tenant_id = $1) AS \"here!\"",
        Uuid::from_bytes(tenant),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    if !here {
        t.rollback().await?;
        return Ok(None);
    }
    let v = place(&mut t, subject, at, since_ms).await?;
    t.commit().await?;
    Ok(Some(v))
}

/// The latest placement of `subject`, whatever its tenant: the routing lookup (TI-17).
///
/// # Errors
/// [`StoreError`].
pub async fn cell_of(pool: &PgPool, subject: &Subject) -> Result<Option<Placed>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT cell AS "cell!", dedicated AS "dedicated!", version AS "version!"
             FROM access.placement_cell($1, $2)"#,
        subject.kind(),
        subject.bytes(),
    )
    .fetch_optional(pool)
    .await?;
    row.map(|r| {
        Ok(Placed {
            cell: r.cell,
            dedicated: r.dedicated,
            version: unsigned(r.version)?,
        })
    })
    .transpose()
}

/// Every placement version of `subject` in the transaction's tenant, oldest first.
///
/// # Errors
/// [`StoreError`].
pub async fn history(t: &mut TenantTx, subject: &Subject) -> Result<Vec<Placed>, StoreError> {
    sqlx::query!(
        "SELECT cell, dedicated, version FROM access.placement
          WHERE tenant_id = $1 AND subject_kind = $2 AND subject = $3 ORDER BY version",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        subject.kind(),
        subject.bytes(),
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| {
        Ok(Placed {
            cell: r.cell,
            dedicated: r.dedicated,
            version: unsigned(r.version)?,
        })
    })
    .collect()
}

/// The tenant of `domain` in this cell, when the cell has it.
///
/// # Errors
/// [`StoreError`].
pub async fn domain_tenant(
    app: &PgPool,
    domain: &DomainId,
) -> Result<Option<[u8; 16]>, StoreError> {
    let t = sqlx::query_scalar!(
        "SELECT access.domain_tenant($1) AS tenant",
        domain.as_bytes().as_slice(),
    )
    .fetch_one(app)
    .await?;
    Ok(t.map(Uuid::into_bytes))
}

/// This cell as its configuration declares it (OP-158 m.3 (o), (p)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellProfile {
    /// The cell's name.
    pub cell: String,
    /// Its region, when declared.
    pub region: Option<String>,
    /// `regional` or `multi-region-sync`.
    pub class: String,
    /// `replicated` or `single-node` (HL-40).
    pub durability: String,
    /// The tenant a dedicated cell serves alone (OP-12, OP-48).
    pub dedicated_to: Option<[u8; 16]>,
}

/// The cell's declared profile, when one is recorded.
///
/// # Errors
/// [`StoreError`].
pub async fn cell_profile<'e, E: sqlx::PgExecutor<'e>>(
    db: E,
) -> Result<Option<CellProfile>, StoreError> {
    let row = sqlx::query!(
        "SELECT cell, region, class, durability, dedicated_to FROM access_ops.cell_profile
          ORDER BY version DESC LIMIT 1"
    )
    .fetch_optional(db)
    .await?;
    Ok(row.map(|r| CellProfile {
        cell: r.cell,
        region: r.region,
        class: r.class,
        durability: r.durability,
        dedicated_to: r.dedicated_to.map(Uuid::into_bytes),
    }))
}

/// Records `profile` as the cell's next version unless it is the latest already. Returns
/// whether a version was written.
///
/// # Errors
/// [`StoreError`]; a value outside the columns' checks fails in the database.
pub async fn declare_cell(app: &PgPool, profile: &CellProfile) -> Result<bool, StoreError> {
    if cell_profile(app).await?.as_ref() == Some(profile) {
        return Ok(false);
    }
    sqlx::query!(
        "INSERT INTO access_ops.cell_profile (version, cell, region, class, durability, dedicated_to)
         SELECT COALESCE((SELECT max(version) FROM access_ops.cell_profile), 0) + 1, $1, $2, $3, $4, $5",
        profile.cell,
        profile.region,
        profile.class,
        profile.durability,
        profile.dedicated_to.map(Uuid::from_bytes),
    )
    .execute(app)
    .await?;
    Ok(true)
}

/// Writes the next version of the realm's residency against its committed
/// `idp.realm.residency` (OP-158 m.3 (o)).
///
/// # Errors
/// [`StoreError`].
pub async fn put_residency(
    t: &mut TenantTx,
    bound: &Bound,
    (region, class): (&str, &str),
) -> Result<(), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    sqlx::query!(
        "INSERT INTO access.realm_residency (tenant_id, realm_id, version, region, class, domain_id, decision_pos)
         SELECT $1, $2,
                COALESCE((SELECT max(version) FROM access.realm_residency
                           WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                $3, $4, $5, $6",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        region,
        class,
        bound.domain().as_bytes().as_slice(),
        bound.raw_position(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The cell's declared profile, read in the transaction.
///
/// # Errors
/// [`StoreError`].
pub async fn cell_profile_in(t: &mut TenantTx) -> Result<Option<CellProfile>, StoreError> {
    cell_profile(&mut *t.tx).await
}

/// The realm's declared residency `(region, class)`, when one is.
///
/// # Errors
/// [`StoreError`].
pub async fn residency(t: &mut TenantTx) -> Result<Option<(String, String)>, StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    let row = sqlx::query!(
        "SELECT region, class FROM access.realm_residency
          WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(row.map(|r| (r.region, r.class)))
}

/// Which end of a rehome a committed ALLOW is (E14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Decided in the realm's governing domain.
    From,
    /// Decided in the domain the realm moves to.
    To,
}

/// One end of a rehome: a committed ALLOW of `idp.realm.rehome` (E14, OP-158 m.3 (o)).
pub struct End<'a> {
    /// Which end.
    pub side: Side,
    /// The realm's governing domain.
    pub from: &'a DomainId,
    /// The domain it moves to.
    pub to: &'a DomainId,
    /// Position of the decision record in the end's domain.
    pub position: u64,
    /// The Exercise nonce.
    pub nonce: &'a [u8],
    /// The intent digest of the decision.
    pub intent: [u8; 32],
}

/// Records `end` for the transaction's realm. `false` when it is already recorded.
///
/// # Errors
/// [`StoreError`]; an end that is not a committed ALLOW of this intent in its domain, or a from
/// end outside the realm's governing domain, fails in the database.
pub async fn record_end(t: &mut TenantTx, end: &End<'_>) -> Result<bool, StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    let (side, domain) = match end.side {
        Side::From => ("from", end.from),
        Side::To => ("to", end.to),
    };
    let done = sqlx::query!(
        "INSERT INTO access.rehome_ends
           (tenant_id, realm_id, side, from_domain, to_domain, domain_id, decision_pos, nonce, intent_digest)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (tenant_id, domain_id, decision_pos) DO NOTHING",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        side,
        end.from.as_bytes().as_slice(),
        end.to.as_bytes().as_slice(),
        domain.as_bytes().as_slice(),
        signed(end.position)?,
        end.nonce,
        end.intent.as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// A completed rehome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rehomed {
    /// Its version among the realm's rehomes.
    pub version: u64,
    /// The from end's position in the old domain.
    pub from_pos: u64,
    /// The to end's position in the new domain.
    pub to_pos: u64,
}

/// Moves the transaction's realm from `from` to `to` when both ends of that move are recorded,
/// unused and younger than 24 h; otherwise nothing changes and the realm stays (E14, OP-158
/// m.18 (e)).
///
/// # Errors
/// [`StoreError`].
pub async fn complete_rehome(
    t: &mut TenantTx,
    from: &DomainId,
    to: &DomainId,
) -> Result<Option<Rehomed>, StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    let (tenant, realm) = (
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    );
    let ends = sqlx::query!(
        r#"SELECT
             (SELECT e.decision_pos FROM access.rehome_ends e
               WHERE e.tenant_id = $1 AND e.realm_id = $2 AND e.side = 'from'
                 AND e.from_domain = $3 AND e.to_domain = $4
                 AND NOT EXISTS (SELECT 1 FROM access.realm_rehomes h
                                  WHERE h.tenant_id = $1 AND h.from_domain = e.domain_id
                                    AND h.from_pos = e.decision_pos)
                 AND e.created_at > now() - interval '24 hours'
               ORDER BY e.decision_pos LIMIT 1) AS from_pos,
             (SELECT e.decision_pos FROM access.rehome_ends e
               WHERE e.tenant_id = $1 AND e.realm_id = $2 AND e.side = 'to'
                 AND e.from_domain = $3 AND e.to_domain = $4
                 AND NOT EXISTS (SELECT 1 FROM access.realm_rehomes h
                                  WHERE h.tenant_id = $1 AND h.to_domain = e.domain_id
                                    AND h.to_pos = e.decision_pos)
                 AND e.created_at > now() - interval '24 hours'
               ORDER BY e.decision_pos LIMIT 1) AS to_pos"#,
        tenant,
        realm,
        from.as_bytes().as_slice(),
        to.as_bytes().as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    let (Some(from_pos), Some(to_pos)) = (ends.from_pos, ends.to_pos) else {
        return Ok(None);
    };
    sqlx::query!(
        "INSERT INTO access.realm_governors (tenant_id, realm_id, domain_id) VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
        tenant,
        realm,
        to.as_bytes().as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    let version = sqlx::query_scalar!(
        "INSERT INTO access.realm_rehomes (tenant_id, realm_id, version, from_domain, to_domain, from_pos, to_pos)
         SELECT $1, $2,
                COALESCE((SELECT max(version) FROM access.realm_rehomes
                           WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                $3, $4, $5, $6
         RETURNING version",
        tenant,
        realm,
        from.as_bytes().as_slice(),
        to.as_bytes().as_slice(),
        from_pos,
        to_pos,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    let moved = sqlx::query!(
        "UPDATE access.realms SET governing_domain_id = $4
          WHERE tenant_id = $1 AND realm_id = $2 AND governing_domain_id = $3 AND status = 'active'",
        tenant,
        realm,
        from.as_bytes().as_slice(),
        to.as_bytes().as_slice(),
    )
    .execute(&mut *t.tx)
    .await?;
    if moved.rows_affected() != 1 {
        return Err(StoreError::Stale);
    }
    Ok(Some(Rehomed {
        version: unsigned(version)?,
        from_pos: unsigned(from_pos)?,
        to_pos: unsigned(to_pos)?,
    }))
}

/// The realm's rehome ends not yet used by a completed rehome and not expired, 24 h after they
/// were recorded (OP-158 m.18 (e)): (side, from, to, position).
///
/// # Errors
/// [`StoreError`].
pub async fn open_ends(
    t: &mut TenantTx,
) -> Result<Vec<(Side, DomainId, DomainId, u64)>, StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    let tenant = Uuid::from_bytes(*t.tenant.as_bytes());
    sqlx::query!(
        "SELECT e.side, e.from_domain, e.to_domain, e.decision_pos FROM access.rehome_ends e
          WHERE e.tenant_id = $1 AND e.realm_id = $2
            AND e.created_at > now() - interval '24 hours'
            AND NOT EXISTS (SELECT 1 FROM access.realm_rehomes h
                             WHERE h.tenant_id = $1
                               AND ((h.from_domain = e.domain_id AND h.from_pos = e.decision_pos)
                                 OR (h.to_domain = e.domain_id AND h.to_pos = e.decision_pos)))
          ORDER BY e.created_at, e.decision_pos",
        tenant,
        Uuid::from_bytes(*realm.as_bytes()),
    )
    .fetch_all(&mut *t.tx)
    .await?
    .into_iter()
    .map(|r| {
        let id = |b: Vec<u8>| {
            <[u8; 32]>::try_from(b.as_slice())
                .map(DomainId::from_bytes)
                .map_err(|_| StoreError::Corrupt)
        };
        Ok((
            if r.side == "from" {
                Side::From
            } else {
                Side::To
            },
            id(r.from_domain)?,
            id(r.to_domain)?,
            unsigned(r.decision_pos)?,
        ))
    })
    .collect()
}

/// Whether `domain` is an authority domain of the transaction's tenant in this cell.
///
/// # Errors
/// [`StoreError`].
pub async fn tenant_domain(t: &mut TenantTx, domain: &DomainId) -> Result<bool, StoreError> {
    let found = sqlx::query_scalar!(
        "SELECT access.domain_tenant($2) IS NOT DISTINCT FROM $1 AS \"found!\"",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        domain.as_bytes().as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok(found)
}

/// The authority domains of `tenant` in this cell, oldest first.
///
/// # Errors
/// [`StoreError`].
pub async fn tenant_domains(app: &PgPool, tenant: [u8; 16]) -> Result<Vec<DomainId>, StoreError> {
    sqlx::query_scalar!(
        r#"SELECT d AS "d!" FROM access.tenant_domains($1) AS d"#,
        Uuid::from_bytes(tenant),
    )
    .fetch_all(app)
    .await?
    .into_iter()
    .map(|b| {
        <[u8; 32]>::try_from(b.as_slice())
            .map(DomainId::from_bytes)
            .map_err(|_| StoreError::Corrupt)
    })
    .collect()
}

/// Adopts `tenant`, moving here with its id, as an active tenant placed in `cell`; nothing when
/// it is here already. A dedicated cell adopts only its own tenant (OP-12, OP-48).
///
/// # Errors
/// [`StoreError`]; another tenant on a dedicated cell fails in the database.
pub async fn adopt_tenant(app: &PgPool, tenant: [u8; 16], cell: &str) -> Result<bool, StoreError> {
    let mut t = TenantTx::begin_tenant(app, TenantId::from_bytes(tenant)).await?;
    let done = sqlx::query!(
        "INSERT INTO access.tenants (tenant_id, placement_id, status) VALUES ($1, $2, 'active')
         ON CONFLICT (tenant_id) DO NOTHING",
        Uuid::from_bytes(tenant),
        cell,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}
