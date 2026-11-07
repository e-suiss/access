//! Schema Publication Packages as their publisher published them (§8.17.10.2, §9.13, E10, X21):
//! one immutable row per fingerprint and per (publisher, namespace, catalog version). A row is a
//! statement; no domain is changed by it. A package is kept per domain it is offered to and
//! read only in that domain's scope (TN-20). Nothing is updated or deleted (OP-73).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// Most rows one namespace listing returns.
pub const MAX_LISTED: i64 = 64;

/// One published package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationRow {
    /// The package fingerprint.
    pub fingerprint: [u8; 32],
    /// The publisher Party.
    pub publisher: [u8; 16],
    /// The namespace.
    pub namespace: String,
    /// The catalog version.
    pub catalog_version: u64,
    /// The package's canonical bytes.
    pub package: Vec<u8>,
    /// When it was published, Unix milliseconds of the caller's trusted clock.
    pub published_ms: u64,
}

/// Why a package was not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kept {
    /// Kept now.
    New,
    /// The same fingerprint was already kept.
    Same,
    /// The publisher already published another package as this version (E10: immutable).
    VersionTaken,
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn bytes<const N: usize>(v: &[u8]) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// Keeps `row` as offered to `domain` (app role).
///
/// # Errors
/// [`StoreError`].
pub async fn keep(
    app: &PgPool,
    domain: &DomainId,
    row: &PublicationRow,
) -> Result<Kept, StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    let inserted = sqlx::query!(
        "INSERT INTO access.schema_publication
           (domain_id, fingerprint, publisher, namespace, catalog_version, package, published_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        row.fingerprint.as_slice(),
        row.publisher.as_slice(),
        row.namespace,
        signed(row.catalog_version)?,
        row.package,
        signed(row.published_ms)?,
    )
    .execute(&mut *t.tx)
    .await?;
    let kept = if inserted.rows_affected() == 1 {
        Kept::New
    } else {
        let same = sqlx::query_scalar!(
            "SELECT 1 AS \"one!\" FROM access.schema_publication
              WHERE domain_id = $1 AND fingerprint = $2",
            domain.as_bytes().as_slice(),
            row.fingerprint.as_slice(),
        )
        .fetch_optional(&mut *t.tx)
        .await?;
        if same.is_some() {
            Kept::Same
        } else {
            Kept::VersionTaken
        }
    };
    t.commit().await?;
    Ok(kept)
}

/// The packages offered to `domain` for `namespace`, newest version first, at most
/// [`MAX_LISTED`].
///
/// # Errors
/// [`StoreError`].
pub async fn of_namespace(
    app: &PgPool,
    domain: &DomainId,
    namespace: &str,
) -> Result<Vec<PublicationRow>, StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    let rows = sqlx::query!(
        "SELECT fingerprint, publisher, namespace, catalog_version, package, published_ms
           FROM access.schema_publication WHERE domain_id = $1 AND namespace = $2
          ORDER BY catalog_version DESC, fingerprint LIMIT $3",
        domain.as_bytes().as_slice(),
        namespace,
        MAX_LISTED,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(PublicationRow {
                fingerprint: bytes(&r.fingerprint)?,
                publisher: bytes(&r.publisher)?,
                namespace: r.namespace,
                catalog_version: unsigned(r.catalog_version)?,
                package: r.package,
                published_ms: unsigned(r.published_ms)?,
            })
        })
        .collect()
}
