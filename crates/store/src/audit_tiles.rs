//! The identity audit tree's tiles and yearly shards (OP-37, OP-158 m.3 (w)): a full tile of 256
//! hashes is written once; a shard records the tree at the last checkpoint of a year.

use sqlx::PgPool;

use crate::StoreError;
use crate::audit::CheckpointRow;
use crate::identity::Cursor;

/// Hashes in a full tile (C2SP tlog-tiles, height 8).
pub const TILE: usize = 256;

/// A full tile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TileRow {
    /// Its level; level 0 holds leaf hashes.
    pub level: u8,
    /// Its index within the level.
    pub n: u64,
    /// Its [`TILE`] hashes.
    pub hashes: Vec<[u8; 32]>,
    /// The row of the last leaf under it.
    pub end: Cursor,
}

/// A frozen yearly shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardRow {
    /// The calendar year (UTC).
    pub year: i32,
    /// The tree size at the year's last checkpoint; 0 when the year had none.
    pub size: u64,
    /// The tree head at that size.
    pub root: [u8; 32],
    /// The checkpoint's signed note.
    pub note: Option<String>,
    /// Tile objects written for the shard.
    pub tiles: u32,
}

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn signed(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn split(bytes: &[u8]) -> Result<Vec<[u8; 32]>, StoreError> {
    if bytes.len() != TILE * 32 {
        return Err(StoreError::Corrupt);
    }
    Ok(bytes.as_chunks::<32>().0.to_vec())
}

fn tile_of(level: i16, n: i64, hashes: &[u8], xid: i64, id: i64) -> Result<TileRow, StoreError> {
    Ok(TileRow {
        level: u8::try_from(level).map_err(|_| StoreError::Corrupt)?,
        n: unsigned(n)?,
        hashes: split(hashes)?,
        end: Cursor {
            xid: unsigned(xid)?,
            id,
        },
    })
}

/// The highest full tile of `level`.
///
/// # Errors
/// [`StoreError`].
pub async fn last_tile(checkpointer: &PgPool, level: u8) -> Result<Option<TileRow>, StoreError> {
    let r = sqlx::query!(
        r#"SELECT level, n, hashes, end_xid::text::bigint AS "end_xid!", end_id
             FROM access_ops.audit_tiles WHERE level = $1 ORDER BY n DESC LIMIT 1"#,
        i16::from(level),
    )
    .fetch_optional(checkpointer)
    .await?;
    r.map(|r| tile_of(r.level, r.n, &r.hashes, r.end_xid, r.end_id))
        .transpose()
}

/// Up to `limit` full tiles of `level` from index `from` on, in order.
///
/// # Errors
/// [`StoreError`].
pub async fn tiles(
    checkpointer: &PgPool,
    level: u8,
    from: u64,
    limit: u32,
) -> Result<Vec<TileRow>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT level, n, hashes, end_xid::text::bigint AS "end_xid!", end_id
             FROM access_ops.audit_tiles WHERE level = $1 AND n >= $2 ORDER BY n LIMIT $3"#,
        i16::from(level),
        signed(from)?,
        i64::from(limit),
    )
    .fetch_all(checkpointer)
    .await?;
    rows.into_iter()
        .map(|r| tile_of(r.level, r.n, &r.hashes, r.end_xid, r.end_id))
        .collect()
}

/// Appends a full tile; a second tile at the same place fails.
///
/// # Errors
/// [`StoreError`].
pub async fn append_tile(checkpointer: &PgPool, tile: &TileRow) -> Result<(), StoreError> {
    if tile.hashes.len() != TILE {
        return Err(StoreError::Range);
    }
    let hashes: Vec<u8> = tile.hashes.iter().flatten().copied().collect();
    sqlx::query!(
        "INSERT INTO access_ops.audit_tiles (level, n, hashes, end_xid, end_id)
         VALUES ($1, $2, $3, $4::bigint::text::xid8, $5)",
        i16::from(tile.level),
        signed(tile.n)?,
        hashes,
        signed(tile.end.xid)?,
        tile.end.id,
    )
    .execute(checkpointer)
    .await?;
    Ok(())
}

/// The year (UTC) of the first checkpoint, if any.
///
/// # Errors
/// [`StoreError`].
pub async fn first_checkpoint_year(checkpointer: &PgPool) -> Result<Option<i32>, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT extract(year FROM created_at AT TIME ZONE 'UTC')::int AS "year!"
             FROM access_ops.audit_checkpoint ORDER BY size LIMIT 1"#
    )
    .fetch_optional(checkpointer)
    .await?)
}

/// The current year (UTC) by the database's clock.
///
/// # Errors
/// [`StoreError`].
pub async fn current_year(checkpointer: &PgPool) -> Result<i32, StoreError> {
    Ok(
        sqlx::query_scalar!(
            r#"SELECT extract(year FROM now() AT TIME ZONE 'UTC')::int AS "year!""#
        )
        .fetch_one(checkpointer)
        .await?,
    )
}

/// The last signed checkpoint created before the end of `year` (UTC).
///
/// # Errors
/// [`StoreError`].
pub async fn year_end_checkpoint(
    checkpointer: &PgPool,
    year: i32,
) -> Result<Option<CheckpointRow>, StoreError> {
    let r = sqlx::query!(
        r#"SELECT size, root, frontier, xid::text::bigint AS "xid!", id, note
             FROM access_ops.audit_checkpoint
            WHERE created_at < make_timestamptz($1 + 1, 1, 1, 0, 0, 0, 'UTC') AND note IS NOT NULL
            ORDER BY size DESC LIMIT 1"#,
        year,
    )
    .fetch_optional(checkpointer)
    .await?;
    r.map(|r| {
        Ok(CheckpointRow {
            size: unsigned(r.size)?,
            root: <[u8; 32]>::try_from(r.root).map_err(|_| StoreError::Corrupt)?,
            frontier: r
                .frontier
                .into_iter()
                .map(|h| <[u8; 32]>::try_from(h).map_err(|_| StoreError::Corrupt))
                .collect::<Result<_, _>>()?,
            cursor: Cursor {
                xid: unsigned(r.xid)?,
                id: r.id,
            },
            note: r.note,
        })
    })
    .transpose()
}

/// The years already frozen, in order.
///
/// # Errors
/// [`StoreError`].
pub async fn shards(checkpointer: &PgPool) -> Result<Vec<ShardRow>, StoreError> {
    let rows = sqlx::query!(
        "SELECT year, size, root, note, tiles FROM access_ops.audit_shards ORDER BY year"
    )
    .fetch_all(checkpointer)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(ShardRow {
                year: r.year,
                size: unsigned(r.size)?,
                root: <[u8; 32]>::try_from(r.root).map_err(|_| StoreError::Corrupt)?,
                note: r.note,
                tiles: u32::try_from(r.tiles).map_err(|_| StoreError::Corrupt)?,
            })
        })
        .collect()
}

/// Records a frozen shard; a year is frozen once.
///
/// # Errors
/// [`StoreError`].
pub async fn append_shard(checkpointer: &PgPool, shard: &ShardRow) -> Result<(), StoreError> {
    sqlx::query!(
        "INSERT INTO access_ops.audit_shards (year, size, root, note, tiles) VALUES ($1, $2, $3, $4, $5)",
        shard.year,
        signed(shard.size)?,
        shard.root.as_slice(),
        shard.note.as_deref(),
        i32::try_from(shard.tiles).map_err(|_| StoreError::Range)?,
    )
    .execute(checkpointer)
    .await?;
    Ok(())
}
