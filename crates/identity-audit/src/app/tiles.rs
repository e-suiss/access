//! The identity audit tree's tiles and yearly shards (OP-37, OP-158 m.3 (w)). [`extend`] writes
//! each tile once it is full, behind the latest checkpoint; [`freeze_due`] freezes every ended
//! year at its last checkpoint: the tree head is recomputed from the tiles and must be the
//! checkpoint's, then every tile and the signed note go to the cold tier as static objects.

use access_store::audit::{AuditRow, CheckpointRow};
use access_store::audit_tiles::{ShardRow, TileRow};
use access_store::identity::Cursor;
use suiss_ledger::Hash;

use crate::AuditError;
use crate::domain::tiles::{
    LEVELS, WIDTH, bytes, entries, levels, log_dir, path, root_from_partials, tile_root,
};
use crate::domain::{Leaf as _, leaf};
use crate::ports::{ColdStore, TileStore};

/// Tiles read per page.
const PAGE: u32 = 256;

/// Tiles per level, as a `usize`.
const TILE: usize = 256;

fn page_len(v: usize) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

async fn extend_leaves<T: TileStore>(store: &T, upto: &CheckpointRow) -> Result<u32, AuditError> {
    let last = store.last_tile(0).await?;
    let (mut n, mut after) = match &last {
        Some(t) => (t.n.saturating_add(1), t.end),
        None => (0, Cursor::default()),
    };
    let mut written = 0_u32;
    let mut hashes: Vec<Hash> = Vec::with_capacity(TILE);
    let mut end = after;
    loop {
        let want = u32::try_from(TILE.saturating_sub(hashes.len())).unwrap_or(PAGE);
        let rows: Vec<AuditRow> = store
            .rows_after(after, want)
            .await?
            .into_iter()
            .take_while(|r| r.cursor() <= upto.cursor)
            .collect();
        let Some(last_row) = rows.last() else {
            return Ok(written);
        };
        after = last_row.cursor();
        for r in &rows {
            hashes.push(leaf(r)?);
            end = r.cursor();
        }
        if hashes.len() == TILE {
            store
                .append_tile(&TileRow {
                    level: 0,
                    n,
                    hashes: std::mem::take(&mut hashes),
                    end,
                })
                .await?;
            written = written.saturating_add(1);
            n = n.saturating_add(1);
        }
    }
}

async fn extend_level<T: TileStore>(store: &T, level: u8) -> Result<u32, AuditError> {
    let below = level.checked_sub(1).ok_or(AuditError::Proof)?;
    let mut n = store
        .last_tile(level)
        .await?
        .map_or(0, |t| t.n.saturating_add(1));
    let mut written = 0_u32;
    loop {
        let lower = store.tiles(below, n.saturating_mul(WIDTH), PAGE).await?;
        if lower.len() < TILE {
            return Ok(written);
        }
        let end = lower.last().map(|t| t.end).ok_or(AuditError::Proof)?;
        let hashes = lower
            .iter()
            .map(|t| tile_root(&t.hashes))
            .collect::<Result<Vec<_>, _>>()?;
        store
            .append_tile(&TileRow {
                level,
                n,
                hashes,
                end,
            })
            .await?;
        written = written.saturating_add(1);
        n = n.saturating_add(1);
    }
}

/// Writes every tile that is full behind `upto`, the latest checkpoint. Returns how many.
///
/// # Errors
/// [`AuditError`]; what was written stays and the next call continues.
pub async fn extend<T: TileStore>(store: &T, upto: &CheckpointRow) -> Result<u32, AuditError> {
    let mut written = extend_leaves(store, upto).await?;
    for level in 1..LEVELS {
        written = written.saturating_add(extend_level(store, level).await?);
    }
    Ok(written)
}

/// The entries of the last, partial tile of each level of a tree of `size`.
async fn partials<T: TileStore>(store: &T, size: u64) -> Result<Vec<Vec<Hash>>, AuditError> {
    let mut out = Vec::new();
    for level in 0..levels(size) {
        let want = entries(size, level) % WIDTH;
        let full = entries(size, level) / WIDTH;
        let have = if level == 0 {
            let after = match full.checked_sub(1) {
                Some(last) => store
                    .tiles(0, last, 1)
                    .await?
                    .first()
                    .filter(|t| t.n == last)
                    .map(|t| t.end)
                    .ok_or(AuditError::Proof)?,
                None => Cursor::default(),
            };
            let rows = store
                .rows_after(after, u32::try_from(want).map_err(|_| AuditError::Proof)?)
                .await?;
            rows.iter().map(leaf).collect::<Result<Vec<_>, _>>()?
        } else {
            let below = level.saturating_sub(1);
            let lower = store
                .tiles(
                    below,
                    full.saturating_mul(WIDTH),
                    u32::try_from(want).map_err(|_| AuditError::Proof)?,
                )
                .await?;
            lower
                .iter()
                .map(|t| tile_root(&t.hashes))
                .collect::<Result<Vec<_>, _>>()?
        };
        if page_len(have.len()) != want {
            return Err(AuditError::Proof);
        }
        out.push(have);
    }
    Ok(out)
}

/// Writes the full tiles of `level` a tree of `size` has, checking each level-(L≥1) tile against
/// the roots of the tiles below it; returns the roots of the tiles written.
async fn write_level<T: TileStore, S: ColdStore>(
    (store, cold): (&T, &S),
    (dir, size, level): (&str, u64, u8),
    below: &[Hash],
) -> Result<(Vec<Hash>, u32), AuditError> {
    let full = entries(size, level) / WIDTH;
    let mut roots = Vec::new();
    let mut n = 0_u64;
    while n < full {
        let page = store.tiles(level, n, PAGE).await?;
        if page.is_empty() {
            return Err(AuditError::Proof);
        }
        for t in page.into_iter().take_while(|t| t.n < full) {
            if t.n != n {
                return Err(AuditError::Proof);
            }
            if level > 0 {
                let from =
                    usize::try_from(n.saturating_mul(WIDTH)).map_err(|_| AuditError::Proof)?;
                let under = below
                    .get(from..from.saturating_add(TILE))
                    .ok_or(AuditError::Proof)?;
                if under != t.hashes.as_slice() {
                    return Err(AuditError::Proof);
                }
            }
            cold.put(
                &format!("{dir}/{}", path(level, n, None)),
                &bytes(&t.hashes),
            )
            .await?;
            roots.push(tile_root(&t.hashes)?);
            n = n.saturating_add(1);
        }
    }
    Ok((roots, u32::try_from(full).unwrap_or(u32::MAX)))
}

/// Freezes one year at `checkpoint`, its last.
///
/// # Errors
/// [`AuditError::Proof`] when the tiles do not give the checkpoint's tree head; [`AuditError`]
/// otherwise. Nothing is recorded then, and objects already written are kept (write-once).
pub async fn freeze<T: TileStore, S: ColdStore>(
    (store, cold): (&T, &S),
    year: i32,
    checkpoint: Option<&CheckpointRow>,
) -> Result<ShardRow, AuditError> {
    let Some(cp) = checkpoint else {
        let empty = ShardRow {
            year,
            size: 0,
            root: tile_root(&[])?,
            note: None,
            tiles: 0,
        };
        store.append_shard(&empty).await?;
        return Ok(empty);
    };
    let note = cp.note.as_deref().ok_or(AuditError::Proof)?;
    let origin = note.lines().next().ok_or(AuditError::Proof)?;
    let dir = log_dir(origin);
    let edges = partials(store, cp.size).await?;
    if root_from_partials(cp.size, &edges)? != cp.root {
        return Err(AuditError::Proof);
    }
    let mut below: Vec<Hash> = Vec::new();
    let mut tiles = 0_u32;
    for level in 0..levels(cp.size) {
        let (roots, n) = write_level((store, cold), (&dir, cp.size, level), &below).await?;
        tiles = tiles.saturating_add(n);
        let edge = edges.get(usize::from(level)).ok_or(AuditError::Proof)?;
        if !edge.is_empty() {
            let full = entries(cp.size, level) / WIDTH;
            cold.put(
                &format!("{dir}/{}", path(level, full, Some(page_len(edge.len())))),
                &bytes(edge),
            )
            .await?;
            tiles = tiles.saturating_add(1);
        }
        below = roots;
    }
    cold.put(&format!("{dir}/shards/{year}/checkpoint"), note.as_bytes())
        .await?;
    let shard = ShardRow {
        year,
        size: cp.size,
        root: cp.root,
        note: Some(note.to_owned()),
        tiles,
    };
    store.append_shard(&shard).await?;
    Ok(shard)
}

/// Freezes every ended year not frozen yet, oldest first; stops at the first that fails.
///
/// # Errors
/// [`AuditError`]; the failed year and those after it are tried again next time.
pub async fn freeze_due<T: TileStore, S: ColdStore>(
    store: &T,
    cold: &S,
) -> Result<Vec<ShardRow>, AuditError> {
    let (first, now) = store.years().await?;
    let Some(first) = first else {
        return Ok(Vec::new());
    };
    let done = store.shards().await?;
    let mut out = Vec::new();
    for year in first..now {
        if done.iter().any(|s| s.year == year) {
            continue;
        }
        let cp = store.year_end(year).await?;
        if let Some(cp) = &cp {
            extend(store, cp).await?;
        }
        out.push(freeze((store, cold), year, cp.as_ref()).await?);
    }
    Ok(out)
}
