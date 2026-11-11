//! The identity audit tree as C2SP tlog-tiles (OP-37, OP-158 m.3 (w)): tiles of height 8, 256
//! hashes each; a level-0 tile holds leaf hashes, a level-L tile the roots of 256 level-(L-1)
//! tiles. Pure.

use suiss_ledger::Hash;
use suiss_ledger::merkle::Frontier;

use crate::AuditError;

/// Hashes in a full tile.
pub const WIDTH: u64 = 256;

/// Tile height in tree levels.
pub const HEIGHT: u32 = 8;

/// The deepest tile level: eight levels cover every `u64` tree size.
pub const LEVELS: u8 = 8;

/// The C2SP tile path `tile/<L>/<N>[.p/<W>]`, the index in 3-digit groups with `x` before each
/// group but the last.
#[must_use]
pub fn path(level: u8, n: u64, partial: Option<u64>) -> String {
    let digits = format!("{n}");
    let pad = match digits.len() % 3 {
        1 => "00",
        2 => "0",
        _ => "",
    };
    let padded = format!("{pad}{digits}");
    let groups: Vec<&str> = padded
        .as_bytes()
        .chunks(3)
        .map(|g| std::str::from_utf8(g).unwrap_or_default())
        .collect();
    let mut index = String::new();
    for (i, g) in groups.iter().enumerate() {
        if i.saturating_add(1) < groups.len() {
            index.push('x');
            index.push_str(g);
            index.push('/');
        } else {
            index.push_str(g);
        }
    }
    match partial {
        Some(w) => format!("tile/{level}/{index}.p/{w}"),
        None => format!("tile/{level}/{index}"),
    }
}

/// The directory of a log's static objects, from its origin.
#[must_use]
pub fn log_dir(origin: &str) -> String {
    let log: String = origin
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("tiles/{log}")
}

/// The root of a tile's entries (a perfect subtree when the tile is full).
///
/// # Errors
/// [`AuditError::Frontier`].
pub fn tile_root(entries: &[Hash]) -> Result<Hash, AuditError> {
    let mut f = Frontier::default();
    for e in entries {
        f.push(*e)?;
    }
    Ok(f.root())
}

/// Entries of level `level` in a tree of `size` leaves: the complete subtrees of `256^level`.
#[must_use]
pub fn entries(size: u64, level: u8) -> u64 {
    size.checked_shr(HEIGHT.saturating_mul(u32::from(level)))
        .unwrap_or(0)
}

/// The levels a tree of `size` has tiles at.
#[must_use]
pub fn levels(size: u64) -> u8 {
    (0..LEVELS)
        .take_while(|l| entries(size, *l) > 0)
        .fold(0, |n, _| n.saturating_add(1))
}

/// The tile bytes: the hashes, concatenated.
#[must_use]
pub fn bytes(entries: &[Hash]) -> Vec<u8> {
    entries.iter().flatten().copied().collect()
}

/// The tree head of `size` from the entries of the last, partial tile of each level
/// (`partials[L]` holds `entries(size, L) % 256` hashes): its frontier is one perfect subtree per
/// set bit of `size`, and each lies in one of those tiles.
///
/// # Errors
/// [`AuditError::Proof`] when a level holds the wrong number of entries.
pub fn root_from_partials(size: u64, partials: &[Vec<Hash>]) -> Result<Hash, AuditError> {
    let mut nodes = Vec::new();
    for level in (0..levels(size)).rev() {
        let want = entries(size, level) % WIDTH;
        let have = partials.get(usize::from(level)).ok_or(AuditError::Proof)?;
        if u64::try_from(have.len()).ok() != Some(want) {
            return Err(AuditError::Proof);
        }
        let mut at = 0_usize;
        for bit in (0..HEIGHT).rev() {
            if want & (1 << bit) == 0 {
                continue;
            }
            let span = 1_usize << bit;
            let end = at.checked_add(span).ok_or(AuditError::Proof)?;
            nodes.push(tile_root(have.get(at..end).ok_or(AuditError::Proof)?)?);
            at = end;
        }
    }
    Ok(Frontier::from_parts(size, nodes)?.root())
}

#[cfg(test)]
mod tests;
