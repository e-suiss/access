//! A roaring bitmap of `u32` (§9.7A.1, OP-158 m.3 (u)): 16-bit high keys, each with an array
//! container (at most 4 096 sorted low halves) or a 65 536-bit bitmap container. The wire form
//! is the portable roaring format without run containers (cookie 12346), so another roaring
//! reader can open it.

use std::collections::BTreeMap;

/// Largest array container; one more value turns it into a bitmap (the roaring rule).
pub const ARRAY_MAX: usize = 4_096;

/// Words of a bitmap container.
const WORDS: usize = 1_024;

/// The portable cookie of a roaring bitmap without run containers.
pub const COOKIE: u32 = 12_346;

/// Why bytes are not a roaring bitmap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BitmapError {
    /// The bytes end before the form does, or go on after it.
    #[error("truncated or trailing bytes")]
    Length,
    /// The cookie is not 12346 (run containers are not read).
    #[error("unknown cookie")]
    Cookie,
    /// Keys are not strictly increasing, an array is not sorted, an offset is wrong or a
    /// cardinality does not match its container.
    #[error("malformed container")]
    Container,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Container {
    Array(Vec<u16>),
    Bits(Box<[u64; WORDS]>),
}

impl Container {
    fn len(&self) -> usize {
        match self {
            Self::Array(a) => a.len(),
            Self::Bits(b) => b
                .iter()
                .map(|w| usize::try_from(w.count_ones()).unwrap_or(0))
                .sum(),
        }
    }

    fn contains(&self, low: u16) -> bool {
        match self {
            Self::Array(a) => a.binary_search(&low).is_ok(),
            Self::Bits(b) => {
                let (w, bit) = (usize::from(low >> 6), u32::from(low & 63));
                b.get(w).is_some_and(|word| word & (1u64 << bit) != 0)
            }
        }
    }

    fn insert(&mut self, low: u16) -> bool {
        match self {
            Self::Array(a) => match a.binary_search(&low) {
                Ok(_) => false,
                Err(i) => {
                    a.insert(i, low);
                    if a.len() > ARRAY_MAX {
                        *self = Self::Bits(to_bits(a));
                    }
                    true
                }
            },
            Self::Bits(b) => {
                let (w, bit) = (usize::from(low >> 6), u32::from(low & 63));
                let Some(word) = b.get_mut(w) else {
                    return false;
                };
                let was = *word & (1u64 << bit) != 0;
                *word |= 1u64 << bit;
                !was
            }
        }
    }

    fn remove(&mut self, low: u16) -> bool {
        match self {
            Self::Array(a) => match a.binary_search(&low) {
                Ok(i) => {
                    a.remove(i);
                    true
                }
                Err(_) => false,
            },
            Self::Bits(b) => {
                let (w, bit) = (usize::from(low >> 6), u32::from(low & 63));
                let Some(word) = b.get_mut(w) else {
                    return false;
                };
                let was = *word & (1u64 << bit) != 0;
                *word &= !(1u64 << bit);
                if was && self.len() <= ARRAY_MAX {
                    *self = Self::Array(self.lows());
                }
                was
            }
        }
    }

    fn lows(&self) -> Vec<u16> {
        match self {
            Self::Array(a) => a.clone(),
            Self::Bits(b) => (0..=u16::MAX)
                .filter(|low| {
                    let (w, bit) = (usize::from(low >> 6), u32::from(low & 63));
                    b.get(w).is_some_and(|word| word & (1u64 << bit) != 0)
                })
                .collect(),
        }
    }

    fn and(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Bits(a), Self::Bits(b)) => {
                let mut out = Box::new([0u64; WORDS]);
                for ((o, x), y) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
                    *o = x & y;
                }
                let c = Self::Bits(out);
                if c.len() <= ARRAY_MAX {
                    Self::Array(c.lows())
                } else {
                    c
                }
            }
            (Self::Array(a), b) | (b, Self::Array(a)) => {
                Self::Array(a.iter().copied().filter(|l| b.contains(*l)).collect())
            }
        }
    }
}

fn to_bits(lows: &[u16]) -> Box<[u64; WORDS]> {
    let mut b = Box::new([0u64; WORDS]);
    for low in lows {
        let (w, bit) = (usize::from(low >> 6), u32::from(low & 63));
        if let Some(word) = b.get_mut(w) {
            *word |= 1u64 << bit;
        }
    }
    b
}

/// A set of `u32`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bitmap {
    containers: BTreeMap<u16, Container>,
}

const fn split(v: u32) -> (u16, u16) {
    #[expect(clippy::cast_possible_truncation, reason = "the two halves of a u32")]
    ((v >> 16) as u16, v as u16)
}

impl Bitmap {
    /// The empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            containers: BTreeMap::new(),
        }
    }

    /// Adds `v`; whether it was new.
    pub fn insert(&mut self, v: u32) -> bool {
        let (high, low) = split(v);
        self.containers
            .entry(high)
            .or_insert_with(|| Container::Array(Vec::new()))
            .insert(low)
    }

    /// Removes `v`; whether it was there.
    pub fn remove(&mut self, v: u32) -> bool {
        let (high, low) = split(v);
        let Some(c) = self.containers.get_mut(&high) else {
            return false;
        };
        let was = c.remove(low);
        if c.len() == 0 {
            self.containers.remove(&high);
        }
        was
    }

    /// Whether `v` is in the set.
    #[must_use]
    pub fn contains(&self, v: u32) -> bool {
        let (high, low) = split(v);
        self.containers.get(&high).is_some_and(|c| c.contains(low))
    }

    /// Number of values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.containers.values().map(Container::len).sum()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.containers.is_empty()
    }

    /// The values in increasing order.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.containers.iter().flat_map(|(high, c)| {
            c.lows()
                .into_iter()
                .map(move |low| (u32::from(*high) << 16) | u32::from(low))
        })
    }

    /// The values in both sets (Leopard's `MEMBER2GROUP(U) ∩ GROUP2GROUP(G)`).
    #[must_use]
    pub fn and(&self, other: &Self) -> Self {
        let mut out = Self::new();
        for (high, a) in &self.containers {
            if let Some(b) = other.containers.get(high) {
                let c = a.and(b);
                if c.len() > 0 {
                    out.containers.insert(*high, c);
                }
            }
        }
        out
    }

    /// Whether the two sets share a value.
    #[must_use]
    pub fn intersects(&self, other: &Self) -> bool {
        self.containers.iter().any(|(high, a)| {
            other
                .containers
                .get(high)
                .is_some_and(|b| a.and(b).len() > 0)
        })
    }

    /// The portable roaring form (no run containers).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&COOKIE.to_le_bytes());
        let n = u32::try_from(self.containers.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&n.to_le_bytes());
        for (high, c) in &self.containers {
            out.extend_from_slice(&high.to_le_bytes());
            let card = u16::try_from(c.len().saturating_sub(1)).unwrap_or(u16::MAX);
            out.extend_from_slice(&card.to_le_bytes());
        }
        let header = 8usize.saturating_add(self.containers.len().saturating_mul(8));
        let mut offset = header;
        for c in self.containers.values() {
            out.extend_from_slice(&u32::try_from(offset).unwrap_or(u32::MAX).to_le_bytes());
            offset = offset.saturating_add(body_len(c.len()));
        }
        for c in self.containers.values() {
            match c {
                Container::Array(a) if a.len() <= ARRAY_MAX => {
                    for low in a {
                        out.extend_from_slice(&low.to_le_bytes());
                    }
                }
                Container::Array(a) => {
                    for w in &*to_bits(a) {
                        out.extend_from_slice(&w.to_le_bytes());
                    }
                }
                Container::Bits(b) => {
                    for w in b.as_ref() {
                        out.extend_from_slice(&w.to_le_bytes());
                    }
                }
            }
        }
        out
    }

    /// Reads the portable roaring form, checking every count against the bytes present: keys
    /// strictly increasing, arrays strictly sorted, offsets exact and nothing after the last
    /// container.
    ///
    /// # Errors
    /// [`BitmapError`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BitmapError> {
        let mut r = Cursor { bytes, at: 0 };
        if r.u32()? != COOKIE {
            return Err(BitmapError::Cookie);
        }
        let n = usize::try_from(r.u32()?).map_err(|_| BitmapError::Length)?;
        if n > 1 << 16 {
            return Err(BitmapError::Container);
        }
        let header = n.checked_mul(8).ok_or(BitmapError::Length)?;
        if bytes.len().saturating_sub(8) < header {
            return Err(BitmapError::Length);
        }
        let mut descriptors = Vec::new();
        let mut last: Option<u16> = None;
        for _ in 0..n {
            let high = r.u16()?;
            if last.is_some_and(|l| l >= high) {
                return Err(BitmapError::Container);
            }
            last = Some(high);
            let card = usize::from(r.u16()?).saturating_add(1);
            descriptors.push((high, card));
        }
        let mut expected = 8usize.saturating_add(header);
        for (_, card) in &descriptors {
            let offset = usize::try_from(r.u32()?).map_err(|_| BitmapError::Length)?;
            if offset != expected {
                return Err(BitmapError::Container);
            }
            expected = expected.saturating_add(body_len(*card));
        }
        let mut containers = BTreeMap::new();
        for (high, card) in descriptors {
            let c = if card <= ARRAY_MAX {
                let mut a = Vec::new();
                for _ in 0..card {
                    let low = r.u16()?;
                    if a.last().is_some_and(|l| *l >= low) {
                        return Err(BitmapError::Container);
                    }
                    a.push(low);
                }
                Container::Array(a)
            } else {
                let mut b = Box::new([0u64; WORDS]);
                for w in b.as_mut_slice() {
                    *w = r.u64()?;
                }
                let c = Container::Bits(b);
                if c.len() != card {
                    return Err(BitmapError::Container);
                }
                c
            };
            containers.insert(high, c);
        }
        if r.at != bytes.len() {
            return Err(BitmapError::Length);
        }
        Ok(Self { containers })
    }
}

const fn body_len(card: usize) -> usize {
    if card <= ARRAY_MAX {
        card.saturating_mul(2)
    } else {
        WORDS * 8
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], BitmapError> {
        let end = self.at.checked_add(N).ok_or(BitmapError::Length)?;
        let s = self.bytes.get(self.at..end).ok_or(BitmapError::Length)?;
        self.at = end;
        <[u8; N]>::try_from(s).map_err(|_| BitmapError::Length)
    }

    fn u16(&mut self) -> Result<u16, BitmapError> {
        self.take::<2>().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Result<u32, BitmapError> {
        self.take::<4>().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Result<u64, BitmapError> {
        self.take::<8>().map(u64::from_le_bytes)
    }
}

impl FromIterator<u32> for Bitmap {
    fn from_iter<I: IntoIterator<Item = u32>>(iter: I) -> Self {
        let mut b = Self::new();
        for v in iter {
            b.insert(v);
        }
        b
    }
}

#[cfg(test)]
mod tests;
