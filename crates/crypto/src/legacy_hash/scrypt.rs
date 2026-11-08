//! scrypt (RFC 7914) over aws-lc-rs PBKDF2-HMAC-SHA-256, only for verifying imported legacy
//! hashes.

use core::num::NonZeroU32;

use aws_lc_rs::pbkdf2::{PBKDF2_HMAC_SHA256, derive};
use zeroize::{Zeroize, Zeroizing};

type Block = [u32; 16];

fn salsa20_8(b: &mut Block) {
    let mut x = *b;
    for _ in 0..4 {
        let qr = |st: &mut Block, ia: usize, ib: usize, ic: usize, id: usize| {
            let get = |st: &Block, i: usize| st.get(i).copied().unwrap_or(0);
            let set = |st: &mut Block, i: usize, v: u32| {
                if let Some(slot) = st.get_mut(i) {
                    *slot = v;
                }
            };
            let v = get(st, ib) ^ get(st, ia).wrapping_add(get(st, id)).rotate_left(7);
            set(st, ib, v);
            let v = get(st, ic) ^ get(st, ib).wrapping_add(get(st, ia)).rotate_left(9);
            set(st, ic, v);
            let v = get(st, id) ^ get(st, ic).wrapping_add(get(st, ib)).rotate_left(13);
            set(st, id, v);
            let v = get(st, ia) ^ get(st, id).wrapping_add(get(st, ic)).rotate_left(18);
            set(st, ia, v);
        };
        qr(&mut x, 0, 4, 8, 12);
        qr(&mut x, 5, 9, 13, 1);
        qr(&mut x, 10, 14, 2, 6);
        qr(&mut x, 15, 3, 7, 11);
        qr(&mut x, 0, 1, 2, 3);
        qr(&mut x, 5, 6, 7, 4);
        qr(&mut x, 10, 11, 8, 9);
        qr(&mut x, 15, 12, 13, 14);
    }
    for (o, v) in b.iter_mut().zip(x.iter()) {
        *o = o.wrapping_add(*v);
    }
    x.zeroize();
}

fn xor_into(a: &mut Block, b: &Block) {
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= y;
    }
}

fn block_mix(b: &[Block], y: &mut [Block]) {
    let mut x = b.last().copied().unwrap_or([0; 16]);
    let half = b.len() / 2;
    for (i, bi) in b.iter().enumerate() {
        xor_into(&mut x, bi);
        salsa20_8(&mut x);
        let slot = if i % 2 == 0 {
            i / 2
        } else {
            half.saturating_add(i / 2)
        };
        if let Some(s) = y.get_mut(slot) {
            *s = x;
        }
    }
    x.zeroize();
}

fn ro_mix(x: &mut [Block], n: usize) -> Option<()> {
    let len = x.len();
    let mut table: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::with_capacity(len.checked_mul(n)?));
    let mut scratch: Zeroizing<Vec<Block>> = Zeroizing::new(vec![[0; 16]; len]);
    for _ in 0..n {
        table.extend_from_slice(x);
        block_mix(x, &mut scratch);
        x.copy_from_slice(&scratch);
    }
    let mask = u64::try_from(n).ok()?.checked_sub(1)?;
    for _ in 0..n {
        let last = x.last()?;
        let int = u64::from(last[0]) | u64::from(last[1]).checked_shl(32)?;
        let j = usize::try_from(int & mask).ok()?;
        let start = j.checked_mul(len)?;
        let slot = table.get(start..start.checked_add(len)?)?;
        for (cur, old) in x.iter_mut().zip(slot.iter()) {
            xor_into(cur, old);
        }
        block_mix(x, &mut scratch);
        x.copy_from_slice(&scratch);
    }
    Some(())
}

/// scrypt with `N = n` (a power of two), `r`, `p`; `None` on parameters out of range.
pub(super) fn scrypt(
    password: &[u8],
    salt: &[u8],
    n: u64,
    r: u32,
    p: u32,
    out: &mut [u8],
) -> Option<()> {
    if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 || out.is_empty() {
        return None;
    }
    let one = NonZeroU32::new(1)?;
    let r = usize::try_from(r).ok()?;
    let block_bytes = r.checked_mul(128)?;
    let total = block_bytes.checked_mul(usize::try_from(p).ok()?)?;
    let mut buf = Zeroizing::new(vec![0u8; total]);
    derive(PBKDF2_HMAC_SHA256, one, salt, password, &mut buf);
    let n = usize::try_from(n).ok()?;
    for chunk in buf.chunks_exact_mut(block_bytes) {
        let mut words: Vec<Block> = chunk
            .as_chunks::<64>()
            .0
            .iter()
            .map(|blk| {
                let mut w = [0u32; 16];
                for (o, le) in w.iter_mut().zip(blk.as_chunks::<4>().0) {
                    *o = u32::from_le_bytes(*le);
                }
                w
            })
            .collect();
        let mixed = ro_mix(&mut words, n);
        for (le, w) in chunk
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(words.iter().flatten())
        {
            *le = w.to_le_bytes();
        }
        words.zeroize();
        mixed?;
    }
    derive(PBKDF2_HMAC_SHA256, one, &buf, password, out);
    Some(())
}
