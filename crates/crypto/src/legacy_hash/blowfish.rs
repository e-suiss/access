//! bcrypt's `EksBlowfish` (Provos and Mazières, OpenBSD `bcrypt.c`), only for verifying
//! imported legacy hashes.

use zeroize::{Zeroize, Zeroizing};

use super::blowfish_tables::{P, S};

/// Longest password bcrypt reads, in bytes.
pub(super) const MAX_KEY: usize = 72;

const CTEXT: &[u8; 24] = b"OrpheanBeholderScryDoubt";

struct State {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Drop for State {
    fn drop(&mut self) {
        self.p.zeroize();
        for b in &mut self.s {
            b.zeroize();
        }
    }
}

fn word(stream: &mut impl Iterator<Item = u8>) -> u32 {
    let mut w = [0u8; 4];
    for b in &mut w {
        *b = stream.next().unwrap_or(0);
    }
    u32::from_be_bytes(w)
}

impl State {
    fn new() -> Self {
        Self { p: P, s: S }
    }

    fn f(&self, x: u32) -> u32 {
        let [x0, x1, x2, x3] = x.to_be_bytes();
        let [s0, s1, s2, s3] = &self.s;
        let pick = |sbox: &[u32; 256], i: u8| sbox.get(usize::from(i)).copied().unwrap_or(0);
        (pick(s0, x0).wrapping_add(pick(s1, x1)) ^ pick(s2, x2)).wrapping_add(pick(s3, x3))
    }

    fn encipher(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        let [p0, mid @ .., p17] = &self.p;
        l ^= p0;
        for [pa, pb] in mid.as_chunks::<2>().0 {
            r ^= self.f(l) ^ pa;
            l ^= self.f(r) ^ pb;
        }
        r ^= p17;
        (r, l)
    }

    fn expand(&mut self, salt: Option<&[u8; 16]>, key: &[u8]) {
        let mut k = key.iter().copied().cycle();
        for p in &mut self.p {
            *p ^= word(&mut k);
        }
        let mut sw = salt.map(|s| s.iter().copied().cycle());
        let (mut l, mut r) = (0u32, 0u32);
        for i in (0..18).step_by(2) {
            if let Some(s) = sw.as_mut() {
                l ^= word(s);
                r ^= word(s);
            }
            (l, r) = self.encipher(l, r);
            if let Some(x) = self.p.get_mut(i) {
                *x = l;
            }
            if let Some(x) = self.p.get_mut(i.wrapping_add(1)) {
                *x = r;
            }
        }
        for b in 0..4 {
            for i in (0..256).step_by(2) {
                if let Some(s) = sw.as_mut() {
                    l ^= word(s);
                    r ^= word(s);
                }
                (l, r) = self.encipher(l, r);
                if let Some(sb) = self.s.get_mut(b) {
                    if let Some(x) = sb.get_mut(i) {
                        *x = l;
                    }
                    if let Some(x) = sb.get_mut(i.wrapping_add(1)) {
                        *x = r;
                    }
                }
            }
        }
    }
}

/// The 24-byte bcrypt output for `cost` (`2^cost` rounds), `salt` and `password`; the
/// password is cut at [`MAX_KEY`] bytes and NUL-terminated as in OpenBSD. `None` when
/// `cost` is outside 4..=31.
pub(super) fn bcrypt(cost: u32, salt: &[u8; 16], password: &[u8]) -> Option<[u8; 24]> {
    if !(4..=31).contains(&cost) {
        return None;
    }
    let rounds = 1u64.checked_shl(cost)?;
    let mut key = Zeroizing::new(Vec::with_capacity(MAX_KEY.saturating_add(1)));
    key.extend(password.iter().take(MAX_KEY));
    key.push(0);
    let mut st = State::new();
    st.expand(Some(salt), &key);
    for _ in 0..rounds {
        st.expand(None, &key);
        st.expand(None, salt);
    }
    let mut c = [0u32; 6];
    for (w, bytes) in c.iter_mut().zip(CTEXT.as_chunks::<4>().0) {
        *w = u32::from_be_bytes(*bytes);
    }
    for _ in 0..64 {
        for [l, r] in c.as_chunks_mut::<2>().0 {
            (*l, *r) = st.encipher(*l, *r);
        }
    }
    let mut out = [0u8; 24];
    for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(c.iter()) {
        *o = w.to_be_bytes();
    }
    Some(out)
}
