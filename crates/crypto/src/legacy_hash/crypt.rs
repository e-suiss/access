//! Digests and the `crypt(3)` families: md5-crypt (`$1$`, Kamp) and sha-crypt (`$5$`, `$6$`,
//! Drepper), with their own base64 orderings.

use aws_lc_rs::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA512};
use zeroize::Zeroizing;

use super::md5::md5;

/// A digest an imported hash names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Digest {
    /// MD5 (RFC 1321).
    Md5,
    /// SHA-1.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Digest {
    /// The digest of the concatenation of `parts`.
    pub(super) fn of(self, parts: &[&[u8]]) -> Zeroizing<Vec<u8>> {
        let alg = match self {
            Self::Md5 => return Zeroizing::new(md5(parts).to_vec()),
            Self::Sha1 => &SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &SHA256,
            Self::Sha512 => &SHA512,
        };
        let mut ctx = Context::new(alg);
        for p in parts {
            ctx.update(p);
        }
        Zeroizing::new(ctx.finish().as_ref().to_vec())
    }
}

/// The `crypt(3)` alphabet.
const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn to64(out: &mut String, d: &[u8], [b2, b1, b0]: [usize; 3], n: usize) {
    let byte = |i: usize| u32::from(d.get(i).copied().unwrap_or(0));
    let mut w = byte(b2).wrapping_shl(16) | byte(b1).wrapping_shl(8) | byte(b0);
    for _ in 0..n {
        let i = usize::try_from(w & 0x3f).unwrap_or(0);
        out.push(char::from(ITOA64.get(i).copied().unwrap_or(b'.')));
        w = w.wrapping_shr(6);
    }
}

/// An index past every digest, read as a zero byte.
const Z: usize = usize::MAX;

const MD5_ORDER: [[usize; 3]; 5] = [[0, 6, 12], [1, 7, 13], [2, 8, 14], [3, 9, 15], [4, 10, 5]];

const SHA256_ORDER: [[usize; 3]; 10] = [
    [0, 10, 20],
    [21, 1, 11],
    [12, 22, 2],
    [3, 13, 23],
    [24, 4, 14],
    [15, 25, 5],
    [6, 16, 26],
    [27, 7, 17],
    [18, 28, 8],
    [9, 19, 29],
];

const SHA512_ORDER: [[usize; 3]; 21] = [
    [0, 21, 42],
    [22, 43, 1],
    [44, 2, 23],
    [3, 24, 45],
    [25, 46, 4],
    [47, 5, 26],
    [6, 27, 48],
    [28, 49, 7],
    [50, 8, 29],
    [9, 30, 51],
    [31, 52, 10],
    [53, 11, 32],
    [12, 33, 54],
    [34, 55, 13],
    [56, 14, 35],
    [15, 36, 57],
    [37, 58, 16],
    [59, 17, 38],
    [18, 39, 60],
    [40, 61, 19],
    [62, 20, 41],
];

fn encode(d: &[u8], order: &[[usize; 3]], tail: [usize; 3], tail_n: usize) -> String {
    let mut out = String::with_capacity(order.len().saturating_mul(4).saturating_add(4));
    for g in order {
        to64(&mut out, d, *g, 4);
    }
    to64(&mut out, d, tail, tail_n);
    out
}

fn cycled(block: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(block.iter().copied().cycle().take(len).collect())
}

/// md5-crypt: the 22-character hash for `password` and `salt` (at most 8 bytes are read).
pub(super) fn md5_crypt(password: &[u8], salt: &[u8]) -> String {
    let salt = salt.get(..salt.len().min(8)).unwrap_or_default();
    let alt = md5(&[password, salt, password]);
    let mut ctx: Zeroizing<Vec<u8>> = Zeroizing::new([password, b"$1$", salt].concat());
    ctx.extend(cycled(&alt, password.len()).iter());
    let mut i = password.len();
    while i > 0 {
        if i & 1 == 1 {
            ctx.push(0);
        } else {
            ctx.push(password.first().copied().unwrap_or(0));
        }
        i = i.wrapping_shr(1);
    }
    let mut fin = md5(&[&ctx]);
    for r in 0..1000u32 {
        let odd = r & 1 == 1;
        let mut parts: Vec<&[u8]> = Vec::with_capacity(4);
        parts.push(if odd { password } else { &fin });
        if r % 3 != 0 {
            parts.push(salt);
        }
        if r % 7 != 0 {
            parts.push(password);
        }
        parts.push(if odd { &fin } else { password });
        let next = md5(&parts);
        fin = next;
    }
    encode(&fin, &MD5_ORDER, [Z, Z, 11], 2)
}

/// sha-crypt default rounds.
pub(super) const SHA_CRYPT_DEFAULT_ROUNDS: u32 = 5000;

/// sha-crypt: the hash part for `password`, `salt` (at most 16 bytes are read) and `rounds`
/// (clamped to 1000..=999 999 999 as in Drepper's specification).
pub(super) fn sha_crypt(sha512: bool, password: &[u8], salt: &[u8], rounds: u32) -> String {
    let hash = if sha512 {
        Digest::Sha512
    } else {
        Digest::Sha256
    };
    let rounds = rounds.clamp(1000, 999_999_999);
    let salt = salt.get(..salt.len().min(16)).unwrap_or_default();
    let alt = hash.of(&[password, salt, password]);
    let mut a_in: Zeroizing<Vec<u8>> = Zeroizing::new([password, salt].concat());
    a_in.extend(cycled(&alt, password.len()).iter());
    let mut bit = password.len();
    while bit > 0 {
        if bit & 1 == 1 {
            a_in.extend_from_slice(&alt);
        } else {
            a_in.extend_from_slice(password);
        }
        bit = bit.wrapping_shr(1);
    }
    let mut acc = hash.of(&[&a_in]);
    let pw_rep: Zeroizing<Vec<u8>> = Zeroizing::new(password.repeat(password.len()));
    let pseq = cycled(&hash.of(&[&pw_rep]), password.len());
    let first = usize::from(acc.first().copied().unwrap_or(0));
    let salt_rep: Zeroizing<Vec<u8>> = Zeroizing::new(salt.repeat(first.saturating_add(16)));
    let sseq = cycled(&hash.of(&[&salt_rep]), salt.len());
    for round in 0..rounds {
        let odd = round & 1 == 1;
        let mut parts: Vec<&[u8]> = Vec::with_capacity(4);
        parts.push(if odd { &pseq } else { &acc });
        if round % 3 != 0 {
            parts.push(&sseq);
        }
        if round % 7 != 0 {
            parts.push(&pseq);
        }
        parts.push(if odd { &acc } else { &pseq });
        let next = hash.of(&parts);
        acc = next;
    }
    if sha512 {
        encode(&acc, &SHA512_ORDER, [Z, Z, 63], 2)
    } else {
        encode(&acc, &SHA256_ORDER, [Z, 31, 30], 3)
    }
}
