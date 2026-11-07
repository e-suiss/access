//! `Idempotency-Key` on the management API (TN-126, OP-151 m.3 (c)): keys, their scope, the
//! request digest a key is bound to, and the kept answer's encoding.

use super::SurfaceScope;

/// How long a first answer is kept (OP-151 m.3 (c): 24 hours).
pub const RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

/// How long a running request holds its key before a retry of the same request may take it
/// over: three whole-request timeouts (§14.6).
pub const LEASE_MS: u64 = 30_000;

/// Longest key (TN-126).
pub const MAX_KEY: usize = 255;

/// Largest answer kept.
pub const MAX_ANSWER: usize = 512 * 1024;

/// Whether `key` is a usable key: 1 to 255 visible ASCII characters (TN-126).
#[must_use]
pub fn valid_key(key: &[u8]) -> bool {
    !key.is_empty() && key.len() <= MAX_KEY && key.iter().all(|c| (0x21..=0x7e).contains(c))
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(&u64::try_from(p.len()).unwrap_or(u64::MAX).to_be_bytes());
        buf.extend_from_slice(p);
    }
    suiss_crypto::digest::sha256(&buf)
}

/// The key's scope: (surface, caller, key) (OP-151 m.3 (c)). Another caller's identical key is
/// another scope and never reads this one's answer.
#[must_use]
pub fn scope(surface: &SurfaceScope, caller: &[u8; 32], key: &[u8]) -> [u8; 32] {
    digest(&[
        b"access/api-idempotency/v1",
        surface.key().as_bytes(),
        caller,
        key,
    ])
}

/// The digest a key is bound to: method, path, query and body. Another request under the key
/// is `422` (TN-126, TI-8).
#[must_use]
pub fn request(method: &str, path_and_query: &str, body: &[u8]) -> [u8; 32] {
    digest(&[method.as_bytes(), path_and_query.as_bytes(), body])
}

/// A kept answer: status, the headers to replay and the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// HTTP status.
    pub status: u16,
    /// Header names and values.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Body.
    pub body: Vec<u8>,
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    out.extend_from_slice(&u32::try_from(bytes.len()).ok()?.to_be_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

fn get<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, rest) = input.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    let (item, rest) = rest.split_at_checked(len)?;
    *input = rest;
    Some(item)
}

impl Answer {
    /// The stored form; `None` when it is larger than [`MAX_ANSWER`].
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.status.to_be_bytes());
        out.extend_from_slice(&u32::try_from(self.headers.len()).ok()?.to_be_bytes());
        for (name, value) in &self.headers {
            put(&mut out, name.as_bytes())?;
            put(&mut out, value)?;
        }
        put(&mut out, &self.body)?;
        (out.len() <= MAX_ANSWER).then_some(out)
    }

    /// Reads the stored form.
    #[must_use]
    pub fn decode(mut input: &[u8]) -> Option<Self> {
        let (status, rest) = input.split_first_chunk::<2>()?;
        let status = u16::from_be_bytes(*status);
        let (count, rest) = rest.split_first_chunk::<4>()?;
        let count = u32::from_be_bytes(*count);
        input = rest;
        let mut headers = Vec::new();
        for _ in 0..count {
            let name = std::str::from_utf8(get(&mut input)?).ok()?.to_owned();
            let value = get(&mut input)?.to_vec();
            headers.push((name, value));
        }
        let body = get(&mut input)?.to_vec();
        input.is_empty().then_some(Self {
            status,
            headers,
            body,
        })
    }
}
