//! Roughtime client messages (draft-ietf-ntp-roughtime, version `0x8000000c`), sans-I/O: the
//! request packet for a caller-drawn nonce and the verification of a server's answer against
//! its long-term Ed25519 key (TI-RT2, FA-3, OP-158 m.3 (k)). The driver sends the packet over
//! UDP and feeds the answer back.

use alloc::vec::Vec;

use sha2::{Digest as _, Sha512};

use crate::sig::Backend;

/// The protocol version this client speaks.
pub const VERSION: u32 = 0x8000_000c;

/// Smallest request packet a server answers (amplification bound).
pub const MIN_REQUEST: usize = 1024;

/// Largest answer the client reads.
pub const MAX_RESPONSE: usize = 4096;

const MAGIC: &[u8; 8] = b"ROUGHTIM";
const DELEGATION_CONTEXT: &[u8] = b"RoughTime v1 delegation signature\0";
const RESPONSE_CONTEXT: &[u8] = b"RoughTime v1 response signature\0";
const MAX_TAGS: usize = 64;

/// Message tags, read as little-endian `u32`.
#[allow(
    missing_docs,
    reason = "the names are the protocol's own four-letter tags"
)]
pub mod tag {
    const fn t(b: [u8; 4]) -> u32 {
        u32::from_le_bytes(b)
    }
    pub const SIG: u32 = t(*b"SIG\0");
    pub const VER: u32 = t(*b"VER\0");
    pub const NONC: u32 = t(*b"NONC");
    pub const DELE: u32 = t(*b"DELE");
    pub const PATH: u32 = t(*b"PATH");
    pub const RADI: u32 = t(*b"RADI");
    pub const PUBK: u32 = t(*b"PUBK");
    pub const MIDP: u32 = t(*b"MIDP");
    pub const SREP: u32 = t(*b"SREP");
    pub const MINT: u32 = t(*b"MINT");
    pub const ROOT: u32 = t(*b"ROOT");
    pub const CERT: u32 = t(*b"CERT");
    pub const MAXT: u32 = t(*b"MAXT");
    pub const INDX: u32 = t(*b"INDX");
    pub const ZZZZ: u32 = t(*b"ZZZZ");
}

/// Why an answer is not a trusted reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RoughtimeError {
    /// The packet or a nested message is malformed.
    #[error("malformed message")]
    Malformed,
    /// A required tag is missing.
    #[error("missing tag")]
    Missing,
    /// The server speaks another version.
    #[error("version")]
    Version,
    /// The answer is not for this request's nonce or is not in the server's Merkle tree.
    #[error("not an answer to this request")]
    Unrelated,
    /// A signature does not verify under the long-term or the delegated key.
    #[error("signature")]
    Signature,
    /// The midpoint lies outside the delegation's validity.
    #[error("outside the delegation window")]
    Window,
}

/// A verified reading: the midpoint and radius the server signed, in seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    /// Seconds since the Unix epoch.
    pub midpoint: u64,
    /// Seconds either side of the midpoint.
    pub radius: u32,
}

impl Reading {
    /// The midpoint in Unix milliseconds.
    #[must_use]
    pub const fn midpoint_ms(&self) -> u64 {
        self.midpoint.saturating_mul(1000)
    }

    /// The radius in milliseconds.
    #[must_use]
    pub const fn radius_ms(&self) -> u64 {
        (self.radius as u64).saturating_mul(1000)
    }
}

/// Encodes a tag-value message; `fields` must be sorted by tag and each value a multiple of
/// four bytes.
///
/// # Errors
/// [`RoughtimeError::Malformed`].
pub fn encode(fields: &[(u32, &[u8])]) -> Result<Vec<u8>, RoughtimeError> {
    let n = u32::try_from(fields.len()).map_err(|_| RoughtimeError::Malformed)?;
    if fields.windows(2).any(|w| matches!(w, [a, b] if a.0 >= b.0))
        || fields.iter().any(|(_, v)| v.len() % 4 != 0)
    {
        return Err(RoughtimeError::Malformed);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&n.to_le_bytes());
    let mut offset = 0_u32;
    for (_, v) in fields.iter().take(fields.len().saturating_sub(1)) {
        let len = u32::try_from(v.len()).map_err(|_| RoughtimeError::Malformed)?;
        offset = offset.checked_add(len).ok_or(RoughtimeError::Malformed)?;
        out.extend_from_slice(&offset.to_le_bytes());
    }
    for (t, _) in fields {
        out.extend_from_slice(&t.to_le_bytes());
    }
    for (_, v) in fields {
        out.extend_from_slice(v);
    }
    Ok(out)
}

fn word(bytes: &[u8], at: usize) -> Result<u32, RoughtimeError> {
    let end = at.checked_add(4).ok_or(RoughtimeError::Malformed)?;
    let b: [u8; 4] = bytes
        .get(at..end)
        .and_then(|s| s.try_into().ok())
        .ok_or(RoughtimeError::Malformed)?;
    Ok(u32::from_le_bytes(b))
}

fn index(n: u32) -> Result<usize, RoughtimeError> {
    usize::try_from(n).map_err(|_| RoughtimeError::Malformed)
}

/// Decodes a tag-value message into its fields, in order.
///
/// # Errors
/// [`RoughtimeError::Malformed`].
pub fn decode(msg: &[u8]) -> Result<Vec<(u32, &[u8])>, RoughtimeError> {
    let n = index(word(msg, 0)?)?;
    if n == 0 || n > MAX_TAGS {
        return Err(RoughtimeError::Malformed);
    }
    let header = n.checked_mul(8).ok_or(RoughtimeError::Malformed)?;
    let values = msg.get(header..).ok_or(RoughtimeError::Malformed)?;
    if values.len() % 4 != 0 {
        return Err(RoughtimeError::Malformed);
    }
    let mut bounds = Vec::new();
    bounds.push(0_usize);
    for i in 1..n {
        bounds.push(index(word(
            msg,
            i.checked_mul(4).ok_or(RoughtimeError::Malformed)?,
        )?)?);
    }
    bounds.push(values.len());
    let mut out = Vec::new();
    let mut previous: Option<u32> = None;
    for i in 0..n {
        let at = n
            .checked_add(i)
            .and_then(|k| k.checked_sub(1))
            .and_then(|k| k.checked_mul(4))
            .and_then(|k| k.checked_add(4))
            .ok_or(RoughtimeError::Malformed)?;
        let t = word(msg, at)?;
        if previous.is_some_and(|p| p >= t) {
            return Err(RoughtimeError::Malformed);
        }
        previous = Some(t);
        let (Some(&lo), Some(&hi)) = (bounds.get(i), bounds.get(i.saturating_add(1))) else {
            return Err(RoughtimeError::Malformed);
        };
        if lo > hi || lo % 4 != 0 {
            return Err(RoughtimeError::Malformed);
        }
        out.push((t, values.get(lo..hi).ok_or(RoughtimeError::Malformed)?));
    }
    Ok(out)
}

fn get<'a>(fields: &[(u32, &'a [u8])], t: u32) -> Result<&'a [u8], RoughtimeError> {
    fields
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, v)| *v)
        .ok_or(RoughtimeError::Missing)
}

fn fixed<const N: usize>(fields: &[(u32, &[u8])], t: u32) -> Result<[u8; N], RoughtimeError> {
    get(fields, t)?
        .try_into()
        .map_err(|_| RoughtimeError::Malformed)
}

/// Frames a message as a packet.
///
/// # Errors
/// [`RoughtimeError::Malformed`].
pub fn frame(msg: &[u8]) -> Result<Vec<u8>, RoughtimeError> {
    let len = u32::try_from(msg.len()).map_err(|_| RoughtimeError::Malformed)?;
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(msg);
    Ok(out)
}

/// The message inside a packet.
///
/// # Errors
/// [`RoughtimeError::Malformed`].
pub fn unframe(packet: &[u8]) -> Result<&[u8], RoughtimeError> {
    let rest = packet
        .strip_prefix(MAGIC)
        .ok_or(RoughtimeError::Malformed)?;
    let len = index(word(rest, 0)?)?;
    let msg = rest.get(4..).ok_or(RoughtimeError::Malformed)?;
    if msg.len() != len {
        return Err(RoughtimeError::Malformed);
    }
    Ok(msg)
}

/// The request packet for `nonce`, padded to [`MIN_REQUEST`] bytes. The nonce is drawn by
/// the caller's RNG port, fresh for every request.
///
/// # Errors
/// [`RoughtimeError::Malformed`].
pub fn request(nonce: &[u8; 32]) -> Result<Vec<u8>, RoughtimeError> {
    let version = VERSION.to_le_bytes();
    let unpadded = encode(&[(tag::VER, &version), (tag::NONC, nonce), (tag::ZZZZ, &[])])?;
    let pad = MIN_REQUEST
        .saturating_sub(12)
        .saturating_sub(unpadded.len());
    let zeros: Vec<u8> = core::iter::repeat_n(0_u8, pad).collect();
    frame(&encode(&[
        (tag::VER, &version),
        (tag::NONC, nonce),
        (tag::ZZZZ, &zeros),
    ])?)
}

fn hash(prefix: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update([prefix]);
    for p in parts {
        h.update(p);
    }
    let full = h.finalize();
    full.get(..32)
        .and_then(|s| <[u8; 32]>::try_from(s).ok())
        .unwrap_or_default()
}

/// The Merkle leaf of a request packet.
#[must_use]
pub fn leaf(request: &[u8]) -> [u8; 32] {
    hash(0x00, &[request])
}

fn signed(context: &[u8], body: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(context);
    m.extend_from_slice(body);
    m
}

fn verify(
    backend: &impl Backend,
    key: &[u8; 32],
    context: &[u8],
    body: &[u8],
    sig: &[u8; 64],
) -> Result<(), RoughtimeError> {
    if backend.ed25519(key, &signed(context, body), sig) {
        Ok(())
    } else {
        Err(RoughtimeError::Signature)
    }
}

fn u64_of(fields: &[(u32, &[u8])], t: u32) -> Result<u64, RoughtimeError> {
    Ok(u64::from_le_bytes(fixed::<8>(fields, t)?))
}

/// Verifies `response` to the `request` packet that carried `nonce`, under the server's
/// long-term key `server`.
///
/// # Errors
/// [`RoughtimeError`]; the reading is not used.
pub fn verify_response(
    backend: &impl Backend,
    server: &[u8; 32],
    request: &[u8],
    nonce: &[u8; 32],
    response: &[u8],
) -> Result<Reading, RoughtimeError> {
    if response.len() > MAX_RESPONSE {
        return Err(RoughtimeError::Malformed);
    }
    let top = decode(unframe(response)?)?;
    if fixed::<4>(&top, tag::VER)? != VERSION.to_le_bytes() {
        return Err(RoughtimeError::Version);
    }
    if fixed::<32>(&top, tag::NONC)? != *nonce {
        return Err(RoughtimeError::Unrelated);
    }
    let cert = decode(get(&top, tag::CERT)?)?;
    let dele_bytes = get(&cert, tag::DELE)?;
    verify(
        backend,
        server,
        DELEGATION_CONTEXT,
        dele_bytes,
        &fixed::<64>(&cert, tag::SIG)?,
    )?;
    let dele = decode(dele_bytes)?;
    let online = fixed::<32>(&dele, tag::PUBK)?;
    let srep_bytes = get(&top, tag::SREP)?;
    verify(
        backend,
        &online,
        RESPONSE_CONTEXT,
        srep_bytes,
        &fixed::<64>(&top, tag::SIG)?,
    )?;
    let srep = decode(srep_bytes)?;
    let root = fixed::<32>(&srep, tag::ROOT)?;
    let mut node = leaf(request);
    let mut at = u32::from_le_bytes(fixed::<4>(&top, tag::INDX)?);
    let path = get(&top, tag::PATH)?;
    let (siblings, rest) = path.as_chunks::<32>();
    if !rest.is_empty() || siblings.len() > 32 {
        return Err(RoughtimeError::Malformed);
    }
    for sibling in siblings {
        node = if at & 1 == 0 {
            hash(0x01, &[&node, sibling.as_slice()])
        } else {
            hash(0x01, &[sibling.as_slice(), &node])
        };
        at >>= 1;
    }
    if at != 0 || node != root {
        return Err(RoughtimeError::Unrelated);
    }
    let midpoint = u64_of(&srep, tag::MIDP)?;
    let radius = u32::from_le_bytes(fixed::<4>(&srep, tag::RADI)?);
    if midpoint < u64_of(&dele, tag::MINT)? || midpoint > u64_of(&dele, tag::MAXT)? {
        return Err(RoughtimeError::Window);
    }
    Ok(Reading { midpoint, radius })
}

/// The nonce a request packet carries.
///
/// # Errors
/// [`RoughtimeError`].
pub fn nonce_of(request: &[u8]) -> Result<[u8; 32], RoughtimeError> {
    fixed::<32>(&decode(unframe(request)?)?, tag::NONC)
}

/// The answering side, as the local Roughtime twin runs it (OP-69: a real server, not a
/// stand-in clock): a long-term key that delegates to an online key for a window.
#[cfg(all(feature = "testing", feature = "signer"))]
pub mod responder {
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    use super::{
        DELEGATION_CONTEXT, MIN_REQUEST, RESPONSE_CONTEXT, RoughtimeError, VERSION, encode, frame,
        leaf, nonce_of, signed, tag,
    };
    use crate::signer::Signer;

    /// A server: its online key and the signed certificate of it.
    pub struct Responder {
        online: Box<dyn Signer + Send + Sync>,
        cert: Vec<u8>,
    }

    impl Responder {
        /// Delegates `online` for `mint..=maxt` seconds under `long_term`.
        ///
        /// # Errors
        /// [`RoughtimeError::Signature`] when a key cannot sign.
        pub fn new(
            long_term: &dyn Signer,
            online: Box<dyn Signer + Send + Sync>,
            mint: u64,
            maxt: u64,
        ) -> Result<Self, RoughtimeError> {
            let crate::cose::PublicKey::Ed25519(pubk) = online.public_key() else {
                return Err(RoughtimeError::Signature);
            };
            let dele = encode(&[
                (tag::PUBK, &pubk),
                (tag::MINT, &mint.to_le_bytes()),
                (tag::MAXT, &maxt.to_le_bytes()),
            ])?;
            let sig = long_term
                .sign(&signed(DELEGATION_CONTEXT, &dele))
                .map_err(|_| RoughtimeError::Signature)?;
            let cert = encode(&[(tag::SIG, &sig), (tag::DELE, &dele)])?;
            Ok(Self { online, cert })
        }

        /// The answer to `request` at `midpoint` seconds with `radius`.
        ///
        /// # Errors
        /// [`RoughtimeError`] for a request that is too short or malformed.
        pub fn respond(
            &self,
            request: &[u8],
            midpoint: u64,
            radius: u32,
        ) -> Result<Vec<u8>, RoughtimeError> {
            if request.len() < MIN_REQUEST {
                return Err(RoughtimeError::Malformed);
            }
            let nonce = nonce_of(request)?;
            let root = leaf(request);
            let srep = encode(&[
                (tag::RADI, &radius.to_le_bytes()),
                (tag::MIDP, &midpoint.to_le_bytes()),
                (tag::ROOT, &root),
            ])?;
            let sig = self
                .online
                .sign(&signed(RESPONSE_CONTEXT, &srep))
                .map_err(|_| RoughtimeError::Signature)?;
            frame(&encode(&[
                (tag::SIG, &sig),
                (tag::VER, &VERSION.to_le_bytes()),
                (tag::NONC, &nonce),
                (tag::PATH, &[]),
                (tag::SREP, &srep),
                (tag::CERT, &self.cert),
                (tag::INDX, &0_u32.to_le_bytes()),
            ])?)
        }
    }
}

#[cfg(test)]
mod tests;
