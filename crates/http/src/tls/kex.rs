//! The key exchange side of the TLS listeners (CR-12, OP-159 m.3 (t)): a client that lists
//! `X25519MLKEM768` always gets it, by a `HelloRetryRequest` when it sent only a classic key share
//! (an `advertise-only` client); every handshake is counted in `access_tls_handshakes_total` by
//! listener, group and outcome; and a browser-facing certificate is never ML-DSA (CR-12 m.5).

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::task::{Context, Poll};

use rustls::{NamedGroup, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The hybrid group (RFC 10024).
pub const X25519MLKEM768: u16 = 0x11ec;
/// X25519.
pub const X25519: u16 = 0x001d;
/// P-256.
pub const SECP256R1: u16 = 0x0017;

/// Most bytes of a `ClientHello` kept to read its key shares (two full TLS records).
const MAX_HELLO: usize = 2 * (5 + 16_384);

/// The `group` label of a key exchange group code.
#[must_use]
pub const fn group_label(code: u16) -> &'static str {
    match code {
        X25519MLKEM768 => "x25519mlkem768",
        X25519 => "x25519",
        SECP256R1 => "secp256r1",
        _ => "other",
    }
}

/// What a `ClientHello` offers: the groups it sent key shares for, and its supported groups, in
/// the client's order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Offer {
    /// The `key_share` groups.
    pub shares: Vec<u16>,
    /// The `supported_groups`.
    pub supported: Vec<u16>,
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<usize> {
        self.take(1)?.first().map(|b| usize::from(*b))
    }

    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
    }

    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(
            usize::from(*b.first()?) << 16 | usize::from(*b.get(1)?) << 8 | usize::from(*b.get(2)?),
        )
    }

    fn vec16(&mut self) -> Option<Reader<'a>> {
        let n = usize::from(self.u16()?);
        Some(Reader(self.take(n)?))
    }
}

/// The handshake bytes of the TLS records at the start of `stream`.
fn handshake_bytes(stream: &[u8]) -> Vec<u8> {
    let mut r = Reader(stream);
    let mut out = Vec::new();
    while let (Some(kind), Some(_), Some(len)) = (r.u8(), r.u16(), r.u16()) {
        let Some(fragment) = r.take(usize::from(len)) else {
            break;
        };
        if kind != 22 {
            break;
        }
        out.extend_from_slice(fragment);
    }
    out
}

/// The offer of the first `ClientHello` in `stream`, the raw bytes a client sent first.
#[must_use]
pub fn client_hello_offer(stream: &[u8]) -> Option<Offer> {
    let hs = handshake_bytes(stream);
    let mut r = Reader(&hs);
    if r.u8()? != 1 {
        return None;
    }
    let len = r.u24()?;
    let mut hello = Reader(r.take(len)?);
    hello.take(2 + 32)?;
    let session = hello.u8()?;
    hello.take(session)?;
    hello.vec16()?;
    let compression = hello.u8()?;
    hello.take(compression)?;
    let mut extensions = hello.vec16()?;
    let mut offer = Offer::default();
    while let (Some(kind), Some(mut body)) = (extensions.u16(), extensions.vec16()) {
        match kind {
            10 => {
                let mut list = body.vec16()?;
                while let Some(g) = list.u16() {
                    offer.supported.push(g);
                }
            }
            51 => {
                let mut list = body.vec16()?;
                while let (Some(g), Some(_)) = (list.u16(), list.vec16()) {
                    offer.shares.push(g);
                }
            }
            _ => {}
        }
    }
    Some(offer)
}

/// The first bytes a connection read, kept for [`client_hello_offer`].
#[derive(Clone, Debug, Default)]
pub(crate) struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub(crate) fn offer(&self) -> Option<Offer> {
        let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        client_hello_offer(&bytes)
    }

    fn keep(&self, read: &[u8]) {
        let mut bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let room = MAX_HELLO.saturating_sub(bytes.len());
        if let Some(part) = read.get(..read.len().min(room)) {
            bytes.extend_from_slice(part);
        }
    }
}

/// A stream that keeps the first [`MAX_HELLO`] bytes it reads in a [`Capture`].
pub(crate) struct Recording<IO> {
    io: IO,
    capture: Capture,
    kept: usize,
}

impl<IO> Recording<IO> {
    pub(crate) const fn new(io: IO, capture: Capture) -> Self {
        Self {
            io,
            capture,
            kept: 0,
        }
    }

    /// Stops keeping and forgets what was kept: after the handshake nothing more is read into
    /// the capture.
    pub(crate) fn stop(&mut self) {
        self.kept = MAX_HELLO;
        self.capture
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Recording<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.io).poll_read(cx, buf);
        if self.kept < MAX_HELLO
            && let Some(read) = buf.filled().get(before..)
            && !read.is_empty()
        {
            self.capture.keep(read);
            self.kept = self.kept.saturating_add(read.len());
        }
        polled
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Recording<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

/// The post-quantum twin of each server configuration this module built: the same
/// configuration whose only key exchange group is `X25519MLKEM768`.
static TWINS: Mutex<Vec<(Weak<ServerConfig>, Arc<ServerConfig>)>> = Mutex::new(Vec::new());

/// The provider with `X25519MLKEM768` as its only key exchange group.
pub(crate) fn pq_only(
    provider: &rustls::crypto::CryptoProvider,
) -> Arc<rustls::crypto::CryptoProvider> {
    let mut pq = provider.clone();
    pq.kx_groups
        .retain(|g| u16::from(g.name()) == X25519MLKEM768);
    Arc::new(pq)
}

/// Remembers `twin` as the post-quantum configuration of `config`.
pub(crate) fn pair(config: &Arc<ServerConfig>, twin: ServerConfig) {
    let mut twins = TWINS.lock().unwrap_or_else(PoisonError::into_inner);
    twins.retain(|(w, _)| w.strong_count() > 0);
    twins.push((Arc::downgrade(config), Arc::new(twin)));
}

/// The configuration to finish a handshake with: the post-quantum twin of `config` when the
/// client lists `X25519MLKEM768` among its groups, so the hybrid group is chosen even when the
/// client sent only a classic key share (CR-12 m.2, m.3).
pub(crate) fn for_hello(
    config: &Arc<ServerConfig>,
    groups: Option<&[NamedGroup]>,
) -> Arc<ServerConfig> {
    let pq = groups.is_some_and(|g| g.iter().any(|n| u16::from(*n) == X25519MLKEM768));
    if !pq {
        return config.clone();
    }
    let twins = TWINS.lock().unwrap_or_else(PoisonError::into_inner);
    twins
        .iter()
        .find(|(w, _)| core::ptr::eq(w.as_ptr(), Arc::as_ptr(config)))
        .map_or_else(|| config.clone(), |(_, t)| t.clone())
}

/// How a handshake ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Completed with the client's first key share.
    Ok,
    /// Completed after a `HelloRetryRequest`.
    Retry,
    /// Did not complete.
    Failed,
}

impl Outcome {
    const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Retry => "retry",
            Self::Failed => "failed",
        }
    }
}

/// Counts one handshake on `listener`. A completed one is counted under its negotiated group;
/// a failed one under the first key share the client sent, so a failed handshake that carried
/// the hybrid share counts as a hybrid failure.
pub(crate) fn count(
    listener: &'static str,
    negotiated: Option<u16>,
    offer: Option<&Offer>,
    outcome: Outcome,
) {
    let group = negotiated
        .or_else(|| offer.and_then(|o| o.shares.first().copied()))
        .map_or("other", group_label);
    access_telemetry::signals::TLS_HANDSHAKES.incr([listener, group, outcome.label()]);
}

/// The ML-DSA signature algorithm OIDs (FIPS 204, RFC 9881), DER: 2.16.840.1.101.3.4.3.17–19.
const ML_DSA_OIDS: [[u8; 11]; 3] = [
    [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
    ],
    [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
    ],
    [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
    ],
];

/// Whether the certificate `der` names ML-DSA anywhere: its key, its signature or an
/// extension. Browser-facing TLS keeps classic certificates (CR-12 m.5).
#[must_use]
pub fn names_ml_dsa(der: &[u8]) -> bool {
    ML_DSA_OIDS
        .iter()
        .any(|oid| der.windows(oid.len()).any(|w| w == oid))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code"
    )]

    use super::*;

    fn hello(shares: &[(u16, usize)], supported: &[u16]) -> Vec<u8> {
        let mut ext = Vec::new();
        let mut groups = Vec::new();
        for g in supported {
            groups.extend_from_slice(&g.to_be_bytes());
        }
        ext.extend_from_slice(&10u16.to_be_bytes());
        ext.extend_from_slice(&u16::try_from(groups.len() + 2).unwrap().to_be_bytes());
        ext.extend_from_slice(&u16::try_from(groups.len()).unwrap().to_be_bytes());
        ext.extend_from_slice(&groups);
        let mut ks = Vec::new();
        for (g, n) in shares {
            ks.extend_from_slice(&g.to_be_bytes());
            ks.extend_from_slice(&u16::try_from(*n).unwrap().to_be_bytes());
            ks.extend(std::iter::repeat_n(7u8, *n));
        }
        ext.extend_from_slice(&51u16.to_be_bytes());
        ext.extend_from_slice(&u16::try_from(ks.len() + 2).unwrap().to_be_bytes());
        ext.extend_from_slice(&u16::try_from(ks.len()).unwrap().to_be_bytes());
        ext.extend_from_slice(&ks);
        let mut body = vec![3, 3];
        body.extend([0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1];
        hs.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut out = Vec::new();
        for chunk in hs.chunks(1000) {
            out.extend_from_slice(&[22, 3, 1]);
            out.extend_from_slice(&u16::try_from(chunk.len()).unwrap().to_be_bytes());
            out.extend_from_slice(chunk);
        }
        out
    }

    // CR-12 m.3, OP-159 m.3 (t)
    #[test]
    fn the_offer_is_read_across_records() {
        let optimistic = hello(
            &[(X25519MLKEM768, 1216), (X25519, 32)],
            &[X25519MLKEM768, X25519],
        );
        assert_eq!(
            client_hello_offer(&optimistic),
            Some(Offer {
                shares: vec![X25519MLKEM768, X25519],
                supported: vec![X25519MLKEM768, X25519],
            })
        );
        let advertise = hello(&[(X25519, 32)], &[X25519, X25519MLKEM768]);
        assert_eq!(
            client_hello_offer(&advertise).map(|o| o.shares),
            Some(vec![X25519])
        );
        assert_eq!(client_hello_offer(&optimistic[..20]), None);
        assert_eq!(client_hello_offer(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(group_label(0x0018), "other");
    }

    // CR-12 m.5
    #[test]
    fn an_ml_dsa_oid_is_found() {
        let mut der = vec![0x30, 0x10];
        der.extend_from_slice(&ML_DSA_OIDS[1]);
        assert!(names_ml_dsa(&der));
        assert!(!names_ml_dsa(&der[..der.len() - 1]));
    }
}
