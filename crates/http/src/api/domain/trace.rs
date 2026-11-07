//! W3C Trace Context (OP-67 m.1, OP-65, OP-151 m.3 (p)): the client's `traceparent` is used when
//! well-formed, else a trace id is drawn from the RNG port; `Request-Id` is the trace id.

/// One request's trace context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceContext {
    /// The 16-byte trace id.
    pub trace_id: [u8; 16],
    /// The caller's 8-byte parent span id; zero when the trace started here.
    pub parent_id: [u8; 8],
    /// The trace flags.
    pub flags: u8,
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

fn hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0_u8; N];
    let (pairs, _) = b.as_chunks::<2>();
    for (o, [h, l]) in out.iter_mut().zip(pairs) {
        *o = hex_digit(*h)?.wrapping_mul(16).wrapping_add(hex_digit(*l)?);
    }
    Some(out)
}

/// Lower-case hex of `bytes`.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(d));
            }
        }
    }
    out
}

impl TraceContext {
    /// Parses a `traceparent` value (W3C Trace Context §3.2): version `00`, lower-case hex, a
    /// non-zero trace id and parent id. A later version is read by its first four fields, as
    /// the specification asks; `ff` is invalid.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split('-');
        let version = parts.next()?;
        let trace = parts.next()?;
        let parent = parts.next()?;
        let flags = parts.next()?;
        let [v] = hex::<1>(version)?;
        if v == 0xff || (v == 0 && parts.next().is_some()) {
            return None;
        }
        let trace_id = hex::<16>(trace)?;
        let parent_id = hex::<8>(parent)?;
        let [flags] = hex::<1>(flags)?;
        if trace_id == [0; 16] || parent_id == [0; 8] {
            return None;
        }
        Some(Self {
            trace_id,
            parent_id,
            flags,
        })
    }

    /// A context that starts a trace with `trace_id`.
    #[must_use]
    pub const fn start(trace_id: [u8; 16]) -> Self {
        Self {
            trace_id,
            parent_id: [0; 8],
            flags: 0,
        }
    }

    /// The `Request-Id` value: the trace id, lower-case hex (OP-67 m.1).
    #[must_use]
    pub fn request_id(&self) -> String {
        to_hex(&self.trace_id)
    }
}
