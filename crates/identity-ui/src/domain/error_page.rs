//! N5: the hosted error page of an authorization request that cannot go back to the app
//! (§8.10, §8.15.2, X-L8, X41, OP-153 m.3 (jj)): the page names who can fix it and shows a
//! short reference instead of the raw error code.

/// Crockford's base32 alphabet.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Who owns an error (§8.15.2, E25).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// The app's developer: an unknown client, an unregistered redirect address, a malformed
    /// request.
    App,
    /// The sign-in provider upstream.
    Upstream,
    /// Access itself: briefly unavailable.
    Access,
}

impl Owner {
    /// The page's `owner` parameter.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::App => "app",
            Self::Upstream => "upstream",
            Self::Access => "access",
        }
    }
}

/// The reference shown for a request: the Crockford base32 of the request id's first 30 bits,
/// as `XXXX-XX` (OP-153 m.3 (jj)). The request id is the trace id, 32 hexadecimal digits; any
/// other id is read by its UTF-8 bytes.
#[must_use]
pub fn reference(request_id: &str) -> String {
    let hex: Option<u32> = request_id
        .get(..8)
        .filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit()))
        .and_then(|h| u32::from_str_radix(h, 16).ok());
    let first = hex.unwrap_or_else(|| {
        let mut b = [0_u8; 4];
        for (d, s) in b.iter_mut().zip(request_id.bytes()) {
            *d = s;
        }
        u32::from_be_bytes(b)
    });
    let bits = first >> 2;
    let mut out = String::with_capacity(7);
    for i in (0_u32..6).rev() {
        let shift = i.saturating_mul(5);
        let idx = usize::try_from(bits.checked_shr(shift).unwrap_or(0) & 31).unwrap_or(0);
        out.push(char::from(CROCKFORD.get(idx).copied().unwrap_or(b'0')));
        if i == 2 {
            out.push('-');
        }
    }
    out
}

/// The hosted error page for an authorization request: `base` is the realm issuer URL.
#[must_use]
pub fn location(base: &str, error: &str, owner: Owner, request_id: &str) -> String {
    format!(
        "{base}/login/error?error={error}&owner={}&ref={}",
        owner.name(),
        reference(request_id)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-153 m.3 (jj)
    #[test]
    fn the_reference_is_the_first_thirty_bits() {
        assert_eq!(reference("00000000000000000000000000000000"), "0000-00");
        assert_eq!(reference("ffffffff00000000000000000000000f"), "ZZZZ-ZZ");
        let r = reference("4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(r.len(), 7);
        assert!(r.bytes().all(|c| c == b'-' || CROCKFORD.contains(&c)));
        assert_eq!(reference("4bf92f3577b34da6a3ce929d0e0e4736"), r);
        assert_eq!(reference("req-1").len(), 7);
        assert_eq!(
            location(
                "https://acme.example",
                "invalid-client",
                Owner::App,
                "00000000"
            ),
            "https://acme.example/login/error?error=invalid-client&owner=app&ref=0000-00"
        );
    }
}
