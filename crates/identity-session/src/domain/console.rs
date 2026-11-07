//! The console session policy (TN-128, TN-129, TN-33, OP-151 m.3 (f)): a session for the
//! management listener's surfaces, 12 hours absolute and 15 minutes idle, bound to the client's
//! network (its ASN when a `GeoResolver` source is configured, else its /24 or /48 prefix; its full
//! address when the realm asks), carried by a strict host-only cookie that is DBSC-ready. The
//! cookie carries navigation and the identity plane's own screens only; it authorises no
//! authority read and no write (MD-14).

use core::net::IpAddr;

use access_kernel::json::{b64url_decode, b64url_encode};
use suiss_crypto::digest::context_digest;
use suiss_crypto::secret::Secret;

/// The console session cookie. `__Host-` keeps it on the management origin only: no `Domain`,
/// `Secure`, and `Path=/` as the prefix demands (RFC 6265bis §4.1.3.2).
pub const CONSOLE_COOKIE: &str = "__Host-access-console";

/// The double-submit copy of the session's CSRF token, readable by the console's script.
pub const CSRF_COOKIE: &str = "__Host-access-console-csrf";

/// The request header carrying the CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Absolute lifetime (TN-129, OP-151 m.3 (f)).
pub const ABSOLUTE_MS: u64 = 12 * 3_600_000;

/// Idle lifetime (TN-129, OP-151 m.3 (f)).
pub const IDLE_MS: u64 = 15 * 60_000;

const CSRF_CONTEXT: &str = "access/console-csrf/v1";

/// What the console session's network binding takes from the realm session policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BindingPolicy {
    /// The realm asks for the client's full address (TN-129 "optional IP binding").
    pub full_ip: bool,
}

/// The network a console session is bound to (TN-129, OP-151 m.1 (b)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// The client's autonomous system, when a `GeoResolver` source answers.
    Asn(u32),
    /// The client's IPv4 /24.
    V4Prefix([u8; 3]),
    /// The client's IPv6 /48.
    V6Prefix([u8; 6]),
    /// The client's full address, when the realm asks for it.
    Address(IpAddr),
}

impl Binding {
    /// The binding of a client at `ip` with `asn` (the `GeoResolver` answer; `None` without a source)
    /// under `policy`. A full address binding is the strictest and wins; otherwise the ASN when
    /// known, else the prefix, which is narrower than any ASN (OP-151 m.1 (b)).
    #[must_use]
    pub fn of(ip: IpAddr, asn: Option<u32>, policy: BindingPolicy) -> Self {
        let ip = ip.to_canonical();
        if policy.full_ip {
            return Self::Address(ip);
        }
        if let Some(a) = asn {
            return Self::Asn(a);
        }
        match ip {
            IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                Self::V4Prefix([a, b, c])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                Self::V6Prefix([o[0], o[1], o[2], o[3], o[4], o[5]])
            }
        }
    }

    /// The stored form: a kind byte and the value.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Asn(a) => [&[1u8][..], &a.to_be_bytes()].concat(),
            Self::V4Prefix(p) => [&[2u8][..], p].concat(),
            Self::V6Prefix(p) => [&[3u8][..], p].concat(),
            Self::Address(IpAddr::V4(v4)) => [&[4u8][..], &v4.octets()].concat(),
            Self::Address(IpAddr::V6(v6)) => [&[6u8][..], &v6.octets()].concat(),
        }
    }

    /// Reads [`Binding::encode`]; `None` for anything else.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes.split_first()? {
            (1, a) => Some(Self::Asn(u32::from_be_bytes(a.try_into().ok()?))),
            (2, p) => Some(Self::V4Prefix(p.try_into().ok()?)),
            (3, p) => Some(Self::V6Prefix(p.try_into().ok()?)),
            (4, a) => Some(Self::Address(IpAddr::from(<[u8; 4]>::try_from(a).ok()?))),
            (6, a) => Some(Self::Address(IpAddr::from(<[u8; 16]>::try_from(a).ok()?))),
            _ => None,
        }
    }

    /// Whether a request from `ip` with `asn` stays inside this binding. The request's binding
    /// is computed the way the session's was; a different kind never matches, so a `GeoResolver` source
    /// that appears or disappears mid-session ends the session rather than widening it (TI-9).
    #[must_use]
    pub fn holds(&self, ip: IpAddr, asn: Option<u32>, policy: BindingPolicy) -> bool {
        *self == Self::of(ip, asn, policy)
    }
}

/// The stored facts of a console session a request is checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleFacts {
    /// Created, Unix milliseconds.
    pub created_ms: u64,
    /// Last use, Unix milliseconds.
    pub last_seen_ms: u64,
    /// The subject's epoch moved past the session's, or the subject cannot authenticate.
    pub revoked: bool,
    /// Ended by sign-out or a revoke.
    pub ended: bool,
    /// Its network binding.
    pub binding: Binding,
}

/// What a console session check found; anything but [`ConsoleCheck::Valid`] serves nothing but
/// the sign-in page (G57).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleCheck {
    /// Live.
    Valid,
    /// Signed out or revoked from the session list.
    Ended,
    /// Behind its subject's epoch (TN-50).
    Revoked,
    /// Unused for [`IDLE_MS`].
    IdleExpired,
    /// Older than [`ABSOLUTE_MS`].
    Expired,
    /// Presented from outside its network binding.
    BindingMismatch,
}

impl ConsoleCheck {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Ended => "ended",
            Self::Revoked => "revoked",
            Self::IdleExpired => "idle-expired",
            Self::Expired => "expired",
            Self::BindingMismatch => "binding-mismatch",
        }
    }
}

/// Checks a console session presented from `ip` (with `asn`) at `now_ms` (TN-129).
#[must_use]
pub fn check(
    f: &ConsoleFacts,
    ip: IpAddr,
    asn: Option<u32>,
    policy: BindingPolicy,
    now_ms: u64,
) -> ConsoleCheck {
    if f.ended {
        return ConsoleCheck::Ended;
    }
    if f.revoked {
        return ConsoleCheck::Revoked;
    }
    if now_ms >= f.created_ms.saturating_add(ABSOLUTE_MS) {
        return ConsoleCheck::Expired;
    }
    if now_ms >= f.last_seen_ms.saturating_add(IDLE_MS) {
        return ConsoleCheck::IdleExpired;
    }
    if !f.binding.holds(ip, asn, policy) {
        return ConsoleCheck::BindingMismatch;
    }
    ConsoleCheck::Valid
}

/// When a live session ends at the latest: its absolute end or its idle end, whichever is
/// first.
#[must_use]
pub const fn ends_ms(f: &ConsoleFacts) -> u64 {
    let absolute = f.created_ms.saturating_add(ABSOLUTE_MS);
    let idle = f.last_seen_ms.saturating_add(IDLE_MS);
    if absolute < idle { absolute } else { idle }
}

/// The session's CSRF token (TN-131): derived from the session cookie value, so it is bound to
/// the session and dies with it. The console reads it from [`CSRF_COOKIE`] and echoes it in
/// [`CSRF_HEADER`].
#[must_use]
pub fn csrf_token(cookie: &Secret<[u8; 32]>) -> String {
    b64url_encode(&context_digest(CSRF_CONTEXT, cookie.expose()).0)
}

/// Whether `presented` (the header) and `double` (the cookie) both equal the session's CSRF
/// token, compared in constant time.
#[must_use]
pub fn csrf_ok(cookie: &Secret<[u8; 32]>, presented: &str, double: &str) -> bool {
    let want = Secret::new(context_digest(CSRF_CONTEXT, cookie.expose()).0);
    match (b64url_decode(presented), b64url_decode(double)) {
        (Ok(p), Ok(d)) => want.ct_eq_bytes(&p) & want.ct_eq_bytes(&d),
        _ => false,
    }
}

/// The session cookie (TN-128, TN-131, TN-33): `Secure`, `HttpOnly`, `SameSite=Strict`,
/// host-only, no `Max-Age` (it ends with the browser or the session, whichever is first).
#[must_use]
pub fn session_cookie(value: &str) -> String {
    format!("{CONSOLE_COOKIE}={value}; Path=/; Secure; HttpOnly; SameSite=Strict")
}

/// The CSRF double-submit cookie: readable by the console's own script, `Strict`, host-only.
#[must_use]
pub fn csrf_cookie(token: &str) -> String {
    format!("{CSRF_COOKIE}={token}; Path=/; Secure; SameSite=Strict")
}

/// Removes both cookies.
#[must_use]
pub fn clear_cookies() -> [String; 2] {
    [CONSOLE_COOKIE, CSRF_COOKIE]
        .map(|name| format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"))
}

/// The device-bound key a DBSC registration will attach to the session (TN-33): the slot the
/// session keeps. Until DBSC lands no session has one, and the `Sec-Session-*` handshake
/// answers `501`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DbscKey(pub [u8; 32]);

#[cfg(test)]
mod tests;
