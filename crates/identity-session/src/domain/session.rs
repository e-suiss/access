//! The identity plane login session (§12.0.3, TN-36, CR-38): server-side, an opaque cookie
//! whose digest alone is stored, idle and absolute lifetimes, and death by `session_epoch`
//! (TN-50, MD-7). "Keep me signed in" changes only the cookie's persistence; it remembers no
//! authority decision and satisfies no CT2+ requirement (TN-36, X33).

use core::fmt::Write as _;

use suiss_crypto::digest::sha256;

/// The session cookie: host-only, so it never leaves the realm's own host (TN-17).
pub const SESSION_COOKIE: &str = "__Host-access-session";

/// The device marker cookie (X33).
pub const MARKER_COOKIE: &str = "__Host-access-device";

/// The flow device cookie: binds a flow and its suspended steps to the starting browser.
pub const FLOW_COOKIE: &str = "__Host-access-flow";

const COOKIE_CONTEXT: &[u8] = b"access/session-cookie/v1\0";
const MARKER_CONTEXT: &[u8] = b"access/device-marker/v1\0";

/// The stored digest of a session cookie value.
#[must_use]
pub fn cookie_digest(value: &[u8; 32]) -> [u8; 32] {
    sha256(&[COOKIE_CONTEXT, value.as_slice()].concat())
}

/// The stored digest of a device marker value.
#[must_use]
pub fn marker_digest(value: &[u8; 32]) -> [u8; 32] {
    sha256(&[MARKER_CONTEXT, value.as_slice()].concat())
}

/// A realm's session lifetimes (TN-36, PD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Idle timeout: 1 hour to 30 days.
    pub idle_ms: u64,
    /// Absolute lifetime: 1 hour to 90 days.
    pub absolute_ms: u64,
}

const HOUR_MS: u64 = 3_600_000;
const DAY_MS: u64 = 86_400_000;

/// Why a lifetime is outside its range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("session lifetime outside the TN-36 range")]
pub struct LifetimeOutOfRange;

impl SessionPolicy {
    /// TN-36: idle 7 days, absolute 30 days.
    pub const DEFAULT: Self = Self {
        idle_ms: 7 * DAY_MS,
        absolute_ms: 30 * DAY_MS,
    };

    /// A policy within TN-36's ranges.
    ///
    /// # Errors
    /// [`LifetimeOutOfRange`].
    pub const fn new(idle_ms: u64, absolute_ms: u64) -> Result<Self, LifetimeOutOfRange> {
        if idle_ms < HOUR_MS
            || idle_ms > 30 * DAY_MS
            || absolute_ms < HOUR_MS
            || absolute_ms > 90 * DAY_MS
            || idle_ms > absolute_ms
        {
            return Err(LifetimeOutOfRange);
        }
        Ok(Self {
            idle_ms,
            absolute_ms,
        })
    }
}

/// The stored facts a check reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionFacts {
    /// The epoch the session carries.
    pub session_epoch: i64,
    /// The subject's epoch now (Δ = 0 from the primary, MD-7).
    pub subject_epoch: i64,
    /// The subject can authenticate (TN-49 `active`).
    pub subject_active: bool,
    /// Last use.
    pub last_seen_ms: u64,
    /// Idle timeout.
    pub idle_ms: u64,
    /// Absolute end.
    pub expires_ms: u64,
    /// Already ended.
    pub ended: bool,
}

/// What a check found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionCheck {
    /// Live.
    Valid,
    /// Ended by sign-out or an administrator.
    Ended,
    /// Behind its subject's epoch: deactivation, a password or MFA change, sign-out
    /// everywhere (TN-50, TN-64).
    Revoked,
    /// Idle too long.
    IdleExpired,
    /// Past its absolute end.
    Expired,
}

/// Checks a session at `now_ms`. Anything but [`SessionCheck::Valid`] issues nothing (G57).
#[must_use]
pub const fn check(f: &SessionFacts, now_ms: u64) -> SessionCheck {
    if f.ended {
        return SessionCheck::Ended;
    }
    if f.session_epoch < f.subject_epoch || !f.subject_active {
        return SessionCheck::Revoked;
    }
    if now_ms >= f.expires_ms {
        return SessionCheck::Expired;
    }
    if now_ms >= f.last_seen_ms.saturating_add(f.idle_ms) {
        return SessionCheck::IdleExpired;
    }
    SessionCheck::Valid
}

/// A `Set-Cookie` value (RFC 6265bis): `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no
/// `Domain` (the `__Host-` prefix). `max_age_s` is `None` for a browser-session cookie.
#[must_use]
pub fn set_cookie(name: &str, value: &str, max_age_s: Option<u64>) -> String {
    let mut out = format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax");
    if let Some(s) = max_age_s {
        let _ = write!(out, "; Max-Age={s}");
    }
    out
}

/// A `Set-Cookie` value that removes a cookie.
#[must_use]
pub fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> SessionFacts {
        SessionFacts {
            session_epoch: 3,
            subject_epoch: 3,
            subject_active: true,
            last_seen_ms: 1_000,
            idle_ms: 100,
            expires_ms: 5_000,
            ended: false,
        }
    }

    // TN-36, TN-50, MD-7, G57
    #[test]
    fn idle_absolute_epoch_and_end() {
        assert_eq!(check(&facts(), 1_050), SessionCheck::Valid);
        assert_eq!(check(&facts(), 1_100), SessionCheck::IdleExpired);
        let long_idle = SessionFacts {
            idle_ms: 10_000,
            ..facts()
        };
        assert_eq!(check(&long_idle, 5_000), SessionCheck::Expired);
        let behind = SessionFacts {
            subject_epoch: 4,
            ..facts()
        };
        assert_eq!(check(&behind, 1_050), SessionCheck::Revoked);
        let inactive = SessionFacts {
            subject_active: false,
            ..facts()
        };
        assert_eq!(check(&inactive, 1_050), SessionCheck::Revoked);
        let ended = SessionFacts {
            ended: true,
            ..facts()
        };
        assert_eq!(check(&ended, 1_050), SessionCheck::Ended);
    }

    // TN-36
    #[test]
    fn lifetimes_stay_in_range() {
        assert!(SessionPolicy::new(HOUR_MS, HOUR_MS).is_ok());
        assert!(SessionPolicy::new(HOUR_MS - 1, DAY_MS).is_err());
        assert!(SessionPolicy::new(31 * DAY_MS, 90 * DAY_MS).is_err());
        assert!(SessionPolicy::new(DAY_MS, 91 * DAY_MS).is_err());
        assert!(SessionPolicy::new(2 * DAY_MS, DAY_MS).is_err());
        assert_eq!(
            SessionPolicy::new(7 * DAY_MS, 30 * DAY_MS),
            Ok(SessionPolicy::DEFAULT)
        );
    }

    // CR-38, CR-43, TN-17
    #[test]
    fn cookies_are_host_only_and_http_only() {
        let c = set_cookie(SESSION_COOKIE, "abc", Some(60));
        assert!(c.starts_with("__Host-access-session=abc; Path=/; Secure; HttpOnly"));
        assert!(c.ends_with("; Max-Age=60"));
        assert!(!c.contains("Domain"));
        assert!(!set_cookie(SESSION_COOKIE, "abc", None).contains("Max-Age"));
        assert_ne!(cookie_digest(&[1; 32]), marker_digest(&[1; 32]));
    }
}
