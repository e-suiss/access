//! The password step's decision and its wire form (TN-82, CR-40, OP-36): every refusal that
//! could tell whether an account exists has one status, one body and one header set.

use core::net::IpAddr;

use suiss_crypto::digest::sha256;

use crate::domain::throttle::KeyKind;

const KEY_CONTEXT: &[u8] = b"access/login-throttle/v1\0";

/// The network a counter keys on: an IPv4 address, or an IPv6 /64 (one subscriber).
#[must_use]
pub fn network(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.octets().to_vec(),
            None => v6.octets().get(..8).unwrap_or_default().to_vec(),
        },
    }
}

/// A counter key: a digest, so the counters hold no personal data (OP-146 m.5 (f)).
#[must_use]
pub fn counter_key(
    kind: KeyKind,
    tenant: &[u8; 16],
    realm: &[u8; 16],
    identifier: Option<&str>,
    network: Option<&[u8]>,
) -> [u8; 32] {
    let mut m = KEY_CONTEXT.to_vec();
    m.push(kind.tag());
    m.extend_from_slice(tenant);
    m.extend_from_slice(realm);
    for part in [identifier.map(str::as_bytes), network] {
        let part = part.unwrap_or_default();
        m.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
        m.extend_from_slice(part);
    }
    sha256(&m)
}

/// The outcome of a password attempt. A decision, not an error: capacity and storage
/// failures are errors and answer 503.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordLogin {
    /// The password matched an active account.
    Accepted {
        /// Internal subject id.
        subject: [u8; 16],
        /// The subject's session epoch, for the session I5 opens.
        session_epoch: i64,
        /// The stored hash was upgraded (CR-37).
        rehashed: bool,
        /// Failed attempts the account's counter held before this one (OP-35); SL2 reads it as
        /// the brute-force signal (IDP-39).
        prior_failures: u32,
    },
    /// Wrong password, unknown, locked, suspended or deactivated account: one answer (TN-82).
    Rejected {
        /// Wait this long before answering (adaptive delay; never on the wire).
        pad_ms: u64,
    },
    /// Too many attempts for this identifier or network; the same for every identifier.
    Throttled {
        /// `Retry-After`, in whole seconds.
        retry_after_s: u64,
    },
}

/// A refusal's RFC 9457 problem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Problem {
    /// HTTP status.
    pub status: u16,
    /// Problem type suffix.
    pub code: &'static str,
    /// Title.
    pub title: &'static str,
    /// `Retry-After` seconds, when set.
    pub retry_after_s: Option<u64>,
}

/// TN-82: the single refusal of the password step.
pub const REJECTED: Problem = Problem {
    status: 401,
    code: "login-failed",
    title: "The sign-in details are not correct",
    retry_after_s: None,
};

/// OP-36: capacity shedding (hash semaphore, breach check, database).
#[must_use]
pub const fn unavailable(retry_after_s: u64) -> Problem {
    Problem {
        status: 503,
        code: "temporarily-unavailable",
        title: "Try again shortly",
        retry_after_s: Some(retry_after_s),
    }
}

/// Whole seconds, rounded up, at least one.
#[must_use]
pub const fn ceil_seconds(ms: u64) -> u64 {
    let s = ms.div_ceil(1000);
    if s == 0 { 1 } else { s }
}

impl PasswordLogin {
    /// The wire answer of a refusal; `None` for an accepted attempt.
    #[must_use]
    pub const fn problem(&self) -> Option<Problem> {
        match self {
            Self::Accepted { .. } => None,
            Self::Rejected { .. } => Some(REJECTED),
            Self::Throttled { retry_after_s } => Some(Problem {
                status: 429,
                code: "too-many-attempts",
                title: "Too many attempts",
                retry_after_s: Some(*retry_after_s),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    // OP-146, TN-82
    #[test]
    fn keys_separate_kinds_scopes_and_networks() {
        let (t, r) = ([1; 16], [2; 16]);
        let a = counter_key(KeyKind::Account, &t, &r, Some("alice"), None);
        assert_ne!(
            a,
            counter_key(KeyKind::Account, &t, &[3; 16], Some("alice"), None)
        );
        assert_ne!(
            a,
            counter_key(KeyKind::AccountIp, &t, &r, Some("alice"), None)
        );
        assert_ne!(
            counter_key(KeyKind::Ip, &t, &r, None, Some(b"ab")),
            counter_key(KeyKind::Ip, &t, &r, Some("a"), Some(b"b"))
        );
        let v6a = network(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)));
        let v6b = network(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 9, 9, 9, 9)));
        assert_eq!(v6a, v6b);
        let mapped = network(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()));
        assert_eq!(mapped, network(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    // TN-82, CR-40
    #[test]
    fn every_rejection_has_one_answer() {
        let a = PasswordLogin::Rejected { pad_ms: 0 }.problem();
        let b = PasswordLogin::Rejected { pad_ms: 900 }.problem();
        assert_eq!(a, b);
        assert_eq!(a, Some(REJECTED));
        assert_eq!(
            PasswordLogin::Throttled { retry_after_s: 2 }
                .problem()
                .map(|p| (p.status, p.retry_after_s)),
            Some((429, Some(2)))
        );
        assert_eq!(ceil_seconds(1), 1);
        assert_eq!(ceil_seconds(0), 1);
        assert_eq!(ceil_seconds(30_001), 31);
    }
}
