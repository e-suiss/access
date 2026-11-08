//! What is kept of a client address at rest (OP-151 m.1 (b), OP-47): its keyed pseudonym and its
//! `/24` or `/48` prefix, never the address; nothing of it reaches telemetry.

use std::net::IpAddr;

/// The address in its 16-byte form (IPv4 mapped).
#[must_use]
pub fn octets(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// The address's network prefix: `/24` for IPv4 (also when mapped), `/48` for IPv6.
#[must_use]
pub fn prefix(ip: IpAddr) -> String {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(v6) => {
            let [s0, s1, s2, ..] = v6.segments();
            format!("{s0:x}:{s1:x}:{s2:x}::/48")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-151 m.1 (b)
    #[test]
    fn prefixes() {
        assert_eq!(prefix("203.0.113.77".parse().unwrap()), "203.0.113.0/24");
        assert_eq!(
            prefix("::ffff:203.0.113.77".parse().unwrap()),
            "203.0.113.0/24"
        );
        assert_eq!(
            prefix("2001:db8:aa:bb::1".parse().unwrap()),
            "2001:db8:aa::/48"
        );
        assert_eq!(
            octets("203.0.113.77".parse().unwrap()),
            octets("::ffff:203.0.113.77".parse().unwrap())
        );
    }
}
