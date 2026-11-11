//! The client address behind trusted proxies (§17.9.6, OP-35, OP-148, OP-158 m.3 (v)):
//! `X-Forwarded-For` is read only when the TCP peer is in the configured trusted proxy list,
//! which is empty by default. The address is the right-most one in the header that is not a
//! trusted proxy; anything unreadable leaves the peer itself. The header never reaches a route.

use std::net::IpAddr;

use axum::http::HeaderMap;

/// The header a proxy appends the client address to.
pub const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Most addresses read from the header.
pub const MAX_HOPS: usize = 16;

/// One CIDR block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

/// Why a trusted proxy entry is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("trusted proxy entry is not an address or a CIDR block: {0}")]
pub struct BadCidr(pub String);

impl Cidr {
    /// `addr/len`, or a bare address as a host block.
    ///
    /// # Errors
    /// [`BadCidr`].
    pub fn parse(text: &str) -> Result<Self, BadCidr> {
        let bad = || BadCidr(text.to_owned());
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let network: IpAddr = addr.trim().parse().map_err(|_| bad())?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.trim().parse::<u8>().map_err(|_| bad())?,
            None => max,
        };
        if prefix > max {
            return Err(bad());
        }
        Ok(Self { network, prefix })
    }

    /// Whether `ip` is in the block.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX
                    .checked_shl(32_u32.saturating_sub(u32::from(self.prefix)))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128_u32.saturating_sub(u32::from(self.prefix)))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// The proxies whose `X-Forwarded-For` is read; none by default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    /// The list of `entries`, each an address or a CIDR block.
    ///
    /// # Errors
    /// [`BadCidr`] for the first entry that is neither.
    pub fn parse<S: AsRef<str>>(entries: &[S]) -> Result<Self, BadCidr> {
        entries
            .iter()
            .map(|e| Cidr::parse(e.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// Whether `ip` is a trusted proxy.
    #[must_use]
    pub fn trusts(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }

    /// The client address of a request from `peer` with `headers`.
    #[must_use]
    pub fn client(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.trusts(peer) {
            return peer;
        }
        let mut hops = Vec::new();
        for value in headers.get_all(X_FORWARDED_FOR) {
            let Ok(text) = value.to_str() else {
                return peer;
            };
            for part in text.split(',') {
                if hops.len() >= MAX_HOPS {
                    return peer;
                }
                let Ok(ip) = part.trim().parse::<IpAddr>() else {
                    return peer;
                };
                hops.push(ip);
            }
        }
        hops.into_iter()
            .rev()
            .find(|ip| !self.trusts(*ip))
            .unwrap_or(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
    }

    fn xff(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(X_FORWARDED_FOR, v);
        }
        h
    }

    // §17.9.6
    #[test]
    fn the_header_is_read_only_from_a_trusted_proxy() {
        let none = TrustedProxies::default();
        assert_eq!(
            none.client(ip("10.0.0.1"), &xff("198.51.100.7")),
            ip("10.0.0.1")
        );
        let lb = TrustedProxies::parse(&["10.0.0.0/8", "2001:db8::/32"]).unwrap_or_default();
        assert_eq!(
            lb.client(ip("10.0.0.1"), &xff("198.51.100.7")),
            ip("198.51.100.7")
        );
        assert_eq!(
            lb.client(ip("192.0.2.9"), &xff("198.51.100.7")),
            ip("192.0.2.9")
        );
        assert_eq!(
            lb.client(ip("10.0.0.1"), &xff("203.0.113.5, 198.51.100.7, 10.1.1.1")),
            ip("198.51.100.7"),
            "the right-most address that is not a proxy"
        );
        assert_eq!(lb.client(ip("10.0.0.1"), &xff("not-an-ip")), ip("10.0.0.1"));
        assert_eq!(
            lb.client(ip("2001:db8::1"), &xff("198.51.100.7")),
            ip("198.51.100.7")
        );
        assert_eq!(
            lb.client(ip("::ffff:10.0.0.1"), &xff("198.51.100.7")),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn an_entry_is_an_address_or_a_block() {
        assert!(TrustedProxies::parse(&["10.0.0.0/33"]).is_err());
        assert!(TrustedProxies::parse(&["proxy.internal"]).is_err());
        assert!(TrustedProxies::parse(&["192.0.2.1"]).is_ok());
        assert!(Cidr::parse("0.0.0.0/0").is_ok_and(|c| c.contains(ip("198.51.100.7"))));
    }
}
