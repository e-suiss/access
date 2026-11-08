//! The MX/A lookup of the sign-up's first step (TN-80, OP-153 m.11 (f)): one DNS query over UDP
//! to the host's first `nameserver`, MX first, then A and AAAA when no MX is published
//! (RFC 5321 §5.1). A null MX (RFC 7505) or a missing name is undeliverable; a resolver that does
//! not answer, answers `SERVFAIL` or truncates is `Unknown`, and the out-of-band code stays the
//! proof of the mailbox.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::ports::{Deliverability, MailDomains, MailFuture};

/// Record types queried.
const MX: u16 = 15;
const A: u16 = 1;
const AAAA: u16 = 28;

/// Largest answer read over UDP (RFC 1035 §4.2.1 without EDNS).
const MAX_ANSWER: usize = 512;

/// What one query said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Records of the asked type; for MX, whether any one is not a null MX.
    Records {
        /// At least one usable record.
        usable: bool,
    },
    /// The name exists without records of the asked type.
    NoData,
    /// The name does not exist (`NXDOMAIN`).
    NoName,
    /// Anything else: `SERVFAIL`, `REFUSED`, truncation, a malformed or foreign answer.
    Unknown,
}

/// The query packet for `name` and `qtype` with transaction `id`; `None` for a name that is
/// not ASCII labels of 1–63 bytes within 253 bytes.
#[must_use]
pub fn query(id: u16, name: &str, qtype: u16) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return None;
    }
    let mut q = Vec::with_capacity(name.len().saturating_add(18));
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        let n = u8::try_from(label.len())
            .ok()
            .filter(|n| (1..=63).contains(n))?;
        q.push(n);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1_u16.to_be_bytes());
    Some(q)
}

fn u16_at(p: &[u8], at: usize) -> Option<u16> {
    let b = p.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
}

/// The offset after the name at `at`; a compression pointer ends the name.
fn skip_name(p: &[u8], mut at: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *p.get(at)?;
        if len & 0xC0 == 0xC0 {
            return at.checked_add(2);
        }
        if len == 0 {
            return at.checked_add(1);
        }
        at = at.checked_add(usize::from(len))?.checked_add(1)?;
    }
    None
}

/// Reads the answer to a query with `id` and `qtype`.
#[must_use]
pub fn read(packet: &[u8], id: u16, qtype: u16) -> Answer {
    read_inner(packet, id, qtype).unwrap_or(Answer::Unknown)
}

fn read_inner(p: &[u8], id: u16, qtype: u16) -> Option<Answer> {
    let flags = u16_at(p, 2)?;
    if u16_at(p, 0)? != id || flags & 0x8000 == 0 || flags & 0x0200 != 0 {
        return Some(Answer::Unknown);
    }
    match flags & 0x000F {
        0 => {}
        3 => return Some(Answer::NoName),
        _ => return Some(Answer::Unknown),
    }
    let (qd, an) = (u16_at(p, 4)?, u16_at(p, 6)?);
    let mut at = 12_usize;
    for _ in 0..qd {
        at = skip_name(p, at)?.checked_add(4)?;
    }
    let mut seen = false;
    let mut usable = false;
    for _ in 0..an {
        at = skip_name(p, at)?;
        let rtype = u16_at(p, at)?;
        let rdlen = usize::from(u16_at(p, at.checked_add(8)?)?);
        let rdata = at.checked_add(10)?;
        let end = rdata.checked_add(rdlen)?;
        p.get(rdata..end)?;
        if rtype == qtype {
            seen = true;
            usable |= qtype != MX || p.get(rdata.checked_add(2)?).is_some_and(|b| *b != 0);
        }
        at = end;
    }
    Some(if seen {
        Answer::Records { usable }
    } else {
        Answer::NoData
    })
}

/// The first `nameserver` of a `resolv.conf`.
#[must_use]
pub fn nameserver(resolv_conf: &str) -> Option<SocketAddr> {
    resolv_conf.lines().find_map(|l| {
        let mut w = l.split_whitespace();
        (w.next() == Some("nameserver"))
            .then(|| w.next())
            .flatten()
            .and_then(|a| a.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

/// The decision over the MX answer and, without MX, the address answers.
#[must_use]
pub fn decide(mx: Answer, addresses: &[Answer]) -> Deliverability {
    match mx {
        Answer::Records { usable: true } => Deliverability::Deliverable,
        Answer::Records { usable: false } | Answer::NoName => Deliverability::Undeliverable,
        Answer::Unknown => Deliverability::Unknown,
        Answer::NoData => {
            if addresses
                .iter()
                .any(|a| matches!(a, Answer::Records { .. }))
            {
                Deliverability::Deliverable
            } else if addresses.contains(&Answer::Unknown) {
                Deliverability::Unknown
            } else {
                Deliverability::Undeliverable
            }
        }
    }
}

/// A resolver over UDP.
#[derive(Clone, Copy, Debug)]
pub struct DnsMailDomains {
    server: SocketAddr,
    timeout: Duration,
}

impl DnsMailDomains {
    /// Queries `server` with one deadline per query.
    #[must_use]
    pub const fn new(server: SocketAddr, timeout: Duration) -> Self {
        Self { server, timeout }
    }

    async fn ask(&self, name: &str, qtype: u16) -> Answer {
        let Ok(random) = access_crypto::random::bytes::<2>() else {
            return Answer::Unknown;
        };
        let id = u16::from_be_bytes(random);
        let Some(packet) = query(id, name, qtype) else {
            return Answer::Unknown;
        };
        let bind: SocketAddr = if self.server.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0_u16; 8], 0))
        };
        let exchange = async {
            let socket = UdpSocket::bind(bind).await.ok()?;
            socket.connect(self.server).await.ok()?;
            socket.send(&packet).await.ok()?;
            let mut buf = [0_u8; MAX_ANSWER];
            loop {
                let len = socket.recv(&mut buf).await.ok()?;
                let answer = read(buf.get(..len)?, id, qtype);
                if u16_at(&buf, 0) == Some(id) {
                    return Some(answer);
                }
            }
        };
        match tokio::time::timeout(self.timeout, exchange).await {
            Ok(Some(a)) => a,
            _ => Answer::Unknown,
        }
    }
}

impl MailDomains for DnsMailDomains {
    fn deliverable<'a>(&'a self, domain: &'a str) -> MailFuture<'a> {
        Box::pin(async move {
            let mx = self.ask(domain, MX).await;
            if mx != Answer::NoData {
                return decide(mx, &[]);
            }
            let a = self.ask(domain, A).await;
            let aaaa = self.ask(domain, AAAA).await;
            decide(mx, &[a, aaaa])
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(id: u16, rcode: u8, records: &[(u16, &[u8])]) -> Vec<u8> {
        let mut p = query(id, "example.com", MX).unwrap();
        p[2] = 0x81;
        p[3] = 0x80 | rcode;
        p[7] = u8::try_from(records.len()).unwrap();
        for (t, rdata) in records {
            p.extend_from_slice(&[0xC0, 12]);
            p.extend_from_slice(&t.to_be_bytes());
            p.extend_from_slice(&[0, 1, 0, 0, 1, 0]);
            p.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            p.extend_from_slice(rdata);
        }
        p
    }

    // OP-153 m.11 (f), TN-80
    #[test]
    fn mx_null_mx_missing_names_and_address_fallback_decide_deliverability() {
        let mx = answer(7, 0, &[(MX, &[0, 10, 4, b'm', b'a', b'i', b'l', 0xC0, 12])]);
        assert_eq!(read(&mx, 7, MX), Answer::Records { usable: true });
        assert_eq!(decide(read(&mx, 7, MX), &[]), Deliverability::Deliverable);
        let null = answer(7, 0, &[(MX, &[0, 0, 0])]);
        assert_eq!(
            decide(read(&null, 7, MX), &[]),
            Deliverability::Undeliverable
        );
        let nx = answer(7, 3, &[]);
        assert_eq!(decide(read(&nx, 7, MX), &[]), Deliverability::Undeliverable);
        let servfail = answer(7, 2, &[]);
        assert_eq!(decide(read(&servfail, 7, MX), &[]), Deliverability::Unknown);
        let empty = answer(7, 0, &[]);
        assert_eq!(read(&empty, 7, MX), Answer::NoData);
        let a = answer(7, 0, &[(A, &[192, 0, 2, 1])]);
        assert_eq!(
            decide(Answer::NoData, &[read(&a, 7, A), Answer::NoData]),
            Deliverability::Deliverable
        );
        assert_eq!(
            decide(Answer::NoData, &[Answer::NoData, Answer::NoData]),
            Deliverability::Undeliverable
        );
        assert_eq!(
            decide(Answer::NoData, &[Answer::Unknown, Answer::NoData]),
            Deliverability::Unknown
        );
        assert_eq!(read(&mx, 8, MX), Answer::Unknown);
        let mut truncated = mx.clone();
        truncated[2] |= 0x02;
        assert_eq!(read(&truncated, 7, MX), Answer::Unknown);
        assert_eq!(read(&mx[..20], 7, MX), Answer::Unknown);
    }

    #[test]
    fn queries_take_ascii_labels_only_and_the_first_nameserver() {
        assert!(query(1, "bad..example", MX).is_none());
        assert!(query(1, "exämple.com", MX).is_none());
        assert!(query(1, &"a".repeat(64), MX).is_none());
        assert_eq!(
            nameserver("# x\nsearch lan\nnameserver 10.0.0.53\nnameserver 1.1.1.1\n"),
            Some(SocketAddr::from(([10, 0, 0, 53], 53)))
        );
        assert_eq!(nameserver("search lan\n"), None);
    }
}
