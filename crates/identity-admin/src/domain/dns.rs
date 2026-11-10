//! The DNS messages a domain verification exchanges over DNS-over-HTTPS (RFC 8484, RFC 1035,
//! TN-90): a query for TXT or MX, and the answer's records read with every length bounded
//! before it is used (OP-4). Sans-I/O: the adapter carries the bytes.

/// A record type the watch asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rtype {
    /// TXT (16).
    Txt,
    /// MX (15).
    Mx,
    /// CNAME (5), for custom domains (OP-156 m.3 (i)).
    Cname,
}

impl Rtype {
    const fn code(self) -> u16 {
        match self {
            Self::Txt => 16,
            Self::Mx => 15,
            Self::Cname => 5,
        }
    }
}

/// Why an answer could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DnsError {
    /// The name is not a DNS name Access asks for.
    #[error("bad name")]
    Name,
    /// The answer is truncated, malformed or over its limits.
    #[error("malformed answer")]
    Malformed,
    /// The server failed to answer (any RCODE other than NOERROR and NXDOMAIN).
    #[error("server failure")]
    Server,
}

/// Most answer records read.
pub const MAX_ANSWERS: u16 = 64;

/// Most compression pointers followed in one name.
const MAX_JUMPS: usize = 16;

/// The wire query for `name` and `rtype`: id 0 as RFC 8484 §4.1 asks, recursion desired.
///
/// # Errors
/// [`DnsError::Name`].
pub fn query(name: &str, rtype: Rtype) -> Result<Vec<u8>, DnsError> {
    let mut out = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    if name.is_empty() || name.len() > 253 {
        return Err(DnsError::Name);
    }
    for label in name.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len()).map_err(|_| DnsError::Name)?;
        if len == 0 || len > 63 || !label.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(DnsError::Name);
        }
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&rtype.code().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

fn u16_at(m: &[u8], at: usize) -> Result<u16, DnsError> {
    let b = m.get(at..at.checked_add(2).ok_or(DnsError::Malformed)?);
    let b = b.ok_or(DnsError::Malformed)?;
    Ok(u16::from_be_bytes([
        *b.first().ok_or(DnsError::Malformed)?,
        *b.get(1).ok_or(DnsError::Malformed)?,
    ]))
}

/// Reads the name at `at`; returns it and the offset after it in the record.
fn name_at(m: &[u8], at: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = at;
    let mut end = None;
    let mut jumps = 0usize;
    let mut total = 0usize;
    loop {
        let len = *m.get(pos).ok_or(DnsError::Malformed)?;
        match len {
            0 => {
                let after = end.unwrap_or(pos.checked_add(1).ok_or(DnsError::Malformed)?);
                return Ok((labels.join("."), after));
            }
            l if l & 0xc0 == 0xc0 => {
                let ptr = usize::from(u16_at(m, pos)? & 0x3fff);
                if end.is_none() {
                    end = Some(pos.checked_add(2).ok_or(DnsError::Malformed)?);
                }
                jumps = jumps.saturating_add(1);
                if jumps > MAX_JUMPS || ptr >= m.len() {
                    return Err(DnsError::Malformed);
                }
                pos = ptr;
            }
            l if l & 0xc0 == 0 => {
                let start = pos.checked_add(1).ok_or(DnsError::Malformed)?;
                let stop = start
                    .checked_add(usize::from(l))
                    .ok_or(DnsError::Malformed)?;
                let label = m.get(start..stop).ok_or(DnsError::Malformed)?;
                total = total.saturating_add(usize::from(l)).saturating_add(1);
                if total > 255 {
                    return Err(DnsError::Malformed);
                }
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                pos = stop;
            }
            _ => return Err(DnsError::Malformed),
        }
    }
}

/// A TXT record's character strings, joined (RFC 1035 §3.3.14).
fn txt_strings(rdata: &[u8]) -> Result<String, DnsError> {
    let mut text = String::new();
    let mut at = 0usize;
    while at < rdata.len() {
        let len = usize::from(*rdata.get(at).ok_or(DnsError::Malformed)?);
        let from = at.checked_add(1).ok_or(DnsError::Malformed)?;
        let to = from.checked_add(len).ok_or(DnsError::Malformed)?;
        text.push_str(&String::from_utf8_lossy(
            rdata.get(from..to).ok_or(DnsError::Malformed)?,
        ));
        at = to;
    }
    Ok(text)
}

/// The records of type `rtype` in the answer section of `m`: each TXT record's strings joined,
/// or each MX record's exchange host. NXDOMAIN is no records.
///
/// # Errors
/// [`DnsError`].
pub fn answers(m: &[u8], rtype: Rtype) -> Result<Vec<String>, DnsError> {
    let flags = u16_at(m, 2)?;
    if flags & 0x8000 == 0 || flags & 0x0200 != 0 {
        return Err(DnsError::Malformed);
    }
    match flags & 0x000f {
        0 => {}
        3 => return Ok(Vec::new()),
        _ => return Err(DnsError::Server),
    }
    let qd = u16_at(m, 4)?;
    let an = u16_at(m, 6)?;
    if qd > 1 || an > MAX_ANSWERS {
        return Err(DnsError::Malformed);
    }
    let mut pos = 12usize;
    for _ in 0..qd {
        let (_, after) = name_at(m, pos)?;
        pos = after.checked_add(4).ok_or(DnsError::Malformed)?;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        let (_, after) = name_at(m, pos)?;
        let ty = u16_at(m, after)?;
        let len = usize::from(u16_at(m, after.checked_add(8).ok_or(DnsError::Malformed)?)?);
        let start = after.checked_add(10).ok_or(DnsError::Malformed)?;
        let stop = start.checked_add(len).ok_or(DnsError::Malformed)?;
        let rdata = m.get(start..stop).ok_or(DnsError::Malformed)?;
        if ty == rtype.code() {
            match rtype {
                Rtype::Txt => out.push(txt_strings(rdata)?),
                Rtype::Mx => {
                    let host_at = start.checked_add(2).ok_or(DnsError::Malformed)?;
                    if len < 3 {
                        return Err(DnsError::Malformed);
                    }
                    out.push(name_at(m, host_at)?.0);
                }
                Rtype::Cname => out.push(name_at(m, start)?.0),
            }
        }
        pos = stop;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn answer(rtype: u16, rdata: &[u8], rcode: u8) -> Vec<u8> {
        let mut q = query("_suiss-access.acme.example", Rtype::Txt).unwrap();
        q[2] = 0x81;
        q[3] = 0x80 | rcode;
        q[7] = 1;
        q.extend_from_slice(&[0xc0, 12]);
        q.extend_from_slice(&rtype.to_be_bytes());
        q.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        q.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        q.extend_from_slice(rdata);
        q
    }

    // TN-90, OP-4
    #[test]
    fn txt_and_mx_answers_are_read_within_their_bounds() {
        let txt = answer(16, b"\x14suiss-access-verify=\x03tok", 0);
        assert_eq!(
            answers(&txt, Rtype::Txt).unwrap(),
            vec![String::from("suiss-access-verify=tok")]
        );
        let mut mx_rdata = vec![0, 10, 4];
        mx_rdata.extend_from_slice(b"mail");
        mx_rdata.extend_from_slice(&[0xc0, 26]);
        let mx = answer(15, &mx_rdata, 0);
        assert_eq!(
            answers(&mx, Rtype::Mx).unwrap(),
            vec![String::from("mail.acme.example")]
        );
        assert_eq!(
            answers(&answer(16, b"", 3), Rtype::Txt).unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            answers(&answer(16, b"", 2), Rtype::Txt),
            Err(DnsError::Server)
        );
        let mut short = txt.clone();
        short.truncate(txt.len() - 2);
        assert_eq!(answers(&short, Rtype::Txt), Err(DnsError::Malformed));
        let mut looped = answer(15, &[0, 10, 0xc0, 0], 0);
        let at = looped.len() - 2;
        looped[at] = 0xc0;
        looped[at + 1] = u8::try_from(at).unwrap();
        assert_eq!(answers(&looped, Rtype::Mx), Err(DnsError::Malformed));
        assert_eq!(query("a..b", Rtype::Mx), Err(DnsError::Name));
    }

    // OP-156 m.3 (i)
    #[test]
    fn cname_answers_name_their_target() {
        let mut rdata = vec![4];
        rdata.extend_from_slice(b"acme");
        rdata.extend_from_slice(&[5]);
        rdata.extend_from_slice(b"suiss");
        rdata.extend_from_slice(&[2]);
        rdata.extend_from_slice(b"id");
        rdata.push(0);
        assert_eq!(
            answers(&answer(5, &rdata, 0), Rtype::Cname).unwrap(),
            vec![String::from("acme.suiss.id")]
        );
        assert_eq!(
            answers(&answer(16, b"\x01x", 0), Rtype::Cname).unwrap(),
            Vec::<String>::new()
        );
    }
}
