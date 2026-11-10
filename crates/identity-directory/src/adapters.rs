//! The LDAP pull client (§10.6.4, OP-155 m.3 (n)): LDAPS with TLS 1.3 only (CR-12), a simple bind
//! with the connector's service account, then a paged subtree search above the watermark. It
//! sends three operations (bind, search, unbind) and nothing that replicates.

use std::sync::Arc;
use std::time::Duration;

use access_crypto::Secret;
use rustls::RootCertStore;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::ber::{self, BerError, Reader, cat, int, tlv};
use crate::domain::{MAX_ENTRIES, READ, SourceEntry};

/// Longest one pull may take.
pub const DEADLINE: Duration = Duration::from_secs(300);

/// Entries per page.
pub const PAGE: u64 = 500;

const PAGED: &str = "1.2.840.113556.1.4.319";

/// Why a pull failed; nothing was applied.
#[derive(Debug, thiserror::Error)]
pub enum PullError {
    /// The source refused the bind or the search, with its result code.
    #[error("refused by the source: {0}")]
    Refused(u64),
    /// The source answered outside the protocol or above the limits.
    #[error(transparent)]
    Ber(#[from] BerError),
    /// No answer: connection, TLS or the deadline.
    #[error("source unavailable")]
    Unavailable,
    /// The configuration was refused.
    #[error("configuration: {0}")]
    Config(&'static str),
}

/// Where the source is and how the connector proves who it is.
pub struct Source {
    /// `host:port` of the LDAPS listener.
    pub addr: String,
    /// The name the source's certificate is checked for.
    pub server_name: String,
    /// The roots for that certificate, PEM.
    pub roots_pem: Vec<u8>,
    /// The service account's DN.
    pub bind_dn: String,
    /// Its password, from the vault.
    pub password: Secret<String>,
    /// The subtree to read.
    pub base: String,
}

impl core::fmt::Debug for Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Source")
            .field("addr", &self.addr)
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

fn octets(s: &[u8]) -> Vec<u8> {
    tlv(0x04, s)
}

fn message(id: u64, op: Vec<u8>, controls: Option<Vec<u8>>) -> Vec<u8> {
    let mut parts = vec![int(0x02, id), op];
    if let Some(c) = controls {
        parts.push(tlv(0xa0, &c));
    }
    tlv(0x30, &cat(&parts))
}

fn eq(attr: &str, value: &str) -> Vec<u8> {
    tlv(
        0xa3,
        &cat(&[octets(attr.as_bytes()), octets(value.as_bytes())]),
    )
}

/// `(&(|(objectClass=user)(objectClass=inetOrgPerson)(objectClass=group)(objectClass=groupOfNames))(uSNChanged>=n))`.
fn search_filter(watermark: u64) -> Vec<u8> {
    let classes = cat(&[
        eq("objectClass", "user"),
        eq("objectClass", "inetOrgPerson"),
        eq("objectClass", "group"),
        eq("objectClass", "groupOfNames"),
    ]);
    let above = tlv(
        0xa5,
        &cat(&[
            octets(b"uSNChanged"),
            octets(watermark.saturating_add(1).to_string().as_bytes()),
        ]),
    );
    tlv(0xa0, &cat(&[tlv(0xa1, &classes), above]))
}

fn search(id: u64, base: &str, watermark: u64, cookie: &[u8]) -> Vec<u8> {
    let attrs: Vec<Vec<u8>> = READ.iter().map(|a| octets(a.as_bytes())).collect();
    let op = tlv(
        0x63,
        &cat(&[
            octets(base.as_bytes()),
            tlv(0x0a, &[2]),
            tlv(0x0a, &[0]),
            int(0x02, 0),
            int(0x02, 0),
            tlv(0x01, &[0]),
            search_filter(watermark),
            tlv(0x30, &cat(&attrs)),
        ]),
    );
    let value = tlv(0x30, &cat(&[int(0x02, PAGE), octets(cookie)]));
    let control = tlv(
        0x30,
        &cat(&[octets(PAGED.as_bytes()), tlv(0x01, &[0]), octets(&value)]),
    );
    message(id, op, Some(tlv(0x30, &control)))
}

async fn read<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Result<Vec<u8>, PullError> {
    let mut chunk = [0_u8; 8192];
    let total = loop {
        if let Some(n) = ber::frame_len(buf)? {
            break n;
        }
        let n = s
            .read(&mut chunk)
            .await
            .map_err(|_| PullError::Unavailable)?;
        if n == 0 {
            return Err(PullError::Unavailable);
        }
        buf.extend_from_slice(chunk.get(..n).ok_or(PullError::Unavailable)?);
    };
    while buf.len() < total {
        let n = s
            .read(&mut chunk)
            .await
            .map_err(|_| PullError::Unavailable)?;
        if n == 0 {
            return Err(PullError::Unavailable);
        }
        buf.extend_from_slice(chunk.get(..n).ok_or(PullError::Unavailable)?);
    }
    let rest = buf.split_off(total);
    Ok(core::mem::replace(buf, rest))
}

/// One message's protocol operation: its tag, its content and its controls.
type Op = (u8, Vec<u8>, Option<Vec<u8>>);

fn op(msg: &[u8]) -> Result<Op, BerError> {
    let mut outer = Reader::new(msg);
    let mut m = Reader::new(outer.expect(0x30)?);
    m.expect(0x02)?;
    let o = m.element()?;
    let controls = if m.is_empty() {
        None
    } else {
        Some(m.expect(0xa0)?.to_vec())
    };
    Ok((o.tag, o.content.to_vec(), controls))
}

fn result_code(content: &[u8]) -> Result<u64, BerError> {
    let mut r = Reader::new(content);
    ber::integer(r.expect(0x0a)?)
}

fn entry(content: &[u8]) -> Result<SourceEntry, BerError> {
    let mut r = Reader::new(content);
    let dn = String::from_utf8(r.expect(0x04)?.to_vec()).map_err(|_| BerError::Malformed)?;
    let mut attrs = Reader::new(r.expect(0x30)?);
    let mut out = SourceEntry {
        dn,
        ..SourceEntry::default()
    };
    while !attrs.is_empty() {
        let mut a = Reader::new(attrs.expect(0x30)?);
        let name = String::from_utf8(a.expect(0x04)?.to_vec())
            .map_err(|_| BerError::Malformed)?
            .to_ascii_lowercase();
        let mut vals = Reader::new(a.expect(0x31)?);
        let held = out.attributes.entry(name).or_default();
        while !vals.is_empty() {
            held.push(vals.expect(0x04)?.to_vec());
        }
    }
    Ok(out)
}

fn cookie(controls: Option<&[u8]>) -> Result<Vec<u8>, BerError> {
    let Some(c) = controls else {
        return Ok(Vec::new());
    };
    let mut list = Reader::new(c);
    while !list.is_empty() {
        let mut ctl = Reader::new(list.expect(0x30)?);
        let oid = ctl.expect(0x04)?;
        if oid != PAGED.as_bytes() {
            continue;
        }
        let mut next = ctl.element()?;
        if next.tag == 0x01 {
            next = ctl.element()?;
        }
        let mut value = Reader::new(next.content);
        let mut seq = Reader::new(value.expect(0x30)?);
        seq.expect(0x02)?;
        return Ok(seq.expect(0x04)?.to_vec());
    }
    Ok(Vec::new())
}

fn connector(roots_pem: &[u8]) -> Result<TlsConnector, PullError> {
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(
        CertificateDer::pem_slice_iter(roots_pem).filter_map(Result::ok),
    );
    if added == 0 {
        return Err(PullError::Config("no root certificate"));
    }
    // CR-12
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| PullError::Config("tls"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(tls)))
}

impl Source {
    /// The entries changed above `watermark`, at most [`MAX_ENTRIES`].
    ///
    /// # Errors
    /// [`PullError`].
    pub async fn changes(&self, watermark: u64) -> Result<Vec<SourceEntry>, PullError> {
        tokio::time::timeout(DEADLINE, self.pull(watermark))
            .await
            .map_err(|_| PullError::Unavailable)?
    }

    async fn pull(&self, watermark: u64) -> Result<Vec<SourceEntry>, PullError> {
        let name = ServerName::try_from(self.server_name.clone())
            .map_err(|_| PullError::Config("server name"))?;
        let tcp = TcpStream::connect(&self.addr)
            .await
            .map_err(|_| PullError::Unavailable)?;
        let mut s = connector(&self.roots_pem)?
            .connect(name, tcp)
            .await
            .map_err(|_| PullError::Unavailable)?;
        let bind = message(
            1,
            tlv(
                0x60,
                &cat(&[
                    int(0x02, 3),
                    octets(self.bind_dn.as_bytes()),
                    tlv(0x80, self.password.expose().as_bytes()),
                ]),
            ),
            None,
        );
        s.write_all(&bind)
            .await
            .map_err(|_| PullError::Unavailable)?;
        let mut buf = Vec::new();
        let (tag, content, _) = op(&read(&mut s, &mut buf).await?)?;
        if tag != 0x61 {
            return Err(BerError::Malformed.into());
        }
        match result_code(&content)? {
            0 => {}
            code => return Err(PullError::Refused(code)),
        }
        let mut out = Vec::new();
        let mut page_cookie = Vec::new();
        let mut id = 2_u64;
        loop {
            s.write_all(&search(id, &self.base, watermark, &page_cookie))
                .await
                .map_err(|_| PullError::Unavailable)?;
            loop {
                let (tag, content, controls) = op(&read(&mut s, &mut buf).await?)?;
                match tag {
                    0x64 => {
                        if out.len() < MAX_ENTRIES {
                            out.push(entry(&content)?);
                        }
                    }
                    0x73 => {}
                    0x65 => {
                        match result_code(&content)? {
                            0 => {}
                            code => return Err(PullError::Refused(code)),
                        }
                        page_cookie = cookie(controls.as_deref())?;
                        break;
                    }
                    _ => return Err(BerError::Malformed.into()),
                }
            }
            if page_cookie.is_empty() || out.len() >= MAX_ENTRIES {
                break;
            }
            id = id.saturating_add(1);
        }
        let _ = s
            .write_all(&message(id.saturating_add(1), vec![0x42, 0x00], None))
            .await;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // §10.6.4, IDP-17
    #[test]
    fn the_search_reads_only_its_attributes() {
        let m = search(2, "dc=corp", 7, &[]);
        let text = String::from_utf8_lossy(&m);
        for f in crate::domain::FORBIDDEN {
            assert!(!text.contains(f), "{f}");
        }
        assert!(text.contains("uSNChanged") && text.contains('8'));
        assert!(text.contains(PAGED));
        let (tag, _, controls) = op(&m).unwrap();
        assert_eq!(tag, 0x63);
        assert!(controls.is_some());
    }
}
