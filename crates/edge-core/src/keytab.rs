//! The MIT keytab format (version `0x0502`) as the Kerberos gateway reads it (§10.6.4, OP-155
//! m.3 (o)). Sans-I/O and allocation-light: an entry points into the caller's buffer, which the
//! gateway keeps in secret memory. Only entries of the configured SPN under an AES256 enctype are
//! kept; a keytab without one is refused, so the gateway does not start.

use access_internal_api::edge::kerberos::ENCTYPES;

/// Largest keytab read.
pub const MAX_KEYTAB: usize = 64 * 1024;

/// Most entries kept.
pub const MAX_ENTRIES: usize = 64;

/// Why a keytab is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeytabError {
    /// Not a version `0x0502` keytab, truncated, or larger than [`MAX_KEYTAB`].
    #[error("malformed keytab")]
    Malformed,
    /// No AES256 key of the configured SPN.
    #[error("no AES256 key for the configured SPN")]
    NoKey,
}

/// One kept entry. The key is `key` within the buffer that was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The principal's realm.
    pub realm: String,
    /// The principal's name components.
    pub components: Vec<String>,
    /// The principal's name type.
    pub name_type: u32,
    /// The key version.
    pub kvno: u32,
    /// The enctype.
    pub enctype: i32,
    /// Where the key lies in the buffer.
    pub key: core::ops::Range<usize>,
}

impl Entry {
    /// The principal, `component/component@REALM`.
    #[must_use]
    pub fn principal(&self) -> String {
        let mut s = self.components.join("/");
        s.push('@');
        s.push_str(&self.realm);
        s
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
    end: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<core::ops::Range<usize>, KeytabError> {
        let next = self.at.checked_add(n).ok_or(KeytabError::Malformed)?;
        if next > self.end {
            return Err(KeytabError::Malformed);
        }
        let r = self.at..next;
        self.at = next;
        Ok(r)
    }

    fn bytes(&mut self, n: usize) -> Result<&[u8], KeytabError> {
        let r = self.take(n)?;
        self.buf.get(r).ok_or(KeytabError::Malformed)
    }

    fn u8(&mut self) -> Result<u8, KeytabError> {
        self.bytes(1)?
            .first()
            .copied()
            .ok_or(KeytabError::Malformed)
    }

    fn u16(&mut self) -> Result<u16, KeytabError> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes(
            b.try_into().map_err(|_| KeytabError::Malformed)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, KeytabError> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes(
            b.try_into().map_err(|_| KeytabError::Malformed)?,
        ))
    }

    fn text(&mut self) -> Result<String, KeytabError> {
        let n = usize::from(self.u16()?);
        let b = self.bytes(n)?;
        core::str::from_utf8(b)
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_graphic()))
            .map(String::from)
            .ok_or(KeytabError::Malformed)
    }
}

/// The AES256 entries of `spn` in the keytab `buf`.
///
/// # Errors
/// [`KeytabError`].
pub fn read(buf: &[u8], spn: &str) -> Result<Vec<Entry>, KeytabError> {
    if buf.len() > MAX_KEYTAB || buf.get(..2) != Some(&[0x05, 0x02]) {
        return Err(KeytabError::Malformed);
    }
    let mut out = Vec::new();
    let mut c = Cursor {
        buf,
        at: 2,
        end: buf.len(),
    };
    while c.at < buf.len() {
        c.end = buf.len();
        let size = i32::from_be_bytes(c.bytes(4)?.try_into().map_err(|_| KeytabError::Malformed)?);
        let len = usize::try_from(size.unsigned_abs()).map_err(|_| KeytabError::Malformed)?;
        let start = c.at;
        let end = start.checked_add(len).ok_or(KeytabError::Malformed)?;
        if end > buf.len() {
            return Err(KeytabError::Malformed);
        }
        if size <= 0 {
            c.at = end;
            continue;
        }
        c.end = end;
        let count = c.u16()?;
        let realm = c.text()?;
        let mut components = Vec::new();
        for _ in 0..count {
            components.push(c.text()?);
        }
        let name_type = c.u32()?;
        c.u32()?;
        let vno8 = c.u8()?;
        let enctype = i32::from(c.u16()?);
        let key_len = usize::from(c.u16()?);
        let key = c.take(key_len)?;
        let kvno = if c.end.saturating_sub(c.at) >= 4 {
            match c.u32()? {
                0 => u32::from(vno8),
                v => v,
            }
        } else {
            u32::from(vno8)
        };
        c.at = end;
        let e = Entry {
            realm,
            components,
            name_type,
            kvno,
            enctype,
            key,
        };
        if e.principal() == spn && ENCTYPES.contains(&e.enctype) && out.len() < MAX_ENTRIES {
            out.push(e);
        }
    }
    if out.is_empty() {
        Err(KeytabError::NoKey)
    } else {
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    fn entry(components: &[&str], enctype: u16, kvno: u32, key: &[u8]) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend(u16::try_from(components.len()).unwrap().to_be_bytes());
        for s in std::iter::once(&"CORP.EXAMPLE").chain(components) {
            e.extend(u16::try_from(s.len()).unwrap().to_be_bytes());
            e.extend(s.as_bytes());
        }
        e.extend(1_u32.to_be_bytes());
        e.extend(0_u32.to_be_bytes());
        e.push(u8::try_from(kvno.min(255)).unwrap());
        e.extend(enctype.to_be_bytes());
        e.extend(u16::try_from(key.len()).unwrap().to_be_bytes());
        e.extend(key);
        e.extend(kvno.to_be_bytes());
        let mut out = i32::try_from(e.len()).unwrap().to_be_bytes().to_vec();
        out.extend(e);
        out
    }

    // IDP-17, OP-155 m.3 (o)
    #[test]
    fn only_aes256_keys_of_the_spn_are_kept() {
        let spn = "HTTP/access.corp.example@CORP.EXAMPLE";
        let k1: Vec<u8> = (0_u8..32).collect();
        let mut kt = vec![0x05, 0x02];
        kt.extend(entry(&["HTTP", "access.corp.example"], 18, 3, &k1));
        kt.extend(entry(&["HTTP", "access.corp.example"], 23, 3, &k1[..16]));
        kt.extend((-8_i32).to_be_bytes());
        kt.extend([0; 8]);
        kt.extend(entry(&["HTTP", "other.corp.example"], 18, 3, &k1));
        kt.extend(entry(&["HTTP", "access.corp.example"], 20, 300, &k1));
        let got = read(&kt, spn).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].enctype, got[0].kvno), (18, 3));
        assert_eq!(&kt[got[0].key.clone()], k1.as_slice());
        assert_eq!((got[1].enctype, got[1].kvno), (20, 300));
        assert_eq!(
            read(&kt, "HTTP/nowhere@CORP.EXAMPLE"),
            Err(KeytabError::NoKey)
        );
        let mut rc4 = vec![0x05, 0x02];
        rc4.extend(entry(&["HTTP", "access.corp.example"], 23, 3, &k1[..16]));
        assert_eq!(read(&rc4, spn), Err(KeytabError::NoKey));
        assert_eq!(read(&[0x05, 0x01], spn), Err(KeytabError::Malformed));
        let mut cut = kt.clone();
        cut.truncate(kt.len() - 5);
        assert_eq!(read(&cut, spn), Err(KeytabError::Malformed));
    }
}
