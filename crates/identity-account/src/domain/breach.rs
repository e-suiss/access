//! The breached-password check's pure part (IDP-3, OP-146 m.4 (e)): the k-anonymity range
//! query and the reading of a range body. Only the five-character prefix leaves the process.

use access_crypto::breach::range_digest;

use crate::domain::password::Password;

/// A password's range query: the prefix asked for and the suffix looked for.
pub struct RangeQuery {
    digest: [u8; 40],
}

/// The range body is not a list of `SUFFIX:COUNT` lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed range body")]
pub struct MalformedRange;

impl RangeQuery {
    /// The query of `password`.
    #[must_use]
    pub fn of(password: &Password) -> Self {
        Self {
            digest: range_digest(password.bytes()),
        }
    }

    /// The five upper-case hex characters sent out.
    #[must_use]
    pub fn prefix(&self) -> &str {
        self.digest
            .get(..5)
            .and_then(|p| core::str::from_utf8(p).ok())
            .unwrap_or_default()
    }

    fn suffix(&self) -> &[u8] {
        self.digest.get(5..).unwrap_or_default()
    }

    /// Whether `body`, the range of [`RangeQuery::prefix`], lists the password. Padding
    /// entries (count 0) list nothing.
    ///
    /// # Errors
    /// [`MalformedRange`].
    pub fn listed_in(&self, body: &str) -> Result<bool, MalformedRange> {
        let mut found = false;
        for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (suffix, count) = line.split_once(':').ok_or(MalformedRange)?;
            if suffix.len() != 35 || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(MalformedRange);
            }
            let count: u64 = count.trim().parse().map_err(|_| MalformedRange)?;
            if count > 0 && suffix.as_bytes().eq_ignore_ascii_case(self.suffix()) {
                found = true;
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // IDP-3, OP-146
    #[test]
    fn prefix_and_lookup() {
        let q = RangeQuery::of(&Password::new("P@ssw0rd").unwrap());
        assert_eq!(q.prefix(), "21BD1");
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    2DC183F740EE76F27B78EB39C8AD972A757:52579\r\n\
                    3DC183F740EE76F27B78EB39C8AD972A757:0\r\n";
        assert_eq!(q.listed_in(body), Ok(true));
        let padded = "2dc183f740ee76f27b78eb39c8ad972a757:0\n";
        assert_eq!(q.listed_in(padded), Ok(false));
        assert_eq!(q.listed_in(""), Ok(false));
        assert_eq!(q.listed_in("<html>"), Err(MalformedRange));
    }
}
