//! The Public Suffix List, embedded at build time from the pinned copy in `data/` (TN-18,
//! OP-153 m.25 (f)): `data/SOURCES` names its upstream commit and `data/SHA256SUMS` its digest.
//! Nothing is fetched at build or run time.

use std::sync::LazyLock;

use publicsuffix::{List, Psl as _};

use super::rp::PublicSuffix;

/// The pinned list, as committed.
pub const LIST: &str = include_str!("../../data/public_suffix_list.dat");

/// The pinned digest line (`sha256  file`).
pub const SHA256SUMS: &str = include_str!("../../data/SHA256SUMS");

static PARSED: LazyLock<Option<List>> = LazyLock::new(|| LIST.parse().ok());

/// Registrable domains (eTLD+1) by the embedded list, ICANN and private sections both, as
/// browsers count Related Origins labels; a suffix the list does not name is one label (the
/// list's implicit `*` rule).
#[derive(Clone, Copy, Debug, Default)]
pub struct Psl;

impl Psl {
    /// The label a Related Origins list counts for `host`: the first label of its registrable
    /// domain. `None` for a host that is itself a public suffix.
    #[must_use]
    pub fn label(host: &str) -> Option<&str> {
        Self.registrable(host)?.split('.').next()
    }
}

impl PublicSuffix for Psl {
    fn registrable<'h>(&self, host: &'h str) -> Option<&'h str> {
        if host.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        let domain = PARSED.as_ref()?.domain(host.as_bytes())?;
        let start = host.len().checked_sub(domain.as_bytes().len())?;
        host.get(start..)
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    // OP-153 m.25 (f), §14.7
    #[test]
    fn the_embedded_list_is_the_pinned_one() {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, LIST.as_bytes());
        let hex = digest.as_ref().iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        assert_eq!(
            SHA256SUMS.split_whitespace().collect::<Vec<_>>(),
            [hex.as_str(), "public_suffix_list.dat"]
        );
        assert!(PARSED.is_some());
    }

    // TN-18, OP-153 m.22 (j), m.25 (f)
    #[test]
    fn the_registrable_domain_follows_the_list() {
        for (host, registrable) in [
            ("shop.acme.example", Some("acme.example")),
            ("acme.example", Some("acme.example")),
            ("www.acme.co.uk", Some("acme.co.uk")),
            ("brand.github.io", Some("brand.github.io")),
            ("a.b.acme.com.tr", Some("acme.com.tr")),
            ("co.uk", None),
            ("github.io", None),
            ("example", None),
            ("Acme.example", None),
        ] {
            assert_eq!(Psl.registrable(host), registrable, "{host}");
        }
        assert_eq!(Psl::label("www.acme.co.uk"), Some("acme"));
        assert_eq!(Psl::label("brand.github.io"), Some("brand"));
        assert_eq!(Psl::label("co.uk"), None);
    }
}
