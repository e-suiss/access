//! Consumer e-mail, ISP and university domains (OP-153 m.1 (d), TN-90): a domain on the list
//! never gets autojoin or a corporate-domain relaxation. The list is
//! `conformance/data/consumer-email-domains.txt`, read once at start; an operator may add to it
//! and a tenant cannot narrow it.

use std::collections::BTreeSet;

const EMBEDDED: &str = include_str!("../../../../conformance/data/consumer-email-domains.txt");

/// A line of a domain list outside its format.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("line {0}: not a lower-case domain or suffix rule")]
pub struct ListError(pub usize);

/// The consumer domain list.
#[derive(Clone, Debug, Default)]
pub struct ConsumerDomains {
    exact: BTreeSet<String>,
    suffixes: BTreeSet<String>,
    middle: BTreeSet<String>,
}

fn label_ok(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !l.starts_with('-')
        && !l.ends_with('-')
}

fn domain_ok(d: &str) -> bool {
    d.len() <= 253 && d.contains('.') && d.split('.').all(label_ok)
}

impl ConsumerDomains {
    /// The list Access ships.
    ///
    /// # Errors
    /// [`ListError`] when the shipped file is outside its format.
    pub fn embedded() -> Result<Self, ListError> {
        let mut list = Self::default();
        list.add(EMBEDDED)?;
        Ok(list)
    }

    /// Adds an operator's lines to the list; nothing is ever removed (OP-153 m.1 (d)).
    ///
    /// # Errors
    /// [`ListError`] naming the first bad line; the list is then unchanged.
    pub fn add(&mut self, text: &str) -> Result<(), ListError> {
        let mut next = self.clone();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = ListError(n.saturating_add(1));
            if let Some(rest) = line.strip_prefix("*.") {
                if let Some(label) = rest.strip_suffix(".*") {
                    if !label_ok(label) {
                        return Err(bad);
                    }
                    next.middle.insert(label.to_owned());
                } else if rest.split('.').all(label_ok) {
                    next.suffixes.insert(rest.to_owned());
                } else {
                    return Err(bad);
                }
            } else if domain_ok(line) {
                next.exact.insert(line.to_owned());
            } else {
                return Err(bad);
            }
        }
        *self = next;
        Ok(())
    }

    /// Whether `domain` (the part after `@`) is a consumer domain; compared in lower case.
    #[must_use]
    pub fn contains(&self, domain: &str) -> bool {
        let d = domain.trim_end_matches('.').to_ascii_lowercase();
        if self.exact.contains(&d) {
            return true;
        }
        if self
            .suffixes
            .iter()
            .any(|s| d == *s || d.strip_suffix(s.as_str()).is_some_and(|p| p.ends_with('.')))
        {
            return true;
        }
        let labels: Vec<&str> = d.split('.').collect();
        labels.len() >= 2
            && labels
                .len()
                .checked_sub(2)
                .and_then(|i| labels.get(i))
                .is_some_and(|l| self.middle.contains(*l))
    }

    /// How many exact domains the list holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exact.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty() && self.middle.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // TN-90, OP-153 m.1 (d)
    #[test]
    fn the_shipped_list_refuses_consumer_isp_and_university_domains() {
        let list = ConsumerDomains::embedded().unwrap();
        assert!(list.len() > 30_000);
        for d in [
            "gmail.com",
            "Yandex.com.TR",
            "ttmail.com",
            "turk.net",
            "metu.edu.tr",
            "cs.metu.edu.tr",
            "mit.edu",
            "ox.ac.uk",
            "u-tokyo.ac.jp",
            "ankara.k12.tr",
        ] {
            assert!(list.contains(d), "{d}");
        }
        for d in ["acme.com", "edu.example", "acme.com.tr", "mail.acme.io"] {
            assert!(!list.contains(d), "{d}");
        }
    }

    // OP-153 m.1 (d)
    #[test]
    fn an_operator_only_adds_and_a_bad_line_changes_nothing() {
        let mut list = ConsumerDomains::embedded().unwrap();
        let before = list.len();
        list.add("# ours\nmail.example.org\n*.school.example\n")
            .unwrap();
        assert!(list.contains("mail.example.org"));
        assert!(list.contains("a.school.example"));
        assert!(list.contains("gmail.com"));
        assert_eq!(list.len(), before + 1);
        assert_eq!(list.add("ok.example\nNot A Domain\n"), Err(ListError(2)));
        assert!(!list.contains("ok.example"));
    }
}
