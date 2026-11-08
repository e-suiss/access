//! The pseudonymous context a PEP names a bootstrap Exercise by (§13.7.4, OP-152 m.5 (b)): a
//! keyed pseudonym of the client's address prefix or an attestation class, never the address.
//! The authority core counts bootstrap Grants per PEP and context and hour; a request without
//! one is counted under its PEP alone.

/// A pseudonymous rate context.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RateContext(String);

impl RateContext {
    /// The longest context.
    pub const MAX_LEN: usize = 96;

    /// The prefix of an address-prefix pseudonym.
    pub const ADDRESS: &'static str = "ip:";

    /// The prefix of an attestation class.
    pub const ATTESTATION: &'static str = "att:";

    /// The context with this wire form: 1 to [`Self::MAX_LEN`] ASCII letters, digits, `-`, `_`,
    /// `.` or `:`.
    #[must_use]
    pub fn parse(wire: &str) -> Option<Self> {
        let fits = (1..=Self::MAX_LEN).contains(&wire.len())
            && wire
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
        fits.then(|| Self(String::from(wire)))
    }

    /// The context of a keyed address-prefix pseudonym.
    #[must_use]
    pub fn address(pseudonym: &[u8; 32]) -> Self {
        use std::fmt::Write as _;
        let mut s = String::from(Self::ADDRESS);
        for b in pseudonym {
            let _ = write!(s, "{b:02x}");
        }
        Self(s)
    }

    /// The context of an attestation class; `None` when the class does not fit the grammar.
    #[must_use]
    pub fn attestation(class: &str) -> Option<Self> {
        Self::parse(&format!("{}{class}", Self::ATTESTATION))
    }

    /// The wire form.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-152 m.5 (b): a context is a short token of a closed alphabet
    #[test]
    fn a_context_is_a_pseudonym_or_a_class() {
        let a = RateContext::address(&[0xab; 32]);
        assert_eq!(a.name().len(), 3 + 64);
        assert_eq!(RateContext::parse(a.name()), Some(a));
        assert_eq!(
            RateContext::attestation("android-strongbox")
                .unwrap()
                .name(),
            "att:android-strongbox"
        );
        for bad in [
            "",
            "192.168.1.1/24",
            "2001:db8::1 x",
            "ip:zz zz",
            "ünicode",
            &"a".repeat(RateContext::MAX_LEN + 1),
        ] {
            assert_eq!(RateContext::parse(bad), None, "{bad}");
        }
    }
}
