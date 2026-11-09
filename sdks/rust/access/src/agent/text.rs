//! Text that arrives with a decision, a remediation, a tool listing or an Agent Card (A-7, SI-16,
//! §6.6, §9.4.1): data for planning, never an instruction. It has no `Display`, so it is not
//! formatted into a prompt by accident, and nothing in this SDK branches on its content.

use alloc::string::String;

/// A text value kept as data.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Untrusted(String);

impl Untrusted {
    pub(crate) fn new(text: &str) -> Self {
        Self(String::from(text))
    }

    /// The text, for display as data or comparison with a known identifier.
    #[must_use]
    pub fn as_data(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for Untrusted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Untrusted({} bytes)", self.0.len())
    }
}
