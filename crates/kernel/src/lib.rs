//! Access Kernel (CMP-24).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

/// Version of the Kernel public API (OP-1 rule 4: every semantic version's Kernel is kept).
pub const API_VERSION: ApiVersion = ApiVersion { major: 0, minor: 0 };

/// A Kernel public API version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiVersion {
    /// Incremented on breaking changes.
    pub major: u16,
    /// Incremented on additive changes.
    pub minor: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_version_starts_at_zero() {
        assert_eq!(API_VERSION, ApiVersion { major: 0, minor: 0 });
    }
}
