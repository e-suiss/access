//! X.509 client certificates of the identity plane (§10.2.5, MD-8, OP-155 m.3 (m)), free of I/O
//! except through [`ports::Fetch`] (OP-63).
//!
//! - [`domain::cert`]: the certificate fields path validation does not expose, read with the
//!   bounded DER reader (CR-10: at most 8 KB).
//! - [`domain::path`]: path validation with rustls-webpki to the realm's accepted CAs, for client
//!   authentication.
//! - [`domain::ocsp`]: the in-house RFC 6960 client: a bounded DER request and the checks of a
//!   signed response.
//! - [`domain::crl`]: CRLs, read and checked by rustls-webpki.
//! - [`domain::login`]: what a verified certificate says for sign-in: the identifier it maps to,
//!   whether its issuer policy is a hardware-bound PIV policy, its thumbprint.
//! - [`app`]: revocation, fail-closed: a certificate whose status is unknown, unreachable or
//!   stale is refused, and answers are kept until their `nextUpdate`.

pub mod app;
pub mod domain;
pub mod ports;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// Why a certificate is refused; a decision, not an infrastructure error (OP-64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum X509Error {
    /// Not well-formed DER, or larger than allowed.
    #[error("malformed certificate")]
    Malformed,
    /// No path to an accepted CA for client authentication.
    #[error("no valid path")]
    Path,
    /// The certificate names no identifier the realm's rule maps, or more than one.
    #[error("no identifier")]
    Identifier,
}

impl X509Error {
    /// The stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "certificate-malformed",
            Self::Path => "certificate-path",
            Self::Identifier => "certificate-identifier",
        }
    }
}
