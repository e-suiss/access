//! Access's own small ACME client (RFC 8555, OP-156 m.3 (i), (z)): one account key, ES256 JWS
//! with a fresh nonce per request, `dns` identifiers, the TLS-ALPN-01 challenge only (RFC 8737)
//! and a CSR for a key made in this process.
//!
//! - [`jws`]: the flattened JWS of every request, the account JWK and its thumbprint, the key
//!   authorization and its TLS-ALPN-01 digest.
//! - [`wire`]: the resources the server answers with, read with every size bounded.

pub mod jws;
pub mod wire;

/// Why an ACME exchange failed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AcmeError {
    /// The server did not answer, or not in time.
    #[error("unreachable")]
    Unreachable,
    /// The server answered with something that is not ACME, or a URL off its own origin.
    #[error("protocol: {0}")]
    Protocol(&'static str),
    /// The server refused with an RFC 8555 problem of this type.
    #[error("refused: {0}")]
    Refused(String),
    /// The order or a challenge became invalid.
    #[error("invalid: {0}")]
    Invalid(&'static str),
    /// The order did not become valid within the polls allowed.
    #[error("timed out")]
    Timeout,
    /// The account or certificate key failed.
    #[error("key")]
    Key,
    /// The server offers no TLS-ALPN-01 challenge for the identifier.
    #[error("no tls-alpn-01 challenge")]
    NoChallenge,
    /// The issued certificate does not name the host, carry the key or cover now.
    #[error("certificate does not match the order")]
    Certificate,
    /// The challenge could not be published to the TLS listeners.
    #[error("challenge not published")]
    Publish,
}

impl AcmeError {
    /// Stable reason code, shown on the domain's status.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unreachable => "acme-unreachable",
            Self::Protocol(_) => "acme-protocol",
            Self::Refused(_) => "acme-refused",
            Self::Invalid(_) => "acme-invalid",
            Self::Timeout => "acme-timeout",
            Self::Key => "acme-key",
            Self::NoChallenge => "acme-no-tls-alpn",
            Self::Certificate => "acme-certificate-mismatch",
            Self::Publish => "acme-publish",
        }
    }

    /// Whether trying again later may help.
    #[must_use]
    pub const fn transient(&self) -> bool {
        matches!(self, Self::Unreachable | Self::Timeout | Self::Publish)
    }
}
