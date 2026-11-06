//! A headless client for a local Access deployment (OP-69, OP-149 m.26 (b), (c), (e), m.29
//! (b)). It runs the real protocol against a running Access and prints what it got: the
//! authorization code flow with PKCE and DPoP through the Frontend API's JSON login, with a
//! password or the test user's software passkey, optionally naming a platform product as the
//! token's RFC 8707 resource; an approval on the hosted Approval Surface; a `party_compromise`
//! Claim handed to Claim Ingest with a product's PEP certificate; and a platform client's
//! stream status. TLS is verified against the local CA, always; `http://` is refused.

pub mod adp;
pub mod approve;
pub mod claims;
pub mod dpop;
pub mod http;
pub mod intent;
pub mod login;
pub mod passkey;
pub mod platform;
pub mod token;

/// Why a step did not complete.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Not an `https` URL, or one that cannot be split.
    #[error("not an https URL: {0}")]
    Url(String),
    /// A file could not be read, or is not what it should hold.
    #[error("{0}: {1}")]
    File(String, String),
    /// TLS could not be set up or did not complete.
    #[error("tls: {0}")]
    Tls(String),
    /// The connection failed or the answer was not HTTP/1.1.
    #[error("http: {0}")]
    Http(String),
    /// Access answered, but not what the flow needs; the answer is kept for the operator.
    #[error("unexpected answer at {step}: {status} {body}")]
    Unexpected {
        /// The step of the flow.
        step: &'static str,
        /// The status.
        status: u16,
        /// The body, as text.
        body: String,
    },
    /// A key could not be made or used.
    #[error("key: {0}")]
    Key(String),
    /// A value could not be encoded.
    #[error("encoding")]
    Encode,
    /// A signed answer did not verify.
    #[error("verification: {0}")]
    Verify(String),
}
