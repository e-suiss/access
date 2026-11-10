//! The ports of custom domains (OP-63): the ACME server's HTTPS, the account key in the
//! identity signer, the TLS listeners that answer a TLS-ALPN-01 challenge, the DNS a
//! verification reads and the pause between polls.

use core::future::Future;
use core::time::Duration;

/// A dependency did not answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unavailable: {0}")]
pub struct Unavailable(pub String);

/// One HTTP answer of the ACME server, with the headers ACME needs (RFC 8555 §6.5, §7.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Answer {
    /// Status.
    pub status: u16,
    /// `Replay-Nonce`.
    pub nonce: Option<String>,
    /// `Location`.
    pub location: Option<String>,
    /// `Retry-After` in seconds.
    pub retry_after_s: Option<u64>,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// The body.
    pub body: Vec<u8>,
}

/// HTTPS to the configured ACME directory's origin only.
pub trait AcmeHttp: Send + Sync {
    /// `GET url`, the body read up to `max_body` bytes.
    fn get(
        &self,
        url: &str,
        max_body: usize,
    ) -> impl Future<Output = Result<Answer, Unavailable>> + Send;

    /// `HEAD url` (a new nonce).
    fn head(&self, url: &str) -> impl Future<Output = Result<Answer, Unavailable>> + Send;

    /// `POST url` with an `application/jose+json` body, the answer read up to `max_body`.
    fn post(
        &self,
        url: &str,
        body: &[u8],
        max_body: usize,
    ) -> impl Future<Output = Result<Answer, Unavailable>> + Send;
}

/// The ACME account key: ECDSA P-256 in the identity signer, purpose `acme` (OP-156 m.3 (i)).
pub trait AccountKey: Send + Sync {
    /// The uncompressed SEC1 public point.
    fn public_point(&self) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send;

    /// Signs a JWS signing input: raw `r ‖ s`.
    fn sign(&self, input: &[u8]) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send;
}

/// The TLS listeners' TLS-ALPN-01 answers (RFC 8737): a published challenge is served for
/// `host` on every node until it is withdrawn.
pub trait Challenges: Send + Sync {
    /// Serves the challenge whose key authorization digest is `digest` for `host`.
    fn publish(
        &self,
        host: &str,
        digest: [u8; 32],
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// Stops serving the challenge for `host`.
    fn withdraw(&self, host: &str) -> impl Future<Output = Result<(), Unavailable>> + Send;
}

/// The DNS records a verification reads, over the operator's DNS-over-HTTPS resolver.
pub trait DnsProbe: Send + Sync {
    /// The TXT strings at `name`, each record's strings joined.
    fn txt(&self, name: &str) -> impl Future<Output = Result<Vec<String>, Unavailable>> + Send;

    /// The CNAME targets of `name`.
    fn cname(&self, name: &str) -> impl Future<Output = Result<Vec<String>, Unavailable>> + Send;
}

/// The wait between two polls of an order.
pub trait Pause: Send + Sync {
    /// Waits `d`.
    fn pause(&self, d: Duration) -> impl Future<Output = ()> + Send;
}

/// Waits on the Tokio timer.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioPause;

impl Pause for TokioPause {
    async fn pause(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }
}
