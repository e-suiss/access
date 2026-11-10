//! What SL2 needs from the outside world (OP-63): a GeoIP/ASN source, address pseudonyms, the
//! breach corpus, an HTTP GET for the range API and one transaction over the identity tables.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use access_identity_account::domain::password::Password;
use access_identity_account::ports::AccountTx;
use access_store::identity::TenantTx;

use crate::domain::assess::Breach;
use crate::domain::geo::GeoAnswer;

/// A boxed future, for the ports a request-scoped service holds as trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The state of the GeoIP/ASN source, as the management surface states it (OP-151 m.1 (b)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeoStatus {
    /// No source is configured: geographic signals are unavailable.
    NotConfigured,
    /// A source is configured but cannot be read.
    Unreadable,
    /// A source is loaded.
    Ready {
        /// The database type it declares.
        database_type: String,
        /// When it was built, Unix seconds.
        build_epoch: u64,
    },
}

impl GeoStatus {
    /// The administrator-facing text.
    #[must_use]
    pub const fn text(&self) -> &'static str {
        match self {
            Self::NotConfigured => "GeoIP source not configured",
            Self::Unreadable => "GeoIP source unreadable",
            Self::Ready { .. } => "GeoIP source loaded",
        }
    }
}

/// IP → country, ASN and coarse position (OP-151 m.1 (b)). Data is never embedded; the source
/// is a file the operator provides.
pub trait GeoResolver: Send + Sync {
    /// What the source says about `ip`; [`GeoAnswer::Unavailable`] when it cannot say.
    fn locate(&self, ip: IpAddr) -> GeoAnswer;
    /// The source's state.
    fn status(&self) -> GeoStatus;
}

/// Keyed pseudonyms of addresses, per realm (OP-151 m.1 (b)).
pub trait IpPseudonyms: Send + Sync {
    /// The pseudonym of `ip` in `realm`; `None` when no key is available.
    fn pseudonym(&self, tenant: &[u8; 16], realm: &[u8; 16], ip: IpAddr) -> Option<[u8; 32]>;

    /// The pseudonym of the IPv4 /24 or IPv6 /48 holding `ip` in `realm`, the bootstrap rate
    /// context (OP-152 m.5 (b)); `None` when no key is available.
    fn prefix(&self, tenant: &[u8; 16], realm: &[u8; 16], ip: IpAddr) -> Option<[u8; 32]>;
}

/// The breached-password check of a sign-in (IDP-3, OP-151 m.3 (o)).
pub trait BreachProbe: Send + Sync {
    /// Whether `password` is in the corpus; [`Breach::Unavailable`] when the corpus cannot
    /// answer, never [`Breach::Clean`] (G50).
    fn check<'a>(&'a self, password: &'a Password) -> BoxFuture<'a, Breach>;
}

/// An answer of [`RangeFetch`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// HTTP status.
    pub status: u16,
    /// The body.
    pub body: Vec<u8>,
}

/// No answer: unreachable, refused, too slow or malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("no answer")]
pub struct NoAnswer;

/// An outbound `GET` (the SSRF-guarded client in production).
pub trait RangeFetch: Send + Sync {
    /// `GET url` with `headers`, the body read up to `max_body` bytes.
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max_body: usize,
    ) -> impl Future<Output = Result<Fetched, NoAnswer>> + Send;
}

/// One transaction over the identity tables that SL2 reads and writes with the business change
/// (OP-10, OP-63): the account transaction and its realm-scoped store transaction.
pub trait RiskTx: AccountTx {
    /// The realm-scoped store transaction.
    fn store(&mut self) -> &mut TenantTx;
}
