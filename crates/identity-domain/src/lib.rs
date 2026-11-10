//! Custom domains of a realm (OP-156 m.3 (i), §10.2.4, §12.1.2, TN-16, TN-17, TN-20).
//!
//! - [`domain`]: which hosts a realm may register, the two DNS records that verify one, how long
//!   a verification and a certificate last, and the RP ID rule for passkeys.
//! - [`der`] and [`x509`]: the small DER writer, the CSR, the TLS-ALPN-01 challenge certificate
//!   and the fields of an issued leaf Access checks.
//! - [`acme`]: the JWS and resources of Access's own ACME client (RFC 8555, RFC 8737).
//! - [`app`]: one issuance, and the pass that verifies, issues and renews a realm's domains.
//! - [`ports`] and [`adapters`]: the ACME server's HTTPS, the account key, the TLS listeners'
//!   challenge answers, DNS and the realm KEK.

pub mod acme;
pub mod adapters;
pub mod app;
pub mod der;
pub mod domain;
pub mod ports;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod x509;
