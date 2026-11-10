//! Access Kerberos/SPNEGO gateway (§10.6.4, IDP-17, OP-155 m.3 (o), MD-1, §14.5 C FFI profile).
//!
//! Access is never a KDC: the gateway only accepts tickets (RFC 4559 HTTP Negotiate) with its
//! own keytab and reaches access-server over the mTLS edge channel. It never writes a store,
//! never decides who someone is and signs nothing (IDI-11, P-ID-5). libgssapi, the only C code,
//! links into this process alone; every ASN.1 token is read first by the parser worker.
//!
//! - **Listener:** its own HTTP/1.1 endpoint over TLS 1.3 (Negotiate is bound to one connection,
//!   so HTTP/2 and pooling proxies break it). Any failure falls back to normal sign-in.
//! - **Tickets:** the SPN matches exactly, AES256 enctypes only, key versions tracked; NTLM is
//!   refused.
//! - **Keytab:** read once from the operator's secret store into `memfd_secret` memory before
//!   the lockdown and handed to libkrb5 as an in-memory keytab; never written to disk.
//! - **`S4U2Proxy`:** with a configured backend SPN, a request under `/proxy/` is forwarded to the
//!   backend with a ticket obtained for the user by constrained delegation.

pub mod accept;
pub mod config;
pub mod http;
pub mod keytab;
pub mod proxy;

/// One line on stderr; the gateway has no telemetry stack and never logs a body or a ticket.
pub fn log(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "access-gw-kerberos: {line}");
}
