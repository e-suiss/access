//! Access LDAP gateway (§10.6.3, IDP-16, OP-155 m.3 (n), MD-1).
//!
//! LDAP is a compatibility surface, not a directory product. The gateway speaks `LDAPv3` to
//! clients and reaches access-server only over the mTLS edge channel: it never writes a store,
//! never holds a credential and never decides who someone is (IDI-11, P-ID-5).
//!
//! - **Operations:** bind, search, unbind, abandon, `StartTLS`, `WhoAmI`, RFC 3062 password modify.
//!   Add, Delete, `ModifyDN`, Modify and Compare answer `unwillingToPerform` (53).
//! - **Transport:** LDAPS by default; `StartTLS` is off unless the operator opens a cleartext
//!   listener for it, where a simple bind without TLS answers `confidentialityRequired` (13).
//! - **Binds:** only the LDAP credential class (directory app passwords), as `dn=token` or under
//!   the holder's DN; SASL EXTERNAL with a client certificate. No SCRAM, no DIGEST-MD5. An
//!   unauthenticated bind is refused; anonymous clients read the root DSE only.
//! - **Limits:** a message is at most 256 KiB and 32 levels deep, checked before decoding;
//!   filters are at most 16 deep; a search returns at most 5000 entries in pages of at most 1000.

pub mod ber;
pub mod config;
pub mod dse;
pub mod server;
pub mod session;
pub mod translate;

/// One line on stderr; the gateway has no telemetry stack and never logs a body.
pub fn log(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "access-gw-ldap: {line}");
}
