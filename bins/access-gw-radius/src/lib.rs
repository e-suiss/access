//! Access RADIUS gateway (§10.6.5, IDP-18, IDP-33, OP-155 m.3 (f), MD-1).
//!
//! The gateway's one job is an `authentication` Claim for VPN and network access. It speaks
//! RADIUS to network access servers and reaches access-server only over the mTLS edge channel:
//! it never writes a store, never holds a credential and never decides who someone is (IDI-11,
//! P-ID-5).
//!
//! - **Transport:** `RadSec` only (RFC 6614) with RADIUS/1.1 (RFC 9765, ALPN `radius/1.1`), TLS 1.3,
//!   a client certificate required and registered with the gateway. There is no UDP listener.
//! - **Methods:** PAP inside TLS, with a directory app password. MS-CHAP and MS-CHAPv2 are refused
//!   (an NTLM derivative), as are CHAP and EAP. No eduroam profile (IDP-33).
//! - **Limits:** a packet is at most 4096 bytes, checked before it is read.

pub mod config;
pub mod packet;
pub mod server;

/// One line on stderr; the gateway has no telemetry stack and never logs a body.
pub fn log(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "access-gw-radius: {line}");
}
