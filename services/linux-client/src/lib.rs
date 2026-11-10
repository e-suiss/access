//! The Linux client (OP-156 m.3 (p), IDP-32, MD-8): the `access-linuxd` daemon, written on
//! public crates only (OP-62), and the NSS and PAM modules that speak
//! `conformance/cddl/linux-client.cddl` to it over a Unix domain socket.

pub mod adapters;
pub mod app;
pub mod breakglass;
pub mod contract;
pub mod domain;
pub mod ports;
