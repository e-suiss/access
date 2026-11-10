//! The Access Linux client's channel as the NSS and PAM modules speak it (OP-156 m.3 (p),
//! IDP-32): the messages of `conformance/cddl/linux-client.cddl`, a blocking client of the
//! `access-linuxd` socket and the modules' safe halves. The C ABI shells hold the `unsafe`
//! (R-2).

#[cfg(unix)]
pub mod client;
pub mod nss;
pub mod pam;
pub mod wire;
