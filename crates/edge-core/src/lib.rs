//! The edge core every protocol gateway is built on (§10.6, OP-155 m.3 (c), MD-1, IDP-26,
//! IDI-11). A gateway turns a legacy protocol exchange into an identity-plane authentication;
//! it never issues anything, never writes a store and never reaches the authority plane.
//!
//! The seven shared layers:
//!
//! 1. **Realm resolution**: the gateway serves the one realm it is registered in, named by
//!    access-server at [`EdgeCore::connect`]; [`EdgeCore::realm`] refuses any other.
//! 2. **Subject lookup**: [`EdgeCore::subject`] asks access-server over the edge channel.
//! 3. **Claim issuance**: [`EdgeCore::issue`] reports an authentication; the realm issuer inside
//!    access-server signs the Claim (P-ID-5).
//! 4. **Keys**: the gateway holds only its channel identity (its client certificate and key,
//!    read before the lockdown); every signature is made by access-server and its signers.
//! 5. **Audit**: [`EdgeCore::audit`] writes codes, never bodies, to the realm's audit log.
//! 6. **Governor**: [`governor::Governor`] token buckets per caller key.
//! 7. **Health and metrics**: [`health::Health`], labelled by call and outcome only (OP-47).
//!
//! Untrusted XML, DER and ASN.1 are parsed only in the parser worker ([`parser`], [`pool`],
//! [`ipc`]); [`spnego`] holds what it reads from a Kerberos `Negotiate` token.

#[cfg(feature = "channel")]
pub mod channel;
#[cfg(feature = "channel")]
mod core;
pub mod governor;
pub mod health;
pub mod ipc;
pub mod keytab;
pub mod parser;
pub mod pool;
pub mod saml;
pub mod spnego;

#[cfg(feature = "channel")]
pub use crate::core::{EdgeCore, EdgeError};
