//! The SAML 2.0 identity provider and WS-Federation passive requestor of Access, sans-I/O
//! (§10.6.1, §10.6.5, MD-18, OP-155 m.3 (c) to (f)).
//!
//! Untrusted XML is never parsed here: the parser worker reads and verifies every message and
//! returns its facts (`access_internal_api::saml`). The [`domain`] decides on those facts against
//! the realm's registrations and interop profiles and writes canonical XML; the [`app`] writes
//! Responses, assertions, metadata and WS-Federation tokens and has them signed through the
//! [`ports`]' `XmlSigner`, backed by the identity signer's `saml` key; the [`adapters`] encrypt
//! for a pinned certificate.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;

pub use adapters::encrypt;
pub use app::{assertion, binding, dsig, metadata, wsfed};
pub use domain::{alg, profile, request, sp, time, uri, wire, xml};
