//! The SAML 2.0 identity provider and WS-Federation passive requestor of Access, sans-I/O
//! (§10.6.1, §10.6.5, MD-18, OP-155 m.3 (c) to (f)).
//!
//! Untrusted XML is never parsed here: the parser worker reads and verifies every message and
//! returns its facts (`access_edge_core::saml`). This crate decides on those facts against the
//! realm's registrations ([`sp`], [`profile`], [`request`]), writes canonical Responses,
//! assertions, metadata and WS-Federation tokens ([`xml`], [`assertion`], [`metadata`],
//! [`wsfed`]), signs them through an [`dsig::XmlSigner`] backed by the identity signer's `saml`
//! key, encrypts for a pinned certificate ([`encrypt`]), and carries the bodies between
//! access-server and the SAML gateway ([`wire`]).

pub mod alg;
pub mod assertion;
pub mod binding;
pub mod dsig;
pub mod encrypt;
pub mod metadata;
pub mod profile;
pub mod request;
pub mod sp;
pub mod time;
pub mod uri;
pub mod wire;
pub mod wsfed;
pub mod xml;
