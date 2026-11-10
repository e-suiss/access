//! The person-attribute credential issuer (OP-155 m.3 (p), E55, IDP-21, PI-3; Ek B 4196, 5039):
//! a realm issues SD-JWT VCs (`dc+sd-jwt`) of a closed set of person attributes over OID4VCI's
//! pre-authorized code flow, each bound to the holder's device key or an agent `KeyBinding`, with
//! its `vct` under the realm issuer and an entry in the realm's status list. Every other
//! credential type is refused: the issuer role for anything but person attributes stays WATCH
//! (Ek B 4836). A credential is a carrier of Claim input, never authority.
//!
//! [`domain`] is the pure core (types, metadata and offer, key proof, credential), [`ports`] what
//! the issuer needs from the identity plane, and [`app`] the use cases.

pub mod app;
pub mod domain;
pub mod ports;
