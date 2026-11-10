//! The SCIM 2.0 server and outbound client of the identity plane (IDP-23, IDP-29, OP-155 m.3
//! (g)).
//!
//! Inbound, a registered SCIM client provisions Users, Groups and Devices of one realm under
//! `/realms/{slug}/scim/v2/` with its opaque bearer secret. Users are accounts: every write goes
//! through the account use cases, personal values are sealed in the realm's PII vault, and a
//! deleted resource is a tombstone whose id and `externalId` are never used again (OP-73,
//! INV-32). The client is a Claim source: its group memberships and HR attributes become its own
//! unsigned Claims over the SCIM channel, which select holders only through a
//! `subject-selection` Acceptance and never write a Grant (INV-16, §9.13.8 k.7).
//!
//! Outbound, the realm pushes the life cycle of its users and groups to registered SCIM targets
//! through the outbox; a target's answer is logged, and is a Claim only where a domain accepts
//! that target as an issuer.

pub mod app;
pub mod domain;
pub mod ports;
