//! Active Directory sync (§10.6.4, IDP-17, OP-155 m.3 (n)): an incremental LDAP pull connector.
//!
//! The default way a directory reaches a realm is a pull: the connector binds to the directory
//! over LDAPS with a service account and reads the entries whose `uSNChanged` passed the last
//! watermark. SCIM push stays the alternative. Accounts are keyed by `objectGUID`; memberships
//! obey the same single-issuer and Acceptance rules as SCIM, so a connector's memberships count
//! only for groups the realm accepted it as issuer of. Passwords never travel: sign-in stays with
//! delegation or SPNEGO, and the connector cannot replicate secrets (no `DCSync`).
//!
//! Access does not replace Active Directory and has no write path into it (IDP-38).

pub mod adapters;
pub mod app;
pub mod ber;
pub mod domain;
pub mod ports;
