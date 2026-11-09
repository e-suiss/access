//! The token vault of the identity plane (MD-13, E36, EI-26, AG-32, AG-39, AG-40, §11.13,
//! OP-154 m.3 (t)).
//!
//! - A **Resource** is realm configuration (`idp.vault.resource_enable`, `resource_register`,
//!   `resource_disable`): an upstream from the shipped catalog or the realm's own, its client,
//!   scopes, `scope_mapping` and registered executors. A catalog entry grants nothing.
//! - A **connection** is one person's account at an upstream, opened only after the person's
//!   AAS for the agent client (AS-M15); its **`TokenSet`** is sealed under the person's subject
//!   DEK and refreshed under a lease before it expires. A lapsed connection waits on the person.
//! - A **release** happens only against an Exercise the authority plane allowed, for the
//!   registered executor that is its PEP, once, for the connection's owner, and never past the
//!   decision's horizon (G59, U65, U66). CT2+ tokens stay with the executor (path (a)); path (b)
//!   needs CT0–CT1, the realm's open mode and a short or revocable token. Holding a token is
//!   never authority (AGI-2), and the upstream token's content is not guaranteed (N-54).
//! - Access keeps no shared secrets for people and is no PAM: the vault holds only OAuth tokens
//!   a person connected, and agents have no route to it.

pub mod app;
pub mod domain;
pub mod ports;
