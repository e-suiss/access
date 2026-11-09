//! Access Executor (B21, AG-40, E62–E64, OP-154 m.3 (u)): a registered executor runs an
//! agent's allowed Exercises durably, one idempotent step at a time, reports each effect as an
//! `effect_attestation` Claim and confirms a pause or stop with an `executor_control` Claim. It
//! decides nothing: every step is an Access decision, asked with the actor's own statement,
//! and Access never depends on it (OP-62).
//!
//! [`domain`] is the pure core (history, next step, Claims, Web Bot Auth), [`app`] the use
//! cases, [`store`] the executor's own SQL module, [`drivers`] the OAuth HTTP and MCP client
//! drivers, [`adapters`] the `/executor/v1/*` routes and [`https`] the production ports.

pub mod adapters;
pub mod app;
pub mod contract;
pub mod domain;
pub mod drivers;
pub mod https;
pub mod ports;
pub mod store;
#[cfg(feature = "testing")]
pub mod testing;
