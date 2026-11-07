//! The management API's common layer (OP-65, OP-151 m.2 M0): the realm-admin surface under
//! `/admin/v1/realms/{slug}/…` and the platform-admin surface under `/admin/v1/platform/…`,
//! served on the management listener only (CMP-15.5, §17.9.6). The contract is
//! `sdks/openapi/admin-v1.json`, generated from [`schema::openapi`] (`just admin-contract`).
//!
//! Every route is a row of the endpoint permission manifest ([`manifest::MANIFEST`], TN-113):
//! its method and path, surface, whether it reads (a holder-bound token with a scope) or writes
//! (the caller's AIS, compiled into an Exercise: TN-110), and whether a caller without the
//! permission gets `404` or `403`. The router is built from the manifest only, and the guard
//! each row gets enforces the row: request id, rate limits, caller, idempotency and lifecycle
//! headers.
//!
//! # Adding a route
//!
//! 1. Add a [`manifest::Route`] constant and list it in [`manifest::MANIFEST`]; give it a
//!    [`manifest::GROUPS`] prefix if it starts a new route group.
//! 2. Write the handler in `api/app/handlers.rs` (or a module of its own under `api/app/`); it
//!    reads the verified caller from [`app::Ctx`], and a write submits through
//!    [`app::submit`]. Problems come from [`crate::problem::codes`]; add new codes there and to
//!    [`crate::problem::CODES`].
//! 3. Register it in [`app::router`] with `.handle(operation_id, handler)`; never call
//!    `.route(` anywhere in `api/` (`cargo xtask check` rule `endpoint-manifest`).
//! 4. Describe its body in [`schema`] and run `just admin-contract`; the generated 401/403/404
//!    tests in `crates/http/tests/admin_manifest.rs` cover the new row without changes.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod manifest;
pub mod ports;
pub mod schema;

pub use app::{Api, router};
