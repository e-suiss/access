//! The product client API (OP-149): Instance key lookup (m.5) and tenant snapshots (m.4) for
//! Suiss products, behind the transport-authenticated client the ADP uses (OP-141 m.18 (b)).
//! The contract is `sdks/openapi/access-v1.json`.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
pub mod schema;
