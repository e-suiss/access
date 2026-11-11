//! CMP-1 Access Decision Profile (L1-ADP, OP-141 m.17): `AuthZEN` evaluation over the core.

pub mod adapters;
pub mod app;
pub mod cbor;
pub mod domain;
pub mod eligibility;
pub mod hub;
pub mod payload;
pub mod pep;
pub mod ports;
pub mod publication;
pub mod report;
pub mod sandbox;
// OP-158 m.4 (b)
pub mod watch;
