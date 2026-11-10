//! HR connectors (OP-156 m.3 (q), IDP-35): each pulls an HR system's records and pushes them to
//! Access's `…/hr-sources/{source}/records:batch` with public crates only (OP-62) and its own
//! database. The vendor order is fixed in OP-156 m.3 (q).

pub mod app;
pub mod contract;
pub mod domain;
pub mod https;
pub mod key;
pub mod ports;
pub mod service;
pub mod store;
#[cfg(feature = "testing")]
pub mod testing;
