//! Access offline verifier SDK (§9.10, §9.12, OP-150 m.3 (c)): what a device, robot or resource
//! server needs to accept or refuse a use of a Portable Authority Proof without reaching Access,
//! within the horizon, Δ and offline slice its `ValidityContract` declares. It builds on the open
//! Kernel and `esuiss-crypto` only.
//!
//! The verifier declares what it can do in a Verifier Profile, keeps a trusted clock and a
//! tamper-evident counter behind ports (CMP-17, T25), and reports its local uses when it
//! reconnects, as a hash-chained Offline Exercise Report.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod caps;
pub mod counter;
pub mod metadata;
pub mod offline;
pub mod profile;
pub mod replay;
pub mod report;
pub mod status;
#[cfg(feature = "testing")]
pub mod testing;
pub mod time;
