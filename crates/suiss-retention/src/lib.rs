//! Suiss shared retention contract (OP-76, OP-147 m.2): the retention classes of Ek C C.0,
//! the per-tenant schedule of a class, litigation and regulator holds, and the pure destroy
//! decision every Suiss product runs before it crypto-shreds a key (OP-73, OP-74, OP-75).
//!
//! Access is the only source of schedules and holds (OP-147 m.1); a product keeps a cache.
//! The crate is pure: no I/O, clock or randomness. The caller passes trusted time and the age
//! of its policy snapshot.

#![no_std]

extern crate alloc;

mod class;
mod decision;
mod hold;
mod ids;
mod schedule;
mod time;

pub use class::{Class, UnknownClass};
pub use decision::{Decision, Defer, Occurrence, Record, Retain, SNAPSHOT_MAX_AGE, may_destroy};
pub use hold::{Hold, HoldKind, HoldScope};
pub use ids::{HoldId, SubjectId, TenantId};
pub use schedule::{Basis, Event, Length, Period, PolicyVersion, Schedule};
pub use time::Timestamp;
