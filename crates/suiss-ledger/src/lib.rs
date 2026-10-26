//! Suiss shared ledger platform (OP-76): domain log, sequencer, outbox, durability
//! boundary, checkpoint, witness client and replica.
//!
//! The engine is pure (OP-8, OP-130 m.1): no I/O, clock or randomness. A driver feeds it the
//! trusted time and the outcome of each storage commit.

#![no_std]

extern crate alloc;

pub mod merkle;
pub mod sequencer;

/// A SHA-256 output.
pub type Hash = [u8; 32];
