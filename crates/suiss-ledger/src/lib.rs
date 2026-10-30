//! Suiss shared ledger engine (OP-76, OP-140 m.5): Merkle frontier, single-writer sequencer,
//! storage port, durability fence, checkpoints and their publication order, replica follower
//! and trusted time.
//!
//! The engine is pure (OP-8, OP-130 m.1): no I/O, clock or randomness. A driver feeds it the
//! trusted time and the outcome of each storage commit.

#![no_std]

extern crate alloc;

pub mod checkpoint;
pub mod fence;
pub mod merkle;
pub mod port;
pub mod replica;
pub mod sequencer;
pub mod time;

/// A SHA-256 output.
pub type Hash = [u8; 32];
