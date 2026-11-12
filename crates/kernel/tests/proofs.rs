//! CR-K1…CR-K9: Kani harnesses (`cargo kani --tests`, CI `formal`) and their proptest mirrors
//! (CR-47, OP-159 m.3 (w)). The sources live in `src/proofs/`.

#![cfg(not(any(target_family = "wasm", target_os = "android")))]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    missing_docs,
    reason = "test code"
)]

#[path = "../src/proofs/mod.rs"]
mod proofs;
