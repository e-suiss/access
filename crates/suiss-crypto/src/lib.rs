//! Suiss shared cryptography (OP-76, OP-140): deterministic CBOR, digests and Merkle proofs,
//! signature and `COSE_Sign1` verification, and C2SP signed notes and checkpoints.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(feature = "verify")]
pub mod cose;
#[cfg(feature = "verify")]
pub mod dcbor;
#[cfg(feature = "verify")]
pub mod digest;
#[cfg(feature = "verify")]
pub mod note;
#[cfg(feature = "verify")]
pub mod sig;
