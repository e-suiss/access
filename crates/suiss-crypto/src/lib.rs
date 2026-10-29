//! Suiss shared cryptography (OP-76): deterministic CBOR with the Access profile (OP-106).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "verify")]
pub mod dcbor;
