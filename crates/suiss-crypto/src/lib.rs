//! Suiss shared cryptography (OP-76, OP-140): deterministic CBOR, digests and Merkle proofs,
//! signature and `COSE_Sign1` verification, and C2SP signed notes and checkpoints; with the
//! server features, secrets, envelope encryption and signing on aws-lc-rs.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "aws-lc"), forbid(unsafe_code))]

extern crate alloc;

#[cfg(feature = "aws-lc")]
pub mod aws;
#[cfg(feature = "verify")]
pub mod cose;
#[cfg(feature = "verify")]
pub mod dcbor;
#[cfg(feature = "verify")]
pub mod digest;
#[cfg(feature = "aws-lc")]
pub mod dit;
#[cfg(feature = "aead")]
pub mod envelope;
#[cfg(feature = "verify")]
pub mod note;
#[cfg(feature = "aws-lc")]
pub mod secret;
#[cfg(feature = "verify")]
pub mod sig;
#[cfg(feature = "signer")]
pub mod signer;
