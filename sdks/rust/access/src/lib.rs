//! Access SDK for Rust (CMP-17, OP-150 m.3 (c), (k)): the policy enforcement point's side of an
//! Access decision and the resource server's verification of an authority token. It builds on
//! the open Kernel and `esuiss-crypto` only and does no I/O: time, the decision point, keys,
//! replay state, nonces, status lists and introspection are ports the caller supplies.
//!
//! A PEP asks Access before an effect and applies the answer before the effect: anything other
//! than a verified ALLOW for this intent, this audience and this actor is a DENY (X21, TI-9).
//! There is no fail-open switch.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod authorize;
pub mod resource;
pub mod transport;
