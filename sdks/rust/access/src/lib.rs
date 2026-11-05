//! Access SDK for Rust (CMP-17, OP-150 m.3 (c), (k)): the policy enforcement point's side of an
//! Access decision. It builds on the open Kernel and `esuiss-crypto` only.
//!
//! A PEP asks Access before an effect and applies the answer before the effect: anything other
//! than a verified ALLOW for this intent, this audience and this actor is a DENY (X21, TI-9).
//! There is no fail-open switch.

#![forbid(unsafe_code)]

pub mod authorize;
