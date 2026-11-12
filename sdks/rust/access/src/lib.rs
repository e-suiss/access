//! Access SDK for Rust (CMP-17, T41, OP-150 m.3 (c), (k), OP-151 m.3 (g)): one package with two
//! modules kept apart in code. `auth` is the identity side: an OpenID Connect relying party
//! (discovery, PKCE, `state`, `nonce`, ID token validation), DPoP proofs and the refresh
//! single-flight. `authorize` and `resource` are the enforcement side: the policy enforcement
//! point's half of an Access decision and the resource server's verification of an authority
//! token. With the `mcp` feature, `mcp` makes an MCP server a resource server and the domain's
//! PEP. `agent` is the agent's side of a decision: the agent contract A-1 to A-12 and its A2A
//! extension (OP-154 m.3 (w), (y)). It builds on the open Kernel and `esuiss-crypto` only and does no I/O: time, randomness,
//! the decision point, keys, replay state, nonces, status lists and introspection are ports the
//! caller supplies.
//!
//! A PEP asks Access before an effect and applies the answer before the effect: anything other
//! than a verified ALLOW for this intent, this audience and this actor is a DENY (X21, TI-9).
//! There is no fail-open switch.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod agent;
pub mod approver;
pub mod auth;
pub mod authorize;
pub mod kex;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod metadata;
pub mod ordering;
pub mod reason;
pub mod resource;
pub mod transport;
