//! Conformance and security suites of the realm authorization server (OP-146 I11, Ek B Stage 5
//! K19): the Fosite error-class regression corpus, the metamorphic realm and tenant isolation
//! check, the token-confusion fuzzer (TN-23 test 4) and the negative boundary rows,
//! against real PostgreSQL and a real identity signer.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::type_complexity,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "../support/mod.rs"]
mod support;

mod boundaries;
mod confusion;
mod fosite;
mod isolation;
