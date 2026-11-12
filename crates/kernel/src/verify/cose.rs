//! `COSE_Sign1` verification profile (CR-55 m.4, m.6, CR-7); the code is shared (OP-140 m.2),
//! with the Kernel's ML-DSA layer in front (OP-159 m.3 (c)).

pub use suiss_crypto::cose::*;

pub use super::ml_dsa::{verify_sign1, verify_sign1_detached, verify_sign1_with};

#[cfg(test)]
mod tests;
