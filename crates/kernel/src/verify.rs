//! Signature verification of Access artefacts over the shared primitives (CR-9, CR-53…CR-55,
//! OP-140 m.2).

pub mod cose;
pub mod jws;
pub mod key_scope;
pub mod sd_jwt;

pub use suiss_crypto::sig::{
    Backend, P256_N, PureBackend, SignatureError, ed25519, ed25519_precheck, p256,
};
