//! Cryptography for Access.

pub mod backend;
pub mod secret;

pub use backend::AwsLcBackend;
pub use secret::Secret;
