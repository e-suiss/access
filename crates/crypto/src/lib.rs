//! Cryptography for Access: the shared server primitives (OP-140 m.4) and Access's own
//! identifiers and secret files.

pub mod event_id;
pub mod opaque_id;
pub mod secret_file;

pub use suiss_crypto::{dit, envelope, secret};

/// aws-lc-rs verification backend (CR-13, CR-54).
pub mod backend {
    pub use suiss_crypto::aws::AwsLcBackend;
}

pub use backend::AwsLcBackend;
pub use secret::Secret;
