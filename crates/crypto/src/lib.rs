//! Cryptography for Access: the shared server primitives (OP-140 m.4) and Access's own
//! identifiers and secret files.

pub mod blind_rsa;
pub mod breach;
pub mod client_secret_jwt;
pub mod dpop;
pub mod event_id;
pub mod ip_pseudonym;
pub mod jose;
pub mod jwe;
pub mod legacy_hash;
pub mod migration_bundle;
pub mod oauth;
pub mod ocsp;
pub mod opaque_id;
pub mod platform;
pub mod privacy_pass;
pub mod projection;
pub mod pseudonym;
pub mod random;
pub mod realm_index;
pub mod rsa_id;
pub mod scim_cursor;
pub mod sd_jwt;
pub mod secret_file;
pub mod sigv4;
pub mod token;
pub mod totp;
pub mod webauthn;
pub mod webhook;
pub mod xmlsec;

pub use suiss_crypto::{dit, envelope, secret};

/// aws-lc-rs verification backend (CR-13, CR-54).
pub mod backend {
    pub use suiss_crypto::aws::AwsLcBackend;
}

pub use backend::AwsLcBackend;
pub use secret::Secret;
