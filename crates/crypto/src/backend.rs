//! aws-lc-rs verification backend for the server (CR-13, CR-54). The Kernel runs its CR-53
//! pre-checks before calling it.

use access_kernel::verify::Backend;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, ED25519, UnparsedPublicKey};

/// Server backend; differential-tested against the Kernel's pure-Rust backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct AwsLcBackend;

impl Backend for AwsLcBackend {
    fn ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .is_ok()
    }

    fn p256(&self, public_key_sec1: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_sec1)
            .verify(message, signature)
            .is_ok()
    }
}
