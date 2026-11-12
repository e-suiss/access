//! aws-lc-rs verification backend for servers (CR-13, CR-54). [`crate::sig`] runs its CR-53
//! pre-checks before calling it.

use crate::cose::Algorithm;
use crate::sig::Backend;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ED25519, ML_DSA_44, ML_DSA_65, ML_DSA_87, UnparsedPublicKey,
};

use crate::dit::DitGuard;

/// Server backend; differential-tested against the pure-Rust [`crate::sig::PureBackend`].
#[derive(Clone, Copy, Debug, Default)]
pub struct AwsLcBackend;

impl Backend for AwsLcBackend {
    fn ed25519(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        // CR-39 m.6
        let _dit = DitGuard::new();
        UnparsedPublicKey::new(&ED25519, public_key)
            .verify(message, signature)
            .is_ok()
    }

    fn p256(&self, public_key_sec1: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
        // CR-39 m.6
        let _dit = DitGuard::new();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_sec1)
            .verify(message, signature)
            .is_ok()
    }

    // CR-41 m.4, OP-159 m.3 (c)
    fn ml_dsa(&self, alg: Algorithm, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // CR-39 m.6
        let _dit = DitGuard::new();
        let verification = match alg {
            Algorithm::MlDsa44 => &ML_DSA_44,
            Algorithm::MlDsa65 => &ML_DSA_65,
            Algorithm::MlDsa87 => &ML_DSA_87,
            _ => return false,
        };
        UnparsedPublicKey::new(verification, public_key)
            .verify(message, signature)
            .is_ok()
    }

    fn supports(&self, alg: Algorithm) -> bool {
        alg.enabled()
            || matches!(
                alg,
                Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87
            )
    }
}
