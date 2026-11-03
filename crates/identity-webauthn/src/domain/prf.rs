//! PRF extension configuration (§10.2.4): per-credential salts with domain separation and
//! first/second rotation. The server stores salts and `prf.enabled`; it never stores, accepts
//! or returns PRF output.

use access_crypto::webauthn::sha256;

const CONTEXT: &[u8] = b"access/webauthn-prf/v1\0";

/// A PRF evaluation input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrfSalt(pub [u8; 32]);

impl PrfSalt {
    /// `SHA-256("access/webauthn-prf/v1" ‖ 0x00 ‖ purpose ‖ 0x00 ‖ seed)`: the purpose separates
    /// uses of one credential's PRF; `seed` is fresh randomness.
    #[must_use]
    pub fn derive(purpose: &str, seed: &[u8; 32]) -> Self {
        let mut message = CONTEXT.to_vec();
        message.extend_from_slice(purpose.as_bytes());
        message.push(0);
        message.extend_from_slice(seed);
        Self(sha256(&message))
    }
}

/// PRF state of one credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfConfig {
    /// `prf.enabled` from registration.
    pub enabled: bool,
    /// The current salt.
    pub first: PrfSalt,
    /// The next salt while a rotation is in progress.
    pub second: Option<PrfSalt>,
}

impl PrfConfig {
    /// A configuration with one salt.
    #[must_use]
    pub const fn new(enabled: bool, first: PrfSalt) -> Self {
        Self {
            enabled,
            first,
            second: None,
        }
    }

    /// Starts a rotation: assertions evaluate both salts until it completes.
    #[must_use]
    pub const fn begin_rotation(self, next: PrfSalt) -> Self {
        Self {
            second: Some(next),
            ..self
        }
    }

    /// Completes a rotation: the second salt becomes the first.
    #[must_use]
    pub fn complete_rotation(self) -> Self {
        match self.second {
            Some(next) => Self {
                enabled: self.enabled,
                first: next,
                second: None,
            },
            None => self,
        }
    }
}
