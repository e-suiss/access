//! What the certificate authority needs from the outside world (OP-63): the realm's CA key in
//! the identity signer, and randomness for serials and nonces. Each fails closed (MD-8).

use std::future::Future;

use crate::domain::key::Ed25519Public;

/// A port could not answer; nothing is issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unavailable")]
pub struct Unavailable;

/// Why the CA key did not sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CaRefusal {
    /// The realm's CA is off: no key signs.
    #[error("certificate authority off")]
    Off,
    /// Another key signs now (a rotation happened in between).
    #[error("ca key changed")]
    Changed,
    /// The signer could not be reached or could not sign.
    #[error("signer unavailable")]
    Unavailable,
}

/// The realm's SSH CA key, held by the identity signer under its `ssh-ca` purpose.
pub trait CaKey: Send + Sync {
    /// The key that signs certificates of `realm` now; `None` while the CA is off.
    fn active(
        &self,
        realm: [u8; 16],
    ) -> impl Future<Output = Result<Option<Ed25519Public>, Unavailable>> + Send;

    /// The Ed25519 signature of `data` by `key`, only while `key` is the one that signs.
    fn sign(
        &self,
        realm: [u8; 16],
        key: Ed25519Public,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<[u8; 64], CaRefusal>> + Send;
}

/// Randomness (OP-63: the RNG is a port).
pub trait Random: Send + Sync {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable>;
}
