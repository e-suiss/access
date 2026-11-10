//! Port implementations (OP-63): PostgreSQL flows, sessions and passkeys, and operating
//! system randomness.

pub mod passkeys;
mod payment;
pub mod pg;
mod push;
mod recovery;

use crate::SessionError;
use crate::ports::Random;

/// The operating system's random source through aws-lc-rs.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), SessionError> {
        for chunk in out.chunks_mut(32) {
            let bytes = access_crypto::random::bytes::<32>().map_err(|_| SessionError::Random)?;
            for (d, s) in chunk.iter_mut().zip(bytes) {
                *d = s;
            }
        }
        Ok(())
    }

    fn salt(&self) -> Result<[u8; 16], SessionError> {
        access_crypto::random::bytes::<16>().map_err(|_| SessionError::Random)
    }
}
