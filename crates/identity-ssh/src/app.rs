//! The certificate authority's use cases (OP-63): a certificate for an allowed projection,
//! drawn and signed by the realm's CA key and checked before it is handed out.

use crate::SshError;
use crate::domain::cert::{Certificate, Fields};
use crate::domain::projection::{Drawn, Projection};
use crate::ports::{CaKey, CaRefusal, Random, Unavailable};

/// How often a zero serial is drawn again before giving up.
const DRAWS: usize = 4;

/// Why no certificate was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IssueError {
    /// The realm's CA is off.
    #[error("certificate authority off")]
    Off,
    /// The fields are refused.
    #[error("refused: {0}")]
    Refused(SshError),
    /// A port could not answer.
    #[error("unavailable")]
    Unavailable,
}

impl From<Unavailable> for IssueError {
    fn from(_: Unavailable) -> Self {
        Self::Unavailable
    }
}

/// A signed certificate and what it says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issued {
    /// The certificate.
    pub certificate: Certificate,
    /// Its fields, as signed.
    pub fields: Fields,
}

/// A serial (never 0) and a nonce from `random`.
///
/// # Errors
/// [`Unavailable`].
pub fn draw(random: &impl Random) -> Result<Drawn, Unavailable> {
    let mut nonce = [0_u8; 32];
    random.fill(&mut nonce)?;
    for _ in 0..DRAWS {
        let mut serial = [0_u8; 8];
        random.fill(&mut serial)?;
        let serial = u64::from_be_bytes(serial);
        if serial != 0 {
            return Ok(Drawn { serial, nonce });
        }
    }
    Err(Unavailable)
}

/// The certificate of `projection` in `realm`, signed by the key that signs now. A rotation in
/// between is tried once more with the new key; the signature is checked before it is returned.
///
/// # Errors
/// [`IssueError`].
pub async fn certify(
    ca: &impl CaKey,
    random: &impl Random,
    realm: [u8; 16],
    projection: &Projection,
) -> Result<Issued, IssueError> {
    for _ in 0..2 {
        let key = ca.active(realm).await?.ok_or(IssueError::Off)?;
        let fields = projection.fields(key, draw(random)?);
        let tbs = fields.to_be_signed().map_err(IssueError::Refused)?;
        let signature = match ca.sign(realm, key, tbs.clone()).await {
            Ok(s) => s,
            Err(CaRefusal::Changed) => continue,
            Err(CaRefusal::Off) => return Err(IssueError::Off),
            Err(CaRefusal::Unavailable) => return Err(IssueError::Unavailable),
        };
        suiss_crypto::sig::ed25519(&suiss_crypto::sig::PureBackend, &key.0, &tbs, &signature)
            .map_err(|_| IssueError::Unavailable)?;
        let certificate = fields
            .certificate(&signature)
            .map_err(IssueError::Refused)?;
        return Ok(Issued {
            certificate,
            fields,
        });
    }
    Err(IssueError::Unavailable)
}

#[cfg(test)]
mod tests;
