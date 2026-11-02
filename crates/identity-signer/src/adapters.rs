//! Adapters of the identity signer's ports: a key factory that creates realm keys in the
//! signer process and seals each one under the realm's KEK (CR-21 m.3, T31).

use access_crypto::jose::JwsAlg;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::envelope::{Dek, Kek, Sealed, open_body, seal_body};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{SignError, Signer, SoftSigner};

use crate::ports::{Generated, KeyFactory};

/// Binds the sealed key to what it is for; distinct from the authority's operational keys.
const SEAL_CONTEXT: &[u8] = b"access/identity-signer/realm-key";

/// Creates realm keys on aws-lc-rs and seals each PKCS#8 document under its own DEK, wrapped
/// by the realm's KEK; the plaintext never leaves memory (CR-21 m.3).
pub struct SealedFactory<K> {
    kek: K,
}

impl<K: Kek> SealedFactory<K> {
    /// A factory sealing under `kek`.
    pub const fn new(kek: K) -> Self {
        Self { kek }
    }
}

fn from_pkcs8(alg: JwsAlg, doc: &Secret<Vec<u8>>) -> Result<Box<dyn Signer + Send>, SignError> {
    Ok(match alg {
        JwsAlg::Es256 => Box::new(SoftSigner::p256_from_pkcs8(doc)?),
        JwsAlg::Ed25519 => Box::new(SoftSigner::ed25519_from_pkcs8(doc)?),
    })
}

impl<K: Kek> KeyFactory for SealedFactory<K> {
    fn generate(&mut self, alg: JwsAlg) -> Result<Generated, SignError> {
        let (signer, doc): (Box<dyn Signer + Send>, _) = match alg {
            JwsAlg::Es256 => {
                let (s, d) = SoftSigner::generate_p256()?;
                (Box::new(s), d)
            }
            JwsAlg::Ed25519 => {
                let (s, d) = SoftSigner::generate_ed25519()?;
                (Box::new(s), d)
            }
        };
        let dek = Dek::generate().map_err(|_| SignError::Random)?;
        let wrapped = self.kek.wrap(&dek).map_err(|_| SignError::Key)?;
        let sealed = seal_body(dek, SEAL_CONTEXT, doc.expose()).map_err(|_| SignError::Key)?;
        let v = Value::Map(vec![
            (Value::text("kek"), Value::text(self.kek.id())),
            (Value::text("wrapped"), Value::Bytes(wrapped)),
            (Value::text("nonce"), Value::Bytes(sealed.nonce.to_vec())),
            (Value::text("ciphertext"), Value::Bytes(sealed.ciphertext)),
        ]);
        Ok(Generated {
            signer,
            sealed: dcbor::encode(&v, Limits::CEILING).map_err(|_| SignError::Encode)?,
        })
    }

    fn load(&mut self, alg: JwsAlg, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError> {
        let v = dcbor::decode(sealed, Limits::CEILING).map_err(|_| SignError::Key)?;
        let bytes = |k: &str| match v.get(k) {
            Some(Value::Bytes(b)) => Ok(b.clone()),
            _ => Err(SignError::Key),
        };
        let dek = self
            .kek
            .unwrap(&bytes("wrapped")?)
            .map_err(|_| SignError::Key)?;
        let body = Sealed {
            nonce: bytes("nonce")?.try_into().map_err(|_| SignError::Key)?,
            ciphertext: bytes("ciphertext")?,
        };
        let doc = open_body(&dek, SEAL_CONTEXT, &body).map_err(|_| SignError::Key)?;
        from_pkcs8(alg, &Secret::new(doc.to_vec()))
    }
}

#[cfg(test)]
mod tests;
