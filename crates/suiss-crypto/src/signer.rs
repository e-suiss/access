//! Signing behind a port (OP-140 m.4, CR-9, CR-13): a software signer on aws-lc-rs for tests
//! and development, and the formats signers produce: `COSE_Sign1`, C2SP note signatures and
//! checkpoint cosignatures. The PKCS#11 key store implements the same port.

use alloc::string::String;
use alloc::vec::Vec;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _,
};

use crate::cose::{ALG, Algorithm, CONTENT_TYPE, KID, PublicKey, to_be_signed};
use crate::dcbor::{self, Limits, Value};
use crate::dit::DitGuard;
use crate::note::{Verifier, base64_encode, cosigned_message};
use crate::secret::Secret;
use crate::sig::{P256_HALF_N, P256_N};

/// Why signing failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// The random source failed.
    #[error("random source")]
    Random,
    /// The key could not be created or read.
    #[error("bad key")]
    Key,
    /// The signer failed.
    #[error("signing failed")]
    Sign,
    /// The signer's algorithm cannot produce this format.
    #[error("algorithm not usable here")]
    Algorithm,
    /// The output could not be encoded.
    #[error("encoding")]
    Encode,
}

impl SignError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Random => "sign-random",
            Self::Key => "sign-key",
            Self::Sign => "sign-failed",
            Self::Algorithm => "sign-algorithm",
            Self::Encode => "sign-encode",
        }
    }
}

/// A signing key. Implementations keep the private key out of reach of the caller.
pub trait Signer {
    /// The algorithm the key signs with.
    fn algorithm(&self) -> Algorithm;

    /// The public key.
    fn public_key(&self) -> PublicKey;

    /// Signs `message`: 64 bytes, Ed25519 or ECDSA P-256 `r ‖ s` with low S (CR-9).
    ///
    /// # Errors
    /// [`SignError`].
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError>;
}

/// Turns an ECDSA P-256 `r ‖ s` into its low-S form: `s` becomes `n − s` when above `n / 2`.
///
/// # Errors
/// [`SignError::Sign`] for a signature that is not 64 bytes.
pub fn low_s(signature: &mut [u8]) -> Result<(), SignError> {
    if signature.len() != 64 {
        return Err(SignError::Sign);
    }
    let s = signature.get_mut(32..64).ok_or(SignError::Sign)?;
    if *s <= P256_HALF_N[..] {
        return Ok(());
    }
    let mut borrow = false;
    for (out, n) in s.iter_mut().rev().zip(P256_N.iter().rev()) {
        let (d1, b1) = n.overflowing_sub(*out);
        let (d2, b2) = d1.overflowing_sub(u8::from(borrow));
        *out = d2;
        borrow = b1 || b2;
    }
    Ok(())
}

enum Pair {
    Ed25519(Ed25519KeyPair),
    P256(EcdsaKeyPair),
}

/// An in-process signer on aws-lc-rs. Keys come from PKCS#8 documents; production keys live in
/// an HSM behind the same [`Signer`] port.
pub struct SoftSigner {
    pair: Pair,
}

impl SoftSigner {
    /// A new Ed25519 key, with its PKCS#8 document for storage.
    ///
    /// # Errors
    /// [`SignError`].
    pub fn generate_ed25519() -> Result<(Self, Secret<Vec<u8>>), SignError> {
        let doc =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| SignError::Random)?;
        let doc = Secret::new(doc.as_ref().to_vec());
        Ok((Self::ed25519_from_pkcs8(&doc)?, doc))
    }

    /// A new ECDSA P-256 key, with its PKCS#8 document for storage.
    ///
    /// # Errors
    /// [`SignError`].
    pub fn generate_p256() -> Result<(Self, Secret<Vec<u8>>), SignError> {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| SignError::Random)?;
        let doc = Secret::new(doc.as_ref().to_vec());
        Ok((Self::p256_from_pkcs8(&doc)?, doc))
    }

    /// An Ed25519 key from its PKCS#8 document.
    ///
    /// # Errors
    /// [`SignError::Key`].
    pub fn ed25519_from_pkcs8(doc: &Secret<Vec<u8>>) -> Result<Self, SignError> {
        let pair = Ed25519KeyPair::from_pkcs8(doc.expose()).map_err(|_| SignError::Key)?;
        Ok(Self {
            pair: Pair::Ed25519(pair),
        })
    }

    /// An ECDSA P-256 key from its PKCS#8 document.
    ///
    /// # Errors
    /// [`SignError::Key`].
    pub fn p256_from_pkcs8(doc: &Secret<Vec<u8>>) -> Result<Self, SignError> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.expose())
            .map_err(|_| SignError::Key)?;
        Ok(Self {
            pair: Pair::P256(pair),
        })
    }

    /// An ECDSA P-256 key from its private scalar `d` and uncompressed SEC1 public point, as a
    /// private JWK carries them (RFC 7518 §6.2.2); the pair must verify.
    ///
    /// # Errors
    /// [`SignError::Key`].
    pub fn p256_from_parts(d: &Secret<Vec<u8>>, sec1: &[u8]) -> Result<Self, SignError> {
        let pair = EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            d.expose(),
            sec1,
        )
        .map_err(|_| SignError::Key)?;
        Ok(Self {
            pair: Pair::P256(pair),
        })
    }
}

impl Signer for SoftSigner {
    fn algorithm(&self) -> Algorithm {
        match self.pair {
            Pair::Ed25519(_) => Algorithm::Ed25519,
            Pair::P256(_) => Algorithm::Esp256,
        }
    }

    fn public_key(&self) -> PublicKey {
        match &self.pair {
            Pair::Ed25519(p) => {
                let mut k = [0_u8; 32];
                for (d, s) in k.iter_mut().zip(p.public_key().as_ref()) {
                    *d = *s;
                }
                PublicKey::Ed25519(k)
            }
            Pair::P256(p) => PublicKey::P256(p.public_key().as_ref().to_vec()),
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        // CR-39 m.6
        let _dit = DitGuard::new();
        match &self.pair {
            Pair::Ed25519(p) => Ok(p.sign(message).as_ref().to_vec()),
            Pair::P256(p) => {
                let mut sig = p
                    .sign(&SystemRandom::new(), message)
                    .map_err(|_| SignError::Sign)?
                    .as_ref()
                    .to_vec();
                low_s(&mut sig)?;
                Ok(sig)
            }
        }
    }
}

/// Protected memory holding one key's PKCS#8 document (CR-34, SAI-45): `memfd_secret` or
/// locked pages in the signer process.
pub trait KeyPages: Send + Sync {
    /// Runs `f` over the document.
    fn expose(&self, f: &mut dyn FnMut(&[u8]));
}

/// Places a PKCS#8 document in protected memory; `None` when none is left (fail closed).
pub type Pager = dyn Fn(&[u8]) -> Option<Box<dyn KeyPages>> + Send + Sync;

/// A signer whose only long-lived copy of the key is its document in [`KeyPages`]
/// (OP-158 m.3 (y), SAI-45): each signature parses the key, signs and drops it, and aws-lc
/// cleanses the transient copy when it frees it.
pub struct PagedSigner {
    pages: Box<dyn KeyPages>,
    algorithm: Algorithm,
    public: PublicKey,
}

impl PagedSigner {
    /// The signer of the Ed25519 or P-256 document `doc`, placed by `pager`.
    ///
    /// # Errors
    /// [`SignError::Key`] for a document that is not such a key, or when `pager` has no room.
    pub fn new(ed25519: bool, doc: &Secret<Vec<u8>>, pager: &Pager) -> Result<Self, SignError> {
        let soft = if ed25519 {
            SoftSigner::ed25519_from_pkcs8(doc)?
        } else {
            SoftSigner::p256_from_pkcs8(doc)?
        };
        let placed = pager(doc.expose()).ok_or(SignError::Key)?;
        Ok(Self {
            pages: placed,
            algorithm: soft.algorithm(),
            public: soft.public_key(),
        })
    }

    fn parsed(&self, doc: &[u8]) -> Result<SoftSigner, SignError> {
        let pair = match self.algorithm {
            Algorithm::Ed25519 => {
                Pair::Ed25519(Ed25519KeyPair::from_pkcs8(doc).map_err(|_| SignError::Key)?)
            }
            _ => Pair::P256(
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc)
                    .map_err(|_| SignError::Key)?,
            ),
        };
        Ok(SoftSigner { pair })
    }
}

impl Signer for PagedSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let mut out = Err(SignError::Key);
        self.pages.expose(&mut |doc| {
            out = self.parsed(doc).and_then(|s| {
                if s.public_key() == self.public {
                    s.sign(message)
                } else {
                    Err(SignError::Key)
                }
            });
        });
        out
    }
}

/// A tagged `COSE_Sign1` over `payload` whose protected header carries exactly `alg`, the
/// content type and `kid` (L2-SIG-1).
///
/// # Errors
/// [`SignError`].
pub fn sign_sign1(
    signer: &dyn Signer,
    kid: [u8; 32],
    content_type: &str,
    payload: &[u8],
) -> Result<Vec<u8>, SignError> {
    let alg = signer.algorithm();
    if !matches!(
        alg,
        Algorithm::Ed25519 | Algorithm::Esp256 | Algorithm::Es256
    ) {
        return Err(SignError::Algorithm);
    }
    let protected = dcbor::encode(
        &Value::Map(alloc::vec![
            (Value::Unsigned(ALG), Value::int(alg.cose())),
            (Value::Unsigned(CONTENT_TYPE), Value::text(content_type)),
            (Value::Unsigned(KID), Value::Bytes(kid.to_vec())),
        ]),
        Limits::CEILING,
    )
    .map_err(|_| SignError::Encode)?;
    let signature =
        signer.sign(&to_be_signed(&protected, payload).map_err(|_| SignError::Encode)?)?;
    let body = dcbor::encode(
        &Value::Array(alloc::vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(signature),
        ]),
        Limits::CEILING,
    )
    .map_err(|_| SignError::Encode)?;
    let mut out = alloc::vec![0xd2];
    out.extend(body);
    Ok(out)
}

fn ed25519_key(signer: &dyn Signer) -> Result<[u8; 32], SignError> {
    match signer.public_key() {
        PublicKey::Ed25519(k) => Ok(k),
        _ => Err(SignError::Algorithm),
    }
}

fn line(name: &str, id: u32, signature: &[u8]) -> String {
    let mut raw = id.to_be_bytes().to_vec();
    raw.extend_from_slice(signature);
    alloc::format!("\u{2014} {name} {}\n", base64_encode(&raw))
}

/// The verifier key and note signature line of an Ed25519 log key over `body` (L2-CKP-3).
///
/// # Errors
/// [`SignError`].
pub fn sign_note(
    signer: &dyn Signer,
    name: &str,
    body: &str,
) -> Result<(Verifier, String), SignError> {
    let v = Verifier::ed25519(name, ed25519_key(signer)?).map_err(|_| SignError::Key)?;
    let sig = signer.sign(body.as_bytes())?;
    Ok((v.clone(), line(v.name(), v.id(), &sig)))
}

/// The verifier key and cosignature line of an Ed25519 cosigner over a checkpoint body at
/// `timestamp` seconds (L2-CKP-4).
///
/// # Errors
/// [`SignError`].
pub fn cosign(
    signer: &dyn Signer,
    name: &str,
    timestamp: u64,
    body: &str,
) -> Result<(Verifier, String), SignError> {
    let v = Verifier::cosigner(name, ed25519_key(signer)?).map_err(|_| SignError::Key)?;
    let mut sig = timestamp.to_be_bytes().to_vec();
    sig.extend(signer.sign(&cosigned_message(timestamp, body))?);
    Ok((v.clone(), line(v.name(), v.id(), &sig)))
}

#[cfg(test)]
mod tests;
