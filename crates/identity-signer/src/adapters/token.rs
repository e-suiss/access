//! The realm's post-quantum keys inside the HSM (CR-18, OP-159 m.3 (d)): a key factory that
//! makes each ML-DSA key in the token with `CKM_ML_DSA_KEY_PAIR_GEN` and signs with `CKM_ML_DSA`,
//! and passes every classical key to the factory it wraps. Without the mechanisms the profile is
//! refused (`pq-key-unavailable`); there is no software key in its place.

use std::sync::Arc;

use access_crypto::jose::JwsAlg;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::pkcs11::KeyStore;
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::{SignError, Signer};

use crate::ports::{Generated, KeyFactory};

/// The label prefix of the realm ML-DSA keys in the token.
pub const LABEL_PREFIX: &str = "access/identity/pq/";

/// ML-DSA keys in the token, every other key through `inner`.
pub struct TokenPq<F> {
    inner: F,
    store: Arc<KeyStore>,
}

impl<F: KeyFactory> TokenPq<F> {
    /// ML-DSA keys in `store`, the rest through `inner`.
    pub const fn new(inner: F, store: Arc<KeyStore>) -> Self {
        Self { inner, store }
    }

    fn label() -> Result<String, SignError> {
        let id = access_crypto::random::bytes::<16>().map_err(|_| SignError::Random)?;
        Ok(id.iter().fold(String::from(LABEL_PREFIX), |mut out, b| {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
            out
        }))
    }
}

impl<F: KeyFactory> KeyFactory for TokenPq<F> {
    // OP-159 m.3 (d), (r)
    fn pq_ready(&mut self, alg: JwsAlg) -> bool {
        alg.post_quantum()
            && !suiss_crypto::fips::BUILD
            && self
                .store
                .ml_dsa_mechanisms()
                .is_ok_and(suiss_crypto::pkcs11::MlDsaMechanisms::available)
    }

    fn generate(&mut self, alg: JwsAlg) -> Result<Generated, SignError> {
        if !alg.post_quantum() {
            return self.inner.generate(alg);
        }
        if !self.pq_ready(alg) {
            return Err(SignError::Algorithm);
        }
        let label = Self::label()?;
        let signer = self
            .store
            .generate_ml_dsa(&label, alg.algorithm())
            .map_err(|_| SignError::Algorithm)?;
        let reference = Value::Map(vec![(Value::text("hsm"), Value::text(&label))]);
        Ok(Generated {
            signer: Box::new(signer),
            sealed: dcbor::encode(&reference, Limits::CEILING).map_err(|_| SignError::Encode)?,
        })
    }

    fn load(&mut self, alg: JwsAlg, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError> {
        if !alg.post_quantum() {
            return self.inner.load(alg, sealed);
        }
        let v = dcbor::decode(sealed, Limits::CEILING).map_err(|_| SignError::Key)?;
        let Some(Value::Text(label)) = v.get("hsm") else {
            return Err(SignError::Key);
        };
        if !label.starts_with(LABEL_PREFIX) || !self.pq_ready(alg) {
            return Err(SignError::Key);
        }
        let signer = self.store.signer(label).map_err(|_| SignError::Key)?;
        if signer.algorithm() != alg.algorithm() {
            return Err(SignError::Key);
        }
        Ok(Box::new(signer))
    }

    fn generate_rsa_id(&mut self) -> Result<(access_crypto::rsa_id::RsaIdKey, Vec<u8>), SignError> {
        self.inner.generate_rsa_id()
    }

    fn load_rsa_id(&mut self, sealed: &[u8]) -> Result<access_crypto::rsa_id::RsaIdKey, SignError> {
        self.inner.load_rsa_id(sealed)
    }

    fn seal_document(&mut self, doc: &Secret<Vec<u8>>) -> Result<Vec<u8>, SignError> {
        self.inner.seal_document(doc)
    }

    fn open_document(&mut self, sealed: &[u8]) -> Result<Secret<Vec<u8>>, SignError> {
        self.inner.open_document(sealed)
    }
}
