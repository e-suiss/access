//! PKCS#11 key store (OP-94, OP-135 m.4, OP-140 m.4, OP-141 m.18): signing keys, KEKs and MAC
//! keys stay inside the token. Locally and in CI the token is `SoftHSM` (OP-69).

use std::path::Path;
use std::sync::{Arc, Mutex};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use sha2::{Digest as _, Sha256};

use crate::cose::{Algorithm, PublicKey};
use crate::envelope::{Dek, EnvelopeError, Kek};
use crate::secret::Secret;
use crate::signer::{SignError, Signer, low_s};

// DER OIDs: id-Ed25519 (RFC 8410) and prime256v1
const ED25519_PARAMS: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
const P256_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Why a key store operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HsmError {
    /// The module could not be loaded or initialised.
    #[error("module: {0}")]
    Module(CkError),
    /// No token has this label.
    #[error("no token labelled {0}")]
    Token(String),
    /// Login or session failure.
    #[error("session: {0}")]
    Session(CkError),
    /// No key with this label, or more than one.
    #[error("key {0} not found or not unique")]
    Key(String),
    /// The token refused the operation.
    #[error("token: {0}")]
    Operation(CkError),
    /// The token returned a public key in an unexpected form.
    #[error("unexpected public key encoding")]
    Encoding,
    /// A shared session's lock was poisoned.
    #[error("session lock poisoned")]
    Poisoned,
}

impl HsmError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Module(_) => "hsm-module",
            Self::Token(_) => "hsm-token",
            Self::Session(_) | Self::Poisoned => "hsm-session",
            Self::Key(_) => "hsm-key",
            Self::Operation(_) => "hsm-operation",
            Self::Encoding => "hsm-encoding",
        }
    }
}

/// A logged-in PKCS#11 token.
pub struct KeyStore {
    module: Arc<Pkcs11>,
    slot: Slot,
    pin: AuthPin,
}

impl KeyStore {
    /// Loads `module`, finds the token labelled `token` and checks the user PIN.
    ///
    /// # Errors
    /// [`HsmError`].
    pub fn open(module: &Path, token: &str, pin: &Secret<String>) -> Result<Self, HsmError> {
        let ctx = Pkcs11::new(module).map_err(HsmError::Module)?;
        match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(HsmError::Module(e)),
        }
        let slots = ctx.get_slots_with_token().map_err(HsmError::Module)?;
        let slot = slots
            .into_iter()
            .find(|s| {
                ctx.get_token_info(*s)
                    .is_ok_and(|i| i.label().trim_end() == token)
            })
            .ok_or_else(|| HsmError::Token(token.to_owned()))?;
        let store = Self {
            module: Arc::new(ctx),
            slot,
            pin: AuthPin::from(pin.expose().clone()),
        };
        drop(store.session()?);
        Ok(store)
    }

    fn session(&self) -> Result<Session, HsmError> {
        let s = self
            .module
            .open_rw_session(self.slot)
            .map_err(HsmError::Session)?;
        match s.login(UserType::User, Some(&self.pin)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(s),
            Err(e) => Err(HsmError::Session(e)),
        }
    }

    fn one(session: &Session, class: ObjectClass, label: &str) -> Result<ObjectHandle, HsmError> {
        let found = session
            .find_objects(&[
                Attribute::Class(class),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .map_err(HsmError::Operation)?;
        match found.as_slice() {
            [one] => Ok(*one),
            _ => Err(HsmError::Key(label.to_owned())),
        }
    }

    fn generate(&self, label: &str, ed25519: bool) -> Result<HsmSigner, HsmError> {
        let session = self.session()?;
        if Self::one(&session, ObjectClass::PRIVATE_KEY, label).is_ok() {
            return Err(HsmError::Key(label.to_owned()));
        }
        let (mechanism, params) = if ed25519 {
            (Mechanism::EccEdwardsKeyPairGen, ED25519_PARAMS)
        } else {
            (Mechanism::EccKeyPairGen, P256_PARAMS)
        };
        let id = label.as_bytes().to_vec();
        session
            .generate_key_pair(
                &mechanism,
                &[
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::EcParams(params.to_vec()),
                    Attribute::Label(id.clone()),
                ],
                &[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Sign(true),
                    Attribute::Label(id),
                ],
            )
            .map_err(HsmError::Operation)?;
        drop(session);
        self.signer(label)
    }

    /// Generates an Ed25519 signing key inside the token.
    ///
    /// # Errors
    /// [`HsmError`], also when a key with this label exists.
    pub fn generate_ed25519(&self, label: &str) -> Result<HsmSigner, HsmError> {
        self.generate(label, true)
    }

    /// Generates an ECDSA P-256 signing key inside the token.
    ///
    /// # Errors
    /// [`HsmError`], also when a key with this label exists.
    pub fn generate_p256(&self, label: &str) -> Result<HsmSigner, HsmError> {
        self.generate(label, false)
    }

    /// The signing key labelled `label`.
    ///
    /// # Errors
    /// [`HsmError`].
    pub fn signer(&self, label: &str) -> Result<HsmSigner, HsmError> {
        let session = self.session()?;
        let private = Self::one(&session, ObjectClass::PRIVATE_KEY, label)?;
        let public = Self::one(&session, ObjectClass::PUBLIC_KEY, label)?;
        let attrs = session
            .get_attributes(public, &[AttributeType::KeyType, AttributeType::EcPoint])
            .map_err(HsmError::Operation)?;
        let (mut kind, mut point) = (None, None);
        for a in attrs {
            match a {
                Attribute::KeyType(k) => kind = Some(k),
                Attribute::EcPoint(p) => point = Some(p),
                _ => {}
            }
        }
        let der = point.ok_or(HsmError::Encoding)?;
        let point = unwrap_octets(&der);
        let key = match kind {
            Some(k) if k == KeyType::EC_EDWARDS => {
                PublicKey::Ed25519(point.try_into().map_err(|_| HsmError::Encoding)?)
            }
            Some(k) if k == KeyType::EC && point.len() == 65 => PublicKey::P256(point.to_vec()),
            _ => return Err(HsmError::Encoding),
        };
        key.check().map_err(|_| HsmError::Encoding)?;
        Ok(HsmSigner {
            session,
            private,
            key,
        })
    }

    /// Generates an AES-256 KEK inside the token; it never leaves it.
    ///
    /// # Errors
    /// [`HsmError`], also when a key with this label exists.
    pub fn generate_kek(&self, label: &str) -> Result<HsmKek, HsmError> {
        let session = self.session()?;
        if Self::one(&session, ObjectClass::SECRET_KEY, label).is_ok() {
            return Err(HsmError::Key(label.to_owned()));
        }
        session
            .generate_key(&Mechanism::AesKeyGen, &kek_template(label, None))
            .map_err(HsmError::Operation)?;
        drop(session);
        self.kek(label)
    }

    /// The KEK labelled `label`.
    ///
    /// # Errors
    /// [`HsmError`].
    pub fn kek(&self, label: &str) -> Result<HsmKek, HsmError> {
        let session = self.session()?;
        let key = Self::one(&session, ObjectClass::SECRET_KEY, label)?;
        Ok(HsmKek {
            id: label.to_owned(),
            session,
            key,
        })
    }

    /// Imports a known AES-256 KEK, for migration and tests; it cannot be read back.
    ///
    /// # Errors
    /// [`HsmError`], also when a key with this label exists.
    pub fn import_kek(&self, label: &str, value: &Secret<[u8; 32]>) -> Result<HsmKek, HsmError> {
        let session = self.session()?;
        if Self::one(&session, ObjectClass::SECRET_KEY, label).is_ok() {
            return Err(HsmError::Key(label.to_owned()));
        }
        session
            .create_object(&kek_template(label, Some(value.expose().to_vec())))
            .map_err(HsmError::Operation)?;
        drop(session);
        self.kek(label)
    }

    /// Generates a 32-byte HMAC-SHA-256 key inside the token; it never leaves it.
    ///
    /// # Errors
    /// [`HsmError`], also when a key with this label exists.
    pub fn generate_mac(&self, label: &str) -> Result<HsmMac, HsmError> {
        let session = self.session()?;
        if Self::one(&session, ObjectClass::SECRET_KEY, label).is_ok() {
            return Err(HsmError::Key(label.to_owned()));
        }
        session
            .generate_key(&Mechanism::GenericSecretKeyGen, &mac_template(label, None))
            .map_err(HsmError::Operation)?;
        drop(session);
        self.mac(label)
    }

    /// The HMAC key labelled `label`.
    ///
    /// # Errors
    /// [`HsmError`].
    pub fn mac(&self, label: &str) -> Result<HsmMac, HsmError> {
        let session = self.session()?;
        let key = Self::one(&session, ObjectClass::SECRET_KEY, label)?;
        Ok(HsmMac {
            session: Mutex::new(session),
            key,
        })
    }

    /// Generates an AES-256 key for AES-GCM inside the token; it never leaves it.
    ///
    /// # Errors
    /// [`HsmError`], also when a key with this label exists.
    pub fn generate_aead(&self, label: &str) -> Result<HsmAead, HsmError> {
        let session = self.session()?;
        if Self::one(&session, ObjectClass::SECRET_KEY, label).is_ok() {
            return Err(HsmError::Key(label.to_owned()));
        }
        session
            .generate_key(
                &Mechanism::AesKeyGen,
                &[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Encrypt(true),
                    Attribute::Decrypt(true),
                    Attribute::Label(label.as_bytes().to_vec()),
                    Attribute::ValueLen(32.into()),
                ],
            )
            .map_err(HsmError::Operation)?;
        drop(session);
        self.aead(label)
    }

    /// The AES-GCM key labelled `label`.
    ///
    /// # Errors
    /// [`HsmError`].
    pub fn aead(&self, label: &str) -> Result<HsmAead, HsmError> {
        let session = self.session()?;
        let key = Self::one(&session, ObjectClass::SECRET_KEY, label)?;
        Ok(HsmAead {
            session: Mutex::new(session),
            key,
        })
    }

    /// Imports a known HMAC key, for migration and tests; it cannot be read back.
    ///
    /// # Errors
    /// [`HsmError`], also when a key with this label exists.
    pub fn import_mac(&self, label: &str, value: &Secret<[u8; 32]>) -> Result<HsmMac, HsmError> {
        let session = self.session()?;
        if Self::one(&session, ObjectClass::SECRET_KEY, label).is_ok() {
            return Err(HsmError::Key(label.to_owned()));
        }
        session
            .create_object(&mac_template(label, Some(value.expose().to_vec())))
            .map_err(HsmError::Operation)?;
        drop(session);
        self.mac(label)
    }
}

fn mac_template(label: &str, value: Option<Vec<u8>>) -> Vec<Attribute> {
    let mut t = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    match value {
        Some(v) => {
            t.push(Attribute::Class(ObjectClass::SECRET_KEY));
            t.push(Attribute::KeyType(KeyType::GENERIC_SECRET));
            t.push(Attribute::Value(v));
        }
        None => t.push(Attribute::ValueLen(32.into())),
    }
    t
}

fn kek_template(label: &str, value: Option<Vec<u8>>) -> Vec<Attribute> {
    let mut t = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Wrap(true),
        Attribute::Unwrap(true),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    match value {
        Some(v) => {
            t.push(Attribute::Class(ObjectClass::SECRET_KEY));
            t.push(Attribute::KeyType(KeyType::AES));
            t.push(Attribute::Value(v));
        }
        None => t.push(Attribute::ValueLen(32.into())),
    }
    t
}

fn unwrap_octets(der: &[u8]) -> &[u8] {
    match der {
        [0x04, len, rest @ ..] if usize::from(*len) == rest.len() => rest,
        _ => der,
    }
}

/// A signing key inside the token.
pub struct HsmSigner {
    session: Session,
    private: ObjectHandle,
    key: PublicKey,
}

impl Signer for HsmSigner {
    fn algorithm(&self) -> Algorithm {
        match self.key {
            PublicKey::Ed25519(_) => Algorithm::Ed25519,
            _ => Algorithm::Esp256,
        }
    }

    fn public_key(&self) -> PublicKey {
        self.key.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        let sig = if let PublicKey::Ed25519(_) = self.key {
            self.session.sign(
                &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
                self.private,
                message,
            )
        } else {
            let digest: [u8; 32] = Sha256::digest(message).into();
            self.session
                .sign(&Mechanism::Ecdsa, self.private, &digest)
                .map(|mut s| {
                    if low_s(&mut s).is_err() {
                        s.clear();
                    }
                    s
                })
        }
        .map_err(|_| SignError::Sign)?;
        if sig.len() == 64 {
            Ok(sig)
        } else {
            Err(SignError::Sign)
        }
    }
}

/// An HMAC-SHA-256 key inside the token; its session is shared behind a lock.
pub struct HsmMac {
    session: Mutex<Session>,
    key: ObjectHandle,
}

impl HsmMac {
    /// `HMAC-SHA-256(key, message)`.
    ///
    /// # Errors
    /// [`HsmError::Operation`]; [`HsmError::Encoding`] when the token returns another length.
    pub fn mac(&self, message: &[u8]) -> Result<[u8; 32], HsmError> {
        self.session
            .lock()
            .map_err(|_| HsmError::Poisoned)?
            .sign(&Mechanism::Sha256Hmac, self.key, message)
            .map_err(HsmError::Operation)?
            .as_slice()
            .try_into()
            .map_err(|_| HsmError::Encoding)
    }
}

/// An AES-256-GCM key inside the token; its session is shared behind a lock.
pub struct HsmAead {
    session: Mutex<Session>,
    key: ObjectHandle,
}

/// Length of the random AES-GCM nonce.
pub const GCM_NONCE: usize = 12;

impl HsmAead {
    /// `nonce ‖ AES-256-GCM(plaintext, aad)` with a fresh random 96-bit nonce and a 128-bit tag.
    ///
    /// # Errors
    /// [`HsmError::Operation`]; [`HsmError::Encoding`] when no randomness is available.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HsmError> {
        use aws_lc_rs::rand::SecureRandom as _;
        let mut nonce = [0_u8; GCM_NONCE];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| HsmError::Encoding)?;
        let mut iv = nonce;
        let params = cryptoki::mechanism::aead::GcmParams::new(&mut iv, aad, 128.into())
            .map_err(HsmError::Operation)?;
        let sealed = self
            .session
            .lock()
            .map_err(|_| HsmError::Poisoned)?
            .encrypt(&Mechanism::AesGcm(params), self.key, plaintext)
            .map_err(HsmError::Operation)?;
        Ok([nonce.as_slice(), &sealed].concat())
    }

    /// Opens what [`HsmAead::seal`] produced under the same `aad`.
    ///
    /// # Errors
    /// [`HsmError::Operation`] when the tag does not verify; [`HsmError::Encoding`] when the
    /// input is too short.
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, HsmError> {
        if sealed.len() < GCM_NONCE.saturating_add(16) {
            return Err(HsmError::Encoding);
        }
        let (nonce, body) = sealed.split_at(GCM_NONCE);
        let mut iv = [0_u8; GCM_NONCE];
        iv.copy_from_slice(nonce);
        let params = cryptoki::mechanism::aead::GcmParams::new(&mut iv, aad, 128.into())
            .map_err(HsmError::Operation)?;
        self.session
            .lock()
            .map_err(|_| HsmError::Poisoned)?
            .decrypt(&Mechanism::AesGcm(params), self.key, body)
            .map_err(HsmError::Operation)
    }
}

/// A KEK inside the token: it wraps DEKs under AES Key Wrap (RFC 3394), the same output as
/// [`crate::envelope`]'s in-process KEK.
pub struct HsmKek {
    id: String,
    session: Session,
    key: ObjectHandle,
}

impl HsmKek {
    fn dek_template(value: Option<Vec<u8>>) -> Vec<Attribute> {
        let mut t = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
        ];
        if let Some(v) = value {
            t.push(Attribute::Value(v));
        }
        t
    }
}

impl Kek for HsmKek {
    fn id(&self) -> &str {
        &self.id
    }

    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, EnvelopeError> {
        let object = self
            .session
            .create_object(&Self::dek_template(Some(dek.secret().expose().to_vec())))
            .map_err(|_| EnvelopeError::Wrap)?;
        let wrapped = self
            .session
            .wrap_key(&Mechanism::AesKeyWrap, self.key, object);
        let destroyed = self.session.destroy_object(object);
        let wrapped = wrapped.map_err(|_| EnvelopeError::Wrap)?;
        destroyed.map_err(|_| EnvelopeError::Wrap)?;
        Ok(wrapped)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, EnvelopeError> {
        let object = self
            .session
            .unwrap_key(
                &Mechanism::AesKeyWrap,
                self.key,
                wrapped,
                &Self::dek_template(None),
            )
            .map_err(|_| EnvelopeError::Wrap)?;
        let value = self.session.get_attributes(object, &[AttributeType::Value]);
        let destroyed = self.session.destroy_object(object);
        let Some(Attribute::Value(mut bytes)) = value.map_err(|_| EnvelopeError::Wrap)?.pop()
        else {
            return Err(EnvelopeError::Wrap);
        };
        destroyed.map_err(|_| EnvelopeError::Wrap)?;
        let key: Result<[u8; 32], _> = bytes.as_slice().try_into();
        zeroize::Zeroize::zeroize(&mut bytes);
        Ok(Dek::from_secret(Secret::new(
            key.map_err(|_| EnvelopeError::Wrap)?,
        )))
    }
}

#[cfg(test)]
mod tests;
