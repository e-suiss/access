//! PKCS#11 key store (OP-94, OP-135 m.4, OP-140 m.4, OP-141 m.18): signing keys, KEKs and MAC
//! keys stay inside the token. Locally and in CI the token is `SoftHSM` (OP-69).

use std::path::Path;
use std::sync::{Arc, Mutex};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeType, KeyType, MlDsaParameterSetType, ObjectClass, ObjectHandle,
};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use sha2::{Digest as _, Sha256};

use crate::cose::{Algorithm, PublicKey};
use crate::envelope::{Dek, EnvelopeError, Kek};
use crate::secret::Secret;
use crate::signer::{SignError, Signer, low_s};

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
    /// Key handles still hold sessions open: drop them before finalizing (OP-94).
    #[error("{0} key handles still open")]
    Busy(usize),
    /// The token offers no ML-DSA key generation or signing; there is no software fallback
    /// (OP-159 m.3 (d)).
    #[error("token has no ML-DSA mechanism")]
    PqUnavailable,
}

impl HsmError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Module(_) => "hsm-module",
            Self::Token(_) => "hsm-token",
            Self::Session(_) | Self::Poisoned | Self::Busy(_) => "hsm-session",
            Self::Key(_) => "hsm-key",
            Self::Operation(_) => "hsm-operation",
            Self::Encoding => "hsm-encoding",
            Self::PqUnavailable => "pq-key-unavailable",
        }
    }
}

/// Every module a store opened stays loaded until the process exits: unloading a module that
/// used OpenSSL (`SoftHSM`) leaves OpenSSL's exit handler pointing at unmapped code, and the
/// process then crashes at exit (OP-94).
static RESIDENT: Mutex<Vec<Pkcs11>> = Mutex::new(Vec::new());

/// Finalizes a module once its store and every key handle are dropped (OP-94).
pub struct Finalizer {
    module: Pkcs11,
    lease: std::sync::Weak<()>,
}

impl Finalizer {
    /// `C_Finalize`, when nothing of the store is alive any more.
    ///
    /// # Errors
    /// [`HsmError::Busy`] while the store or a handle is alive (nothing is finalized);
    /// [`HsmError::Module`] when the token refuses.
    pub fn finalize(self) -> Result<(), HsmError> {
        let open = self.lease.strong_count();
        if open > 0 {
            return Err(HsmError::Busy(open));
        }
        match self.module.finalize() {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiNotInitialized, _)) => Ok(()),
            Err(e) => Err(HsmError::Module(e)),
        }
    }
}

/// What a token offers for ML-DSA (PKCS#11 3.2 `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_DSA`),
/// read with `C_GetMechanismList` and `C_GetMechanismInfo` (OP-159 m.3 (d)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MlDsaMechanisms {
    /// `CKM_ML_DSA_KEY_PAIR_GEN` is listed with the key-pair generation flag.
    pub key_pair_gen: bool,
    /// `CKM_ML_DSA` is listed with the sign flag.
    pub sign: bool,
    /// `CKM_ML_DSA` is listed with the verify flag.
    pub verify: bool,
}

impl MlDsaMechanisms {
    /// Whether the token can hold an ML-DSA binding or realm key: it generates and signs.
    #[must_use]
    pub const fn available(self) -> bool {
        self.key_pair_gen && self.sign
    }
}

const fn parameter_set(alg: Algorithm) -> Option<MlDsaParameterSetType> {
    match alg {
        Algorithm::MlDsa44 => Some(MlDsaParameterSetType::ML_DSA_44),
        Algorithm::MlDsa65 => Some(MlDsaParameterSetType::ML_DSA_65),
        Algorithm::MlDsa87 => Some(MlDsaParameterSetType::ML_DSA_87),
        _ => None,
    }
}

/// A logged-in PKCS#11 token. Each key handle it gives out holds a session and a lease; the
/// orderly shutdown (OP-158 m.3 (y)) drops every handle, which closes its session, then calls
/// [`KeyStore::finalize`].
pub struct KeyStore {
    module: Arc<Pkcs11>,
    slot: Slot,
    pin: AuthPin,
    lease: Arc<()>,
}

impl KeyStore {
    /// Loads `module`, finds the token labelled `token` and checks the user PIN.
    ///
    /// CR-39 m.6, OP-159 m.26: whether the token labelled `token` is a software token
    /// (`SoftHSM`), the local equivalent of OP-69 that never holds production keys.
    ///
    /// # Errors
    /// [`HsmError`] when the module or the token cannot be read.
    pub fn software(module: &Path, token: &str) -> Result<bool, HsmError> {
        let ctx = Pkcs11::new(module).map_err(HsmError::Module)?;
        match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(HsmError::Module(e)),
        }
        let slots = ctx.get_slots_with_token().map_err(HsmError::Module)?;
        let info = slots
            .into_iter()
            .find_map(|s| {
                ctx.get_token_info(s)
                    .ok()
                    .filter(|i| i.label().trim_end() == token)
            })
            .ok_or_else(|| HsmError::Token(token.to_owned()))?;
        if let Ok(mut resident) = RESIDENT.lock() {
            resident.push(ctx);
        }
        Ok(info.model().trim_end().starts_with("SoftHSM")
            && info.manufacturer_id().trim_end().starts_with("SoftHSM"))
    }

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
        if let Ok(mut resident) = RESIDENT.lock() {
            resident.push(ctx.clone());
        }
        let store = Self {
            module: Arc::new(ctx),
            slot,
            pin: AuthPin::from(pin.expose().clone()),
            lease: Arc::new(()),
        };
        drop(store.session()?);
        Ok(store)
    }

    /// Key handles of this store that are still alive, each holding a session.
    #[must_use]
    pub fn open_handles(&self) -> usize {
        Arc::strong_count(&self.lease).saturating_sub(1)
    }

    /// The last step of an orderly shutdown (OP-94, OP-158 m.3 (y)): with every key handle
    /// dropped, and so every session closed, `C_Finalize`. The module stays loaded until exit.
    /// A module shared with another store of the process is finalized for both.
    ///
    /// # Errors
    /// [`HsmError::Busy`] while handles are alive (nothing is finalized);
    /// [`HsmError::Module`] when the token refuses.
    pub fn finalize(self) -> Result<(), HsmError> {
        let finalizer = self.finalizer();
        drop(self);
        finalizer.finalize()
    }

    /// What finalizes this store's module once the store and every handle are gone, for a
    /// caller that hands the store itself to a key adapter.
    #[must_use]
    pub fn finalizer(&self) -> Finalizer {
        Finalizer {
            module: Pkcs11::clone(&self.module),
            lease: Arc::downgrade(&self.lease),
        }
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

    /// Installs the clone key of a DR pair of tokens (CR-30, OP-158 m.3 (y)): an AES-256 key
    /// the token marks trusted, so it is the only kind of key a cloneable key may be wrapped
    /// under. The same ceremony value goes into both tokens; it cannot be read back. Needs the
    /// security officer's PIN and no open key handle.
    ///
    /// # Errors
    /// [`HsmError::Busy`] while handles are alive; [`HsmError`] otherwise, also when a key
    /// with this label exists.
    pub fn install_clone_key(
        &self,
        so_pin: &Secret<String>,
        label: &str,
        value: &Secret<[u8; 32]>,
    ) -> Result<(), HsmError> {
        let open = self.open_handles();
        if open > 0 {
            return Err(HsmError::Busy(open));
        }
        let session = self
            .module
            .open_rw_session(self.slot)
            .map_err(HsmError::Session)?;
        session
            .login(UserType::So, Some(&AuthPin::from(so_pin.expose().clone())))
            .map_err(HsmError::Session)?;
        if Self::one(&session, ObjectClass::SECRET_KEY, label).is_ok() {
            return Err(HsmError::Key(label.to_owned()));
        }
        session
            .create_object(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
                Attribute::Trusted(true),
                Attribute::Wrap(true),
                Attribute::Unwrap(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Value(value.expose().to_vec()),
            ])
            .map_err(HsmError::Operation)?;
        let logged_out = session.logout().map_err(HsmError::Session);
        drop(session);
        logged_out
    }

    /// Generates a signing key that only a trusted clone key may wrap (CR-30): sensitive, and
    /// extractable solely as a wrapped backup for the DR token.
    ///
    /// # Errors
    /// [`HsmError`], also when a key with this label exists.
    pub fn generate_cloneable(&self, label: &str, ed25519: bool) -> Result<HsmSigner, HsmError> {
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
                &cloneable_template(id),
            )
            .map_err(HsmError::Operation)?;
        drop(session);
        self.signer(label)
    }

    /// The private key labelled `label` wrapped under the trusted clone key `clone_key` (AES
    /// Key Wrap with Padding, RFC 5649), with its public key: the backup that only a token
    /// holding the same clone key opens (CR-30).
    ///
    /// # Errors
    /// [`HsmError::Operation`] when the key is not cloneable or the clone key is not trusted;
    /// [`HsmError`] otherwise.
    pub fn export_clone(&self, label: &str, clone_key: &str) -> Result<WrappedBackup, HsmError> {
        let session = self.session()?;
        let private = Self::one(&session, ObjectClass::PRIVATE_KEY, label)?;
        let wrapping = Self::one(&session, ObjectClass::SECRET_KEY, clone_key)?;
        let wrapped = session
            .wrap_key(&Mechanism::AesKeyWrapPad, wrapping, private)
            .map_err(HsmError::Operation)?;
        drop(session);
        let public = self.signer(label)?.public_key();
        Ok(WrappedBackup { wrapped, public })
    }

    /// Unwraps a [`KeyStore::export_clone`] backup into this token under `label`, as cloneable
    /// as the original, and returns its signer (CR-30).
    ///
    /// # Errors
    /// [`HsmError::Operation`] for another clone key or a corrupt backup;
    /// [`HsmError::Key`] when a key with this label exists; [`HsmError::Encoding`] when the
    /// unwrapped key does not match the backup's public key.
    pub fn import_clone(
        &self,
        label: &str,
        clone_key: &str,
        backup: &WrappedBackup,
    ) -> Result<HsmSigner, HsmError> {
        let session = self.session()?;
        if Self::one(&session, ObjectClass::PRIVATE_KEY, label).is_ok() {
            return Err(HsmError::Key(label.to_owned()));
        }
        let wrapping = Self::one(&session, ObjectClass::SECRET_KEY, clone_key)?;
        let id = label.as_bytes().to_vec();
        let (kind, params, point) = match &backup.public {
            PublicKey::Ed25519(p) => (KeyType::EC_EDWARDS, ED25519_PARAMS, p.to_vec()),
            PublicKey::P256(p) => (KeyType::EC, P256_PARAMS, p.clone()),
            PublicKey::MlDsa(..) => return Err(HsmError::Encoding),
        };
        let mut template = cloneable_template(id.clone());
        template.extend([
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(kind),
        ]);
        let private = session
            .unwrap_key(
                &Mechanism::AesKeyWrapPad,
                wrapping,
                &backup.wrapped,
                &template,
            )
            .map_err(HsmError::Operation)?;
        let public = session.create_object(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(kind),
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::EcParams(params.to_vec()),
            Attribute::EcPoint(octets(&point)),
            Attribute::Label(id),
        ]);
        if let Err(e) = public {
            let _ = session.destroy_object(private);
            return Err(HsmError::Operation(e));
        }
        drop(session);
        let signer = self.signer(label)?;
        if signer.public_key() != backup.public || !signer.pairs() {
            return Err(HsmError::Encoding);
        }
        Ok(signer)
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

    /// The names of every mechanism the token lists (`C_GetMechanismList`), for the startup
    /// report of the PQ profile probe (OP-159 m.3 (d)).
    ///
    /// # Errors
    /// [`HsmError::Module`].
    pub fn mechanism_names(&self) -> Result<Vec<String>, HsmError> {
        let list = self
            .module
            .get_mechanism_list(self.slot)
            .map_err(HsmError::Module)?;
        Ok(list.iter().map(ToString::to_string).collect())
    }

    /// Probes the token for ML-DSA (OP-159 m.3 (d)). A mechanism that is listed but whose
    /// info cannot be read counts as absent.
    ///
    /// # Errors
    /// [`HsmError::Module`] when the mechanism list cannot be read.
    pub fn ml_dsa_mechanisms(&self) -> Result<MlDsaMechanisms, HsmError> {
        let list = self
            .module
            .get_mechanism_list(self.slot)
            .map_err(HsmError::Module)?;
        let info = |t: MechanismType| {
            list.contains(&t)
                .then(|| self.module.get_mechanism_info(self.slot, t).ok())
                .flatten()
        };
        let gen_info = info(MechanismType::ML_DSA_KEY_PAIR_GEN);
        let sig_info = info(MechanismType::ML_DSA);
        Ok(MlDsaMechanisms {
            key_pair_gen: gen_info.is_some_and(|i| i.generate_key_pair()),
            sign: sig_info.is_some_and(|i| i.sign()),
            verify: sig_info.is_some_and(|i| i.verify()),
        })
    }

    /// Generates an ML-DSA signing key of `alg` inside the token (CR-18, MD-6, OP-159 m.3
    /// (d)). Without the mechanisms it refuses; there is no software key in its place.
    ///
    /// # Errors
    /// [`HsmError::PqUnavailable`] when the probe finds no ML-DSA; [`HsmError`] otherwise,
    /// also for a classical `alg` or an existing label.
    pub fn generate_ml_dsa(&self, label: &str, alg: Algorithm) -> Result<HsmSigner, HsmError> {
        let set = parameter_set(alg).ok_or(HsmError::Encoding)?;
        if !self.ml_dsa_mechanisms()?.available() {
            return Err(HsmError::PqUnavailable);
        }
        let session = self.session()?;
        if Self::one(&session, ObjectClass::PRIVATE_KEY, label).is_ok() {
            return Err(HsmError::Key(label.to_owned()));
        }
        let id = label.as_bytes().to_vec();
        session
            .generate_key_pair(
                &Mechanism::MlDsaKeyPairGen,
                &[
                    Attribute::Token(true),
                    Attribute::Verify(true),
                    Attribute::ParameterSet(set.into()),
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
        let signer = self.signer(label)?;
        if !signer.pairs() {
            return Err(HsmError::Encoding);
        }
        Ok(signer)
    }

    fn ml_dsa_public(session: &Session, public: ObjectHandle) -> Result<PublicKey, HsmError> {
        let attrs = session
            .get_attributes(public, &[AttributeType::ParameterSet, AttributeType::Value])
            .map_err(HsmError::Operation)?;
        let (mut set, mut value) = (None, None);
        for a in attrs {
            match a {
                Attribute::ParameterSet(p) => set = Some(p),
                Attribute::Value(v) => value = Some(v),
                _ => {}
            }
        }
        let alg = [Algorithm::MlDsa44, Algorithm::MlDsa65, Algorithm::MlDsa87]
            .into_iter()
            .find(|a| {
                parameter_set(*a)
                    .zip(set)
                    .is_some_and(|(p, s)| cryptoki::object::ParameterSetType::from(p) == s)
            })
            .ok_or(HsmError::Encoding)?;
        Ok(PublicKey::MlDsa(alg, value.ok_or(HsmError::Encoding)?))
    }

    /// The signing key labelled `label`.
    ///
    /// # Errors
    /// [`HsmError`].
    pub fn signer(&self, label: &str) -> Result<HsmSigner, HsmError> {
        let session = self.session()?;
        let private = Self::one(&session, ObjectClass::PRIVATE_KEY, label)?;
        let public = Self::one(&session, ObjectClass::PUBLIC_KEY, label)?;
        let kind_of = session
            .get_attributes(public, &[AttributeType::KeyType])
            .map_err(HsmError::Operation)?;
        if kind_of
            .iter()
            .any(|a| matches!(a, Attribute::KeyType(k) if *k == KeyType::ML_DSA))
        {
            let key = Self::ml_dsa_public(&session, public)?;
            key.check().map_err(|_| HsmError::Encoding)?;
            return Ok(HsmSigner {
                session,
                private,
                key,
                _lease: Arc::clone(&self.lease),
            });
        }
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
            _lease: Arc::clone(&self.lease),
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
            _lease: Arc::clone(&self.lease),
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

    /// Destroys the KEK labelled `label` inside the token, crypto-shredding every key it wrapped
    /// (OP-73). Open handles to it fail from then on.
    ///
    /// # Errors
    /// [`HsmError::Key`] when no KEK, or more than one, has this label; [`HsmError`] otherwise.
    pub fn destroy_kek(&self, label: &str) -> Result<(), HsmError> {
        let session = self.session()?;
        let found = session
            .find_objects(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Wrap(true),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .map_err(HsmError::Operation)?;
        let [key] = found.as_slice() else {
            return Err(HsmError::Key(label.to_owned()));
        };
        session.destroy_object(*key).map_err(HsmError::Operation)
    }

    /// The HMAC key labelled `label` that every process of the token agrees on, made when
    /// missing (TN-29, OP-158 m.3 (y)): processes that make it at once each add one with a
    /// random `CKA_ID`, and all of them use the one with the lowest id.
    ///
    /// # Errors
    /// [`HsmError`].
    pub fn shared_mac(&self, label: &str) -> Result<HsmMac, HsmError> {
        let session = self.session()?;
        let find = |session: &Session| -> Result<Option<ObjectHandle>, HsmError> {
            let found = session
                .find_objects(&[
                    Attribute::Class(ObjectClass::SECRET_KEY),
                    Attribute::Label(label.as_bytes().to_vec()),
                ])
                .map_err(HsmError::Operation)?;
            let mut best: Option<(Vec<u8>, ObjectHandle)> = None;
            for handle in found {
                let id = match session
                    .get_attributes(handle, &[AttributeType::Id])
                    .map_err(HsmError::Operation)?
                    .pop()
                {
                    Some(Attribute::Id(id)) => id,
                    _ => Vec::new(),
                };
                if best.as_ref().is_none_or(|(b, _)| id < *b) {
                    best = Some((id, handle));
                }
            }
            Ok(best.map(|(_, h)| h))
        };
        let key = if let Some(key) = find(&session)? {
            key
        } else {
            let id: [u8; 16] = aws_lc_rs::rand::generate(&aws_lc_rs::rand::SystemRandom::new())
                .map_err(|_| HsmError::Encoding)?
                .expose();
            let mut template = mac_template(label, None);
            template.push(Attribute::Id(id.to_vec()));
            session
                .generate_key(&Mechanism::GenericSecretKeyGen, &template)
                .map_err(HsmError::Operation)?;
            find(&session)?.ok_or_else(|| HsmError::Key(label.to_owned()))?
        };
        Ok(HsmMac {
            session: Mutex::new(session),
            key,
            _lease: Arc::clone(&self.lease),
        })
    }

    /// Destroys every secret key labelled `label`, for keys of an ephemeral protocol whose
    /// generation has passed (TN-29); returns how many.
    ///
    /// # Errors
    /// [`HsmError`].
    pub fn retire_secret(&self, label: &str) -> Result<usize, HsmError> {
        let session = self.session()?;
        let found = session
            .find_objects(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .map_err(HsmError::Operation)?;
        for key in &found {
            session.destroy_object(*key).map_err(HsmError::Operation)?;
        }
        Ok(found.len())
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
            _lease: Arc::clone(&self.lease),
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
            _lease: Arc::clone(&self.lease),
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

fn cloneable_template(label: Vec<u8>) -> Vec<Attribute> {
    vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(true),
        Attribute::WrapWithTrusted(true),
        Attribute::Sign(true),
        Attribute::Label(label),
    ]
}

fn octets(point: &[u8]) -> Vec<u8> {
    let mut der = Vec::new();
    der.push(0x04);
    der.push(u8::try_from(point.len()).unwrap_or(0));
    der.extend_from_slice(point);
    der
}

/// A cloneable key wrapped for the DR token, with its public key (CR-30).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedBackup {
    /// The private key under the clone key, RFC 5649.
    pub wrapped: Vec<u8>,
    /// Its public key.
    pub public: PublicKey,
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
    _lease: Arc<()>,
}

impl HsmSigner {
    /// Whether a fresh signature verifies under the key's public key.
    fn pairs(&self) -> bool {
        let message = b"suiss/pkcs11/pairwise";
        self.sign(message).is_ok_and(|sig| match &self.key {
            PublicKey::Ed25519(p) => {
                crate::sig::ed25519(&crate::aws::AwsLcBackend, p, message, &sig).is_ok()
            }
            PublicKey::P256(p) => {
                crate::sig::p256(&crate::aws::AwsLcBackend, p, message, &sig, true).is_ok()
            }
            PublicKey::MlDsa(alg, p) => {
                crate::sig::Backend::ml_dsa(&crate::aws::AwsLcBackend, *alg, p, message, &sig)
            }
        })
    }
}

impl Signer for HsmSigner {
    fn algorithm(&self) -> Algorithm {
        match self.key {
            PublicKey::Ed25519(_) => Algorithm::Ed25519,
            PublicKey::MlDsa(alg, _) => alg,
            PublicKey::P256(_) => Algorithm::Esp256,
        }
    }

    fn public_key(&self) -> PublicKey {
        self.key.clone()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        if let PublicKey::MlDsa(alg, _) = self.key {
            // CR-41 m.4
            let sig = self
                .session
                .sign(
                    &Mechanism::MlDsa(SignAdditionalContext::new(HedgeType::Preferred, None)),
                    self.private,
                    message,
                )
                .map_err(|_| SignError::Sign)?;
            let want = match alg {
                Algorithm::MlDsa44 => 2420,
                Algorithm::MlDsa65 => 3309,
                _ => 4627,
            };
            return if sig.len() == want {
                Ok(sig)
            } else {
                Err(SignError::Sign)
            };
        }
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
    _lease: Arc<()>,
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
    _lease: Arc<()>,
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
    _lease: Arc<()>,
}

impl HsmKek {
    /// Re-wraps a DEK from this KEK to `to` inside the token (OP-138, OP-158 m.3 (y)): the DEK
    /// is unwrapped into a sensitive session object that only `to` wraps again, so its value
    /// never leaves the token. `to` must be a KEK of the same token.
    ///
    /// # Errors
    /// [`EnvelopeError::Wrap`] for a wrong KEK, a corrupt wrapped key or a KEK of another
    /// token.
    pub fn rewrap(&self, wrapped: &[u8], to: &Self) -> Result<Vec<u8>, EnvelopeError> {
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(true),
        ];
        let object = self
            .session
            .unwrap_key(&Mechanism::AesKeyWrap, self.key, wrapped, &template)
            .map_err(|_| EnvelopeError::Wrap)?;
        let rewrapped = self
            .session
            .wrap_key(&Mechanism::AesKeyWrap, to.key, object);
        let destroyed = self.session.destroy_object(object);
        let rewrapped = rewrapped.map_err(|_| EnvelopeError::Wrap)?;
        destroyed.map_err(|_| EnvelopeError::Wrap)?;
        Ok(rewrapped)
    }

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

#[cfg(any(test, feature = "testing"))]
pub mod token_tests;
