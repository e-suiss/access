//! The cell's `audit-checkpoint` key: one Ed25519 key per cell, apart from every realm key so
//! that realm rotation never touches it, which signs the identity audit log's checkpoints as
//! C2SP signed notes (CMP-22b, §17.6.5, OP-134 m.4, OP-143 m.10, OP-150 m.3 (h)).

use access_crypto::jose::JwsAlg;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::note::{Checkpoint, Verifier, check_name};
use suiss_crypto::signer::{Signer, sign_note};

use crate::SignerError;
use crate::ports::KeyFactory;

/// The key's purpose, its label in the vault and in the protocol.
pub const LABEL: &str = "audit-checkpoint";

/// The identity audit log's origin in cell `cell`: the note key name and the checkpoint's first
/// line.
#[must_use]
pub fn origin(cell: &str) -> String {
    format!("{cell}/{IDENTITY_CHAIN}")
}

/// The identity audit log's chain name: the last segment of its origin.
pub const IDENTITY_CHAIN: &str = "identity-audit";

/// The authority plane's operational audit stream (OP-39, OP-44): a separate chain the same cell
/// key signs, so protocol rejections and audit reads never share a tree with the identity log.
pub const OPERATIONAL_CHAIN: &str = "authority-operational";

/// The origin of the operational chain of the cell whose identity log is `identity_origin`;
/// `None` when that is not an identity log origin.
#[must_use]
pub fn operational_origin(identity_origin: &str) -> Option<String> {
    identity_origin
        .strip_suffix(IDENTITY_CHAIN)
        .filter(|cell| cell.ends_with('/'))
        .map(|cell| format!("{cell}{OPERATIONAL_CHAIN}"))
}

/// Why the cell key cannot be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CellError {
    /// The cell name is not a valid note key name.
    #[error("cell name")]
    Name,
    /// The vault holds the key of another cell.
    #[error("vault holds another cell's key")]
    OtherCell,
    /// The stored key cannot be read or loaded.
    #[error("stored key unusable")]
    Stored,
    /// No key could be created.
    #[error("no key")]
    Generate,
}

/// The cell's audit-checkpoint key.
pub struct CellKey {
    origin: String,
    signer: Box<dyn Signer + Send>,
    verifier: Verifier,
    sealed: Vec<u8>,
}

fn ed25519(key: &PublicKey) -> Option<[u8; 32]> {
    match key {
        PublicKey::Ed25519(k) => Some(*k),
        _ => None,
    }
}

impl CellKey {
    fn of(
        origin: String,
        signer: Box<dyn Signer + Send>,
        sealed: Vec<u8>,
    ) -> Result<Self, CellError> {
        let key = ed25519(&signer.public_key()).ok_or(CellError::Stored)?;
        let verifier = Verifier::ed25519(&origin, key).map_err(|_| CellError::Name)?;
        Ok(Self {
            origin,
            signer,
            verifier,
            sealed,
        })
    }

    /// A new key for `cell`, sealed by the factory.
    ///
    /// # Errors
    /// [`CellError::Name`] or [`CellError::Generate`].
    pub fn generate(cell: &str, factory: &mut dyn KeyFactory) -> Result<Self, CellError> {
        let origin = origin(cell);
        check_name(&origin).map_err(|_| CellError::Name)?;
        let generated = factory
            .generate(JwsAlg::Ed25519)
            .map_err(|_| CellError::Generate)?;
        Self::of(origin, generated.signer, generated.sealed)
    }

    /// The key of `cell` from its stored form; the stored public key must match the unsealed one.
    ///
    /// # Errors
    /// [`CellError`].
    pub fn restore(
        cell: &str,
        stored: &[u8],
        factory: &mut dyn KeyFactory,
    ) -> Result<Self, CellError> {
        let v = dcbor::decode(stored, Limits::CEILING).map_err(|_| CellError::Stored)?;
        let (Some(Value::Text(origin)), Some(Value::Bytes(key)), Some(Value::Bytes(sealed))) =
            (v.get("origin"), v.get("key"), v.get("sealed"))
        else {
            return Err(CellError::Stored);
        };
        if *origin != self::origin(cell) {
            return Err(CellError::OtherCell);
        }
        let signer = factory
            .load(JwsAlg::Ed25519, sealed)
            .map_err(|_| CellError::Stored)?;
        if ed25519(&signer.public_key()).map(|k| k.to_vec()).as_ref() != Some(key) {
            return Err(CellError::Stored);
        }
        Self::of(origin.clone(), signer, sealed.clone())
    }

    /// The stored form: origin, public key and sealed private material, never plaintext.
    #[must_use]
    pub fn stored(&self) -> Option<Vec<u8>> {
        let key = ed25519(&self.signer.public_key())?;
        let v = Value::Map(vec![
            (Value::text("label"), Value::text(LABEL)),
            (Value::text("origin"), Value::text(&self.origin)),
            (Value::text("key"), Value::Bytes(key.to_vec())),
            (Value::text("sealed"), Value::Bytes(self.sealed.clone())),
        ]);
        dcbor::encode(&v, Limits::CEILING).ok()
    }

    /// The log origin and note key name.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The C2SP verifier key a checkpoint verifier pins.
    #[must_use]
    pub fn vkey(&self) -> String {
        self.verifier.to_vkey()
    }

    /// The note signature line over a checkpoint body of this cell's audit log or of its
    /// operational chain (L2-CKP-3, OP-44).
    ///
    /// # Errors
    /// [`SignerError::Note`] for a body that is not a canonical checkpoint of one of these
    /// origins; [`SignerError::Sign`] when the key cannot sign.
    pub fn sign(&self, body: &str) -> Result<String, SignerError> {
        let cp = Checkpoint::parse(body).map_err(|_| SignerError::Note)?;
        let known = cp.origin == self.origin
            || operational_origin(&self.origin).as_deref() == Some(cp.origin.as_str());
        if !known || cp.to_body().ok().as_deref() != Some(body) {
            return Err(SignerError::Note);
        }
        sign_note(self.signer.as_ref(), &self.origin, body)
            .map(|(_, line)| line)
            .map_err(|_| SignerError::Sign)
    }
}

#[cfg(test)]
mod tests;
