//! A realm's SSH user CA keys (OP-156 m.3 (o), IDP-32): Ed25519, made in this process under
//! the `ssh-ca` purpose, sealed by the key factory and never leaving it; they sign the bytes of
//! an OpenSSH certificate or KRL only (artefact `SshCertificate`). Rotation has two phases: a
//! new key is published next to the signing one (servers add it to `TrustedUserCAKeys`), then
//! signs while the old one retires, and the retired key is removed. An emergency replaces every
//! key at once; closing removes them all. The schedule is access-server's.

use access_crypto::jose::JwsAlg;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::signer::{SignError, Signer};

use crate::ports::KeyFactory;
use crate::protocol::{FrameError, Realm};

/// The purpose label of these keys in the vault and in the protocol.
pub const LABEL: &str = "ssh-ca";

/// Most keys a realm's SSH ring holds at once (one signing, one published, one retiring).
pub const MAX_KEYS: usize = 3;

/// Largest certificate or KRL body the key signs.
pub const MAX_DATA: usize = 64 * 1024;

/// Where a key is in its rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    /// Published in `ca.pub`, not signing yet.
    Published,
    /// Signing.
    Active,
    /// Replaced; still published until removed.
    Retiring,
}

const PHASES: [(&str, Phase); 3] = [
    ("published", Phase::Published),
    ("active", Phase::Active),
    ("retiring", Phase::Retiring),
];

impl Phase {
    /// Its name.
    #[must_use]
    pub fn name(self) -> &'static str {
        PHASES
            .iter()
            .find(|(_, p)| *p == self)
            .map_or("", |(n, _)| n)
    }

    /// The phase of a name.
    #[must_use]
    pub fn of(name: &str) -> Option<Self> {
        PHASES.iter().find(|(n, _)| *n == name).map(|(_, p)| *p)
    }
}

/// A rotation step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Publish a new key next to the signing one (`idp.ssh.ca_rotate`).
    Add,
    /// The published key signs; the signing one retires.
    Switch,
    /// Remove retiring keys.
    Remove,
    /// `idp.ssh.ca_emergency`: a new key signs at once and every other key is removed.
    Emergency,
    /// `idp.ssh.ca_disable`: every key is removed; nothing signs.
    Close,
}

const STEPS: [(&str, Step); 5] = [
    ("add", Step::Add),
    ("switch", Step::Switch),
    ("remove", Step::Remove),
    ("emergency", Step::Emergency),
    ("close", Step::Close),
];

impl Step {
    /// Its name.
    #[must_use]
    pub fn name(self) -> &'static str {
        STEPS
            .iter()
            .find(|(_, s)| *s == self)
            .map_or("", |(n, _)| n)
    }

    /// The step of a name.
    #[must_use]
    pub fn of(name: &str) -> Option<Self> {
        STEPS.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
    }
}

/// A key as the protocol describes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    /// The Ed25519 public key.
    pub key: [u8; 32],
    /// Its phase.
    pub phase: Phase,
    /// When it entered its phase, ms.
    pub since: u64,
}

/// A request about SSH CA keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshRequest {
    /// Opens the realm's CA (`idp.ssh.ca_enable`): makes a signing key when there is none;
    /// repeating changes nothing.
    Open(Realm),
    /// The realm's keys.
    Keys(Realm),
    /// Signs `data` with `key`, only while `key` is the signing key.
    Sign {
        /// Realm.
        realm: Realm,
        /// The key the caller built `data` for (a certificate names its CA key).
        key: [u8; 32],
        /// The certificate's signed bytes.
        data: Vec<u8>,
    },
    /// One rotation step.
    Rotate {
        /// Realm.
        realm: Realm,
        /// Step.
        step: Step,
    },
}

/// An answer about SSH CA keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshResponse {
    /// The realm's keys.
    Keys(Vec<KeyInfo>),
    /// The Ed25519 signature.
    Signed([u8; 64]),
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

fn text(v: Option<&Value>) -> Result<String, FrameError> {
    match v {
        Some(Value::Text(t)) => Ok(t.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn bytes(v: Option<&Value>) -> Result<Vec<u8>, FrameError> {
    match v {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(FrameError::Malformed),
    }
}

fn fixed<const N: usize>(v: Option<&Value>) -> Result<[u8; N], FrameError> {
    bytes(v)?.try_into().map_err(|_| FrameError::Malformed)
}

fn realm(v: Option<&Value>) -> Result<Realm, FrameError> {
    fixed(v).map(Realm)
}

fn uint(v: Option<&Value>) -> Result<u64, FrameError> {
    match v {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(FrameError::Malformed),
    }
}

fn key_value(k: &KeyInfo) -> Value {
    map(vec![
        ("key", Value::Bytes(k.key.to_vec())),
        ("phase", Value::text(k.phase.name())),
        ("since", Value::Unsigned(k.since)),
    ])
}

fn key_of(v: &Value) -> Result<KeyInfo, FrameError> {
    Ok(KeyInfo {
        key: fixed(v.get("key"))?,
        phase: Phase::of(&text(v.get("phase"))?).ok_or(FrameError::Malformed)?,
        since: uint(v.get("since"))?,
    })
}

impl SshRequest {
    /// Its CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Open(realm) => map(vec![
                ("op", Value::text("open")),
                ("realm", Value::Bytes(realm.0.to_vec())),
            ]),
            Self::Keys(realm) => map(vec![
                ("op", Value::text("keys")),
                ("realm", Value::Bytes(realm.0.to_vec())),
            ]),
            Self::Sign { realm, key, data } => map(vec![
                ("op", Value::text("sign")),
                ("realm", Value::Bytes(realm.0.to_vec())),
                ("key", Value::Bytes(key.to_vec())),
                ("data", Value::Bytes(data.clone())),
            ]),
            Self::Rotate { realm, step } => map(vec![
                ("op", Value::text("rotate")),
                ("realm", Value::Bytes(realm.0.to_vec())),
                ("step", Value::text(step.name())),
            ]),
        }
    }

    /// The request of a CBOR value.
    ///
    /// # Errors
    /// [`FrameError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, FrameError> {
        match text(v.get("op"))?.as_str() {
            "open" => Ok(Self::Open(realm(v.get("realm"))?)),
            "keys" => Ok(Self::Keys(realm(v.get("realm"))?)),
            "sign" => Ok(Self::Sign {
                realm: realm(v.get("realm"))?,
                key: fixed(v.get("key"))?,
                data: bytes(v.get("data"))?,
            }),
            "rotate" => Ok(Self::Rotate {
                realm: realm(v.get("realm"))?,
                step: Step::of(&text(v.get("step"))?).ok_or(FrameError::Malformed)?,
            }),
            _ => Err(FrameError::Malformed),
        }
    }

    /// The realm it is about.
    #[must_use]
    pub const fn realm(&self) -> Realm {
        match self {
            Self::Open(realm)
            | Self::Keys(realm)
            | Self::Sign { realm, .. }
            | Self::Rotate { realm, .. } => *realm,
        }
    }
}

impl SshResponse {
    /// Its CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Keys(keys) => map(vec![(
                "keys",
                Value::Array(keys.iter().map(key_value).collect()),
            )]),
            Self::Signed(s) => map(vec![("signed", Value::Bytes(s.to_vec()))]),
        }
    }

    /// The answer of a CBOR value.
    ///
    /// # Errors
    /// [`FrameError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, FrameError> {
        if let Some(Value::Array(keys)) = v.get("keys") {
            return Ok(Self::Keys(
                keys.iter().map(key_of).collect::<Result<_, _>>()?,
            ));
        }
        Ok(Self::Signed(fixed(v.get("signed"))?))
    }
}

/// Why an SSH key request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SshKeyError {
    /// No signing key: the CA is off.
    #[error("no signing SSH key")]
    NoKey,
    /// Another key signs now.
    #[error("not the signing key")]
    Changed,
    /// The step does not apply to the ring now.
    #[error("rotation step out of order")]
    Order,
    /// The data is not an OpenSSH certificate body.
    #[error("data")]
    Data,
    /// A key could not be made, sealed, loaded or used.
    #[error("key")]
    Key,
    /// The vault failed.
    #[error("vault")]
    Stored,
}

impl SshKeyError {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoKey => "signer-ssh-no-key",
            Self::Changed => "signer-ssh-key-changed",
            Self::Order => "signer-ssh-order",
            Self::Data => "signer-ssh-data",
            Self::Key => "signer-ssh-key",
            Self::Stored => "signer-outage",
        }
    }
}

struct Key {
    info: KeyInfo,
    sealed: Vec<u8>,
    signer: Box<dyn Signer + Send>,
}

fn ed25519(signer: &dyn Signer) -> Result<[u8; 32], SshKeyError> {
    match signer.public_key() {
        PublicKey::Ed25519(k) => Ok(k),
        _ => Err(SshKeyError::Key),
    }
}

fn new_key<F: KeyFactory + ?Sized>(
    phase: Phase,
    now: u64,
    factory: &mut F,
) -> Result<Key, SshKeyError> {
    let g = factory
        .generate(JwsAlg::Ed25519)
        .map_err(|_: SignError| SshKeyError::Key)?;
    let key = ed25519(g.signer.as_ref())?;
    Ok(Key {
        info: KeyInfo {
            key,
            phase,
            since: now,
        },
        sealed: g.sealed,
        signer: g.signer,
    })
}

/// The certificate key type every body this key signs starts with: `string` of
/// `ssh-ed25519-cert-v01@openssh.com` (artefact `SshCertificate` only).
const CERT_PREFIX: &[u8] = b"\0\0\0\x20ssh-ed25519-cert-v01@openssh.com";

/// A realm's SSH CA keys.
pub struct Ring {
    realm: Realm,
    keys: Vec<Key>,
}

impl Ring {
    /// An empty ring.
    #[must_use]
    pub const fn new(realm: Realm) -> Self {
        Self {
            realm,
            keys: Vec::new(),
        }
    }

    /// The keys, in the order they were made.
    #[must_use]
    pub fn keys(&self) -> Vec<KeyInfo> {
        self.keys.iter().map(|k| k.info).collect()
    }

    /// Opens the CA: makes a signing key when the ring has none.
    ///
    /// # Errors
    /// [`SshKeyError`].
    pub fn open<F: KeyFactory + ?Sized>(
        &mut self,
        now: u64,
        factory: &mut F,
    ) -> Result<bool, SshKeyError> {
        if self.keys.iter().any(|k| k.info.phase == Phase::Active) {
            return Ok(false);
        }
        self.keys.push(new_key(Phase::Active, now, factory)?);
        Ok(true)
    }

    /// Signs `data`, an OpenSSH certificate body, with `key` while it is the signing key.
    ///
    /// # Errors
    /// [`SshKeyError`].
    pub fn sign(&self, key: &[u8; 32], data: &[u8]) -> Result<[u8; 64], SshKeyError> {
        if !data.starts_with(CERT_PREFIX) || data.len() > MAX_DATA {
            return Err(SshKeyError::Data);
        }
        let k = self
            .keys
            .iter()
            .find(|k| k.info.phase == Phase::Active)
            .ok_or(SshKeyError::NoKey)?;
        if k.info.key != *key {
            return Err(SshKeyError::Changed);
        }
        let sig = k.signer.sign(data).map_err(|_| SshKeyError::Key)?;
        <[u8; 64]>::try_from(sig.as_slice()).map_err(|_| SshKeyError::Key)
    }

    /// One rotation step.
    ///
    /// # Errors
    /// [`SshKeyError::Order`] when the step does not apply now.
    pub fn rotate<F: KeyFactory + ?Sized>(
        &mut self,
        step: Step,
        now: u64,
        factory: &mut F,
    ) -> Result<(), SshKeyError> {
        let has = |ks: &[Key], p: Phase| ks.iter().any(|k| k.info.phase == p);
        match step {
            Step::Add => {
                if has(&self.keys, Phase::Published)
                    || !has(&self.keys, Phase::Active)
                    || self.keys.len() >= MAX_KEYS
                {
                    return Err(SshKeyError::Order);
                }
                self.keys.push(new_key(Phase::Published, now, factory)?);
            }
            Step::Switch => {
                if !has(&self.keys, Phase::Published) || has(&self.keys, Phase::Retiring) {
                    return Err(SshKeyError::Order);
                }
                for k in &mut self.keys {
                    let next = match k.info.phase {
                        Phase::Published => Phase::Active,
                        Phase::Active | Phase::Retiring => Phase::Retiring,
                    };
                    if next != k.info.phase {
                        k.info.phase = next;
                        k.info.since = now;
                    }
                }
            }
            Step::Remove => {
                if !has(&self.keys, Phase::Retiring) {
                    return Err(SshKeyError::Order);
                }
                self.keys.retain(|k| k.info.phase != Phase::Retiring);
            }
            Step::Emergency => {
                let fresh = new_key(Phase::Active, now, factory)?;
                self.keys = vec![fresh];
            }
            Step::Close => self.keys.clear(),
        }
        Ok(())
    }

    /// The stored form: each key's public facts and its sealed private key.
    #[must_use]
    pub fn stored(&self) -> Option<Vec<u8>> {
        let keys = self
            .keys
            .iter()
            .map(|k| {
                map(vec![
                    ("key", Value::Bytes(k.info.key.to_vec())),
                    ("phase", Value::text(k.info.phase.name())),
                    ("since", Value::Unsigned(k.info.since)),
                    ("sealed", Value::Bytes(k.sealed.clone())),
                ])
            })
            .collect();
        dcbor::encode(
            &map(vec![
                ("label", Value::text(LABEL)),
                ("realm", Value::Bytes(self.realm.0.to_vec())),
                ("keys", Value::Array(keys)),
            ]),
            Limits::CEILING,
        )
        .ok()
    }

    /// The ring of a stored form; each unsealed key must be the public key stored with it.
    ///
    /// # Errors
    /// [`SshKeyError`].
    pub fn restore<F: KeyFactory + ?Sized>(
        owner: Realm,
        stored: &[u8],
        factory: &mut F,
    ) -> Result<Self, SshKeyError> {
        let v = dcbor::decode(stored, Limits::CEILING).map_err(|_| SshKeyError::Stored)?;
        if text(v.get("label")).ok().as_deref() != Some(LABEL)
            || realm(v.get("realm")).ok() != Some(owner)
        {
            return Err(SshKeyError::Stored);
        }
        let Some(Value::Array(list)) = v.get("keys") else {
            return Err(SshKeyError::Stored);
        };
        let mut keys = Vec::new();
        for k in list {
            let info = key_of(k).map_err(|_| SshKeyError::Stored)?;
            let sealed = bytes(k.get("sealed")).map_err(|_| SshKeyError::Stored)?;
            let signer = factory
                .load(JwsAlg::Ed25519, &sealed)
                .map_err(|_: SignError| SshKeyError::Key)?;
            if ed25519(signer.as_ref())? != info.key {
                return Err(SshKeyError::Stored);
            }
            keys.push(Key {
                info,
                sealed,
                signer,
            });
        }
        Ok(Self { realm: owner, keys })
    }
}

#[cfg(test)]
mod tests;
