//! A realm's SAML signing keys (OP-155 m.3 (d), (e); §10.6.1; Golden SAML, HL-35): RSA-3072, and
//! a P-256 key for service providers whose template supports ECDSA, each with a long-lived
//! self-signed certificate. Keys are made in this process, sealed under the realm's KEK and never
//! leave it; they sign XML `SignedInfo` octets and HTTP-Redirect query strings only (artefact
//! `SamlXml`). Rotation has two phases: a new key is published next to the active one, signing
//! switches to it, and the old one is removed; the schedule (at least 14 days per phase) is the
//! realm policy's, kept by access-server. SHA-1 is never used.

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _,
    RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::secret::Secret;
use suiss_crypto::signer::SignError;

use crate::ports::KeyFactory;
use crate::protocol::{FrameError, Realm};

/// The purpose label of these keys in the vault and in the protocol.
pub const LABEL: &str = "saml";

/// Validity of a SAML certificate (metadata interop: long-lived self-signed, no PKIX).
pub const CERT_VALID_MS: u64 = 10 * 365 * 24 * 3_600_000;

/// Most keys a realm's SAML ring holds at once (one active and one published per algorithm).
pub const MAX_KEYS: usize = 4;

/// The key algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SamlAlg {
    /// RSA-3072, PKCS#1 v1.5.
    Rsa3072,
    /// ECDSA P-256.
    P256,
}

impl SamlAlg {
    /// Its name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Rsa3072 => "rsa-3072",
            Self::P256 => "p-256",
        }
    }

    /// The algorithm of a name.
    #[must_use]
    pub fn of(name: &str) -> Option<Self> {
        [Self::Rsa3072, Self::P256]
            .into_iter()
            .find(|a| a.name() == name)
    }
}

/// The signature method of one signature (RFC 9231 names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SamlSig {
    /// `rsa-sha256`.
    RsaSha256,
    /// `rsa-sha384`.
    RsaSha384,
    /// `rsa-sha512`.
    RsaSha512,
    /// `ecdsa-sha256`.
    EcdsaSha256,
}

const SIGS: [(&str, SamlSig); 4] = [
    ("rsa-sha256", SamlSig::RsaSha256),
    ("rsa-sha384", SamlSig::RsaSha384),
    ("rsa-sha512", SamlSig::RsaSha512),
    ("ecdsa-sha256", SamlSig::EcdsaSha256),
];

impl SamlSig {
    /// Its name.
    #[must_use]
    pub fn name(self) -> &'static str {
        SIGS.iter().find(|(_, s)| *s == self).map_or("", |(n, _)| n)
    }

    /// The method of a name; SHA-1 has none (TI-9).
    #[must_use]
    pub fn of(name: &str) -> Option<Self> {
        SIGS.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
    }

    /// The key algorithm that makes it.
    #[must_use]
    pub const fn key(self) -> SamlAlg {
        match self {
            Self::EcdsaSha256 => SamlAlg::P256,
            Self::RsaSha256 | Self::RsaSha384 | Self::RsaSha512 => SamlAlg::Rsa3072,
        }
    }
}

/// Where a key is in its rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Published in metadata, not signing yet.
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

    fn of(name: &str) -> Option<Self> {
        PHASES.iter().find(|(n, _)| *n == name).map(|(_, p)| *p)
    }
}

/// A rotation step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// T0: publish a new key next to the active one.
    Add,
    /// T1: sign with the newest published key; the active one starts retiring.
    Switch,
    /// T1 + 14 days: remove retiring keys.
    Remove,
    /// `idp.saml.cert_emergency`: a new key signs at once and every other key of the algorithm
    /// is removed.
    Emergency,
}

const STEPS: [(&str, Step); 4] = [
    ("add", Step::Add),
    ("switch", Step::Switch),
    ("remove", Step::Remove),
    ("emergency", Step::Emergency),
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

    fn of(name: &str) -> Option<Self> {
        STEPS.iter().find(|(n, _)| *n == name).map(|(_, s)| *s)
    }
}

/// A key as the protocol describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    /// SHA-256 of the certificate.
    pub kid: [u8; 32],
    /// Its algorithm.
    pub alg: SamlAlg,
    /// Its self-signed certificate, DER.
    pub cert: Vec<u8>,
    /// Its phase.
    pub phase: Phase,
    /// When it entered its phase, ms.
    pub since: u64,
}

/// A request about SAML keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SamlRequest {
    /// Opens the realm's key of `alg` (made on the first opt-in, MD-6); repeating changes
    /// nothing.
    Open {
        /// Realm.
        realm: Realm,
        /// Algorithm.
        alg: SamlAlg,
    },
    /// The realm's published keys.
    Keys(Realm),
    /// Signs `data` with the active key of the method's algorithm.
    Sign {
        /// Realm.
        realm: Realm,
        /// Method.
        sig: SamlSig,
        /// The canonical `SignedInfo` or the HTTP-Redirect signed octets.
        data: Vec<u8>,
    },
    /// One rotation step of the keys of `alg`.
    Rotate {
        /// Realm.
        realm: Realm,
        /// Algorithm.
        alg: SamlAlg,
        /// Step.
        step: Step,
    },
}

/// An answer about SAML keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SamlResponse {
    /// The realm's published keys.
    Keys(Vec<KeyInfo>),
    /// A signature and the certificate of the key that made it.
    Signed {
        /// The signature (PKCS#1 v1.5, or ECDSA `r ‖ s`).
        signature: Vec<u8>,
        /// The key's certificate, DER.
        cert: Vec<u8>,
        /// Its `kid`.
        kid: [u8; 32],
    },
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

fn realm(v: Option<&Value>) -> Result<Realm, FrameError> {
    bytes(v)?
        .try_into()
        .map(Realm)
        .map_err(|_| FrameError::Malformed)
}

fn uint(v: Option<&Value>) -> Result<u64, FrameError> {
    match v {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(FrameError::Malformed),
    }
}

fn key_value(k: &KeyInfo) -> Value {
    map(vec![
        ("kid", Value::Bytes(k.kid.to_vec())),
        ("alg", Value::text(k.alg.name())),
        ("cert", Value::Bytes(k.cert.clone())),
        ("phase", Value::text(k.phase.name())),
        ("since", Value::Unsigned(k.since)),
    ])
}

fn key_of(v: &Value) -> Result<KeyInfo, FrameError> {
    Ok(KeyInfo {
        kid: bytes(v.get("kid"))?
            .try_into()
            .map_err(|_| FrameError::Malformed)?,
        alg: SamlAlg::of(&text(v.get("alg"))?).ok_or(FrameError::Malformed)?,
        cert: bytes(v.get("cert"))?,
        phase: Phase::of(&text(v.get("phase"))?).ok_or(FrameError::Malformed)?,
        since: uint(v.get("since"))?,
    })
}

impl SamlRequest {
    /// Its CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Open { realm, alg } => map(vec![
                ("op", Value::text("open")),
                ("realm", Value::Bytes(realm.0.to_vec())),
                ("alg", Value::text(alg.name())),
            ]),
            Self::Keys(realm) => map(vec![
                ("op", Value::text("keys")),
                ("realm", Value::Bytes(realm.0.to_vec())),
            ]),
            Self::Sign { realm, sig, data } => map(vec![
                ("op", Value::text("sign")),
                ("realm", Value::Bytes(realm.0.to_vec())),
                ("sig", Value::text(sig.name())),
                ("data", Value::Bytes(data.clone())),
            ]),
            Self::Rotate { realm, alg, step } => map(vec![
                ("op", Value::text("rotate")),
                ("realm", Value::Bytes(realm.0.to_vec())),
                ("alg", Value::text(alg.name())),
                ("step", Value::text(step.name())),
            ]),
        }
    }

    /// The request of a CBOR value.
    ///
    /// # Errors
    /// [`FrameError::Malformed`].
    pub fn from_value(v: &Value) -> Result<Self, FrameError> {
        let alg = || SamlAlg::of(&text(v.get("alg"))?).ok_or(FrameError::Malformed);
        match text(v.get("op"))?.as_str() {
            "open" => Ok(Self::Open {
                realm: realm(v.get("realm"))?,
                alg: alg()?,
            }),
            "keys" => Ok(Self::Keys(realm(v.get("realm"))?)),
            "sign" => Ok(Self::Sign {
                realm: realm(v.get("realm"))?,
                sig: SamlSig::of(&text(v.get("sig"))?).ok_or(FrameError::Malformed)?,
                data: bytes(v.get("data"))?,
            }),
            "rotate" => Ok(Self::Rotate {
                realm: realm(v.get("realm"))?,
                alg: alg()?,
                step: Step::of(&text(v.get("step"))?).ok_or(FrameError::Malformed)?,
            }),
            _ => Err(FrameError::Malformed),
        }
    }

    /// The realm it is about.
    #[must_use]
    pub const fn realm(&self) -> Realm {
        match self {
            Self::Open { realm, .. }
            | Self::Keys(realm)
            | Self::Sign { realm, .. }
            | Self::Rotate { realm, .. } => *realm,
        }
    }
}

impl SamlResponse {
    /// Its CBOR value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Keys(keys) => map(vec![(
                "keys",
                Value::Array(keys.iter().map(key_value).collect()),
            )]),
            Self::Signed {
                signature,
                cert,
                kid,
            } => map(vec![(
                "signed",
                map(vec![
                    ("signature", Value::Bytes(signature.clone())),
                    ("cert", Value::Bytes(cert.clone())),
                    ("kid", Value::Bytes(kid.to_vec())),
                ]),
            )]),
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
        let s = v.get("signed").ok_or(FrameError::Malformed)?;
        Ok(Self::Signed {
            signature: bytes(s.get("signature"))?,
            cert: bytes(s.get("cert"))?,
            kid: bytes(s.get("kid"))?
                .try_into()
                .map_err(|_| FrameError::Malformed)?,
        })
    }
}

enum Pair {
    Rsa(RsaKeyPair),
    P256 {
        fixed: EcdsaKeyPair,
        asn1: EcdsaKeyPair,
    },
}

struct Key {
    info: KeyInfo,
    sealed: Vec<u8>,
    pair: Pair,
}

/// Why a SAML key request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SamlKeyError {
    /// No active key of the method's algorithm.
    #[error("no active SAML key")]
    NoKey,
    /// The step does not apply to the ring now.
    #[error("rotation step out of order")]
    Order,
    /// A key could not be made, sealed, loaded or used.
    #[error("key")]
    Key,
    /// The vault failed.
    #[error("vault")]
    Stored,
}

impl SamlKeyError {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoKey => "signer-saml-no-key",
            Self::Order => "signer-saml-order",
            Self::Key => "signer-saml-key",
            Self::Stored => "signer-outage",
        }
    }
}

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len <= 0xff {
        out.push(0x81);
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        out.push(0x82);
        out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

const SHA256_RSA: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const ECDSA_SHA256: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const EC_PUBLIC: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const P256_CURVE: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const CN: [u8; 3] = [0x55, 0x04, 0x03];

#[allow(
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    reason = "proleptic Gregorian conversion over a bounded millisecond count"
)]
fn generalized(ms: u64) -> Vec<u8> {
    let secs = ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let s = format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    tlv(0x18, s.as_bytes())
}

/// A self-signed certificate for `spki` named after the realm, valid from `now`.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "calendar arithmetic over a bounded millisecond count"
)]
fn certificate(pair: &Pair, spki: &[u8], realm: Realm, now: u64) -> Result<Vec<u8>, SamlKeyError> {
    let mut serial = [0_u8; 16];
    aws_lc_rs::rand::fill(&mut serial).map_err(|_| SamlKeyError::Key)?;
    if let Some(first) = serial.first_mut() {
        *first &= 0x7f;
        *first |= 0x01;
    }
    let mut cn = String::from("Access SAML ");
    for b in realm.0.iter().take(8) {
        let _ = std::fmt::Write::write_fmt(&mut cn, format_args!("{b:02x}"));
    }
    let name = seq(&[tlv(0x31, &seq(&[tlv(0x06, &CN), tlv(0x0c, cn.as_bytes())]))]);
    let alg = match pair {
        Pair::Rsa(_) => seq(&[tlv(0x06, &SHA256_RSA), vec![0x05, 0x00]]),
        Pair::P256 { .. } => seq(&[tlv(0x06, &ECDSA_SHA256)]),
    };
    let tbs = seq(&[
        tlv(0xa0, &tlv(0x02, &[0x02])),
        tlv(0x02, &serial),
        alg.clone(),
        name.clone(),
        seq(&[
            generalized(now),
            generalized(now.saturating_add(CERT_VALID_MS)),
        ]),
        name,
        spki.to_vec(),
    ]);
    let rng = SystemRandom::new();
    let signature = match pair {
        Pair::Rsa(k) => {
            let mut sig = vec![0; k.public_modulus_len()];
            k.sign(&RSA_PKCS1_SHA256, &rng, &tbs, &mut sig)
                .map_err(|_| SamlKeyError::Key)?;
            sig
        }
        Pair::P256 { asn1, .. } => asn1
            .sign(&rng, &tbs)
            .map_err(|_| SamlKeyError::Key)?
            .as_ref()
            .to_vec(),
    };
    let mut bits = vec![0];
    bits.extend_from_slice(&signature);
    Ok(seq(&[tbs, alg, tlv(0x03, &bits)]))
}

fn pair_of(alg: SamlAlg, doc: &Secret<Vec<u8>>) -> Result<Pair, SamlKeyError> {
    Ok(match alg {
        SamlAlg::Rsa3072 => {
            Pair::Rsa(RsaKeyPair::from_pkcs8(doc.expose()).map_err(|_| SamlKeyError::Key)?)
        }
        SamlAlg::P256 => Pair::P256 {
            fixed: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, doc.expose())
                .map_err(|_| SamlKeyError::Key)?,
            asn1: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.expose())
                .map_err(|_| SamlKeyError::Key)?,
        },
    })
}

fn spki_of(pair: &Pair) -> Result<Vec<u8>, SamlKeyError> {
    match pair {
        Pair::Rsa(k) => {
            let der: PublicKeyX509Der<'static> =
                k.public_key().as_der().map_err(|_| SamlKeyError::Key)?;
            Ok(der.as_ref().to_vec())
        }
        Pair::P256 { fixed, .. } => {
            let mut bits = vec![0];
            bits.extend_from_slice(fixed.public_key().as_ref());
            Ok(seq(&[
                seq(&[tlv(0x06, &EC_PUBLIC), tlv(0x06, &P256_CURVE)]),
                tlv(0x03, &bits),
            ]))
        }
    }
}

fn new_key<F: KeyFactory + ?Sized>(
    alg: SamlAlg,
    realm: Realm,
    phase: Phase,
    now: u64,
    factory: &mut F,
) -> Result<Key, SamlKeyError> {
    let doc = match alg {
        SamlAlg::Rsa3072 => {
            let k = RsaKeyPair::generate(KeySize::Rsa3072).map_err(|_| SamlKeyError::Key)?;
            let der: Pkcs8V1Der<'static> = k.as_der().map_err(|_| SamlKeyError::Key)?;
            Secret::new(der.as_ref().to_vec())
        }
        SamlAlg::P256 => {
            let d = EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &SystemRandom::new(),
            )
            .map_err(|_| SamlKeyError::Key)?;
            Secret::new(d.as_ref().to_vec())
        }
    };
    let pair = pair_of(alg, &doc)?;
    let sealed = factory
        .seal_document(&doc)
        .map_err(|_: SignError| SamlKeyError::Key)?;
    let cert = certificate(&pair, &spki_of(&pair)?, realm, now)?;
    Ok(Key {
        info: KeyInfo {
            kid: suiss_crypto::digest::sha256(&cert),
            alg,
            cert,
            phase,
            since: now,
        },
        sealed,
        pair,
    })
}

/// A realm's SAML keys.
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

    /// The published keys.
    #[must_use]
    pub fn keys(&self) -> Vec<KeyInfo> {
        self.keys.iter().map(|k| k.info.clone()).collect()
    }

    /// Opens the key of `alg`: makes an active one when the ring has none of it.
    ///
    /// # Errors
    /// [`SamlKeyError`].
    pub fn open<F: KeyFactory + ?Sized>(
        &mut self,
        alg: SamlAlg,
        now: u64,
        factory: &mut F,
    ) -> Result<bool, SamlKeyError> {
        if self.keys.iter().any(|k| k.info.alg == alg) {
            return Ok(false);
        }
        self.keys
            .push(new_key(alg, self.realm, Phase::Active, now, factory)?);
        Ok(true)
    }

    /// Signs `data` with the active key of `sig`'s algorithm.
    ///
    /// # Errors
    /// [`SamlKeyError`].
    pub fn sign(&self, sig: SamlSig, data: &[u8]) -> Result<(Vec<u8>, &KeyInfo), SamlKeyError> {
        let k = self
            .keys
            .iter()
            .find(|k| k.info.phase == Phase::Active && k.info.alg == sig.key())
            .ok_or(SamlKeyError::NoKey)?;
        let rng = SystemRandom::new();
        let signature = match (&k.pair, sig) {
            (Pair::Rsa(p), SamlSig::RsaSha256 | SamlSig::RsaSha384 | SamlSig::RsaSha512) => {
                let padding = match sig {
                    SamlSig::RsaSha384 => &RSA_PKCS1_SHA384,
                    SamlSig::RsaSha512 => &RSA_PKCS1_SHA512,
                    _ => &RSA_PKCS1_SHA256,
                };
                let mut out = vec![0; p.public_modulus_len()];
                p.sign(padding, &rng, data, &mut out)
                    .map_err(|_| SamlKeyError::Key)?;
                out
            }
            (Pair::P256 { fixed, .. }, SamlSig::EcdsaSha256) => fixed
                .sign(&rng, data)
                .map_err(|_| SamlKeyError::Key)?
                .as_ref()
                .to_vec(),
            _ => return Err(SamlKeyError::NoKey),
        };
        Ok((signature, &k.info))
    }

    /// One rotation step for the keys of `alg`.
    ///
    /// # Errors
    /// [`SamlKeyError::Order`] when the step does not apply now.
    pub fn rotate<F: KeyFactory + ?Sized>(
        &mut self,
        alg: SamlAlg,
        step: Step,
        now: u64,
        factory: &mut F,
    ) -> Result<(), SamlKeyError> {
        let has = |ks: &[Key], p: Phase| ks.iter().any(|k| k.info.alg == alg && k.info.phase == p);
        match step {
            Step::Add => {
                if has(&self.keys, Phase::Published)
                    || !has(&self.keys, Phase::Active)
                    || self.keys.len() >= MAX_KEYS
                {
                    return Err(SamlKeyError::Order);
                }
                self.keys
                    .push(new_key(alg, self.realm, Phase::Published, now, factory)?);
            }
            Step::Switch => {
                if !has(&self.keys, Phase::Published) || has(&self.keys, Phase::Retiring) {
                    return Err(SamlKeyError::Order);
                }
                for k in self.keys.iter_mut().filter(|k| k.info.alg == alg) {
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
                    return Err(SamlKeyError::Order);
                }
                self.keys
                    .retain(|k| !(k.info.alg == alg && k.info.phase == Phase::Retiring));
            }
            Step::Emergency => {
                let fresh = new_key(alg, self.realm, Phase::Active, now, factory)?;
                self.keys.retain(|k| k.info.alg != alg);
                self.keys.push(fresh);
            }
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
                    ("kid", Value::Bytes(k.info.kid.to_vec())),
                    ("alg", Value::text(k.info.alg.name())),
                    ("cert", Value::Bytes(k.info.cert.clone())),
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

    /// The ring of a stored form.
    ///
    /// # Errors
    /// [`SamlKeyError`].
    pub fn restore<F: KeyFactory + ?Sized>(
        owner: Realm,
        stored: &[u8],
        factory: &mut F,
    ) -> Result<Self, SamlKeyError> {
        let v = dcbor::decode(stored, Limits::CEILING).map_err(|_| SamlKeyError::Stored)?;
        if text(v.get("label")).ok().as_deref() != Some(LABEL)
            || realm(v.get("realm")).ok() != Some(owner)
        {
            return Err(SamlKeyError::Stored);
        }
        let Some(Value::Array(list)) = v.get("keys") else {
            return Err(SamlKeyError::Stored);
        };
        let mut keys = Vec::new();
        for k in list {
            let info = key_of(k).map_err(|_| SamlKeyError::Stored)?;
            let sealed = bytes(k.get("sealed")).map_err(|_| SamlKeyError::Stored)?;
            let doc = factory
                .open_document(&sealed)
                .map_err(|_: SignError| SamlKeyError::Key)?;
            let pair = pair_of(info.alg, &doc)?;
            keys.push(Key { info, sealed, pair });
        }
        Ok(Self { realm: owner, keys })
    }
}

#[cfg(test)]
mod tests;
