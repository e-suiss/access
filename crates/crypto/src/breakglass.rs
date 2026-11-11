//! The operator break-glass formats (OP-46, CMP-25, G63, OP-157 m.3 (j)): the short-lived M-of-N
//! document that authorises a use, the per-cell key set it is checked against offline, and the
//! signed directive file the tool leaves for `access-server`. Verification needs no network and
//! no database. Nothing here makes an authority decision.

use std::fmt::Write as _;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};
use suiss_crypto::dcbor::{self, Limits, Value};
use zeroize::Zeroizing;

use crate::secret::Secret;
use crate::webauthn::{sha256, verify_ed25519, verify_es256};

/// The longest a document may be valid (§17.7.3 principle 8, PD).
pub const MAX_WINDOW_MS: u64 = 15 * 60 * 1000;

/// The smallest quorum a key set may declare (CMP-25: M-of-N, default 2-of-3).
pub const MIN_THRESHOLD: usize = 2;

/// Domain separation of a document's signing input.
const DOCUMENT_CONTEXT: &[u8] = b"access/breakglass/document/v1\0";

/// Domain separation of a directive's signing input.
const DIRECTIVE_CONTEXT: &[u8] = b"access/breakglass/directive/v1\0";

/// The default WebAuthn relying party id of a cell's security keys.
pub const DEFAULT_RP_ID: &str = "access-breakglass";

/// Why a document, key set or directive is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BreakGlassError {
    /// Not the expected encoding.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// An operation outside the operator path (§17.7.3 scope).
    #[error("unknown operation")]
    UnknownOp,
    /// Longer than 15 minutes, or ends before it starts.
    #[error("validity window longer than 15 minutes")]
    Window,
    /// Not yet valid, or expired.
    #[error("document not valid now")]
    NotNow,
    /// For another cell (§17.7.3 principle 10).
    #[error("document for another cell")]
    Cell,
    /// An approval does not verify, names an unknown key or repeats one.
    #[error("approval does not verify")]
    Approval,
    /// Fewer distinct approvals than the key set's threshold.
    #[error("quorum not met")]
    Quorum,
    /// The key set is not usable.
    #[error("invalid key set: {0}")]
    KeySet(&'static str),
    /// The directive signature does not verify.
    #[error("directive signature does not verify")]
    Signature,
    /// No randomness, or the key could not be made.
    #[error("key unavailable")]
    Key,
}

impl BreakGlassError {
    /// Stable reason code, for the trail and the syslog line.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::UnknownOp => "unknown-op",
            Self::Window => "window",
            Self::NotNow => "not-now",
            Self::Cell => "cell",
            Self::Approval => "approval",
            Self::Quorum => "quorum",
            Self::KeySet(_) => "key-set",
            Self::Signature => "signature",
            Self::Key => "key",
        }
    }
}

/// What the operator path may do (§17.7.3 scope): read configuration, check health, set a
/// feature flag, raise the wholesale `session_epoch` floor, mark the leader unhealthy or
/// healthy again. There is no operation on authority state or user data (G63, SI-22).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Print the cell's configuration file.
    ConfigRead,
    /// Probe the server's health endpoint.
    Health,
    /// Every session issued before the directive ends (MD-7, TN-50).
    EpochFloor,
    /// The leader gives its leases up and leads nothing until marked healthy (TI-2).
    LeaderUnhealthy,
    /// Ends [`Op::LeaderUnhealthy`].
    LeaderHealthy,
    /// An operational feature flag.
    Flag {
        /// `[a-z0-9_.]{1,64}`.
        name: String,
        /// On or off.
        on: bool,
    },
}

fn flag_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

impl Op {
    /// `config.read`, `health`, `epoch.floor`, `leader.unhealthy`, `leader.healthy`,
    /// `flag:<name>:on` or `flag:<name>:off`.
    ///
    /// # Errors
    /// [`BreakGlassError::UnknownOp`].
    pub fn parse(text: &str) -> Result<Self, BreakGlassError> {
        Ok(match text {
            "config.read" => Self::ConfigRead,
            "health" => Self::Health,
            "epoch.floor" => Self::EpochFloor,
            "leader.unhealthy" => Self::LeaderUnhealthy,
            "leader.healthy" => Self::LeaderHealthy,
            _ => {
                let rest = text
                    .strip_prefix("flag:")
                    .ok_or(BreakGlassError::UnknownOp)?;
                let (name, state) = rest.rsplit_once(':').ok_or(BreakGlassError::UnknownOp)?;
                let on = match state {
                    "on" => true,
                    "off" => false,
                    _ => return Err(BreakGlassError::UnknownOp),
                };
                if !flag_name(name) {
                    return Err(BreakGlassError::UnknownOp);
                }
                Self::Flag {
                    name: name.to_owned(),
                    on,
                }
            }
        })
    }

    /// The text form [`Op::parse`] reads.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::ConfigRead => "config.read".to_owned(),
            Self::Health => "health".to_owned(),
            Self::EpochFloor => "epoch.floor".to_owned(),
            Self::LeaderUnhealthy => "leader.unhealthy".to_owned(),
            Self::LeaderHealthy => "leader.healthy".to_owned(),
            Self::Flag { name, on } => format!("flag:{name}:{}", if *on { "on" } else { "off" }),
        }
    }

    /// Whether the operation leaves a directive for the server; reads leave none.
    #[must_use]
    pub const fn directs(&self) -> bool {
        !matches!(self, Self::ConfigRead | Self::Health)
    }
}

/// One approval of a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Approval {
    /// An Ed25519 signature over the document's signing input.
    Ed25519 {
        /// Key id in the cell's key set.
        key: String,
        /// 64-byte signature.
        sig: Vec<u8>,
    },
    /// A FIDO2 assertion whose challenge is the document digest (CTAP2 `getAssertion`).
    Fido2 {
        /// Key id in the cell's key set.
        key: String,
        /// `authenticatorData`.
        authenticator_data: Vec<u8>,
        /// `clientDataJSON`.
        client_data_json: Vec<u8>,
        /// DER ECDSA signature.
        sig: Vec<u8>,
    },
}

impl Approval {
    fn key(&self) -> &str {
        match self {
            Self::Ed25519 { key, .. } | Self::Fido2 { key, .. } => key,
        }
    }

    fn value(&self) -> Value {
        match self {
            Self::Ed25519 { key, sig } => Value::Map(vec![
                (Value::text("key"), Value::text(key)),
                (Value::text("sig"), Value::Bytes(sig.clone())),
            ]),
            Self::Fido2 {
                key,
                authenticator_data,
                client_data_json,
                sig,
            } => Value::Map(vec![
                (Value::text("key"), Value::text(key)),
                (
                    Value::text("auth_data"),
                    Value::Bytes(authenticator_data.clone()),
                ),
                (
                    Value::text("client_data"),
                    Value::Bytes(client_data_json.clone()),
                ),
                (Value::text("sig"), Value::Bytes(sig.clone())),
            ]),
        }
    }

    fn from_value(v: &Value) -> Result<Self, BreakGlassError> {
        let key = text(v, "key", "approval")?;
        let sig = bytes(v, "sig", "approval")?;
        Ok(match (v.get("auth_data"), v.get("client_data")) {
            (None, None) => Self::Ed25519 { key, sig },
            (Some(Value::Bytes(a)), Some(Value::Bytes(c))) => Self::Fido2 {
                key,
                authenticator_data: a.clone(),
                client_data_json: c.clone(),
                sig,
            },
            _ => return Err(BreakGlassError::Malformed("approval")),
        })
    }
}

fn text(v: &Value, k: &str, what: &'static str) -> Result<String, BreakGlassError> {
    match v.get(k) {
        Some(Value::Text(t)) => Ok(t.clone()),
        _ => Err(BreakGlassError::Malformed(what)),
    }
}

fn bytes(v: &Value, k: &str, what: &'static str) -> Result<Vec<u8>, BreakGlassError> {
    match v.get(k) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(BreakGlassError::Malformed(what)),
    }
}

fn unsigned(v: &Value, k: &str, what: &'static str) -> Result<u64, BreakGlassError> {
    match v.get(k) {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(BreakGlassError::Malformed(what)),
    }
}

fn encode(v: &Value, what: &'static str) -> Result<Vec<u8>, BreakGlassError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| BreakGlassError::Malformed(what))
}

fn decode(b: &[u8], what: &'static str) -> Result<Value, BreakGlassError> {
    dcbor::decode(b, Limits::CEILING).map_err(|_| BreakGlassError::Malformed(what))
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        },
    )
}

/// Reads lower- or upper-case hex.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|p| {
            let s = std::str::from_utf8(p).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect()
}

fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let chars = chunk.len().saturating_add(1);
        for i in 0..chars {
            let shift = 18_u32.saturating_sub(u32::try_from(i).unwrap_or(0).saturating_mul(6));
            let idx = usize::try_from((n >> shift) & 63).unwrap_or(0);
            out.push(char::from(ALPHABET.get(idx).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// A public key of a cell's key set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    /// 32 bytes.
    Ed25519(Vec<u8>),
    /// An uncompressed P-256 point of a FIDO2 credential.
    Es256(Vec<u8>),
}

impl PublicKey {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(b) | Self::Es256(b) => b,
        }
    }
}

/// The per-cell key set (§17.7.3 principles 3 and 10), a text file the operator distributes:
///
/// ```text
/// generation 1
/// threshold 2
/// rp access-breakglass
/// ed25519 alice <64 hex>
/// es256 carol <130 hex>
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySet {
    /// Raised by every rotation.
    pub generation: u64,
    /// Distinct approvals a document needs.
    pub threshold: usize,
    /// The relying party id FIDO2 assertions are made for.
    pub rp_id: String,
    /// Key id and key.
    pub keys: Vec<(String, PublicKey)>,
}

fn key_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

impl KeySet {
    /// Parses the text form; blank lines and `#` lines are skipped.
    ///
    /// # Errors
    /// [`BreakGlassError::KeySet`].
    pub fn parse(text: &str) -> Result<Self, BreakGlassError> {
        let mut generation = None;
        let mut threshold = MIN_THRESHOLD;
        let mut rp_id = DEFAULT_RP_ID.to_owned();
        let mut keys: Vec<(String, PublicKey)> = Vec::new();
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts.as_slice() {
                ["generation", n] => {
                    generation = Some(
                        n.parse()
                            .map_err(|_| BreakGlassError::KeySet("generation"))?,
                    );
                }
                ["threshold", n] => {
                    threshold = n
                        .parse()
                        .map_err(|_| BreakGlassError::KeySet("threshold"))?;
                }
                ["rp", id] => (*id).clone_into(&mut rp_id),
                [alg, id, key] => {
                    if !key_id(id) || keys.iter().any(|(k, _)| k == id) {
                        return Err(BreakGlassError::KeySet("key id"));
                    }
                    let raw = unhex(key).ok_or(BreakGlassError::KeySet("key"))?;
                    let public = match *alg {
                        "ed25519" if raw.len() == 32 => PublicKey::Ed25519(raw),
                        "es256" if crate::webauthn::p256_point_valid(&raw) => PublicKey::Es256(raw),
                        _ => return Err(BreakGlassError::KeySet("key")),
                    };
                    if keys.iter().any(|(_, k)| k.bytes() == public.bytes()) {
                        return Err(BreakGlassError::KeySet("repeated key"));
                    }
                    keys.push(((*id).to_owned(), public));
                }
                _ => return Err(BreakGlassError::KeySet("line")),
            }
        }
        let generation = generation.ok_or(BreakGlassError::KeySet("generation"))?;
        if threshold < MIN_THRESHOLD || threshold > keys.len() {
            return Err(BreakGlassError::KeySet("threshold"));
        }
        Ok(Self {
            generation,
            threshold,
            rp_id,
            keys,
        })
    }

    /// Whether `other` holds any of this set's keys: a rotation replaces every key.
    #[must_use]
    pub fn shares_key_with(&self, other: &Self) -> bool {
        self.keys
            .iter()
            .any(|(_, a)| other.keys.iter().any(|(_, b)| a.bytes() == b.bytes()))
    }

    fn key(&self, id: &str) -> Option<&PublicKey> {
        self.keys.iter().find(|(k, _)| k == id).map(|(_, k)| k)
    }
}

/// A short-lived M-of-N document (§17.7.3 principles 3, 4 and 8): `{cell, ops, nonce,
/// not_before, not_after ≤ 15 min}` and its approvals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// The cell it is for.
    pub cell: String,
    /// What it allows.
    pub ops: Vec<Op>,
    /// Single-use nonce.
    pub nonce: [u8; 16],
    /// Start, Unix milliseconds.
    pub not_before_ms: u64,
    /// End, Unix milliseconds.
    pub not_after_ms: u64,
    /// Approvals.
    pub approvals: Vec<Approval>,
}

impl Document {
    /// An unapproved document.
    ///
    /// # Errors
    /// [`BreakGlassError::Window`] beyond 15 minutes; [`BreakGlassError::UnknownOp`] with no op.
    pub fn new(
        cell: &str,
        ops: Vec<Op>,
        nonce: [u8; 16],
        not_before_ms: u64,
        not_after_ms: u64,
    ) -> Result<Self, BreakGlassError> {
        let d = Self {
            cell: cell.to_owned(),
            ops,
            nonce,
            not_before_ms,
            not_after_ms,
            approvals: Vec::new(),
        };
        d.shape()?;
        Ok(d)
    }

    fn shape(&self) -> Result<(), BreakGlassError> {
        if self.ops.is_empty() || self.cell.is_empty() {
            return Err(BreakGlassError::UnknownOp);
        }
        match self.not_after_ms.checked_sub(self.not_before_ms) {
            Some(w) if w > 0 && w <= MAX_WINDOW_MS => Ok(()),
            _ => Err(BreakGlassError::Window),
        }
    }

    fn body(&self) -> Value {
        Value::Map(vec![
            (Value::text("v"), Value::Unsigned(1)),
            (Value::text("cell"), Value::text(&self.cell)),
            (
                Value::text("ops"),
                Value::Array(self.ops.iter().map(|o| Value::Text(o.name())).collect()),
            ),
            (Value::text("nonce"), Value::Bytes(self.nonce.to_vec())),
            (
                Value::text("not_before"),
                Value::Unsigned(self.not_before_ms),
            ),
            (Value::text("not_after"), Value::Unsigned(self.not_after_ms)),
        ])
    }

    /// What every approval signs: a context string and the canonical body.
    ///
    /// # Errors
    /// [`BreakGlassError::Malformed`].
    pub fn signing_input(&self) -> Result<Vec<u8>, BreakGlassError> {
        let mut out = DOCUMENT_CONTEXT.to_vec();
        out.extend(encode(&self.body(), "document")?);
        Ok(out)
    }

    /// The digest that names the document; also the FIDO2 challenge.
    ///
    /// # Errors
    /// [`BreakGlassError::Malformed`].
    pub fn digest(&self) -> Result<[u8; 32], BreakGlassError> {
        Ok(sha256(&self.signing_input()?))
    }

    /// The `clientDataJSON.challenge` value an assertion must carry.
    ///
    /// # Errors
    /// [`BreakGlassError::Malformed`].
    pub fn challenge(&self) -> Result<String, BreakGlassError> {
        Ok(b64url(&self.digest()?))
    }

    /// Adds an Ed25519 approval by `key`.
    ///
    /// # Errors
    /// [`BreakGlassError`].
    pub fn approve(&mut self, id: &str, key: &OperatorKey) -> Result<(), BreakGlassError> {
        let sig = key.sign(&self.signing_input()?);
        self.approvals.push(Approval::Ed25519 {
            key: id.to_owned(),
            sig,
        });
        Ok(())
    }

    /// The file form.
    ///
    /// # Errors
    /// [`BreakGlassError::Malformed`].
    pub fn encode(&self) -> Result<Vec<u8>, BreakGlassError> {
        let Value::Map(mut entries) = self.body() else {
            return Err(BreakGlassError::Malformed("document"));
        };
        entries.push((
            Value::text("approvals"),
            Value::Array(self.approvals.iter().map(Approval::value).collect()),
        ));
        encode(&Value::Map(entries), "document")
    }

    /// Reads the file form; the shape is checked, the approvals are not.
    ///
    /// # Errors
    /// [`BreakGlassError`].
    pub fn decode(b: &[u8]) -> Result<Self, BreakGlassError> {
        let v = decode(b, "document")?;
        if unsigned(&v, "v", "document")? != 1 {
            return Err(BreakGlassError::Malformed("document"));
        }
        let ops = match v.get("ops") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|o| match o {
                    Value::Text(t) => Op::parse(t),
                    _ => Err(BreakGlassError::Malformed("document")),
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(BreakGlassError::Malformed("document")),
        };
        let approvals = match v.get("approvals") {
            Some(Value::Array(a)) => a
                .iter()
                .map(Approval::from_value)
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err(BreakGlassError::Malformed("document")),
        };
        let nonce = <[u8; 16]>::try_from(bytes(&v, "nonce", "document")?)
            .map_err(|_| BreakGlassError::Malformed("document"))?;
        let d = Self {
            cell: text(&v, "cell", "document")?,
            ops,
            nonce,
            not_before_ms: unsigned(&v, "not_before", "document")?,
            not_after_ms: unsigned(&v, "not_after", "document")?,
            approvals,
        };
        d.shape()?;
        Ok(d)
    }

    /// Verifies the document offline for `cell` at `now_ms` (CMP-25): the window is at most 15
    /// minutes and holds `now_ms`, every approval verifies under a distinct key of `keys`, and
    /// at least `keys.threshold` of them are present. Returns the approving key ids.
    ///
    /// # Errors
    /// [`BreakGlassError`].
    pub fn verify(
        &self,
        keys: &KeySet,
        cell: &str,
        now_ms: u64,
    ) -> Result<Vec<String>, BreakGlassError> {
        self.shape()?;
        if self.cell != cell {
            return Err(BreakGlassError::Cell);
        }
        if now_ms < self.not_before_ms || now_ms >= self.not_after_ms {
            return Err(BreakGlassError::NotNow);
        }
        let input = self.signing_input()?;
        let challenge = self.challenge()?;
        let mut approvers: Vec<String> = Vec::new();
        for a in &self.approvals {
            if approvers.iter().any(|k| k == a.key()) {
                return Err(BreakGlassError::Approval);
            }
            let key = keys.key(a.key()).ok_or(BreakGlassError::Approval)?;
            match (a, key) {
                (Approval::Ed25519 { sig, .. }, PublicKey::Ed25519(pk)) => {
                    verify_ed25519(pk, &input, sig).map_err(|_| BreakGlassError::Approval)?;
                }
                (
                    Approval::Fido2 {
                        authenticator_data,
                        client_data_json,
                        sig,
                        ..
                    },
                    PublicKey::Es256(pk),
                ) => fido2(
                    pk,
                    &keys.rp_id,
                    &challenge,
                    authenticator_data,
                    client_data_json,
                    sig,
                )?,
                _ => return Err(BreakGlassError::Approval),
            }
            approvers.push(a.key().to_owned());
        }
        if approvers.len() < keys.threshold {
            return Err(BreakGlassError::Quorum);
        }
        Ok(approvers)
    }
}

/// A FIDO2 assertion (WebAuthn §7.2 steps 11–20, offline subset): `webauthn.get` for the
/// document's challenge, the cell's relying party, user present and verified, ES256 over
/// `authenticatorData ‖ SHA-256(clientDataJSON)`.
fn fido2(
    public: &[u8],
    rp_id: &str,
    challenge: &str,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    sig: &[u8],
) -> Result<(), BreakGlassError> {
    let rp_hash = authenticator_data
        .get(..32)
        .ok_or(BreakGlassError::Approval)?;
    let flags = authenticator_data
        .get(32)
        .copied()
        .ok_or(BreakGlassError::Approval)?;
    if authenticator_data.len() < 37 || rp_hash != sha256(rp_id.as_bytes()) || flags & 0x05 != 0x05
    {
        return Err(BreakGlassError::Approval);
    }
    let client = std::str::from_utf8(client_data_json).map_err(|_| BreakGlassError::Approval)?;
    let compact: String = client.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.contains("\"type\":\"webauthn.get\"")
        || !compact.contains(&format!("\"challenge\":\"{challenge}\""))
    {
        return Err(BreakGlassError::Approval);
    }
    let mut message = authenticator_data.to_vec();
    message.extend(sha256(client_data_json));
    verify_es256(public, &message, sig).map_err(|_| BreakGlassError::Approval)
}

/// An Ed25519 key an approver signs documents with, or the cell's directive key. It never
/// appears in `Debug`.
pub struct OperatorKey {
    pair: Ed25519KeyPair,
}

impl core::fmt::Debug for OperatorKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OperatorKey(<redacted>)")
    }
}

impl OperatorKey {
    /// A fresh key and its seed in hex, for the operator to keep in a 0400 file.
    ///
    /// # Errors
    /// [`BreakGlassError::Key`].
    pub fn generate() -> Result<(Self, Secret<String>), BreakGlassError> {
        let seed = Zeroizing::new(crate::random::bytes::<32>().map_err(|_| BreakGlassError::Key)?);
        let key = Self::from_seed(seed.as_slice())?;
        Ok((key, Secret::new(hex(seed.as_slice()))))
    }

    /// From a 32-byte seed.
    ///
    /// # Errors
    /// [`BreakGlassError::Key`].
    pub fn from_seed(seed: &[u8]) -> Result<Self, BreakGlassError> {
        if seed.len() != 32 {
            return Err(BreakGlassError::Key);
        }
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| BreakGlassError::Key)?;
        Ok(Self { pair })
    }

    /// From the hex seed of a key file.
    ///
    /// # Errors
    /// [`BreakGlassError::Key`].
    pub fn from_hex(seed: &Secret<String>) -> Result<Self, BreakGlassError> {
        let raw = Zeroizing::new(unhex(seed.expose().trim()).ok_or(BreakGlassError::Key)?);
        Self::from_seed(&raw)
    }

    /// The 32-byte public key.
    #[must_use]
    pub fn public(&self) -> Vec<u8> {
        self.pair.public_key().as_ref().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair.sign(message).as_ref().to_vec()
    }
}

/// A signed instruction to `access-server` (OP-157 m.3 (j)), written to the cell's
/// `ops/directives/*.cbor`. It names the document that authorised it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directive {
    /// The cell.
    pub cell: String,
    /// Order among the cell's directives; later wins.
    pub seq: u64,
    /// The operation; never a read.
    pub op: Op,
    /// When the tool wrote it, Unix milliseconds.
    pub at_ms: u64,
    /// The authorising document's digest.
    pub document: [u8; 32],
}

impl Directive {
    fn body(&self) -> Value {
        Value::Map(vec![
            (Value::text("v"), Value::Unsigned(1)),
            (Value::text("cell"), Value::text(&self.cell)),
            (Value::text("seq"), Value::Unsigned(self.seq)),
            (Value::text("op"), Value::Text(self.op.name())),
            (Value::text("at"), Value::Unsigned(self.at_ms)),
            (
                Value::text("document"),
                Value::Bytes(self.document.to_vec()),
            ),
        ])
    }

    /// The signed file form.
    ///
    /// # Errors
    /// [`BreakGlassError`].
    pub fn sign(&self, key: &OperatorKey) -> Result<Vec<u8>, BreakGlassError> {
        if !self.op.directs() {
            return Err(BreakGlassError::UnknownOp);
        }
        let body = encode(&self.body(), "directive")?;
        let mut input = DIRECTIVE_CONTEXT.to_vec();
        input.extend(&body);
        encode(
            &Value::Map(vec![
                (Value::text("body"), Value::Bytes(body)),
                (Value::text("sig"), Value::Bytes(key.sign(&input))),
            ]),
            "directive",
        )
    }

    /// Reads a signed file, verified under the cell's directive key `public`.
    ///
    /// # Errors
    /// [`BreakGlassError`].
    pub fn verify(file: &[u8], public: &[u8]) -> Result<Self, BreakGlassError> {
        let outer = decode(file, "directive")?;
        let body = bytes(&outer, "body", "directive")?;
        let sig = bytes(&outer, "sig", "directive")?;
        let mut input = DIRECTIVE_CONTEXT.to_vec();
        input.extend(&body);
        verify_ed25519(public, &input, &sig).map_err(|_| BreakGlassError::Signature)?;
        let v = decode(&body, "directive")?;
        if unsigned(&v, "v", "directive")? != 1 {
            return Err(BreakGlassError::Malformed("directive"));
        }
        let op = Op::parse(&text(&v, "op", "directive")?)?;
        if !op.directs() {
            return Err(BreakGlassError::UnknownOp);
        }
        Ok(Self {
            cell: text(&v, "cell", "directive")?,
            seq: unsigned(&v, "seq", "directive")?,
            op,
            at_ms: unsigned(&v, "at", "directive")?,
            document: <[u8; 32]>::try_from(bytes(&v, "document", "directive")?)
                .map_err(|_| BreakGlassError::Malformed("directive"))?,
        })
    }
}

/// What a cell's directives add up to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectiveState {
    /// The latest `epoch.floor` time, Unix milliseconds.
    pub epoch_floor_ms: Option<u64>,
    /// The last `leader.*` directive marked the leader unhealthy.
    pub leader_unhealthy: bool,
    /// The last state of each flag.
    pub flags: Vec<(String, bool)>,
    /// The highest sequence number applied.
    pub seq: u64,
}

impl DirectiveState {
    /// Folds verified directives, in any order, into the state they leave.
    #[must_use]
    pub fn fold(directives: &[Directive]) -> Self {
        let mut sorted: Vec<&Directive> = directives.iter().collect();
        sorted.sort_by_key(|d| d.seq);
        let mut out = Self::default();
        for d in sorted {
            out.seq = out.seq.max(d.seq);
            match &d.op {
                Op::EpochFloor => {
                    out.epoch_floor_ms = Some(out.epoch_floor_ms.unwrap_or(0).max(d.at_ms));
                }
                Op::LeaderUnhealthy => out.leader_unhealthy = true,
                Op::LeaderHealthy => out.leader_unhealthy = false,
                Op::Flag { name, on } => {
                    out.flags.retain(|(n, _)| n != name);
                    out.flags.push((name.clone(), *on));
                }
                Op::ConfigRead | Op::Health => {}
            }
        }
        out.flags.sort();
        out
    }

    /// The state of `name`; an unset flag is off.
    #[must_use]
    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|(n, on)| n == name && *on)
    }
}

#[cfg(test)]
mod tests;
