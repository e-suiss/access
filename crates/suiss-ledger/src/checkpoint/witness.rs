//! The witness's side of the checkpoint protocol (§16.6 witness protocol, CMP-6, T17,
//! OP-158 m.3 (d)): a witness keeps, per log, the last checkpoint it cosigned and cosigns a
//! newer one only when a consistency proof from that base verifies; after a handover or
//! recovery the old binding is fenced at the size the record fixed (U11). Two checkpoints of
//! one log with the same size and different roots are equivocation (U9, HL-7).

use suiss_crypto::digest::{ProofError, verify_consistency};
use suiss_crypto::note::Checkpoint;

use crate::Hash;

/// Why a witness does not cosign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The request names another base size than the witness holds; the log retries with it
    /// (C2SP tlog-witness `409`).
    #[error("base is at size {0}")]
    Conflict(u64),
    /// The consistency proof from the base does not verify.
    #[error("inconsistent: {0}")]
    Inconsistent(ProofError),
    /// The checkpoint is older than the base.
    #[error("older than the base")]
    Backwards,
    /// The same size as the base with another root: the log equivocated.
    #[error("same size, another root")]
    Equivocation,
    /// The signing binding is fenced below this size (U11).
    #[error("fenced at size {0}")]
    Fenced(u64),
}

/// A witness's view of one log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogState {
    base: Option<(u64, Hash)>,
    fence: Option<u64>,
}

impl LogState {
    /// Resumes from the stored base and fence.
    #[must_use]
    pub const fn resume(base: Option<(u64, Hash)>, fence: Option<u64>) -> Self {
        Self { base, fence }
    }

    /// The last cosigned size and root.
    #[must_use]
    pub const fn base(&self) -> Option<(u64, Hash)> {
        self.base
    }

    /// The size above which the current binding may not be cosigned.
    #[must_use]
    pub const fn fence(&self) -> Option<u64> {
        self.fence
    }

    /// The size the request must name as `old`.
    #[must_use]
    pub const fn size(&self) -> u64 {
        match self.base {
            Some((s, _)) => s,
            None => 0,
        }
    }

    /// Whether `cp`, with `proof` from base size `old`, may be cosigned.
    ///
    /// # Errors
    /// [`Refusal`].
    pub fn check(&self, old: u64, proof: &[Hash], cp: &Checkpoint) -> Result<(), Refusal> {
        if let Some(max) = self.fence
            && cp.size > max
        {
            return Err(Refusal::Fenced(max));
        }
        let size = self.size();
        if old != size {
            return Err(Refusal::Conflict(size));
        }
        let Some((base, root)) = self.base else {
            return Ok(());
        };
        if cp.size < base {
            return Err(Refusal::Backwards);
        }
        if cp.size == base && cp.root != root {
            return Err(Refusal::Equivocation);
        }
        verify_consistency(base, cp.size, &root, &cp.root, proof).map_err(Refusal::Inconsistent)
    }

    /// The witness cosigned `cp`: it becomes the base.
    ///
    /// # Errors
    /// [`Refusal`] as [`LogState::check`] with an empty proof would for a smaller size.
    pub fn cosigned(&mut self, cp: &Checkpoint) -> Result<(), Refusal> {
        if self.base.is_some_and(|(s, _)| cp.size < s) {
            return Err(Refusal::Backwards);
        }
        self.base = Some((cp.size, cp.root));
        Ok(())
    }

    /// The current binding may sign nothing larger than `max` (U11): the record that moved
    /// the binding fixed `max` (`h + 1` after a handover, `N` after a recovery).
    pub fn fence_at(&mut self, max: u64) {
        self.fence = Some(self.fence.map_or(max, |f| f.min(max)));
    }

    /// A new binding was learned; it starts unfenced from the current base.
    pub const fn rebind(&mut self) {
        self.fence = None;
    }
}

/// Whether two checkpoints of one log contradict each other: same origin and size, other
/// root (U9, HL-7, §9.16).
#[must_use]
pub fn equivocates(a: &Checkpoint, b: &Checkpoint) -> bool {
    a.origin == b.origin && a.size == b.size && a.root != b.root
}

/// Most consistency or inclusion hashes a message carries (RFC 9162 bound for 2^63 leaves).
pub const MAX_PROOF: usize = 63;

/// Longest note a message carries (`witness.cddl`).
pub const MAX_NOTE: usize = 65_536;

/// Longest excerpt a request carries.
pub const MAX_EXCERPT: usize = 4_096;

/// Longest record a binding change carries.
pub const MAX_RECORD: usize = 1_048_576;

/// Why a witness message is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed witness message")]
pub struct WireError;

use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

fn text(v: Option<&Value>, max: usize) -> Result<String, WireError> {
    match v {
        Some(Value::Text(t)) if !t.is_empty() && t.len() <= max => Ok(t.clone()),
        _ => Err(WireError),
    }
}

fn bytes(v: Option<&Value>, max: usize) -> Result<Vec<u8>, WireError> {
    match v {
        Some(Value::Bytes(b)) if !b.is_empty() && b.len() <= max => Ok(b.clone()),
        _ => Err(WireError),
    }
}

fn fixed<const N: usize>(v: Option<&Value>) -> Result<[u8; N], WireError> {
    match v {
        Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| WireError),
        _ => Err(WireError),
    }
}

fn uint(v: Option<&Value>) -> Result<u64, WireError> {
    match v {
        Some(Value::Unsigned(n)) => Ok(*n),
        _ => Err(WireError),
    }
}

fn hashes(v: Option<&Value>) -> Result<Vec<Hash>, WireError> {
    let Some(Value::Array(items)) = v else {
        return Err(WireError);
    };
    if items.len() > MAX_PROOF {
        return Err(WireError);
    }
    items.iter().map(|h| fixed::<32>(Some(h))).collect()
}

fn hash_array(h: &[Hash]) -> Value {
    Value::Array(h.iter().map(|x| Value::Bytes(x.to_vec())).collect())
}

fn keys(v: &Value, allowed: &[&str]) -> Result<(), WireError> {
    let Value::Map(entries) = v else {
        return Err(WireError);
    };
    let known = entries
        .iter()
        .all(|(k, _)| matches!(k, Value::Text(t) if allowed.contains(&t.as_str())));
    if known { Ok(()) } else { Err(WireError) }
}

fn map(entries: Vec<(&str, Option<Value>)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (Value::text(k), v)))
            .collect(),
    )
}

fn encode(v: &Value) -> Result<Vec<u8>, WireError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| WireError)
}

fn decode(b: &[u8]) -> Result<Value, WireError> {
    dcbor::decode(b, Limits::CEILING).map_err(|_| WireError)
}

/// A `tlog-cosignature/v1` (`witness.cddl` `cosignature`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosignature {
    /// The witness key name.
    pub name: String,
    /// Cosigning time, seconds.
    pub timestamp: u64,
    /// Ed25519 signature.
    pub signature: [u8; 64],
}

impl Cosignature {
    fn value(&self) -> Value {
        map(alloc::vec![
            ("name", Some(Value::text(&self.name))),
            ("timestamp", Some(Value::Unsigned(self.timestamp))),
            ("signature", Some(Value::Bytes(self.signature.to_vec()))),
        ])
    }

    fn read(v: &Value) -> Result<Self, WireError> {
        keys(v, &["name", "timestamp", "signature"])?;
        Ok(Self {
            name: text(v.get("name"), 255)?,
            timestamp: uint(v.get("timestamp"))?,
            signature: fixed::<64>(v.get("signature"))?,
        })
    }

    /// The note signature line of this cosignature by key `id`.
    #[must_use]
    pub fn line(&self, id: u32) -> String {
        let mut raw = id.to_be_bytes().to_vec();
        raw.extend_from_slice(&self.timestamp.to_be_bytes());
        raw.extend_from_slice(&self.signature);
        alloc::format!(
            "\u{2014} {} {}\n",
            self.name,
            suiss_crypto::note::base64_encode(&raw)
        )
    }

    /// The cosignature in a note signature line, and its key ID.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_line(line: &str) -> Result<(Self, u32), WireError> {
        let rest = line
            .trim_end_matches('\n')
            .strip_prefix("\u{2014} ")
            .ok_or(WireError)?;
        let (name, b64) = rest.split_once(' ').ok_or(WireError)?;
        let raw = suiss_crypto::note::base64_decode(b64).map_err(|_| WireError)?;
        let (id, rest) = raw.split_first_chunk::<4>().ok_or(WireError)?;
        let (ts, sig) = rest.split_first_chunk::<8>().ok_or(WireError)?;
        Ok((
            Self {
                name: String::from(name),
                timestamp: u64::from_be_bytes(*ts),
                signature: sig.try_into().map_err(|_| WireError)?,
            },
            u32::from_be_bytes(*id),
        ))
    }
}

/// The record that moves the binding and its inclusion in the request's note
/// (`binding-change`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingChange {
    /// Its position.
    pub position: u64,
    /// The record envelope as committed.
    pub record: Vec<u8>,
    /// Its inclusion path.
    pub inclusion: Vec<Hash>,
}

/// A request to cosign a checkpoint (`cosign-request`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CosignRequest {
    /// The domain.
    pub domain: Hash,
    /// The log-signed checkpoint note.
    pub note: String,
    /// The binding-signed excerpt of the key that signed it.
    pub excerpt: Vec<u8>,
    /// The base the request extends: the witness's last cosigned size and root.
    pub base: Option<(u64, Hash)>,
    /// The consistency proof from the base.
    pub consistency: Vec<Hash>,
    /// A handover or recovery record the note covers.
    pub binding_change: Option<BindingChange>,
}

impl CosignRequest {
    /// Its deterministic CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode(&map(alloc::vec![
            ("domain", Some(Value::Bytes(self.domain.to_vec()))),
            ("note", Some(Value::text(&self.note))),
            ("excerpt", Some(Value::Bytes(self.excerpt.clone()))),
            (
                "base",
                self.base.map(|(size, root)| {
                    map(alloc::vec![
                        ("size", Some(Value::Unsigned(size))),
                        ("root", Some(Value::Bytes(root.to_vec()))),
                    ])
                }),
            ),
            ("consistency", Some(hash_array(&self.consistency))),
            (
                "binding_change",
                self.binding_change.as_ref().map(|c| {
                    map(alloc::vec![
                        ("position", Some(Value::Unsigned(c.position))),
                        ("record", Some(Value::Bytes(c.record.clone()))),
                        ("inclusion", Some(hash_array(&c.inclusion))),
                    ])
                }),
            ),
        ]))
    }

    /// Decodes a request.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, WireError> {
        let v = decode(b)?;
        keys(
            &v,
            &[
                "domain",
                "note",
                "excerpt",
                "base",
                "consistency",
                "binding_change",
            ],
        )?;
        let base = match v.get("base") {
            None => None,
            Some(b) => {
                keys(b, &["size", "root"])?;
                Some((uint(b.get("size"))?, fixed::<32>(b.get("root"))?))
            }
        };
        let binding_change = match v.get("binding_change") {
            None => None,
            Some(c) => {
                keys(c, &["position", "record", "inclusion"])?;
                Some(BindingChange {
                    position: uint(c.get("position"))?,
                    record: bytes(c.get("record"), MAX_RECORD)?,
                    inclusion: hashes(c.get("inclusion"))?,
                })
            }
        };
        Ok(Self {
            domain: fixed::<32>(v.get("domain"))?,
            note: text(v.get("note"), MAX_NOTE)?,
            excerpt: bytes(v.get("excerpt"), MAX_EXCERPT)?,
            base,
            consistency: hashes(v.get("consistency"))?,
            binding_change,
        })
    }
}

/// Why a witness refused (`cosign-refusal`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refused {
    /// The base or the proof does not match the witness's state.
    Inconsistent,
    /// The key is not the current binding's operational key.
    UnknownKey,
    /// The binding is fenced.
    Fenced,
    /// The checkpoint is older than the base.
    OlderThanBase,
    /// The request is malformed.
    Malformed,
}

const REFUSALS: [(&str, Refused); 5] = [
    ("inconsistent", Refused::Inconsistent),
    ("unknown-key", Refused::UnknownKey),
    ("fenced", Refused::Fenced),
    ("older-than-base", Refused::OlderThanBase),
    ("malformed", Refused::Malformed),
];

impl Refused {
    /// Its wire name.
    #[must_use]
    pub fn name(self) -> &'static str {
        REFUSALS
            .iter()
            .find(|(_, r)| *r == self)
            .map_or("malformed", |(n, _)| n)
    }

    /// The refusal [`LogState::check`] reports for `r`.
    #[must_use]
    pub const fn of(r: Refusal) -> Self {
        match r {
            Refusal::Fenced(_) => Self::Fenced,
            Refusal::Backwards => Self::OlderThanBase,
            Refusal::Conflict(_) | Refusal::Inconsistent(_) | Refusal::Equivocation => {
                Self::Inconsistent
            }
        }
    }
}

/// A witness's answer (`cosign-response`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CosignResponse {
    /// It cosigned.
    Cosigned(Cosignature),
    /// It refused.
    Refused(Refused),
}

impl CosignResponse {
    /// Its deterministic CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode(&match self {
            Self::Cosigned(c) => c.value(),
            Self::Refused(r) => map(alloc::vec![("refused", Some(Value::text(r.name())))]),
        })
    }

    /// Decodes an answer.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, WireError> {
        let v = decode(b)?;
        if let Some(r) = v.get("refused") {
            keys(&v, &["refused"])?;
            let name = text(Some(r), 64)?;
            return REFUSALS
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, r)| Self::Refused(*r))
                .ok_or(WireError);
        }
        Cosignature::read(&v).map(Self::Cosigned)
    }
}

/// A witness's latest cosigned head of a domain, as monitors pull it (`gossip-entry`), with the
/// cosigned note so the cosignature can be checked (`w2_note`, OP-158 m.4 (b)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GossipEntry {
    /// The witness key name.
    pub witness: String,
    /// The domain.
    pub domain: Hash,
    /// Tree size.
    pub size: u64,
    /// Root.
    pub root: Hash,
    /// Its cosignature.
    pub cosignature: Cosignature,
    /// The log-signed note it cosigned.
    pub note: Option<String>,
}

impl GossipEntry {
    fn value(&self) -> Value {
        map(alloc::vec![
            ("witness", Some(Value::text(&self.witness))),
            ("domain", Some(Value::Bytes(self.domain.to_vec()))),
            ("size", Some(Value::Unsigned(self.size))),
            ("root", Some(Value::Bytes(self.root.to_vec()))),
            ("cosignature", Some(self.cosignature.value())),
            ("w2_note", self.note.as_deref().map(Value::text)),
        ])
    }

    fn read(v: &Value) -> Result<Self, WireError> {
        keys(
            v,
            &[
                "witness",
                "domain",
                "size",
                "root",
                "cosignature",
                "w2_note",
            ],
        )?;
        Ok(Self {
            witness: text(v.get("witness"), 255)?,
            domain: fixed::<32>(v.get("domain"))?,
            size: uint(v.get("size"))?,
            root: fixed::<32>(v.get("root"))?,
            cosignature: Cosignature::read(v.get("cosignature").ok_or(WireError)?)?,
            note: v
                .get("w2_note")
                .map(|n| text(Some(n), MAX_NOTE))
                .transpose()?,
        })
    }

    /// Its deterministic CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode(&self.value())
    }

    /// Decodes an entry.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, WireError> {
        Self::read(&decode(b)?)
    }
}

/// Two cosigned heads of one size with different roots (`equivocation-proof`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EquivocationProof {
    /// The domain.
    pub domain: Hash,
    /// The size both name.
    pub size: u64,
    /// One head.
    pub first: GossipEntry,
    /// The other.
    pub second: GossipEntry,
    /// When it was found, Unix milliseconds.
    pub found_at: u64,
}

impl EquivocationProof {
    /// Its deterministic CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode(&map(alloc::vec![
            ("domain", Some(Value::Bytes(self.domain.to_vec()))),
            ("size", Some(Value::Unsigned(self.size))),
            ("first", Some(self.first.value())),
            ("second", Some(self.second.value())),
            ("found_at", Some(Value::Unsigned(self.found_at))),
        ]))
    }
}

/// One link of a witness's state file (`witness-state-entry`); `hash` is SHA-256 over its
/// deterministic CBOR and the next entry's `prev`. `note` is the cosigned note the witness
/// serves to gossip (`w2_note`); `fence` the size above which the entry's binding may not be
/// cosigned (`w2_fence`, U11; OP-158 m.4 (b)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateEntry {
    /// Sequence number from 0.
    pub seq: u64,
    /// The domain.
    pub domain: Hash,
    /// Cosigned size.
    pub size: u64,
    /// Cosigned root.
    pub root: Hash,
    /// Kid of the binding the checkpoint was under.
    pub binding: Hash,
    /// When, Unix milliseconds.
    pub at: u64,
    /// The previous entry's hash; 32 zero bytes for the first.
    pub prev: Hash,
    /// The cosigned note.
    pub note: Option<String>,
    /// The fence the entry sets.
    pub fence: Option<u64>,
    /// The Ed25519 binding keys the entry learned from a handover record; the entry's
    /// `binding` is then the old binding, fenced at `fence` (`w5_keys`, U11; OP-158 m.4 (b)).
    pub keys: Option<alloc::vec::Vec<Hash>>,
}

impl StateEntry {
    /// Its deterministic CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode(&map(alloc::vec![
            ("seq", Some(Value::Unsigned(self.seq))),
            ("domain", Some(Value::Bytes(self.domain.to_vec()))),
            ("size", Some(Value::Unsigned(self.size))),
            ("root", Some(Value::Bytes(self.root.to_vec()))),
            ("binding", Some(Value::Bytes(self.binding.to_vec()))),
            ("at", Some(Value::Unsigned(self.at))),
            ("prev", Some(Value::Bytes(self.prev.to_vec()))),
            ("w2_note", self.note.as_deref().map(Value::text)),
            ("w2_fence", self.fence.map(Value::Unsigned)),
            ("w5_keys", self.keys.as_deref().map(hash_array)),
        ]))
    }

    /// Decodes an entry.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, WireError> {
        let v = decode(b)?;
        keys(
            &v,
            &[
                "seq", "domain", "size", "root", "binding", "at", "prev", "w2_note", "w2_fence",
                "w5_keys",
            ],
        )?;
        Ok(Self {
            seq: uint(v.get("seq"))?,
            domain: fixed::<32>(v.get("domain"))?,
            size: uint(v.get("size"))?,
            root: fixed::<32>(v.get("root"))?,
            binding: fixed::<32>(v.get("binding"))?,
            at: uint(v.get("at"))?,
            prev: fixed::<32>(v.get("prev"))?,
            note: v
                .get("w2_note")
                .map(|n| text(Some(n), MAX_NOTE))
                .transpose()?,
            fence: v.get("w2_fence").map(|n| uint(Some(n))).transpose()?,
            keys: v.get("w5_keys").map(|k| hashes(Some(k))).transpose()?,
        })
    }

    /// The hash the next entry names as `prev`.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn hash(&self) -> Result<Hash, WireError> {
        Ok(suiss_crypto::digest::sha256(&self.to_bytes()?))
    }
}

/// Largest post-quantum checkpoint or cosign `COSE_Sign1` (`pq-checkpoint.cddl`).
pub const MAX_PQ_SIGN1: usize = 131_072;

/// Largest excerpt of an ML-DSA key (`pq-checkpoint.cddl`).
pub const MAX_PQ_EXCERPT: usize = 16_384;

/// A request to cosign a post-quantum re-anchor checkpoint (CR-45 RA-3, OP-159 m.3 (g)): the
/// T16 note body, its ML-DSA `COSE_Sign1` and the binding-signed excerpt of its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqCosignRequest {
    /// The domain.
    pub domain: Hash,
    /// The note body, byte-identical to the `COSE_Sign1` payload.
    pub body: String,
    /// The tagged `COSE_Sign1`.
    pub sign1: Vec<u8>,
    /// The binding-signed excerpt of the ML-DSA key.
    pub excerpt: Vec<u8>,
}

impl PqCosignRequest {
    /// Its deterministic CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode(&map(alloc::vec![
            ("domain", Some(Value::Bytes(self.domain.to_vec()))),
            ("body", Some(Value::text(&self.body))),
            ("sign1", Some(Value::Bytes(self.sign1.clone()))),
            ("excerpt", Some(Value::Bytes(self.excerpt.clone()))),
        ]))
    }

    /// Decodes a request.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, WireError> {
        let v = decode(b)?;
        keys(&v, &["domain", "body", "sign1", "excerpt"])?;
        Ok(Self {
            domain: fixed::<32>(v.get("domain"))?,
            body: text(v.get("body"), MAX_NOTE)?,
            sign1: bytes(v.get("sign1"), MAX_PQ_SIGN1)?,
            excerpt: bytes(v.get("excerpt"), MAX_PQ_EXCERPT)?,
        })
    }
}

/// A witness's post-quantum cosign (`pq-checkpoint.cddl` `pq-cosign`): its name, the cosign
/// time in seconds and its `COSE_Sign1` over the note body and that time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqCosign {
    /// The witness name.
    pub name: String,
    /// The cosign time, Unix seconds.
    pub timestamp: u64,
    /// The tagged `COSE_Sign1`.
    pub sign1: Vec<u8>,
}

impl PqCosign {
    /// The message a cosign signs: the note body, then `timestamp` as 8 big-endian bytes.
    #[must_use]
    pub fn message(body: &str, timestamp: u64) -> Vec<u8> {
        let mut m = body.as_bytes().to_vec();
        m.extend_from_slice(&timestamp.to_be_bytes());
        m
    }

    /// Its deterministic CBOR.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, WireError> {
        encode(&map(alloc::vec![
            ("name", Some(Value::text(&self.name))),
            ("timestamp", Some(Value::Unsigned(self.timestamp))),
            ("sign1", Some(Value::Bytes(self.sign1.clone()))),
        ]))
    }

    /// Decodes a cosign.
    ///
    /// # Errors
    /// [`WireError`].
    pub fn from_bytes(b: &[u8]) -> Result<Self, WireError> {
        let v = decode(b)?;
        keys(&v, &["name", "timestamp", "sign1"])?;
        Ok(Self {
            name: text(v.get("name"), 255)?,
            timestamp: uint(v.get("timestamp"))?,
            sign1: bytes(v.get("sign1"), MAX_PQ_SIGN1)?,
        })
    }
}
