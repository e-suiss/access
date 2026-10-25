//! Record envelope, field commitments and selective disclosure (§17.6.1, OP-106 m.9–m.15).
//!
//! A record's Merkle leaf binds only its header and one root over salted per-field commitments,
//! so a field can be withheld, or redacted by crypto-shredding, without changing the leaf.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::codec::{Canonical, Fields, ModelError, ident, map, uint, word, word_of};
use crate::digest::{self, Digest, Hash, ProofError};
use crate::model::TrustedTime;

/// A per-field salt; 32 bytes from the RNG port (OP-106 m.15).
pub type Salt = [u8; 32];

/// The four log record kinds (OP-106 m.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKind {
    /// Position 0; its digest is the `DomainID`.
    Genesis,
    /// An opening record.
    Opening,
    /// A `DecisionRecord`.
    Decision,
    /// A Claim record.
    Claim,
}

const KINDS: [(&str, RecordKind); 4] = [
    ("genesis", RecordKind::Genesis),
    ("opening", RecordKind::Opening),
    ("decision", RecordKind::Decision),
    ("claim", RecordKind::Claim),
];

/// The leaf-core header: open in every inclusion proof (address and order, no content).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// `DomainID`; absent only on Genesis.
    pub domain: Option<Digest>,
    /// Position in the domain log; 0 is Genesis.
    pub pos: u64,
    /// Kind.
    pub kind: RecordKind,
    /// Domain trusted time, monotone with `pos` (TI-19).
    pub recorded_at: TrustedTime,
    /// Leaf hash of the previous record; absent only at position 0.
    pub prev: Option<Digest>,
}

impl Header {
    fn check(&self) -> Result<(), ModelError> {
        let genesis = self.kind == RecordKind::Genesis;
        // OP-106 m.10, m.11
        if genesis != (self.pos == 0)
            || genesis == self.domain.is_some()
            || genesis == self.prev.is_some()
        {
            return Err(ModelError::Range);
        }
        Ok(())
    }

    fn entries(&self) -> [(&'static str, Option<Value>); 5] {
        [
            ("domain", self.domain.as_ref().map(Digest::to_value)),
            ("pos", Some(Value::Unsigned(self.pos))),
            ("kind", Some(word_of(self.kind, &KINDS))),
            ("recorded_at", Some(Value::Unsigned(self.recorded_at))),
            ("prev", self.prev.as_ref().map(Digest::to_value)),
        ]
    }

    fn read(f: &mut Fields<'_>) -> Result<Self, ModelError> {
        let h = Self {
            domain: f.opt("domain").map(digest_of).transpose()?,
            pos: uint(f.req("pos")?)?,
            kind: word(f.req("kind")?, &KINDS)?,
            recorded_at: uint(f.req("recorded_at")?)?,
            prev: f.opt("prev").map(digest_of).transpose()?,
        };
        h.check()?;
        Ok(h)
    }

    fn with(&self, rest: impl IntoIterator<Item = (&'static str, Option<Value>)>) -> Value {
        map(self.entries().into_iter().chain(rest))
    }
}

/// An opened field: its value and salt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The field value, any canonical CBOR value.
    pub value: Value,
    /// The field's salt.
    pub salt: Salt,
}

/// Why a record or disclosure is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    /// Not a value of the model.
    #[error("not a record: {0}")]
    Model(#[from] ModelError),
    /// A field is outside the structural limits once committed.
    #[error("field outside the structural limits")]
    Encode,
    /// The disclosed leaf is not in the log.
    #[error("inclusion proof: {0}")]
    Proof(#[from] ProofError),
}

impl From<dcbor::EncodeError> for RecordError {
    fn from(_: dcbor::EncodeError) -> Self {
        Self::Encode
    }
}

/// `FC(name) = SHA-256(0x02 ‖ salt ‖ dCBOR([name, value]))` (OP-106 m.12).
///
/// # Errors
/// [`RecordError::Encode`].
pub fn field_commitment(name: &str, field: &Opened) -> Result<Hash, RecordError> {
    let pair = Value::Array(alloc::vec![Value::text(name), field.value.clone()]);
    Ok(digest::field_commit(
        &field.salt,
        &dcbor::encode(&pair, Limits::CEILING)?,
    ))
}

/// RFC 9162 root over the commitments, ordered by the UTF-8 bytes of the names (OP-106 m.13).
#[must_use]
pub fn field_root(commitments: &BTreeMap<String, Hash>) -> Hash {
    let leaves: Vec<&[u8]> = commitments.values().map(<[u8; 32]>::as_slice).collect();
    digest::root(&leaves)
}

/// The Merkle leaf input of a record: its header and the root of its field commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafCore {
    /// Header.
    pub header: Header,
    /// Field root.
    pub field_root: Hash,
}

impl LeafCore {
    /// `SHA-256(0x00 ‖ dCBOR(leaf-core))`, the record's leaf in the domain log.
    ///
    /// # Errors
    /// [`RecordError::Encode`].
    pub fn leaf_hash(&self) -> Result<Hash, RecordError> {
        Ok(digest::leaf_hash(&self.to_bytes()?))
    }
}

impl Canonical for LeafCore {
    fn to_value(&self) -> Value {
        self.header
            .with([("field_root", Some(Value::Bytes(self.field_root.to_vec())))])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let header = Header::read(&mut f)?;
        let field_root = salt(f.req("field_root")?)?;
        f.done()?;
        Ok(Self { header, field_root })
    }
}

/// A full `record-envelope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordEnvelope {
    /// Header.
    pub header: Header,
    /// Fields by name, each with its own salt.
    pub fields: BTreeMap<String, Opened>,
}

impl RecordEnvelope {
    /// Every field's commitment.
    ///
    /// # Errors
    /// [`RecordError::Encode`].
    pub fn commitments(&self) -> Result<BTreeMap<String, Hash>, RecordError> {
        self.fields
            .iter()
            .map(|(n, f)| Ok((n.clone(), field_commitment(n, f)?)))
            .collect()
    }

    /// The leaf core.
    ///
    /// # Errors
    /// [`RecordError::Encode`].
    pub fn leaf_core(&self) -> Result<LeafCore, RecordError> {
        Ok(LeafCore {
            header: self.header.clone(),
            field_root: field_root(&self.commitments()?),
        })
    }

    /// The leaf hash.
    ///
    /// # Errors
    /// [`RecordError::Encode`].
    pub fn leaf_hash(&self) -> Result<Hash, RecordError> {
        self.leaf_core()?.leaf_hash()
    }

    /// The record's `DomainID`: computed from the canonical bytes for Genesis (OP-117 m.2),
    /// the `domain` field otherwise.
    ///
    /// # Errors
    /// [`RecordError::Encode`].
    pub fn domain(&self) -> Result<Digest, RecordError> {
        match self.header.domain {
            Some(d) => Ok(d),
            None => Ok(digest::domain_id(&self.to_bytes()?)),
        }
    }

    /// A disclosure that opens the fields `open` accepts and withholds the rest.
    ///
    /// # Errors
    /// [`RecordError::Encode`].
    pub fn disclose(&self, open: impl Fn(&str) -> bool) -> Result<Disclosure, RecordError> {
        let mut opened = BTreeMap::new();
        let mut withheld = BTreeMap::new();
        for (name, field) in &self.fields {
            if open(name) {
                opened.insert(name.clone(), field.clone());
            } else {
                withheld.insert(name.clone(), field_commitment(name, field)?);
            }
        }
        Ok(Disclosure {
            header: self.header.clone(),
            opened,
            withheld,
        })
    }
}

fn opened_entries(fields: &BTreeMap<String, Opened>) -> [(&'static str, Option<Value>); 2] {
    let some = !fields.is_empty();
    [
        (
            "fields",
            some.then(|| {
                Value::Map(
                    fields
                        .iter()
                        .map(|(n, f)| (Value::text(n), f.value.clone()))
                        .collect(),
                )
            }),
        ),
        (
            "field_salt",
            some.then(|| {
                Value::Map(
                    fields
                        .iter()
                        .map(|(n, f)| (Value::text(n), Value::Bytes(f.salt.to_vec())))
                        .collect(),
                )
            }),
        ),
    ]
}

fn digest_of(v: &Value) -> Result<Digest, ModelError> {
    <Digest as Canonical>::from_value(v)
}

fn salt(v: &Value) -> Result<[u8; 32], ModelError> {
    match v {
        Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| ModelError::Range),
        _ => Err(ModelError::Shape),
    }
}

fn names<T>(
    v: Option<&Value>,
    read: impl Fn(&Value) -> Result<T, ModelError>,
) -> Result<BTreeMap<String, T>, ModelError> {
    let Some(v) = v else {
        return Ok(BTreeMap::new());
    };
    let mut f = Fields::of(v)?;
    if f.is_empty() {
        return Err(ModelError::Range);
    }
    Ok(f.drain(|k, val| Ok((ident(&Value::text(k))?, read(val)?)))?
        .into_iter()
        .collect())
}

fn read_opened(f: &mut Fields<'_>) -> Result<BTreeMap<String, Opened>, ModelError> {
    let values = names(f.opt("fields"), |v| Ok(v.clone()))?;
    let mut salts = names(f.opt("field_salt"), salt)?;
    // OP-106 m.14, m.15
    if salts.len() != values.len() {
        return Err(ModelError::Range);
    }
    values
        .into_iter()
        .map(|(n, value)| {
            let salt = salts.remove(&n).ok_or(ModelError::Range)?;
            Ok((n, Opened { value, salt }))
        })
        .collect()
}

impl Canonical for RecordEnvelope {
    fn to_value(&self) -> Value {
        self.header.with(opened_entries(&self.fields))
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let header = Header::read(&mut f)?;
        let fields = read_opened(&mut f)?;
        f.done()?;
        if fields.is_empty() {
            return Err(ModelError::Missing);
        }
        Ok(Self { header, fields })
    }
}

/// A `record-disclosure`: the header, the opened fields with their salts, and only the
/// commitments of the withheld ones (§17.6.1 rule 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    /// Header.
    pub header: Header,
    /// Opened fields.
    pub opened: BTreeMap<String, Opened>,
    /// Commitments of withheld fields.
    pub withheld: BTreeMap<String, Hash>,
}

impl Disclosure {
    /// The leaf core; opened commitments are recomputed, never read (TI-11).
    ///
    /// # Errors
    /// [`RecordError::Encode`].
    pub fn leaf_core(&self) -> Result<LeafCore, RecordError> {
        let mut all = self.withheld.clone();
        for (name, field) in &self.opened {
            all.insert(name.clone(), field_commitment(name, field)?);
        }
        Ok(LeafCore {
            header: self.header.clone(),
            field_root: field_root(&all),
        })
    }

    /// The leaf hash.
    ///
    /// # Errors
    /// [`RecordError::Encode`].
    pub fn leaf_hash(&self) -> Result<Hash, RecordError> {
        self.leaf_core()?.leaf_hash()
    }

    /// Checks that this record sits at index `pos` of the domain log of `size` with `root`
    /// (RFC 9162 §2.1.3.2).
    ///
    /// # Errors
    /// [`RecordError::Proof`] or [`RecordError::Encode`].
    pub fn verify_inclusion(
        &self,
        size: u64,
        path: &[Hash],
        root: &Hash,
    ) -> Result<(), RecordError> {
        let leaf = self.leaf_hash()?;
        Ok(digest::verify_inclusion(
            self.header.pos,
            size,
            &leaf,
            path,
            root,
        )?)
    }
}

impl Canonical for Disclosure {
    fn to_value(&self) -> Value {
        self.header
            .with(opened_entries(&self.opened).into_iter().chain([(
                "withheld",
                (!self.withheld.is_empty()).then(|| {
                    Value::Map(
                        self.withheld
                            .iter()
                            .map(|(n, h)| (Value::text(n), Digest(*h).to_value()))
                            .collect(),
                    )
                }),
            )]))
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let header = Header::read(&mut f)?;
        let opened = read_opened(&mut f)?;
        let withheld = names(f.opt("withheld"), |v| Ok(digest_of(v)?.0))?;
        f.done()?;
        if opened.is_empty() && withheld.is_empty() {
            return Err(ModelError::Missing);
        }
        if withheld.keys().any(|n| opened.contains_key(n)) {
            return Err(ModelError::Range);
        }
        Ok(Self {
            header,
            opened,
            withheld,
        })
    }
}

/// Why two leaf cores are not consecutive records of one log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    /// `pos` is not the next position.
    #[error("not the next position")]
    Position,
    /// `prev` is not the previous leaf hash.
    #[error("prev does not match")]
    Prev,
    /// `recorded_at` went backwards (TI-19).
    #[error("time went backwards")]
    Time,
    /// The records belong to different domains.
    #[error("different domain")]
    Domain,
    /// The previous leaf core cannot be encoded.
    #[error("previous leaf outside the structural limits")]
    Encode,
}

/// Checks that `next` directly follows `previous` in the log of `domain` (hash chain, TI-19).
///
/// # Errors
/// The first failed check, as [`LinkError`].
pub fn check_link(previous: &LeafCore, next: &LeafCore, domain: &Digest) -> Result<(), LinkError> {
    if previous.header.pos.checked_add(1) != Some(next.header.pos) {
        return Err(LinkError::Position);
    }
    let leaf = previous.leaf_hash().map_err(|_| LinkError::Encode)?;
    if next.header.prev != Some(Digest(leaf)) {
        return Err(LinkError::Prev);
    }
    if next.header.recorded_at < previous.header.recorded_at {
        return Err(LinkError::Time);
    }
    let same = |d: &Option<Digest>| d.is_none_or(|d| d == *domain);
    if next.header.domain != Some(*domain) || !same(&previous.header.domain) {
        return Err(LinkError::Domain);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
