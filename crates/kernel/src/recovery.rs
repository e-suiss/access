//! Handover and recovery types (§9.15, §13.6, OP-158 m.3 (b)): the inputs of the
//! `domain_handover` and `domain_recover` meta-actions, the rootTerms recovery entry, the two
//! quarantine patterns and the pre-recovery nonce subcode. The meta-actions decide nothing yet:
//! until their semantics land they are refused on the strictest path (OP-158 m.4 (a)).

use alloc::collections::{BTreeMap, BTreeSet};

use suiss_crypto::dcbor::Value;

use crate::codec::{
    Canonical, Fields, ModelError, boolean, map, set_of, set_value, uint, word, word_of,
};
use crate::digest::Digest;
use crate::model::Id;
use crate::verify::key_scope::BindingKey;

/// The blocker subcode of an AIS timed before a recovery whose nonce the continuing lineage
/// does not hold, archive included (TI-RT3, U28, SEC22 R1 (c)).
pub const PRE_RECOVERY: &str = "nonce-closed/pre-recovery";

/// The two ready-made quarantine `policy.set` patterns (SEC22 R1, TI-RT1, RT3). Lifting one is
/// CT3 and does not lift the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Quarantine {
    /// After a forced recovery: pre-N projections need inclusion, CT2+ needs a contribution and
    /// pre-recovery nonces are closed.
    PostRecovery,
    /// After a re-evaluation difference: the divergent record's widening effects are denied.
    Divergence,
}

const QUARANTINES: [(&str, Quarantine); 2] = [
    ("post-recovery", Quarantine::PostRecovery),
    ("divergence", Quarantine::Divergence),
];

impl Quarantine {
    /// The pattern name a `policy.set` carries under `quarantine`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::PostRecovery => "post-recovery",
            Self::Divergence => "divergence",
        }
    }

    /// The pattern named `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        QUARANTINES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, q)| *q)
    }
}

/// A checkpoint by its tree size and root hash (RFC 9162).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct CheckpointRef {
    /// Tree size.
    pub size: u64,
    /// Root hash.
    pub root: Digest,
}

impl CheckpointRef {
    /// The checkpoint of `size` records with `root`.
    #[must_use]
    pub const fn new(size: u64, root: Digest) -> Self {
        Self { size, root }
    }
}

fn digest(v: &Value) -> Result<Digest, ModelError> {
    Digest::from_value(v).ok_or(ModelError::Shape)
}

impl Canonical for CheckpointRef {
    fn to_value(&self) -> Value {
        map([
            ("size", Some(Value::Unsigned(self.size))),
            ("root", Some(self.root.to_value())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let out = Self {
            size: uint(f.req("size")?)?,
            root: digest(f.req("root")?)?,
        };
        f.done()?;
        Ok(out)
    }
}

/// Who holds the recovery keys (SEC20, U16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyHolding {
    /// The users' own devices (passkey or security key).
    Device,
    /// Offline ceremony keys.
    Offline,
}

const HOLDINGS: [(&str, KeyHolding); 2] = [
    ("device", KeyHolding::Device),
    ("offline", KeyHolding::Offline),
];

/// The rootTerms recovery entry of a Genesis (§13.6, SEC20): k-of-n keys, at least two of them
/// hardware-bound, none held by the provider or its operator. Default 3-of-5 for an
/// organization, 2-of-3 for a small domain (PD).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoveryEntry {
    /// How many keys must contribute.
    pub threshold: u64,
    /// The entry's key bindings, by RFC 7638 thumbprint.
    pub keys: BTreeSet<[u8; 32]>,
    /// How many of them must be hardware-bound; at least 2.
    pub hardware_bound_min: u64,
    /// How the keys are held.
    pub held_on: KeyHolding,
    /// The Parties that hold them; a Genesis refuses an entry whose holders meet the provider's
    /// Party (SEC20).
    pub holders: BTreeSet<Id>,
}

/// The least number of hardware-bound recovery keys (SEC20).
pub const HARDWARE_BOUND_MIN: u64 = 2;

impl RecoveryEntry {
    /// An entry; [`Canonical::from_value`] checks its ranges.
    #[must_use]
    pub const fn new(
        threshold: u64,
        keys: BTreeSet<[u8; 32]>,
        hardware_bound_min: u64,
        held_on: KeyHolding,
        holders: BTreeSet<Id>,
    ) -> Self {
        Self {
            threshold,
            keys,
            hardware_bound_min,
            held_on,
            holders,
        }
    }
}

fn kid(v: &Value) -> Result<[u8; 32], ModelError> {
    match v {
        Value::Bytes(b) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| ModelError::Range),
        _ => Err(ModelError::Shape),
    }
}

impl Canonical for RecoveryEntry {
    fn to_value(&self) -> Value {
        map([
            ("threshold", Some(Value::Unsigned(self.threshold))),
            (
                "keys",
                Some(set_value(
                    self.keys.iter().map(|k| Value::Bytes(k.to_vec())),
                )),
            ),
            (
                "hardware_bound_min",
                Some(Value::Unsigned(self.hardware_bound_min)),
            ),
            ("held_on", Some(word_of(self.held_on, &HOLDINGS))),
            (
                "holders",
                Some(set_value(self.holders.iter().map(Canonical::to_value))),
            ),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let out = Self {
            threshold: uint(f.req("threshold")?)?,
            keys: set_of(f.req("keys")?, true, kid)?,
            hardware_bound_min: uint(f.req("hardware_bound_min")?)?,
            held_on: word(f.req("held_on")?, &HOLDINGS)?,
            holders: set_of(f.req("holders")?, true, Id::from_value)?,
        };
        f.done()?;
        let n = u64::try_from(out.keys.len()).map_err(|_| ModelError::Range)?;
        if out.threshold == 0
            || out.threshold > n
            || out.hardware_bound_min < HARDWARE_BOUND_MIN
            || out.hardware_bound_min > n
        {
            return Err(ModelError::Range);
        }
        Ok(out)
    }
}

fn bindings_value(b: &BTreeMap<[u8; 32], BindingKey>) -> Value {
    set_value(b.values().map(Canonical::to_value))
}

fn bindings(v: &Value) -> Result<BTreeMap<[u8; 32], BindingKey>, ModelError> {
    let mut out = BTreeMap::new();
    for item in crate::codec::set_items(v, true)? {
        let b = BindingKey::from_value(item)?;
        if out.insert(b.kid, b).is_some() {
            return Err(ModelError::SetOrder);
        }
    }
    Ok(out)
}

/// The input of `domain_handover` (§16.6, U27, OP-158 m.3 (l)): the new provider binding, the
/// checkpoint `C_k` the outgoing provider's no-write statement cites, and whether it is a binding
/// re-anchor inside one provider (OP-60, RB-0…RB-6).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HandoverInput {
    /// The new binding keys, by `kid`.
    pub binding: BTreeMap<[u8; 32], BindingKey>,
    /// `C_k`.
    pub cited: CheckpointRef,
    /// The outgoing and the incoming provider are the same (OP-60).
    pub reanchor: bool,
}

impl HandoverInput {
    /// The handover to `binding` citing `cited`.
    #[must_use]
    pub const fn new(
        binding: BTreeMap<[u8; 32], BindingKey>,
        cited: CheckpointRef,
        reanchor: bool,
    ) -> Self {
        Self {
            binding,
            cited,
            reanchor,
        }
    }
}

impl Canonical for HandoverInput {
    fn to_value(&self) -> Value {
        map([
            ("binding", Some(bindings_value(&self.binding))),
            ("cited", Some(self.cited.to_value())),
            ("reanchor", self.reanchor.then_some(Value::Bool(true))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let out = Self {
            binding: bindings(f.req("binding")?)?,
            cited: CheckpointRef::from_value(f.req("cited")?)?,
            reanchor: match f.opt("reanchor") {
                None => false,
                Some(b) if boolean(b)? => true,
                Some(_) => return Err(ModelError::Range),
            },
        };
        f.done()?;
        Ok(out)
    }
}

/// The declared lost suffix `(from, to]` of a recovery (SEC22).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct LostSuffix {
    /// N, exclusive.
    pub from: u64,
    /// The highest witnessed size, inclusive.
    pub to: u64,
}

impl LostSuffix {
    /// The suffix `(from, to]`.
    #[must_use]
    pub const fn new(from: u64, to: u64) -> Self {
        Self { from, to }
    }
}

/// The input of `domain_recover` (§13.6, SEC21, SEC22, OP-158 m.3 (b)): the position N, the
/// checkpoint it cites, the witness `checkpoint` Claims, the replica head when one answered, the
/// declared lost suffix and the conflicting branches of a fork, and the new provider binding. The
/// cited checkpoint is a hint: the evaluator computes R* from the Claims it ingested itself.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecoverInput {
    /// N.
    pub n: u64,
    /// The checkpoint N cites.
    pub cited_checkpoint: CheckpointRef,
    /// The witness `checkpoint` Claims the request names.
    pub witness_claims: BTreeSet<Id>,
    /// The replica's head, when a replica answered.
    pub replica_head: Option<CheckpointRef>,
    /// `(N, witness highest]`, when declared.
    pub lost_suffix: Option<LostSuffix>,
    /// The conflicting branches of a fork.
    pub fork: BTreeSet<CheckpointRef>,
    /// The new binding keys, by `kid`.
    pub binding: BTreeMap<[u8; 32], BindingKey>,
}

impl RecoverInput {
    /// A recovery to N citing `cited_checkpoint`, with nothing else declared.
    #[must_use]
    pub const fn new(
        n: u64,
        cited_checkpoint: CheckpointRef,
        binding: BTreeMap<[u8; 32], BindingKey>,
    ) -> Self {
        Self {
            n,
            cited_checkpoint,
            witness_claims: BTreeSet::new(),
            replica_head: None,
            lost_suffix: None,
            fork: BTreeSet::new(),
            binding,
        }
    }
}

impl Canonical for RecoverInput {
    fn to_value(&self) -> Value {
        map([
            ("n", Some(Value::Unsigned(self.n))),
            ("cited_checkpoint", Some(self.cited_checkpoint.to_value())),
            (
                "witness_claims",
                (!self.witness_claims.is_empty())
                    .then(|| set_value(self.witness_claims.iter().map(Canonical::to_value))),
            ),
            (
                "replica_head",
                self.replica_head.as_ref().map(Canonical::to_value),
            ),
            (
                "lost_suffix",
                self.lost_suffix.map(|s| {
                    map([
                        ("from", Some(Value::Unsigned(s.from))),
                        ("to", Some(Value::Unsigned(s.to))),
                    ])
                }),
            ),
            (
                "fork",
                (!self.fork.is_empty())
                    .then(|| set_value(self.fork.iter().map(Canonical::to_value))),
            ),
            ("binding", Some(bindings_value(&self.binding))),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, ModelError> {
        let mut f = Fields::of(v)?;
        let lost_suffix = f
            .opt("lost_suffix")
            .map(|s| {
                let mut g = Fields::of(s)?;
                let out = LostSuffix {
                    from: uint(g.req("from")?)?,
                    to: uint(g.req("to")?)?,
                };
                g.done()?;
                if out.to <= out.from {
                    return Err(ModelError::Range);
                }
                Ok(out)
            })
            .transpose()?;
        let out = Self {
            n: uint(f.req("n")?)?,
            cited_checkpoint: CheckpointRef::from_value(f.req("cited_checkpoint")?)?,
            witness_claims: f
                .opt("witness_claims")
                .map(|w| set_of(w, true, Id::from_value))
                .transpose()?
                .unwrap_or_default(),
            replica_head: f
                .opt("replica_head")
                .map(CheckpointRef::from_value)
                .transpose()?,
            lost_suffix,
            fork: f
                .opt("fork")
                .map(|b| set_of(b, true, CheckpointRef::from_value))
                .transpose()?
                .unwrap_or_default(),
            binding: bindings(f.req("binding")?)?,
        };
        f.done()?;
        if out.lost_suffix.is_some_and(|s| s.from != out.n) {
            return Err(ModelError::Range);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
