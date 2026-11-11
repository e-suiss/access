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

fn state_key(parts: &[&str]) -> alloc::vec::Vec<u8> {
    suiss_crypto::dcbor::encode(
        &Value::Array(parts.iter().map(|p| Value::text(p)).collect()),
        suiss_crypto::dcbor::Limits::CEILING,
    )
    .unwrap_or_default()
}

/// `dCBOR(["recovery_entry"])`: the rootTerms recovery entry the Genesis declared (SEC20).
#[must_use]
pub fn entry_key() -> alloc::vec::Vec<u8> {
    state_key(&["recovery_entry"])
}

/// `dCBOR(["provider_binding"])`: the domain's one provider binding, written by Genesis,
/// `domain_handover` and `domain_recover` only (§9.15, PI-15).
#[must_use]
pub fn binding_key() -> alloc::vec::Vec<u8> {
    state_key(&["provider_binding"])
}

/// `dCBOR(["superseded", kid])`: an old binding key and the checkpoint its successor cites
/// (§9.10 recovery predicate).
#[must_use]
pub fn superseded_key(kid: &[u8; 32]) -> alloc::vec::Vec<u8> {
    suiss_crypto::dcbor::encode(
        &Value::Array(alloc::vec![
            Value::text("superseded"),
            Value::Bytes(kid.to_vec())
        ]),
        suiss_crypto::dcbor::Limits::CEILING,
    )
    .unwrap_or_default()
}

/// `dCBOR(["recovered"])`: the last forced recovery, `{at, pos, n}` (TI-RT3).
#[must_use]
pub fn recovered_key() -> alloc::vec::Vec<u8> {
    state_key(&["recovered"])
}

/// `dCBOR(["versions"])`: the domain minimum and the last activation, `{floor, activated, at}`
/// (OP-56, §15.4).
#[must_use]
pub fn versions_key() -> alloc::vec::Vec<u8> {
    state_key(&["versions"])
}

/// `dCBOR(["retired_algorithms"])`: the algorithms the domain declared broken (§15.16).
#[must_use]
pub fn retired_key() -> alloc::vec::Vec<u8> {
    state_key(&["retired_algorithms"])
}

/// The stored provider binding: its keys, the checkpoint it cites, how it was bound and when.
#[must_use]
pub fn binding_value(
    binding: &BTreeMap<[u8; 32], BindingKey>,
    cited: &CheckpointRef,
    how: &str,
    pos: u64,
) -> Value {
    map([
        ("binding", Some(bindings_value(binding))),
        ("cited", Some(cited.to_value())),
        ("how", Some(Value::text(how))),
        ("since", Some(Value::Unsigned(pos))),
    ])
}

/// A Genesis `binding` field: the first provider binding's keys and its stored value
/// (§9.15: the binding's root is Genesis).
///
/// # Errors
/// [`ModelError`] when it is not a set of binding keys or a key is already superseded.
pub fn genesis_binding(v: &Value) -> Result<(BTreeSet<[u8; 32]>, Value), ModelError> {
    let b = bindings(v)?;
    if b.is_empty() || b.values().any(|k| k.superseded.is_some()) {
        return Err(ModelError::Range);
    }
    let value = map([
        ("binding", Some(bindings_value(&b))),
        ("how", Some(Value::text("genesis"))),
        ("since", Some(Value::Unsigned(0))),
    ]);
    Ok((b.into_keys().collect(), value))
}

/// The `kid`s of a stored provider binding.
///
/// # Errors
/// [`ModelError`] when it does not decode.
pub fn binding_kids(v: &Value) -> Result<BTreeSet<[u8; 32]>, ModelError> {
    let b = v.get("binding").ok_or(ModelError::Missing)?;
    Ok(bindings(b)?.into_keys().collect())
}

/// The stored minimum `(floor, activated, at)`.
///
/// # Errors
/// [`ModelError`] when it does not decode.
pub fn versions_state(
    v: &Value,
) -> Result<
    (
        crate::verify::key_scope::SpecVersions,
        crate::verify::key_scope::SpecVersions,
        u64,
    ),
    ModelError,
> {
    let mut f = Fields::of(v)?;
    let out = (
        crate::verify::key_scope::SpecVersions::from_value(f.req("floor")?)?,
        crate::verify::key_scope::SpecVersions::from_value(f.req("activated")?)?,
        uint(f.req("at")?)?,
    );
    f.done()?;
    Ok(out)
}

/// The stored minimum after an activation of `activated` at `at` over `floor`.
#[must_use]
pub fn versions_value(
    floor: &crate::verify::key_scope::SpecVersions,
    activated: &crate::verify::key_scope::SpecVersions,
    at: u64,
) -> Value {
    map([
        ("floor", Some(floor.to_value())),
        ("activated", Some(activated.to_value())),
        ("at", Some(Value::Unsigned(at))),
    ])
}

/// The contribution class a recovery key gives to a `domain_recover` (SEC20).
pub const RECOVER: &str = "recover";

/// The requirement of a recovery entry: `threshold` `recover` contributions from distinct
/// Instances, bound to the intent, each with human presence, user verification, a
/// phishing-resistant assertion and a hardware-bound key (SEC20). Requiring every contribution
/// hardware-bound is stricter than the entry's `hardware_bound_min`.
#[must_use]
pub fn entry_terms(entry: &RecoveryEntry) -> BTreeSet<crate::model::RequirementTerm> {
    let assurance = [
        "hardware_bound",
        "human_presence",
        "phishing_resistant",
        "uv",
    ]
    .into_iter()
    .map(|d| (alloc::string::String::from(d), 1))
    .collect();
    BTreeSet::from([crate::model::RequirementTerm {
        proof_kind: crate::model::ProofKind::Contribution,
        class: alloc::string::String::from(RECOVER),
        count: entry.threshold,
        binding: crate::model::Binding::IntentDigest,
        freshness_ms: None,
        independence: crate::model::Independence::DistinctInstance,
        consumption: crate::model::Consumption::SingleUse,
        source: None,
        assurance,
    }])
}

/// `dCBOR(["witness_head", ClaimID])`: the `checkpoint-ref` a witness `checkpoint` Claim
/// states, written by the checkpoint ingest beside the Claim (OP-158 m.3 (b), (c)).
#[must_use]
pub fn witness_head_key(claim: &Id) -> alloc::vec::Vec<u8> {
    suiss_crypto::dcbor::encode(
        &Value::Array(alloc::vec![Value::text("witness_head"), claim.to_value()]),
        suiss_crypto::dcbor::Limits::CEILING,
    )
    .unwrap_or_default()
}

/// The head of a witness `checkpoint` Claim: its `witness_head` entry `head`, timed at the
/// Claim's `issued_at`; `None` for a Claim of another class, ended, outside its validity, or
/// without an entry that decodes.
#[must_use]
pub fn witness_head(
    claim: &crate::claim::ClaimState,
    head: Option<&Value>,
    now: u64,
) -> Option<crate::fold::WitnessHead> {
    let s = &claim.statement;
    if claim.ended.is_some()
        || s.class != crate::claim::CHECKPOINT
        || now < s.validity.from
        || now > s.validity.until
    {
        return None;
    }
    let head = CheckpointRef::from_value(head?).ok()?;
    Some(crate::fold::WitnessHead::new(
        head.size,
        head.root.0,
        s.issued_at,
    ))
}

/// When the last forced recovery took effect, from its stored value.
#[must_use]
pub fn recovered_at(v: &Value) -> Option<u64> {
    match v.get("at") {
        Some(Value::Unsigned(t)) => Some(*t),
        _ => None,
    }
}

/// Whether an entry is admissible for a Genesis (SEC20, U16): every holder is a Party of the
/// meta-anchor's root, and no key is one of the provider binding's.
#[must_use]
pub fn admissible(
    entry: &RecoveryEntry,
    roots: &BTreeSet<Id>,
    provider: &BTreeSet<[u8; 32]>,
) -> bool {
    entry.holders.is_subset(roots) && entry.keys.is_disjoint(provider)
}

#[cfg(test)]
mod tests;
