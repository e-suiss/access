//! Replay of a domain's Authority Record with the open Kernel (INV-27, PI-6, TI-3, TI-RT1,
//! OP-158 m.3 (h), (i)): the records are folded into state from Genesis, and every decision is
//! re-evaluated, as far as the record carries its inputs, against the state at `q−1`. A
//! difference is evidence in a [`DivergenceSet`]; it never stops anything (G32).
//!
//! The re-evaluation at `q−1` reads only what a record holds; the intent and its proofs are
//! not in the log, so an outcome is reproduced from its state basis:
//! - `state_basis.at` is `q−1` and every read names the version the fold holds there;
//! - an ALLOW consumes no single-use key the fold already holds;
//! - an ALLOW rests on a basis whose Anchor and every Grant of its lineage are live at `q−1`.
//!
//! An ALLOW that fails one is replayed as DENY. A DENY or `REQUIRE_ACTION` narrows, so only its
//! fold is checked. A redacted (digest-coverage) record ends the fold: what follows is chain,
//! order and root only, and the report says so.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::fold::{self, State};
use access_kernel::meta::{self, AnchorState, ExerciseBasis, GrantBasis, GrantState, kind};
use access_kernel::record::{Disclosure, RecordEnvelope, RecordKind};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::sig::{Backend, ed25519};

/// A recorded or replayed outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Word {
    /// `allow`.
    Allow,
    /// `deny`.
    Deny,
    /// `require_action`.
    RequireAction,
}

const WORDS: [(&str, Word); 3] = [
    ("allow", Word::Allow),
    ("deny", Word::Deny),
    ("require_action", Word::RequireAction),
];

impl Word {
    /// The CDDL word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::RequireAction => "require_action",
        }
    }

    fn of(s: &str) -> Option<Self> {
        WORDS.iter().find(|(w, _)| *w == s).map(|(_, x)| *x)
    }
}

/// The two kinds of difference (OP-158 m.3 (i)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// The recorded effects do not fold: commit stops at the provider, Genesis fold arbitrates.
    Fold,
    /// The recorded outcome is not the replayed one: a declared divergence, nothing stops.
    ReEvaluation,
}

impl Kind {
    /// The CDDL word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Fold => "fold",
            Self::ReEvaluation => "re-evaluation",
        }
    }
}

/// Why a decision did not replay; the report's detail, not part of the signed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reason {
    /// The effects do not fold (L2-REC-2).
    Fold,
    /// `state_basis.at` is not `q−1` (TI-3).
    Position,
    /// A read names another version than the fold holds at `q−1` (TI-3).
    Read,
    /// A single-use key was already consumed (TI-2).
    Consumed,
    /// The basis, or a hop of its lineage, is not live at `q−1`.
    Basis,
}

impl Reason {
    /// The report word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Fold => "fold",
            Self::Position => "state-basis-position",
            Self::Read => "state-basis-read",
            Self::Consumed => "consumed",
            Self::Basis => "basis-not-live",
        }
    }
}

/// One record that did not replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// Its position `q`.
    pub position: u64,
    /// Its `ExerciseID`, or the Claim's digest for a Claim record.
    pub exercise: Digest,
    /// Fold or re-evaluation.
    pub kind: Kind,
    /// What the record says.
    pub recorded: Word,
    /// What the replay gives.
    pub replayed: Word,
    /// Why.
    pub reason: Reason,
}

/// Why records cannot be replayed at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayError {
    /// Positions do not follow each other.
    #[error("order")]
    Order,
    /// Position 0 is not a Genesis that folds.
    #[error("genesis")]
    Genesis,
    /// A divergence set or its signature does not decode or verify.
    #[error("set")]
    Set,
}

/// What a replay covered (`replay coverage`, T19).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    /// Records seen.
    pub records: u64,
    /// Decision records seen.
    pub decisions: u64,
    /// Decisions re-evaluated at `q−1`.
    pub reevaluated: u64,
    /// Records seen after the fold ended: a redacted record, a range not from Genesis or a fold
    /// difference.
    pub digest_only: u64,
}

/// A replay in progress, one record at a time.
#[derive(Clone, Debug, Default)]
pub struct Replay {
    domain: Option<Digest>,
    state: Option<State>,
    next: Option<u64>,
    openings: BTreeMap<Vec<u8>, Value>,
    coverage: Coverage,
    items: Vec<Item>,
    resumed: bool,
}

fn field<'a>(r: &'a RecordEnvelope, name: &str) -> Option<&'a Value> {
    r.fields.get(name).map(|f| &f.value)
}

fn outcome(r: &RecordEnvelope) -> Option<Word> {
    match field(r, "outcome").and_then(|o| o.get("outcome")) {
        Some(Value::Text(t)) => Word::of(t),
        _ => None,
    }
}

fn uint(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Unsigned(n)) => Some(*n),
        _ => None,
    }
}

fn live(state: &State, key: &[u8]) -> Option<Value> {
    state
        .get(key)
        .and_then(|e| e.value.clone())
        .filter(|v| v.get("ended").is_none())
}

/// Whether the basis's Anchor and every Grant of its lineage are live in `state`.
fn basis_live(state: &State, basis: &ExerciseBasis) -> bool {
    let mut at = match basis {
        ExerciseBasis::Anchor(a) => {
            return live(state, &meta::key(kind::ANCHOR, a))
                .and_then(|v| AnchorState::from_value(&v).ok())
                .is_some();
        }
        ExerciseBasis::Holding(h) => h.grant,
        ExerciseBasis::Public(g) => *g,
    };
    for _ in 0..meta::MAX_LINEAGE {
        let Some(g) =
            live(state, &meta::key(kind::GRANT, &at)).and_then(|v| GrantState::from_value(&v).ok())
        else {
            return false;
        };
        match g.content.basis {
            GrantBasis::Anchor(a) => {
                return live(state, &meta::key(kind::ANCHOR, &a))
                    .and_then(|v| AnchorState::from_value(&v).ok())
                    .is_some();
            }
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
    false
}

/// The re-evaluation of decision `r` against `state`, the fold at `q−1`.
fn replay_decision(
    state: &State,
    r: &RecordEnvelope,
    recorded: Word,
    basis: Option<&Value>,
    resumed: bool,
) -> Result<(), Reason> {
    let pos = r.header.pos;
    let sb = field(r, "state_basis").ok_or(Reason::Position)?;
    // TI-3
    if uint(sb.get("at")) != pos.checked_sub(1) {
        return Err(Reason::Position);
    }
    let Some(Value::Array(reads)) = sb.get("reads") else {
        return Err(Reason::Read);
    };
    for read in reads {
        let Value::Array(pair) = read else {
            return Err(Reason::Read);
        };
        let [Value::Bytes(key), Value::Unsigned(version)] = pair.as_slice() else {
            return Err(Reason::Read);
        };
        if state.get(key).map_or(0, |e| e.version) != *version {
            return Err(Reason::Read);
        }
    }
    if recorded != Word::Allow {
        return Ok(());
    }
    // TI-2
    if let Some(Value::Array(keys)) = field(r, "consumption").and_then(|c| c.get("single_use")) {
        for k in keys {
            if let Value::Bytes(k) = k
                && state.get(k).is_some_and(|e| e.value.is_some())
            {
                return Err(Reason::Consumed);
            }
        }
    }
    if basis.is_none() && resumed {
        return Ok(());
    }
    let basis = basis
        .and_then(|b| meta::exercise_basis(b).ok())
        .ok_or(Reason::Basis)?;
    if basis_live(state, &basis) {
        Ok(())
    } else {
        Err(Reason::Basis)
    }
}

impl Replay {
    /// An empty replay; the first record it is given should be Genesis.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A replay that continues from `state`, the fold of `domain` up to `next − 1` (a verified
    /// snapshot, TI-RT4). Openings before `next` are not known: a decision whose opening came
    /// before is re-evaluated without its basis rule.
    #[must_use]
    pub fn resume(domain: Digest, state: State, next: u64) -> Self {
        Self {
            domain: Some(domain),
            state: Some(state),
            next: Some(next),
            resumed: true,
            ..Self::default()
        }
    }

    /// The `DomainID`, once Genesis was seen.
    #[must_use]
    pub const fn domain(&self) -> Option<Digest> {
        self.domain
    }

    /// The folded state, while the fold holds.
    #[must_use]
    pub const fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }

    /// What the replay covered so far.
    #[must_use]
    pub const fn coverage(&self) -> Coverage {
        self.coverage
    }

    /// The records that did not replay, in position order.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    fn exercise(&self, r: &RecordEnvelope) -> Digest {
        match (self.domain, field(r, "nonce")) {
            (Some(d), Some(Value::Bytes(n))) => meta::exercise_id(&d, n).unwrap_or(Digest([0; 32])),
            _ => field(r, "claim")
                .and_then(|c| <Digest as Canonical>::from_value(c).ok())
                .unwrap_or(Digest([0; 32])),
        }
    }

    fn diverged(&mut self, r: &RecordEnvelope, kind: Kind, reason: Reason) {
        let recorded = match r.header.kind {
            RecordKind::Decision => outcome(r).unwrap_or(Word::Deny),
            _ => Word::Allow,
        };
        let item = Item {
            position: r.header.pos,
            exercise: self.exercise(r),
            kind,
            recorded,
            replayed: Word::Deny,
            reason,
        };
        self.items.push(item);
    }

    /// Takes the next record. A decision is re-evaluated at `q−1` when `reevaluate` says so (a
    /// sampling agent's choice) and the fold holds.
    ///
    /// # Errors
    /// [`ReplayError::Order`] for a position out of order; [`ReplayError::Genesis`] when
    /// position 0 is not a Genesis that folds.
    pub fn push(&mut self, d: &Disclosure, reevaluate: bool) -> Result<(), ReplayError> {
        let pos = d.header.pos;
        if self.next.is_some_and(|n| n != pos) {
            return Err(ReplayError::Order);
        }
        self.next = Some(pos.checked_add(1).ok_or(ReplayError::Order)?);
        self.coverage.records = self.coverage.records.saturating_add(1);
        let r = RecordEnvelope {
            header: d.header.clone(),
            fields: d.opened.clone(),
        };
        if r.header.kind == RecordKind::Decision {
            self.coverage.decisions = self.coverage.decisions.saturating_add(1);
        }
        if pos == 0 {
            if !d.withheld.is_empty() {
                self.coverage.digest_only = self.coverage.digest_only.saturating_add(1);
                return Ok(());
            }
            self.state = Some(fold::genesis(&r).map_err(|_| ReplayError::Genesis)?);
            self.domain = Some(r.domain().map_err(|_| ReplayError::Genesis)?);
            return Ok(());
        }
        if !d.withheld.is_empty() {
            self.state = None;
        }
        let Some(mut state) = self.state.take() else {
            self.coverage.digest_only = self.coverage.digest_only.saturating_add(1);
            return Ok(());
        };
        match r.header.kind {
            RecordKind::Opening => {
                if let (Some(Value::Bytes(n)), Some(b)) = (field(&r, "nonce"), field(&r, "basis")) {
                    self.openings.insert(n.clone(), b.clone());
                }
            }
            RecordKind::Decision if reevaluate => {
                self.coverage.reevaluated = self.coverage.reevaluated.saturating_add(1);
                let recorded = outcome(&r).unwrap_or(Word::Deny);
                let basis = match field(&r, "nonce") {
                    Some(Value::Bytes(n)) => self.openings.get(n),
                    _ => None,
                };
                if let Err(reason) = replay_decision(&state, &r, recorded, basis, self.resumed) {
                    self.diverged(&r, Kind::ReEvaluation, reason);
                }
            }
            _ => {}
        }
        if fold::apply(&mut state, &r).is_err() {
            self.diverged(&r, Kind::Fold, Reason::Fold);
            return Ok(());
        }
        self.state = Some(state);
        Ok(())
    }

    /// The divergence set of what did not replay over `range`, by `evaluator` at `at`; `None`
    /// when everything replayed or Genesis was not seen.
    #[must_use]
    pub fn set(&self, range: (u64, u64), evaluator: &str, at: u64) -> Option<DivergenceSet> {
        if self.items.is_empty() {
            return None;
        }
        Some(DivergenceSet {
            domain: self.domain?,
            range,
            items: self.items.clone(),
            evaluator: String::from(evaluator),
            at,
        })
    }
}

/// What a replay found (`divergence-set`, recovery.cddl): signed by the replaying party, it
/// never stops an exit (G32).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergenceSet {
    /// `DomainID`.
    pub domain: Digest,
    /// First and last position replayed.
    pub range: (u64, u64),
    /// What did not replay; never empty.
    pub items: Vec<Item>,
    /// The replaying evaluator's build identity.
    pub evaluator: String,
    /// When, Unix ms.
    pub at: u64,
}

fn entries(e: Vec<(&str, Value)>) -> Value {
    Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
}

fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, ReplayError> {
    match v.get(k) {
        Some(Value::Text(t)) => Ok(t),
        _ => Err(ReplayError::Set),
    }
}

fn number(v: &Value, k: &str) -> Result<u64, ReplayError> {
    uint(v.get(k)).ok_or(ReplayError::Set)
}

impl DivergenceSet {
    /// The `divergence-set` value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let items = self
            .items
            .iter()
            .map(|i| {
                entries(alloc::vec![
                    ("position", Value::Unsigned(i.position)),
                    ("exercise", i.exercise.to_value()),
                    ("kind", Value::text(i.kind.word())),
                    ("recorded", Value::text(i.recorded.word())),
                    ("replayed", Value::text(i.replayed.word())),
                ])
            })
            .collect();
        entries(alloc::vec![
            ("domain", self.domain.to_value()),
            (
                "range",
                entries(alloc::vec![
                    ("from", Value::Unsigned(self.range.0)),
                    ("to", Value::Unsigned(self.range.1)),
                ]),
            ),
            ("items", Value::Array(items)),
            ("evaluator", Value::text(&self.evaluator)),
            ("at", Value::Unsigned(self.at)),
        ])
    }

    /// Its deterministic CBOR bytes, which the replaying party signs.
    ///
    /// # Errors
    /// [`ReplayError::Set`] outside the encoder's limits.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ReplayError> {
        let v = dcbor::decode(
            &dcbor::encode(&self.to_value(), Limits::CEILING).map_err(|_| ReplayError::Set)?,
            Limits::CEILING,
        )
        .map_err(|_| ReplayError::Set)?;
        dcbor::encode(&v, Limits::CEILING).map_err(|_| ReplayError::Set)
    }

    /// Reads a `divergence-set` value; the item reasons are not carried and read as
    /// [`Reason::Fold`] for a fold item, [`Reason::Basis`] otherwise.
    ///
    /// # Errors
    /// [`ReplayError::Set`].
    pub fn from_value(v: &Value) -> Result<Self, ReplayError> {
        let domain = v
            .get("domain")
            .and_then(|d| <Digest as Canonical>::from_value(d).ok())
            .ok_or(ReplayError::Set)?;
        let range = v.get("range").ok_or(ReplayError::Set)?;
        let range = (number(range, "from")?, number(range, "to")?);
        if range.1 < range.0 {
            return Err(ReplayError::Set);
        }
        let Some(Value::Array(raw)) = v.get("items") else {
            return Err(ReplayError::Set);
        };
        let mut items = Vec::with_capacity(raw.len());
        for i in raw {
            let kind = match text(i, "kind")? {
                "fold" => Kind::Fold,
                "re-evaluation" => Kind::ReEvaluation,
                _ => return Err(ReplayError::Set),
            };
            let position = number(i, "position")?;
            if position < range.0 || position > range.1 {
                return Err(ReplayError::Set);
            }
            items.push(Item {
                position,
                exercise: i
                    .get("exercise")
                    .and_then(|d| <Digest as Canonical>::from_value(d).ok())
                    .ok_or(ReplayError::Set)?,
                kind,
                recorded: Word::of(text(i, "recorded")?).ok_or(ReplayError::Set)?,
                replayed: Word::of(text(i, "replayed")?).ok_or(ReplayError::Set)?,
                reason: if kind == Kind::Fold {
                    Reason::Fold
                } else {
                    Reason::Basis
                },
            });
        }
        let evaluator = text(v, "evaluator")?;
        if items.is_empty() || evaluator.is_empty() || evaluator.len() > 255 {
            return Err(ReplayError::Set);
        }
        Ok(Self {
            domain,
            range,
            items,
            evaluator: String::from(evaluator),
            at: number(v, "at")?,
        })
    }
}

/// A [`DivergenceSet`] with the replaying party's Ed25519 signature over its bytes
/// (`signed-divergence-set`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSet {
    /// The set.
    pub set: DivergenceSet,
    /// The signer's raw Ed25519 public key.
    pub key: [u8; 32],
    /// The signature.
    pub sig: [u8; 64],
}

impl SignedSet {
    /// The `signed-divergence-set` bytes.
    ///
    /// # Errors
    /// [`ReplayError::Set`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, ReplayError> {
        let v = entries(alloc::vec![
            ("set", self.set.to_value()),
            ("key", Value::Bytes(self.key.to_vec())),
            ("sig", Value::Bytes(self.sig.to_vec())),
        ]);
        let v = dcbor::decode(
            &dcbor::encode(&v, Limits::CEILING).map_err(|_| ReplayError::Set)?,
            Limits::CEILING,
        )
        .map_err(|_| ReplayError::Set)?;
        dcbor::encode(&v, Limits::CEILING).map_err(|_| ReplayError::Set)
    }

    /// Reads and verifies `signed-divergence-set` bytes: the signature must verify under the
    /// key it names; whether that key may speak for the domain is the reader's question.
    ///
    /// # Errors
    /// [`ReplayError::Set`].
    pub fn verify(backend: &impl Backend, bytes: &[u8]) -> Result<Self, ReplayError> {
        let v = dcbor::decode(bytes, Limits::CEILING).map_err(|_| ReplayError::Set)?;
        let Value::Map(m) = &v else {
            return Err(ReplayError::Set);
        };
        if m.len() != 3 {
            return Err(ReplayError::Set);
        }
        let set = DivergenceSet::from_value(v.get("set").ok_or(ReplayError::Set)?)?;
        let key: [u8; 32] = match v.get("key") {
            Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| ReplayError::Set)?,
            _ => return Err(ReplayError::Set),
        };
        let sig: [u8; 64] = match v.get("sig") {
            Some(Value::Bytes(b)) => b.as_slice().try_into().map_err(|_| ReplayError::Set)?,
            _ => return Err(ReplayError::Set),
        };
        let message = set.to_bytes()?;
        ed25519(backend, &key, &message, &sig).map_err(|_| ReplayError::Set)?;
        Ok(Self { set, key, sig })
    }
}

/// Of each 10 000 decisions a sampling agent re-evaluates at the CT2 rate, how many: 1 %
/// (POLICY DEFAULT, §13.3, OP-158 m.3 (h)). CT3 is re-evaluated whole.
pub const CT2_PER_10K: u16 = 100;

/// Whether a decision record changes authority state: one of its effects sets or removes an
/// Anchor, Grant, Party, Instance, Mandate, Acceptance or policy. A record does not carry its
/// consequence tier; a sampling agent re-evaluates these whole, as CT3, and the others at the
/// CT2 rate (OP-158 m.3 (h)).
#[must_use]
pub fn changes_authority(d: &Disclosure) -> bool {
    let Some(Value::Array(effects)) = d.opened.get("effects").map(|f| &f.value) else {
        return false;
    };
    effects.iter().any(|e| {
        let Value::Array(e) = e else { return false };
        let Some(Value::Bytes(k)) = e.first() else {
            return false;
        };
        matches!(
            dcbor::decode(k, Limits::CEILING),
            Ok(Value::Array(parts)) if matches!(
                parts.first(),
                Some(Value::Text(t)) if [
                    kind::ANCHOR, kind::GRANT, kind::PARTY, kind::INSTANCE, kind::MANDATE,
                    kind::ACCEPTANCE, kind::POLICY,
                ].contains(&t.as_str())
            )
        )
    })
}

/// The CT2-rate sample: `prf` is the agent's keyed, deterministic function of the `ExerciseID`,
/// which the provider cannot predict (OP-158 m.3 (h)); its first two bytes pick 1 in 100.
#[must_use]
pub fn sampled(prf: &[u8; 32]) -> bool {
    let [a, b, ..] = *prf;
    u16::from_be_bytes([a, b]).checked_rem(10_000).unwrap_or(0) < CT2_PER_10K
}
