//! Cooperative handover and binding re-anchor on the authority side (§16.6 HO-1…HO-9, §16.6.1
//! RB-0…RB-6, U27, U11, PI-15, OP-158 m.3 (l)).
//!
//! - The outgoing provider freezes the domain at `k = head + 1`; nothing commits but the
//!   handover batch. The batch is the two binding-signed statements, as Claim records at `k`
//!   and `k + 1`, and the root's `domain_handover` Exercise, whose decision is `h`.
//! - The incoming provider reads the export package to `C_k`, folds it, reproduces `C_k`'s root
//!   and re-evaluates every decision it can; a difference is a divergence set, which stops
//!   nothing (G32). It answers with its continuation statement, signed by its binding.
//! - After the batch and the witnessed `C_{h+1}`, the incoming provider adopts the domain at
//!   `h + 1`; the outgoing provider's domain stays frozen (the database fence) and the witnesses
//!   fence its binding above `h + 1` (U11).

use access_authority_sequencer::domain::{Draft, Item};
use access_authority_sequencer::ports::DomainLog;
use access_authority_signer::handover::{CONTINUATION, Cited, Continuation, NO_WRITE, NoWrite};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::fold::State;
use access_kernel::record::{Disclosure, RecordEnvelope, RecordKind};
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::Authority;
use crate::ports::{Binding, Reader, Salts};

/// The provider conformance profile the incoming provider must pass (§9.1 L3, OP-157 m.3 (s)).
pub const PROVIDER_PROFILE: &str = include_str!("../../../../conformance/profiles/provider.toml");

/// The registry class of the outgoing binding's no-write statement record.
pub const NO_WRITE_CLASS: &str = "handover_no_write";

/// The registry class of the incoming binding's continuation statement record.
pub const CONTINUATION_CLASS: &str = "handover_continuation";

/// The refusal of a write while the domain is frozen.
pub const FROZEN: &str = "handover-frozen";

/// The refusal of a handover to a provider that did not pass the provider profile.
pub const NOT_CONFORMANT: &str = "provider-not-conformant";

/// `SHA-256("access/provider-conformance/v1" ‖ 0x00 ‖ profile ‖ core version)`: what a passing
/// provider-profile run of this open Kernel names. Both installs run the same open vectors, so
/// the outgoing provider recomputes it.
#[must_use]
pub fn conformance_digest() -> Digest {
    let mut input = PROVIDER_PROFILE.as_bytes().to_vec();
    input.extend_from_slice(&access_kernel::version::CORE.to_be_bytes());
    Digest(suiss_crypto::digest::context_digest("access/provider-conformance/v1", &input).0)
}

/// Why a handover step is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HandoverError {
    /// The package is not a whole, full-disclosure export of the domain from Genesis to `C_k`.
    #[error("package: {0}")]
    Package(&'static str),
    /// The re-folded root is not `C_k`'s.
    #[error("root")]
    Root,
    /// The batch or `C_{h+1}` is not the handover the incoming provider answered.
    #[error("batch: {0}")]
    Batch(&'static str),
}

/// What the incoming provider took from the export package (HO-5).
#[derive(Clone, Debug)]
pub struct Received {
    /// The domain.
    pub domain: Digest,
    /// `C_k`.
    pub cited: Cited,
    /// The records `0..k − 1`, as committed.
    pub records: Vec<RecordEnvelope>,
    /// The folded state at `k − 1`.
    pub state: State,
    /// The records as the package disclosed them, for the incoming provider's replay: a
    /// decision it does not reproduce is a divergence set, never a reason to stop (G32).
    pub disclosed: Vec<Disclosure>,
}

/// HO-5: reads `package`, checks it runs from Genesis to `cited` in full disclosure, folds it
/// and reproduces `cited`'s root.
///
/// # Errors
/// [`HandoverError`].
pub fn receive(package: &[u8], cited: Cited) -> Result<Received, HandoverError> {
    let read = crate::domain::export::read_stream(package)
        .map_err(|_| HandoverError::Package("stream"))?;
    if read.coverage != crate::domain::export::Coverage::Full
        || read.range.0 != 0
        || read.range.1.checked_add(1) != Some(cited.0)
    {
        return Err(HandoverError::Package("range"));
    }
    if read.size != cited.0 || read.root != cited.1 {
        return Err(HandoverError::Root);
    }
    let mut records = Vec::with_capacity(read.records.len());
    let mut state = None;
    for (i, d) in read.records.iter().enumerate() {
        if !d.withheld.is_empty() || u64::try_from(i).ok() != Some(d.header.pos) {
            return Err(HandoverError::Package("record"));
        }
        let r = envelope(d);
        match state.as_mut() {
            None => {
                state = Some(
                    access_kernel::fold::genesis(&r)
                        .map_err(|_| HandoverError::Package("genesis"))?,
                );
            }
            Some(s) => {
                access_kernel::fold::apply(s, &r).map_err(|_| HandoverError::Package("fold"))?;
            }
        }
        records.push(r);
    }
    let domain = records
        .first()
        .and_then(|g| g.domain().ok())
        .ok_or(HandoverError::Package("genesis"))?;
    Ok(Received {
        domain,
        cited,
        records,
        state: state.ok_or(HandoverError::Package("genesis"))?,
        disclosed: read.records,
    })
}

fn envelope(d: &Disclosure) -> RecordEnvelope {
    RecordEnvelope {
        header: d.header.clone(),
        fields: d.opened.clone(),
    }
}

/// HO-5: the continuation statement the incoming provider `provider` signs for `received` at
/// `now`.
#[must_use]
pub fn continuation(received: &Received, provider: &str, now: u64) -> Continuation {
    Continuation {
        domain: received.domain,
        provider: String::from(provider),
        from: received.cited,
        conformance: conformance_digest(),
        at: now,
    }
}

/// HO-6: the no-write statement of the outgoing provider `provider` for `domain`, frozen at
/// `frozen_at`, at `now`.
#[must_use]
pub fn no_write(domain: Digest, provider: &str, cited: Cited, frozen_at: u64, now: u64) -> NoWrite {
    NoWrite {
        domain,
        provider: String::from(provider),
        last: cited,
        frozen_at,
        at: now,
    }
}

/// One binding-signed statement the handover batch records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// [`NO_WRITE_CLASS`] or [`CONTINUATION_CLASS`].
    pub class: &'static str,
    /// The `COSE_Sign1`.
    pub sign1: Vec<u8>,
}

impl Statement {
    /// The statement of `content_type` signed as `sign1`.
    #[must_use]
    pub fn of(content_type: &str, sign1: Vec<u8>) -> Option<Self> {
        let class = match content_type {
            NO_WRITE => NO_WRITE_CLASS,
            CONTINUATION => CONTINUATION_CLASS,
            _ => return None,
        };
        Some(Self { class, sign1 })
    }
}

/// Whether the decision envelope `bytes` writes the provider binding (`domain_handover` or
/// `domain_recover`, PI-15).
#[must_use]
pub fn moves_binding(bytes: &[u8]) -> bool {
    let Ok(record) = RecordEnvelope::from_bytes(bytes) else {
        return false;
    };
    record.header.kind == RecordKind::Decision
        && access_kernel::fold::effects(&record).is_ok_and(|e| {
            let key = access_kernel::recovery::binding_key();
            e.iter().any(|(k, v)| *k == key && v.is_some())
        })
}

/// The new binding keys a decision envelope writes, with how (`handover`, `recover`).
#[must_use]
pub fn binding_of(
    record: &RecordEnvelope,
) -> Option<(Vec<access_kernel::verify::key_scope::BindingKey>, String)> {
    let key = access_kernel::recovery::binding_key();
    let effects = access_kernel::fold::effects(record).ok()?;
    let (_, Some(v)) = effects.into_iter().find(|(k, _)| *k == key)? else {
        return None;
    };
    let Some(Value::Text(how)) = v.get("how") else {
        return None;
    };
    let Some(Value::Array(keys)) = v.get("binding") else {
        return None;
    };
    let keys = keys
        .iter()
        .map(|k| access_kernel::verify::key_scope::BindingKey::from_value(k).ok())
        .collect::<Option<Vec<_>>>()?;
    Some((keys, how.clone()))
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Keeps the verified statements of the handover batch the next commit records ahead of
    /// its `domain_handover` Exercise (HO-6).
    pub(crate) fn stage_handover(&mut self, statements: Vec<Statement>) {
        self.handover = statements;
    }

    /// The staged statements as Claim records: no effects, the statement itself in the record
    /// so the log alone shows the double signature (RB-4).
    pub(crate) fn statement_items(&mut self) -> Result<Vec<Item>, CoreError> {
        let staged = self.handover.clone();
        let mut out = Vec::with_capacity(staged.len());
        for s in staged {
            let digest = access_kernel::claim::claim_digest(&s.sign1);
            out.push(Item {
                draft: Draft {
                    kind: RecordKind::Claim,
                    fields: super::fields(
                        &mut self.salts,
                        vec![
                            ("claim", digest.to_value()),
                            ("class", Value::text(s.class)),
                            ("statement", Value::Bytes(s.sign1.clone())),
                        ],
                    )?,
                },
                nonce: None,
                events: Vec::new(),
                proofs: vec![(digest.0, s.sign1)],
                reads: Vec::new(),
                writes: Vec::new(),
                draws: Vec::new(),
                single_use: Vec::new(),
            });
        }
        Ok(out)
    }
}

/// HO-8: what the incoming provider adopts once the batch and `C_{h+1}` came through the
/// mirror: every record from Genesis to `h`, the state the fold holds at `h`, and the head.
#[derive(Clone, Debug)]
pub struct TakeOver {
    /// The domain.
    pub domain: Digest,
    /// `C_k`.
    pub cited: Cited,
    /// `h`.
    pub h: u64,
    /// `C_{h+1}`'s root.
    pub at: [u8; 32],
    /// The store's adoption, run id included.
    pub adoption: access_store::handover::Adoption,
    /// The outgoing binding keys, superseded at `C_{h+1}` citing `C_k` (HO-8).
    pub superseded: Vec<access_kernel::verify::key_scope::BindingKey>,
}

fn kind_word(k: RecordKind) -> &'static str {
    match k {
        RecordKind::Genesis => "genesis",
        RecordKind::Opening => "opening",
        RecordKind::Decision => "decision",
        RecordKind::Claim => "claim",
    }
}

fn class_of(r: &RecordEnvelope) -> Option<&str> {
    match r.fields.get("class").map(|f| &f.value) {
        Some(Value::Text(t)) => Some(t.as_str()),
        _ => None,
    }
}

fn statement_of(r: &RecordEnvelope) -> Option<&[u8]> {
    match r.fields.get("statement").map(|f| &f.value) {
        Some(Value::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    }
}

fn adopted_nonces(
    records: &[RecordEnvelope],
) -> Result<Vec<access_store::handover::AdoptedNonce>, HandoverError> {
    let field = |r: &RecordEnvelope, k: &str| r.fields.get(k).map(|f| f.value.clone());
    let mut actors: std::collections::BTreeMap<Vec<u8>, Vec<u8>> =
        std::collections::BTreeMap::new();
    let mut out = Vec::new();
    for r in records {
        let Some(Value::Bytes(nonce)) = field(r, "nonce") else {
            continue;
        };
        match r.header.kind {
            RecordKind::Opening => {
                let actor = match field(r, "actor") {
                    Some(Value::Bytes(b)) => b,
                    _ => b"anonymous".to_vec(),
                };
                actors.insert(nonce, actor);
            }
            RecordKind::Decision => {
                let intent = field(r, "intent")
                    .and_then(|v| Digest::from_value(&v))
                    .ok_or(HandoverError::Package("intent"))?;
                let outcome = match field(r, "outcome").as_ref().and_then(|o| o.get("outcome")) {
                    Some(Value::Text(t)) => t.clone(),
                    _ => return Err(HandoverError::Package("outcome")),
                };
                out.push(access_store::handover::AdoptedNonce {
                    actor: actors
                        .get(&nonce)
                        .cloned()
                        .unwrap_or_else(|| b"anonymous".to_vec()),
                    nonce,
                    intent_digest: intent.0,
                    decision_pos: r.header.pos,
                    outcome,
                });
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Keys with an amount or a position.
type Keyed = Vec<(Vec<u8>, u64)>;

fn consumed(records: &[RecordEnvelope]) -> (Keyed, Keyed) {
    let mut counters: std::collections::BTreeMap<Vec<u8>, u64> = std::collections::BTreeMap::new();
    let mut single = Vec::new();
    for r in records {
        let Some(c) = r.fields.get("consumption").map(|f| &f.value) else {
            continue;
        };
        if let Some(Value::Array(draws)) = c.get("draws") {
            for d in draws {
                if let Value::Array(pair) = d
                    && let [Value::Bytes(k), Value::Unsigned(n)] = pair.as_slice()
                {
                    let e = counters.entry(k.clone()).or_default();
                    *e = e.saturating_add(*n);
                }
            }
        }
        if let Some(Value::Array(keys)) = c.get("single_use") {
            for k in keys {
                if let Value::Bytes(k) = k {
                    single.push((k.clone(), r.header.pos));
                }
            }
        }
    }
    (counters.into_iter().collect(), single)
}

/// HO-6, RB-4: the batch starts at `k` with the outgoing binding's no-write statement and the
/// incoming provider's own continuation, and ends with the `domain_handover` decision that
/// binds `mine`; that decision.
fn check_batch<'a>(
    received: &Received,
    batch: &'a [RecordEnvelope],
    (continuation, mine): (&[u8], &access_kernel::verify::key_scope::BindingKey),
    outgoing: &[access_kernel::verify::key_scope::BindingKey],
) -> Result<&'a RecordEnvelope, HandoverError> {
    let k = received.cited.0;
    let [first, second, .., last] = batch else {
        return Err(HandoverError::Batch("short"));
    };
    if first.header.pos != k
        || class_of(first) != Some(NO_WRITE_CLASS)
        || class_of(second) != Some(CONTINUATION_CLASS)
        || statement_of(second) != Some(continuation)
    {
        return Err(HandoverError::Batch("statements"));
    }
    let no_write = statement_of(first).ok_or(HandoverError::Batch("statements"))?;
    let (payload, _) = access_authority_signer::handover::verify(
        &suiss_crypto::sig::PureBackend,
        no_write,
        outgoing,
        NO_WRITE,
    )
    .map_err(|_| HandoverError::Batch("no-write"))?;
    let nw = NoWrite::from_bytes(&payload).map_err(|_| HandoverError::Batch("no-write"))?;
    if nw.domain != received.domain || nw.last != received.cited {
        return Err(HandoverError::Batch("no-write"));
    }
    match binding_of(last) {
        Some((keys, how)) if how == "handover" && keys.iter().any(|b| b.kid == mine.kid) => {}
        _ => return Err(HandoverError::Batch("binding")),
    }
    Ok(last)
}

/// HO-8: checks the batch `k..h` and the witnessed `C_{h+1}` the incoming provider read from
/// the outgoing provider's mirror against what it answered: the batch starts at `k` with the
/// outgoing binding's no-write statement and this provider's own `continuation` statement, ends
/// with the `domain_handover` decision that binds `mine`, folds on the received state, and
/// `note` is `C_{h+1}` over exactly those records with a cosignature of an independent
/// `witnesses` key. The adoption for the store, as run `run`.
///
/// # Errors
/// [`HandoverError::Batch`].
pub fn take_over(
    received: &Received,
    batch: &[RecordEnvelope],
    (continuation, mine): (&[u8], &access_kernel::verify::key_scope::BindingKey),
    (note, witnesses): (&str, &[suiss_crypto::note::Verifier]),
    outgoing: &[access_kernel::verify::key_scope::BindingKey],
    run: [u8; 16],
) -> Result<TakeOver, HandoverError> {
    let k = received.cited.0;
    let last = check_batch(received, batch, (continuation, mine), outgoing)?;
    let mut state = received.state.clone();
    let mut all: Vec<RecordEnvelope> = received.records.clone();
    for (i, r) in batch.iter().enumerate() {
        if Some(r.header.pos) != k.checked_add(u64::try_from(i).unwrap_or(u64::MAX)) {
            return Err(HandoverError::Batch("order"));
        }
        access_kernel::fold::apply(&mut state, r).map_err(|_| HandoverError::Batch("fold"))?;
        all.push(r.clone());
    }
    let mut frontier = suiss_ledger::merkle::Frontier::default();
    let mut rows = Vec::with_capacity(all.len());
    for r in &all {
        let leaf = r.leaf_hash().map_err(|_| HandoverError::Batch("leaf"))?;
        frontier
            .push(leaf)
            .map_err(|_| HandoverError::Batch("leaf"))?;
        rows.push(access_store::authority::LogRecord {
            pos: r.header.pos,
            kind: kind_word(r.header.kind),
            recorded_at: r.header.recorded_at,
            leaf_hash: leaf,
            envelope: r.to_bytes().map_err(|_| HandoverError::Batch("encode"))?,
        });
    }
    let (cosigned, accepted) =
        suiss_crypto::note::verify_note(&suiss_crypto::sig::PureBackend, note, witnesses)
            .map_err(|_| HandoverError::Batch("witness"))?;
    let cp = suiss_crypto::note::Checkpoint::parse(&cosigned.body)
        .map_err(|_| HandoverError::Batch("checkpoint"))?;
    let h = last.header.pos;
    if accepted.iter().all(|a| a.timestamp.is_none())
        || Some(cp.size) != h.checked_add(1)
        || cp.root != frontier.root()
    {
        return Err(HandoverError::Batch("checkpoint"));
    }
    let superseded = outgoing
        .iter()
        .map(|b| {
            let mut b = b.clone();
            b.superseded = Some(access_kernel::verify::key_scope::Superseded {
                at: Digest(cp.root),
                cited: Digest(received.cited.1),
            });
            b
        })
        .collect();
    let (counters, single_use) = consumed(&all);
    let nonces = adopted_nonces(&all)?;
    let state_rows = state
        .iter()
        .map(|(key, e)| {
            let value = e
                .value
                .as_ref()
                .map(|v| suiss_crypto::dcbor::encode(v, suiss_crypto::dcbor::Limits::CEILING))
                .transpose()
                .map_err(|_| HandoverError::Batch("state"))?;
            Ok((key.clone(), value, e.version))
        })
        .collect::<Result<Vec<_>, HandoverError>>()?;
    let leaf = rows.last().map(|r| r.leaf_hash).unwrap_or_default();
    let head = access_store::authority::HeadRow {
        pos: h,
        epoch: 0,
        leaf_hash: leaf,
        recorded_at: last.header.recorded_at,
        frontier: frontier.nodes().to_vec(),
    };
    Ok(TakeOver {
        domain: received.domain,
        cited: received.cited,
        h,
        at: cp.root,
        adoption: access_store::handover::Adoption {
            run,
            k,
            cited_root: received.cited.1,
            records: rows,
            head,
            state: state_rows,
            nonces,
            counters,
            single_use,
        },
        superseded,
    })
}
