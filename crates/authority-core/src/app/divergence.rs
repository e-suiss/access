//! Rebuild-diff and divergence (§16.5, RT9, TI-1, TI-16, TI-RT1, G32, G33, OP-158 m.3 (i)).
//!
//! - A fold difference: the state the recorded effects build is not the live state. The
//!   domain's commits stop (a fold notice holds every leader off, sev-1), the fold from Genesis
//!   arbitrates and the live state is rebuilt from the log, which wins; the log is never
//!   rewritten.
//! - A re-evaluation difference: a recorded outcome is not what the open evaluator replays. It
//!   is declared and stops nothing (G32); quarantine is the root's or the Security Party's own
//!   narrowing `policy.set` ([`crate::restrict::patterns::divergence_quarantine`]). The
//!   provider writes no restriction.

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::fold::State;
use access_kernel::record::RecordEnvelope;
use access_store::Pool;
use access_store::divergence::{self, FoldedRow, NewNotice};
use access_store::scope::DomainId;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;

/// What a rebuild-diff found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diff {
    /// The last position folded.
    pub head: u64,
    /// The keys whose live row is not the fold's, in key order.
    pub differing: Vec<Vec<u8>>,
}

/// How many records one read of the log takes while folding.
const STEP: u64 = 4_096;

fn encode(v: &Value) -> Result<Vec<u8>, CoreError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| CoreError::Protocol("state-encoding"))
}

/// Folds `domain`'s log from position `from` (0: Genesis) over `state` up to `head`.
///
/// # Errors
/// [`CoreError::Store`]; [`CoreError::Protocol`] `fold` when the recorded effects do not
/// fold at all.
pub async fn fold_to(
    app: &Pool,
    domain: Digest,
    mut state: Option<State>,
    from: u64,
    head: u64,
) -> Result<State, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let mut at = from;
    while at <= head {
        let to = at.saturating_add(STEP).saturating_sub(1).min(head);
        for r in access_store::authority::read_log(app, &id, at, to).await? {
            let e =
                RecordEnvelope::from_bytes(&r.envelope).map_err(|_| CoreError::Protocol("fold"))?;
            match state.as_mut() {
                None => {
                    state = Some(
                        access_kernel::fold::genesis(&e)
                            .map_err(|_| CoreError::Protocol("fold"))?,
                    );
                }
                Some(s) => {
                    access_kernel::fold::apply(s, &e).map_err(|_| CoreError::Protocol("fold"))?;
                }
            }
        }
        at = to.saturating_add(1);
        if to == u64::MAX {
            break;
        }
    }
    state.ok_or(CoreError::Protocol("fold"))
}

/// The keys where the live rows differ from `folded` (TI-16). A live row without a value and at
/// version 0 is a removed key, the same as one the fold never wrote.
#[must_use]
pub fn differing(folded: &State, stored: &[access_store::authority::StateRow]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut live = std::collections::BTreeMap::new();
    for row in stored {
        live.insert(row.key.as_slice(), (row.value.as_deref(), row.version));
    }
    for (key, entry) in folded {
        let value = entry.value.as_ref().and_then(|v| encode(v).ok());
        match live.remove(key.as_slice()) {
            Some((v, version)) if v == value.as_deref() && version == entry.version => {}
            _ => out.push(key.clone()),
        }
    }
    for (key, (value, version)) in live {
        if value.is_some() || version != 0 {
            out.push(key.to_vec());
        }
    }
    out.sort();
    out
}

/// The rebuild-diff (§16.5, TI-16): folds `domain`'s log from Genesis to its head and compares
/// the result with the live state, key by key.
///
/// # Errors
/// [`CoreError`].
pub async fn rebuild_diff(app: &Pool, domain: Digest) -> Result<Diff, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let head = access_store::authority::read_head(app, &id).await?.pos;
    let folded = fold_to(app, domain, None, 0, head).await?;
    let stored = access_store::authority::state(app, &id).await?;
    Ok(Diff {
        head,
        differing: differing(&folded, &stored),
    })
}

fn tenant_of(t: Option<[u8; 16]>) -> Result<[u8; 16], CoreError> {
    t.ok_or(CoreError::Unavailable("unknown-domain"))
}

/// The evidence of a fold difference: `{domain, head, keys}` in deterministic CBOR.
fn fold_evidence(domain: &Digest, diff: &Diff) -> Result<Vec<u8>, CoreError> {
    encode(&Value::Map(vec![
        (Value::text("domain"), domain.to_value()),
        (Value::text("head"), Value::Unsigned(diff.head)),
        (
            Value::text("keys"),
            Value::Array(
                diff.differing
                    .iter()
                    .map(|k| Value::Bytes(k.clone()))
                    .collect(),
            ),
        ),
    ]))
}

/// Declares a fold difference: the domain's commits stop until [`rebuild`] (RT9, sev-1). Its
/// notice id, `None` when this same difference was declared already.
///
/// # Errors
/// [`CoreError`].
pub async fn declare_fold(
    app: &Pool,
    domain: Digest,
    diff: &Diff,
    now: u64,
) -> Result<Option<u64>, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let tenant = tenant_of(access_store::authority::domain_tenant(app, &id).await?)?;
    let set = fold_evidence(&domain, diff)?;
    let items = u32::try_from(diff.differing.len())
        .unwrap_or(u32::MAX)
        .max(1);
    let declared = divergence::declare(
        app,
        &id,
        tenant,
        &NewNotice {
            kind: "fold",
            source: "rebuild-diff",
            declared_by: None,
            range: (0, diff.head),
            items,
            first_position: diff.head,
            set: &set,
            digest: suiss_crypto::digest::sha256(&set),
        },
    )
    .await?;
    if declared.is_some() {
        // §17.8.2, OP-158 m.3 (i)
        access_telemetry::signals::INTEGRITY_ALARMS.incr(["rebuild_diff"]);
        found(app, domain, tenant, "fold", "provider", now).await;
    }
    Ok(declared)
}

/// A re-evaluation difference to declare: what the open evaluator replayed differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Declared<'a> {
    /// `rebuild-diff`, `replica` or `verifier`.
    pub source: &'a str,
    /// The replica that declared it.
    pub by: Option<&'a str>,
    /// First and last position replayed.
    pub range: (u64, u64),
    /// How many records differ, at least one.
    pub items: u32,
    /// The first that differs.
    pub first: u64,
    /// The (signed) divergence set.
    pub set: &'a [u8],
}

/// Declares a re-evaluation difference (G32, TI-RT1): nothing stops and no restriction is
/// written; the root and the Security Party are told and decide on a quarantine. Its notice
/// id, `None` when the same set was declared before.
///
/// # Errors
/// [`CoreError`].
pub async fn declare(
    app: &Pool,
    domain: Digest,
    d: &Declared<'_>,
    now: u64,
) -> Result<Option<u64>, CoreError> {
    if d.items == 0 || d.range.1 < d.range.0 || d.first < d.range.0 || d.first > d.range.1 {
        return Err(CoreError::Protocol("divergence-set"));
    }
    let id = DomainId::from_bytes(domain.0);
    let tenant = tenant_of(access_store::authority::domain_tenant(app, &id).await?)?;
    let declared = divergence::declare(
        app,
        &id,
        tenant,
        &NewNotice {
            kind: "re-evaluation",
            source: d.source,
            declared_by: d.by,
            range: d.range,
            items: d.items,
            first_position: d.first,
            set: d.set,
            digest: suiss_crypto::digest::sha256(d.set),
        },
    )
    .await?;
    if declared.is_some() {
        found(
            app,
            domain,
            tenant,
            "re-evaluation",
            d.by.unwrap_or("provider"),
            now,
        )
        .await;
    }
    Ok(declared)
}

async fn found(app: &Pool, domain: Digest, tenant: [u8; 16], kind: &str, actor: &str, now: u64) {
    tracing::error!(
        event = "replay.divergence.found",
        kind,
        "a replay of the domain's records differs (G32, TI-RT1)"
    );
    let target = access_kernel::json::b64url_encode(&domain.0);
    let row = access_store::operational::record_operational(
        app,
        &access_store::operational::OperationalEvent {
            event_type: "replay.divergence",
            occurred_at_ms: now,
            tenant: Some(tenant),
            domain: Some(domain.0),
            actor,
            target: &target,
            reason: kind,
            correlation: "",
        },
    )
    .await;
    if let Err(error) = row {
        tracing::warn!(%error, "divergence audit row not kept");
    }
}

/// Whether `domain`'s commits are stopped by a fold difference not yet rebuilt (RT9).
///
/// # Errors
/// [`CoreError::Store`].
pub async fn halted(app: &Pool, domain: Digest) -> Result<bool, CoreError> {
    Ok(divergence::fold_open(app, &DomainId::from_bytes(domain.0)).await?)
}

/// Checks `domain`'s stored log against its commitments up to `head` (FA-14, TI-RT11): every
/// record's leaf is the stored leaf hash and chains to the one before, and the Merkle root of
/// the records is the root of every checkpoint the domain signed over them. A log that passes
/// is a copy the commitments vouch for, whether it is the live one or one restored from a
/// backup.
///
/// # Errors
/// [`CoreError::Protocol`] `commitment` for the first that differs; [`CoreError::Store`].
pub async fn commitments(app: &Pool, domain: Digest, head: u64) -> Result<(), CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let size = head.saturating_add(1);
    let signed: std::collections::BTreeMap<u64, [u8; 32]> =
        access_store::mirror::checkpoints(app, &id, 0, size)
            .await?
            .into_iter()
            .map(|c| (c.size, c.root))
            .collect();
    let bad = || CoreError::Protocol("commitment");
    let mut tree = suiss_ledger::merkle::Frontier::default();
    let mut previous: Option<access_kernel::record::LeafCore> = None;
    let mut at = 0u64;
    while at <= head {
        let to = at.saturating_add(STEP).saturating_sub(1).min(head);
        for r in access_store::authority::read_log(app, &id, at, to).await? {
            let e = RecordEnvelope::from_bytes(&r.envelope).map_err(|_| bad())?;
            let core = e.leaf_core().map_err(|_| bad())?;
            let leaf = core.leaf_hash().map_err(|_| bad())?;
            if leaf != r.leaf_hash || e.header.pos != tree.size() {
                return Err(bad());
            }
            if let Some(prev) = &previous {
                access_kernel::record::check_link(prev, &core, &domain).map_err(|_| bad())?;
            }
            tree.push(leaf).map_err(|_| bad())?;
            if signed
                .get(&tree.size())
                .is_some_and(|root| *root != tree.root())
            {
                return Err(bad());
            }
            previous = Some(core);
        }
        at = to.saturating_add(1);
    }
    if tree.size() == size {
        Ok(())
    } else {
        Err(bad())
    }
}

/// Rebuilds `domain`'s live state from the fold of its log from Genesis, which wins (TI-1,
/// TI-RT1, G33), and resolves its fold notices: commits may start again. The log is checked
/// against its commitments first and is not touched (TI-RT11). No leader may hold the domain.
/// How many rows changed.
///
/// # Errors
/// [`CoreError`]; [`CoreError::Protocol`] `commitment` when the log does not match its
/// commitments: the domain stays stopped until a copy that matches is restored.
pub async fn rebuild(app: &Pool, sequencer: &Pool, domain: Digest) -> Result<u64, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let tenant = tenant_of(access_store::authority::domain_tenant(app, &id).await?)?;
    let head = access_store::authority::read_head(app, &id).await?.pos;
    commitments(app, domain, head).await?;
    let folded = fold_to(app, domain, None, 0, head).await?;
    let rows = folded
        .iter()
        .map(|(key, e)| {
            Ok(FoldedRow {
                key: key.clone(),
                value: e.value.as_ref().map(encode).transpose()?,
                version: e.version,
            })
        })
        .collect::<Result<Vec<_>, CoreError>>()?;
    Ok(divergence::rebuild_state(sequencer, &id, tenant, &rows).await?)
}
