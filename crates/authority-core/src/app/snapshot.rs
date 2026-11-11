//! Verified snapshots and the cold start from one (TI-RT4, TI-16, OP-142, OP-158 m.3 (i)).
//!
//! A snapshot is the folded state at position `pos`: its deterministic CBOR, the SHA-256 of
//! it and the root of the tree of `pos + 1` records, in a checkpoint note of that size the
//! domain's signer signs with one more line, `access-snapshot sha-256:<digest>` (the signer
//! signs checkpoint bodies only). A cold start uses the newest snapshot only when the note
//! verifies under the key of the stored checkpoint of that size, that checkpoint names the same
//! root, the state is the one the note names and a sampled fold check passes: each sampled
//! entry is what the record at its version wrote. Otherwise it folds from Genesis. A snapshot
//! only speeds the fold up; the log stays canonical.

use access_authority_sequencer::ports::NoteSigner;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::fold::{Entry, State};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::record::RecordEnvelope;
use access_store::Pool;
use access_store::divergence::{Snapshot, keep_snapshot, snapshot_before};
use access_store::scope::DomainId;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::note::{Checkpoint, Verifier, verify_checkpoint};
use suiss_crypto::sig::PureBackend;
use suiss_ledger::merkle::Frontier;

use crate::CoreError;

/// The note line that names the snapshot's state digest.
pub const STATE_LINE: &str = "access-snapshot sha-256:";

/// The note line that names when the snapshot was signed.
pub const ISSUED_LINE: &str = "access-snapshot-issued ";

/// How many entries a cold start checks against the records that wrote them (PD).
pub const SAMPLE: usize = 32;

/// Where a cold start began.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    /// From a verified snapshot at this position.
    Snapshot(u64),
    /// From Genesis: there was no snapshot, or it did not verify (TI-RT4).
    Genesis,
}

fn origin(domain: &Digest) -> String {
    format!("sha-256:{}", b64url_encode(&domain.0))
}

fn encode(v: &Value) -> Result<Vec<u8>, CoreError> {
    dcbor::encode(v, Limits::CEILING).map_err(|_| CoreError::Protocol("snapshot"))
}

/// The state's deterministic CBOR: `[[key, version, ? value], …]` in key order.
///
/// # Errors
/// [`CoreError::Protocol`] outside the encoder's limits.
pub fn state_bytes(state: &State) -> Result<Vec<u8>, CoreError> {
    encode(&Value::Array(
        state
            .iter()
            .map(|(k, e)| {
                let mut row = vec![Value::Bytes(k.clone()), Value::Unsigned(e.version)];
                if let Some(v) = &e.value {
                    row.push(v.clone());
                }
                Value::Array(row)
            })
            .collect(),
    ))
}

fn state_of(bytes: &[u8]) -> Option<State> {
    let Ok(Value::Array(rows)) = dcbor::decode(bytes, Limits::CEILING) else {
        return None;
    };
    let mut out = State::new();
    for r in rows {
        let Value::Array(r) = r else { return None };
        let (key, version, value) = match r.as_slice() {
            [Value::Bytes(k), Value::Unsigned(v)] => (k.clone(), *v, None),
            [Value::Bytes(k), Value::Unsigned(v), value] => (k.clone(), *v, Some(value.clone())),
            _ => return None,
        };
        if out.insert(key, Entry { value, version }).is_some() {
            return None;
        }
    }
    Some(out)
}

/// Takes a snapshot of `domain` at its head: folds the log (from a verified snapshot when one
/// exists), has `signer` sign the note at `now` and keeps it. The snapshot.
///
/// # Errors
/// [`CoreError`]; [`CoreError::Unavailable`] `signer` when the signer refuses or is down.
pub async fn take<S: NoteSigner + Sync>(
    app: &Pool,
    signer: &S,
    domain: Digest,
    now: u64,
) -> Result<Snapshot, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let tenant = access_store::authority::domain_tenant(app, &id)
        .await?
        .ok_or(CoreError::Unavailable("unknown-domain"))?;
    let pos = access_store::authority::read_head(app, &id).await?.pos;
    let (state, _) = cold_start(app, domain, pos).await?;
    let state = state_bytes(&state)?;
    let digest = suiss_crypto::digest::sha256(&state);
    let size = pos.checked_add(1).ok_or(CoreError::Protocol("snapshot"))?;
    let mut tree = Frontier::default();
    for h in access_store::mirror::leaf_hashes(app, &id, 0, size).await? {
        tree.push(h).map_err(|_| CoreError::Protocol("snapshot"))?;
    }
    let body = Checkpoint {
        origin: origin(&domain),
        size,
        root: tree.root(),
        extensions: vec![
            format!("{STATE_LINE}{}", b64url_encode(&digest)),
            format!("{ISSUED_LINE}{now}"),
        ],
    }
    .to_body()
    .map_err(|_| CoreError::Protocol("snapshot"))?;
    let noted = signer
        .sign_note(domain, body.clone(), now)
        .await
        .map_err(|_| CoreError::Unavailable("signer"))?;
    let snapshot = Snapshot {
        pos,
        root: tree.root(),
        state_digest: digest,
        state,
        note: format!("{body}\n{}", noted.line),
    };
    keep_snapshot(app, &id, tenant, &snapshot).await?;
    Ok(snapshot)
}

/// The log key of the stored checkpoint of exactly `size` and `root`, if one was signed.
async fn log_key(
    app: &Pool,
    domain: &Digest,
    size: u64,
    root: &[u8; 32],
) -> Result<Option<Verifier>, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let rows = access_store::mirror::checkpoints(app, &id, size.saturating_sub(1), size).await?;
    let Some(row) = rows.into_iter().find(|r| r.size == size && &r.root == root) else {
        return Ok(None);
    };
    let key = suiss_crypto::cose::parse_sign1(&row.excerpt)
        .ok()
        .and_then(|s| s.payload)
        .and_then(|p| access_kernel::verify::key_scope::KeyExcerpt::from_bytes(&p).ok())
        .and_then(|ex| match ex.key.key {
            suiss_crypto::cose::PublicKey::Ed25519(k) => Some(k),
            _ => None,
        });
    Ok(key.and_then(|k| Verifier::ed25519(&origin(domain), k).ok()))
}

/// Whether the entry `(key, e)` is what the record at its version wrote (L2-REC-3).
async fn written(app: &Pool, domain: &Digest, key: &[u8], e: &Entry) -> Result<bool, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let Some(r) = access_store::authority::read_log(app, &id, e.version, e.version)
        .await?
        .into_iter()
        .next()
    else {
        return Ok(false);
    };
    let Ok(record) = RecordEnvelope::from_bytes(&r.envelope) else {
        return Ok(false);
    };
    let canonical = |v: Option<&Value>| v.map(|v| dcbor::encode(v, Limits::CEILING).ok());
    let want = canonical(e.value.as_ref());
    if e.version == 0 {
        return Ok(access_kernel::fold::genesis(&record)
            .ok()
            .and_then(|g| g.get(key).cloned())
            .is_some_and(|g| canonical(g.value.as_ref()) == want));
    }
    Ok(access_kernel::fold::effects(&record).is_ok_and(|fx| {
        fx.iter()
            .any(|(k, v)| k.as_slice() == key && canonical(v.as_ref()) == want)
    }))
}

/// Whether `s` may start a fold (TI-RT4): its note verifies under the key of the stored
/// checkpoint of its size, which names the same root; its state is the digest the note names;
/// and every sampled entry is what the record at its version wrote. The state, when it may.
async fn verified(
    app: &Pool,
    domain: &Digest,
    snap: &Snapshot,
) -> Result<Option<State>, CoreError> {
    let Some(size) = snap.pos.checked_add(1) else {
        return Ok(None);
    };
    let Some(key) = log_key(app, domain, size, &snap.root).await? else {
        return Ok(None);
    };
    let Ok((cp, _)) = verify_checkpoint(&PureBackend, &snap.note, &origin(domain), &key, &[])
    else {
        return Ok(None);
    };
    let named = cp
        .extensions
        .iter()
        .find_map(|l| l.strip_prefix(STATE_LINE))
        .and_then(|d| b64url_decode(d).ok());
    if cp.size != size
        || cp.root != snap.root
        || named.as_deref() != Some(snap.state_digest.as_slice())
        || suiss_crypto::digest::sha256(&snap.state) != snap.state_digest
    {
        return Ok(None);
    }
    let Some(state) = state_of(&snap.state) else {
        return Ok(None);
    };
    let count = state.len();
    if count == 0 {
        return Ok(None);
    }
    let draws =
        access_crypto::random::bytes::<32>().map_err(|_| CoreError::Unavailable("random"))?;
    let keys: Vec<(&Vec<u8>, &Entry)> = state.iter().collect();
    let take = SAMPLE.min(count);
    for i in 0..take {
        let seed = suiss_crypto::digest::sha256(
            &[
                draws.as_slice(),
                &u64::try_from(i).unwrap_or(0).to_be_bytes(),
            ]
            .concat(),
        );
        let [b0, b1, b2, b3, ..] = seed;
        let at = usize::try_from(u32::from_be_bytes([b0, b1, b2, b3]))
            .unwrap_or(0)
            .checked_rem(count)
            .unwrap_or(0);
        let Some((k, e)) = keys.get(at) else {
            return Ok(None);
        };
        if !written(app, domain, k, e).await? {
            return Ok(None);
        }
    }
    Ok(Some(state))
}

/// The state of the newest snapshot of `domain` at or before `head` and its position, when it
/// verifies (TI-RT4).
///
/// # Errors
/// [`CoreError`].
pub async fn verified_before(
    app: &Pool,
    domain: Digest,
    head: u64,
) -> Result<Option<(State, u64)>, CoreError> {
    let id = DomainId::from_bytes(domain.0);
    let Some(s) = snapshot_before(app, &id, head).await? else {
        return Ok(None);
    };
    Ok(verified(app, &domain, &s)
        .await?
        .map(|state| (state, s.pos)))
}

/// The cold start (TI-RT4): the state of `domain` folded up to `head`, from the newest snapshot
/// at or before it that verifies, otherwise from Genesis; and where it began.
///
/// # Errors
/// [`CoreError`].
pub async fn cold_start(
    app: &Pool,
    domain: Digest,
    head: u64,
) -> Result<(State, Start), CoreError> {
    if let Some((state, pos)) = verified_before(app, domain, head).await? {
        let from = pos.saturating_add(1);
        let state = if from > head {
            state
        } else {
            super::divergence::fold_to(app, domain, Some(state), from, head).await?
        };
        return Ok((state, Start::Snapshot(pos)));
    }
    tracing::info!("no verified snapshot; the fold starts from Genesis (TI-RT4)");
    Ok((
        super::divergence::fold_to(app, domain, None, 0, head).await?,
        Start::Genesis,
    ))
}
