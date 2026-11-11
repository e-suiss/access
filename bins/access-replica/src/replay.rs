//! The sampling replay agent (§13.3, §17.6.13, U13, G32, FM-16, OP-158 m.3 (h)): the replica
//! operator's own build replays its copy with the open evaluator, independent of the provider's.
//! Every decision that changes authority state is re-evaluated (CT3), every other at the CT2
//! rate (1 %, POLICY DEFAULT); the sample is the agent's keyed, deterministic choice: its
//! Ed25519 signature over the `ExerciseID` (RFC 8032 signatures are deterministic), which the
//! provider cannot predict. What does not replay is signed with the agent's declared key, kept
//! in its state directory and sent to the domain; nothing stops (G32).

use std::io::Write as _;
use std::path::Path;

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::record::{Disclosure, RecordKind};
use access_verifier::replay::{Replay, SignedSet, changes_authority, sampled};
use suiss_crypto::dcbor::Value;
use suiss_crypto::signer::{Signer as _, SoftSigner};

use crate::state::{Held, Store};

/// The evaluator identity this build writes into a divergence set (FM-16: a different build).
pub(crate) const EVALUATOR: &str = concat!("access-replica/", env!("CARGO_PKG_VERSION"));

/// The context of the sampling signature.
const SAMPLE: &[u8] = b"access-replica/replay-sample/v1\0";

/// What one replay found.
pub(crate) struct Replayed {
    /// Records replayed.
    pub(crate) records: u64,
    /// Decisions re-evaluated.
    pub(crate) reevaluated: u64,
    /// Decisions that did not replay.
    pub(crate) divergent: usize,
    /// The signed set, when one did not, and the digest input of its findings.
    pub(crate) signed: Option<(Vec<u8>, Vec<u8>)>,
}

fn sample(signer: &SoftSigner, exercise: &Digest) -> Result<bool, String> {
    let mut message = SAMPLE.to_vec();
    message.extend_from_slice(&exercise.0);
    let sig = signer.sign(&message).map_err(|e| e.to_string())?;
    Ok(sampled(&suiss_crypto::digest::sha256(&sig)))
}

fn wanted(signer: &SoftSigner, domain: &Digest, d: &Disclosure) -> Result<bool, String> {
    if d.header.kind != RecordKind::Decision || changes_authority(d) {
        return Ok(true);
    }
    match d.opened.get("nonce").map(|f| &f.value) {
        Some(Value::Bytes(n)) => {
            let exercise =
                access_kernel::meta::exercise_id(domain, n).map_err(|e| e.to_string())?;
            sample(signer, &exercise)
        }
        _ => Ok(true),
    }
}

/// Replays the copy in `store` at `now` and signs what did not replay with `signer`.
pub(crate) fn replay(
    store: &Store,
    domain: Digest,
    signer: &SoftSigner,
    now: u64,
) -> Result<Replayed, String> {
    let mut r = Replay::new();
    let size = store.follower.size();
    for pos in 0..size {
        let d = match store.read(pos)? {
            Some(Held::Open(bytes) | Held::Redacted(bytes)) => {
                Disclosure::from_bytes(&bytes).map_err(|_| format!("record {pos}: malformed"))?
            }
            None => return Err(format!("record {pos}: not held")),
        };
        let reevaluate = wanted(signer, &domain, &d)?;
        r.push(&d, reevaluate)
            .map_err(|e| format!("record {pos}: {e}"))?;
    }
    let c = r.coverage();
    let to = size.saturating_sub(1);
    let set = r.set((0, to), EVALUATOR, now);
    let declared = match set {
        Some(set) => {
            let message = set.to_bytes().map_err(|e| e.to_string())?;
            let sig: [u8; 64] = signer
                .sign(&message)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "signature length")?;
            let key = crate::public(signer)?;
            let found: Vec<u8> = set
                .items
                .iter()
                .flat_map(|i| {
                    let mut b = i.position.to_be_bytes().to_vec();
                    b.extend_from_slice(&i.exercise.0);
                    b
                })
                .collect();
            Some((
                found,
                SignedSet { set, key, sig }
                    .to_bytes()
                    .map_err(|e| e.to_string())?,
            ))
        }
        None => None,
    };
    Ok(Replayed {
        records: c.records,
        reevaluated: c.reevaluated,
        divergent: r.items().len(),
        signed: declared,
    })
}

/// Keeps a signed set in `dir` under the digest of what it found (append-only evidence,
/// OP-73): `false` when the same findings were kept, and declared, before.
pub(crate) fn keep(
    dir: &Path,
    domain: &Digest,
    found: &[u8],
    signed: &[u8],
) -> Result<bool, String> {
    let dir = dir.join(b64url_encode(&domain.0)).join("divergence");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(format!(
        "{}.cbor",
        b64url_encode(&suiss_crypto::digest::sha256(found))
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut f) => f
            .write_all(signed)
            .and_then(|()| f.sync_all())
            .map(|()| true)
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}
