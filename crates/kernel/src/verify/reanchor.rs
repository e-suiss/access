//! Post-quantum re-anchor evidence (CR-45 RA-2, RA-3, RA-5, RA-7, OP-159 m.3 (g), (h)): after
//! a domain retires its classical algorithm ([`super::key_scope::classical_retired`]), a classical artefact is accepted only by an
//! inclusion bundle against a post-quantum checkpoint that reaches an anchor the verifier pinned
//! beforehand. A chain of classical signatures from Genesis to the post-quantum key never
//! replaces the pin.

use alloc::vec::Vec;

use suiss_crypto::note::Checkpoint;

use super::Backend;
use super::cose::{KeySet, PublicKey, verify_sign1};
use super::key_scope::{KeyScopeError, commits_artefact, thumbprint};
use super::pq::PqAnchor;
use crate::digest::Digest;
use crate::record::Disclosure;

/// Content type of a post-quantum re-anchor checkpoint (`pq-checkpoint.cddl`).
pub const CHECKPOINT_CONTENT_TYPE: &str = "application/access-pq-checkpoint";
/// Content type of a witness's post-quantum cosign (`pq-checkpoint.cddl`).
pub const COSIGN_CONTENT_TYPE: &str = "application/access-pq-cosign";

/// A witness's post-quantum cosign: its note key name, the cosign time and its `COSE_Sign1`
/// over the note body followed by the time as 8 big-endian bytes.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct PqCosign<'a> {
    /// The witness name.
    pub name: &'a str,
    /// The cosign time, Unix seconds.
    pub timestamp: u64,
    /// The tagged `COSE_Sign1`.
    pub sign1: &'a [u8],
}

impl<'a> PqCosign<'a> {
    /// The cosign of `name` at `timestamp`.
    #[must_use]
    pub const fn new(name: &'a str, timestamp: u64, sign1: &'a [u8]) -> Self {
        Self {
            name,
            timestamp,
            sign1,
        }
    }
}

/// The RA-5 inclusion bundle of an artefact against a post-quantum checkpoint.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct PqBundle<'a> {
    /// The committed record that names the artefact, disclosed.
    pub record: &'a Disclosure,
    /// Its RFC 9162 inclusion path into the checkpoint.
    pub path: &'a [[u8; 32]],
    /// The post-quantum checkpoint, a tagged `COSE_Sign1` over the T16 note body.
    pub checkpoint: &'a [u8],
    /// The witnesses' post-quantum cosigns.
    pub cosigns: &'a [PqCosign<'a>],
}

impl<'a> PqBundle<'a> {
    /// The bundle of `record` at `path` in `checkpoint` with `cosigns`.
    #[must_use]
    pub const fn new(
        record: &'a Disclosure,
        path: &'a [[u8; 32]],
        checkpoint: &'a [u8],
        cosigns: &'a [PqCosign<'a>],
    ) -> Self {
        Self {
            record,
            path,
            checkpoint,
            cosigns,
        }
    }
}

fn ml_dsa_keys(kid: [u8; 32], key: &PublicKey) -> Option<KeySet> {
    let PublicKey::MlDsa(alg, _) = key else {
        return None;
    };
    let mut keys = KeySet::default();
    keys.keys.insert(kid, key.clone());
    keys.allowed.insert(*alg);
    Some(keys)
}

/// Accepts a classical artefact of `domain` with exact-content digest `artefact` after the
/// classical algorithm's retirement (CR-45 RA-5, RA-7, OP-159 m.3 (h)): the anchor the verifier
/// pinned for `domain` signs the post-quantum checkpoint of log `origin`, at least one of the
/// anchor's independent witnesses cosigned it with ML-DSA, and the committed record names the
/// artefact ([`commits_artefact`]) at its position in that checkpoint.
///
/// # Errors
/// [`KeyScopeError::PqAnchorMissing`] without an anchor for `domain`;
/// [`KeyScopeError::Superseded`] without a bundle or when any condition fails.
pub fn accept_retired(
    backend: &impl Backend,
    anchors: &[PqAnchor],
    (domain, origin): (&Digest, &str),
    artefact: &Digest,
    bundle: Option<&PqBundle<'_>>,
) -> Result<(), KeyScopeError> {
    let anchor = anchors
        .iter()
        .find(|a| a.domain == *domain)
        .ok_or(KeyScopeError::PqAnchorMissing)?;
    let b = bundle.ok_or(KeyScopeError::Superseded)?;
    let keys = ml_dsa_keys(anchor.kid, &anchor.key).ok_or(KeyScopeError::Superseded)?;
    let signed = verify_sign1(backend, b.checkpoint, &keys, CHECKPOINT_CONTENT_TYPE)
        .map_err(|_| KeyScopeError::Superseded)?;
    let body = core::str::from_utf8(&signed.payload).map_err(|_| KeyScopeError::Superseded)?;
    let cp = Checkpoint::parse(body).map_err(|_| KeyScopeError::Superseded)?;
    let cosigned = b.cosigns.iter().any(|c| {
        anchor.witnesses.iter().any(|w| {
            w.independent
                && w.name == c.name
                && ml_dsa_keys(thumbprint(&w.key), &w.key).is_some_and(|ks| {
                    let mut message: Vec<u8> = body.as_bytes().to_vec();
                    message.extend_from_slice(&c.timestamp.to_be_bytes());
                    verify_sign1(backend, c.sign1, &ks, COSIGN_CONTENT_TYPE)
                        .is_ok_and(|v| v.payload == message)
                })
        })
    });
    let committed = commits_artefact(b.record, artefact);
    if cp.origin != origin
        || b.record.header.domain != Some(*domain)
        || !cosigned
        || !committed
        || b.record
            .verify_inclusion(cp.size, b.path, &cp.root)
            .is_err()
    {
        return Err(KeyScopeError::Superseded);
    }
    Ok(())
}
