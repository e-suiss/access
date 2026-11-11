//! Signed checkpoints of the domain log (CMP-6, T20, §16.4.4 m.18, OP-143 m.1 E4): a C2SP
//! `tlog-checkpoint` of the committed head, signed as a note by the domain's operational key
//! through the authority signer. A checkpoint is built only from a committed head; without a
//! signature none is emitted (CR-23, G42).

use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::{
    DomainMetadata, KeyScopeError, KeyUsage, SpecVersions, operational_key,
};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::note::{Checkpoint, NoteError, Verifier, parse_note, verify_checkpoint};
use suiss_crypto::sig::Backend;
use suiss_ledger::sequencer::Head;

use crate::SequencerError;
use crate::domain::head_of;
use crate::ports::{Heads, NoteSigner};

pub use access_authority_signer::domain::origin;

/// Digest context of the `SpecVersions` a checkpoint names (§16.4.4 m.17, L0-ENC-22a).
pub const VERSIONS_CONTEXT: &str = "access/versions/v1";

/// Digest context of the signed Domain Metadata a checkpoint names (OP-152 m.5 (h)).
pub const METADATA_CONTEXT: &str = "access/domain-metadata/v1";

const RECORDED_AT: &str = "recorded_at ";
const VERSIONS: &str = "versions ";
const METADATA: &str = "metadata ";
const ISSUED_AT: &str = "issued_at ";

/// Why a checkpoint was not produced or not accepted.
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    /// The committed head could not be read.
    #[error("store: {0}")]
    Store(#[from] SequencerError),
    /// The signer is unreachable or refused, by stable code; the checkpoint waits (G42).
    #[error("unsigned: {0}")]
    Unsigned(String),
    /// The note or checkpoint is malformed or does not verify.
    #[error("note: {0}")]
    Note(#[from] NoteError),
    /// The excerpt does not resolve a checkpoint key of the domain.
    #[error("key: {0}")]
    Key(#[from] KeyScopeError),
    /// The origin is not the domain's.
    #[error("origin")]
    Origin,
    /// An Access extension line is missing or malformed.
    #[error("extension")]
    Extension,
}

/// A signed checkpoint and the excerpt that declares its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    /// The checkpoint body.
    pub checkpoint: Checkpoint,
    /// The signed note: body, empty line, signature line.
    pub note: String,
    /// Binding-signed excerpt of the operational key (CR-58 m.1).
    pub excerpt: Vec<u8>,
    /// The signed Domain Metadata the checkpoint names; witnesses verify the key under it.
    pub metadata: Vec<u8>,
}

/// The Access lines a checkpoint carries after its root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extensions {
    /// `recorded_at` of the head record.
    pub recorded_at: u64,
    /// Digest of the domain's adopted `SpecVersions`.
    pub versions: Digest,
    /// Digest of the signed Domain Metadata current at this head; `None` in a checkpoint
    /// written before the line existed (OP-152 m.5 (h)).
    pub metadata: Option<Digest>,
    /// Signing time; the checkpoint key is resolved at it.
    pub issued_at: u64,
}

/// The digest of the signed Domain Metadata bytes under [`METADATA_CONTEXT`] (OP-152 m.5 (h)).
#[must_use]
pub fn metadata_digest(signed: &[u8]) -> Digest {
    suiss_crypto::digest::context_digest(METADATA_CONTEXT, signed)
}

/// The digest of `versions` under [`VERSIONS_CONTEXT`].
///
/// # Errors
/// [`CheckpointError::Extension`] when they cannot be encoded.
pub fn versions_digest(versions: &SpecVersions) -> Result<Digest, CheckpointError> {
    use access_kernel::codec::Canonical as _;
    let bytes = dcbor::encode(&versions.to_value(), Limits::CEILING)
        .map_err(|_| CheckpointError::Extension)?;
    Ok(suiss_crypto::digest::context_digest(
        VERSIONS_CONTEXT,
        &bytes,
    ))
}

fn digest_text(d: &Digest) -> String {
    format!("sha-256:{}", access_kernel::json::b64url_encode(&d.0))
}

/// The checkpoint of `domain`'s log at `head`, issued at `issued_at`, naming the digest of the
/// signed Domain Metadata current there (L2-CKP-1, L2-CKP-5).
///
/// # Errors
/// [`CheckpointError`] when the head and its frontier disagree.
pub fn body(
    domain: &Digest,
    head: &Head,
    versions: &SpecVersions,
    metadata: &Digest,
    issued_at: u64,
) -> Result<Checkpoint, CheckpointError> {
    let extensions = vec![
        format!("{RECORDED_AT}{}", head.recorded_at),
        format!("{VERSIONS}{}", digest_text(&versions_digest(versions)?)),
        format!("{METADATA}{}", digest_text(metadata)),
        format!("{ISSUED_AT}{issued_at}"),
    ];
    Ok(suiss_ledger::checkpoint::of_head(
        &origin(domain),
        head,
        extensions,
    )?)
}

fn number(line: Option<&String>, prefix: &str) -> Result<u64, CheckpointError> {
    let n = line
        .and_then(|l| l.strip_prefix(prefix))
        .ok_or(CheckpointError::Extension)?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) || (n.len() > 1 && n.starts_with('0'))
    {
        return Err(CheckpointError::Extension);
    }
    n.parse().map_err(|_| CheckpointError::Extension)
}

/// The Access lines of a checkpoint.
///
/// # Errors
/// [`CheckpointError::Extension`].
pub fn extensions(cp: &Checkpoint) -> Result<Extensions, CheckpointError> {
    let (recorded_at, versions, metadata, issued_at) = match cp.extensions.as_slice() {
        [r, v, i] => (r, v, None, i),
        [r, v, m, i] => (r, v, Some(digest_line(m, METADATA)?), i),
        _ => return Err(CheckpointError::Extension),
    };
    Ok(Extensions {
        recorded_at: number(Some(recorded_at), RECORDED_AT)?,
        versions: digest_line(versions, VERSIONS)?,
        metadata,
        issued_at: number(Some(issued_at), ISSUED_AT)?,
    })
}

fn digest_line(line: &str, prefix: &str) -> Result<Digest, CheckpointError> {
    line.strip_prefix(prefix)
        .and_then(|v| v.strip_prefix("sha-256:"))
        .and_then(|v| access_kernel::json::b64url_decode(v).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .map(Digest)
        .ok_or(CheckpointError::Extension)
}

/// Checkpoints the committed head of `domain` at trusted time `now` and has the signer sign it.
///
/// # Errors
/// [`CheckpointError::Unsigned`] when the signer is down or no key may sign: nothing is
/// emitted; [`CheckpointError`] otherwise.
pub async fn checkpoint<H: Heads, S: NoteSigner>(
    heads: &H,
    signer: &S,
    domain: Digest,
    versions: &SpecVersions,
    now: u64,
) -> Result<SignedCheckpoint, CheckpointError> {
    let row = heads.committed(&domain).await?;
    // OP-152 m.5 (h)
    let metadata = signer
        .metadata(domain)
        .await
        .map_err(CheckpointError::Unsigned)?;
    let cp = body(
        &domain,
        &head_of(&row)?,
        versions,
        &metadata_digest(&metadata),
        now,
    )?;
    let text = cp.to_body()?;
    let noted = signer
        .sign_note(domain, text.clone(), now)
        .await
        .map_err(CheckpointError::Unsigned)?;
    let note = format!("{text}\n{}", noted.line);
    if parse_note(&note)?.body != text {
        return Err(CheckpointError::Note(NoteError::Malformed));
    }
    Ok(SignedCheckpoint {
        checkpoint: cp,
        note,
        excerpt: noted.excerpt,
        metadata,
    })
}

/// Verifies a signed checkpoint of `domain` (L2-CKP-3): the origin is the domain's, `excerpt`
/// resolves under verified `metadata` an operational key with usage `checkpoint` at the
/// checkpoint's `issued_at`, and the note's signature by that key verifies.
///
/// # Errors
/// [`CheckpointError`].
pub fn verify(
    backend: &impl Backend,
    note: &str,
    metadata: &DomainMetadata,
    excerpt: &[u8],
    domain: &Digest,
) -> Result<(Checkpoint, Extensions), CheckpointError> {
    let cp = Checkpoint::parse(&parse_note(note)?.body)?;
    let origin = origin(domain);
    if cp.origin != origin {
        return Err(CheckpointError::Origin);
    }
    let ext = extensions(&cp)?;
    let key = operational_key(
        backend,
        metadata,
        domain,
        excerpt,
        KeyUsage::Checkpoint,
        ext.issued_at,
    )?;
    let PublicKey::Ed25519(k) = key.key else {
        return Err(CheckpointError::Note(NoteError::Unverified));
    };
    let log = Verifier::ed25519(&origin, k)?;
    let (cp, _) = verify_checkpoint(backend, note, &origin, &log, &[])?;
    Ok((cp, ext))
}

/// Digest context of a `checkpoint` Claim body: the Claim's value (OP-158 m.6 (j)).
pub const CLAIM_CONTEXT: &str = "access/checkpoint-claim/v1";

/// The `checkpoint-trigger` words.
pub const TRIGGERS: [&str; 4] = ["interval", "records", "heartbeat", "out-of-cycle"];

/// What made a checkpoint (`checkpoint.cddl` `checkpoint-trigger`).
#[must_use]
pub const fn trigger(due: suiss_ledger::checkpoint::cadence::Due) -> &'static str {
    use suiss_ledger::checkpoint::cadence::Due;
    match due {
        Due::Heartbeat => "heartbeat",
        Due::Records => "records",
        Due::OutOfCycle => "out-of-cycle",
        _ => "interval",
    }
}

/// The `checkpoint` Claim body (`checkpoint.cddl` `checkpoint-claim`): the signed note, the
/// excerpt of its key and what made it; the Claim's value is this body's digest (OP-158 m.3
/// (c), m.6).
///
/// # Errors
/// [`CheckpointError::Extension`] when it cannot be encoded.
pub fn claim_body(signed: &SignedCheckpoint, trigger: &str) -> Result<Vec<u8>, CheckpointError> {
    use suiss_crypto::dcbor::Value;
    dcbor::encode(
        &Value::Map(vec![
            (Value::text("note"), Value::text(&signed.note)),
            (Value::text("excerpt"), Value::Bytes(signed.excerpt.clone())),
            (Value::text("trigger"), Value::text(trigger)),
        ]),
        Limits::CEILING,
    )
    .map_err(|_| CheckpointError::Extension)
}

/// The State entry an accepted `checkpoint` Claim `claim` writes for the rollback guard R*:
/// key `dCBOR(["witness_head", claim])`, value `dCBOR(checkpoint-ref)` `{size, root}`
/// (`kernel.cddl`, SEC21, OP-158 m.6 (j)).
///
/// # Errors
/// [`CheckpointError::Extension`] when it cannot be encoded.
pub fn witness_head_entry(
    claim: &access_kernel::model::Id,
    cp: &Checkpoint,
) -> Result<(Vec<u8>, Vec<u8>), CheckpointError> {
    use access_kernel::codec::Canonical as _;
    let head = access_kernel::recovery::CheckpointRef::new(cp.size, Digest(cp.root));
    Ok((
        access_kernel::recovery::witness_head_key(claim),
        head.to_bytes().map_err(|_| CheckpointError::Extension)?,
    ))
}

#[cfg(test)]
mod tests;
