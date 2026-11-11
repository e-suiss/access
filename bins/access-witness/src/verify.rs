//! What the witness checks before it looks at the base (§16.6 witness protocol, CR-58,
//! L2-CKP-3): the Domain Metadata verifies under a binding key the witness trusts and is the
//! one the checkpoint names, the excerpt resolves under it an operational key with usage
//! `checkpoint` at the checkpoint's `issued_at`, and that key signed the note.

use access_kernel::verify::key_scope::{KeyUsage, operational_key, verify_metadata};
use suiss_crypto::cose::PublicKey;
use suiss_crypto::note::{Checkpoint, Verifier, parse_note, verify_checkpoint};
use suiss_crypto::sig::PureBackend;

use crate::config::{Log, origin};

/// Digest context of the Domain Metadata a checkpoint names (OP-152 m.5 (h)).
const METADATA_CONTEXT: &str = "access/domain-metadata/v1";

/// Why a checkpoint is not the domain's.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Malformed note, extension or metadata line.
    Malformed(&'static str),
    /// Not signed by the domain's current binding (403).
    Key(String),
}

fn line<'a>(cp: &'a Checkpoint, prefix: &str) -> Result<&'a str, Refused> {
    cp.extensions
        .iter()
        .find_map(|l| l.strip_prefix(prefix))
        .ok_or(Refused::Malformed("extension"))
}

/// The checkpoint's `issued_at` and `recorded_at`, milliseconds.
pub(crate) fn times(cp: &Checkpoint) -> Result<(u64, u64), Refused> {
    let n = |p| {
        line(cp, p)?
            .parse::<u64>()
            .map_err(|_| Refused::Malformed("extension"))
    };
    Ok((n("issued_at ")?, n("recorded_at ")?))
}

/// Verifies `note` as a checkpoint of `log`, with its `excerpt` and signed `metadata`.
pub(crate) fn checkpoint(
    log: &Log,
    note: &str,
    excerpt: &[u8],
    metadata: &[u8],
) -> Result<Checkpoint, Refused> {
    let parsed = parse_note(note).map_err(|_| Refused::Malformed("note"))?;
    let cp = Checkpoint::parse(&parsed.body).map_err(|_| Refused::Malformed("checkpoint"))?;
    let origin = origin(&log.domain);
    if cp.origin != origin {
        return Err(Refused::Malformed("origin"));
    }
    let named = line(&cp, "metadata sha-256:")?;
    let digest = suiss_crypto::digest::context_digest(METADATA_CONTEXT, metadata);
    if access_kernel::json::b64url_encode(&digest.0) != named {
        return Err(Refused::Key(
            "metadata is not the one the checkpoint names".into(),
        ));
    }
    let md = verify_metadata(&PureBackend, metadata, &log.bindings)
        .map_err(|e| Refused::Key(format!("metadata: {e}")))?;
    if md.domain != log.domain {
        return Err(Refused::Key("metadata of another domain".into()));
    }
    let (issued_at, _) = times(&cp)?;
    let key = operational_key(
        &PureBackend,
        &md,
        &log.domain,
        excerpt,
        KeyUsage::Checkpoint,
        issued_at,
    )
    .map_err(|e| Refused::Key(format!("excerpt: {e}")))?;
    let PublicKey::Ed25519(k) = key.key else {
        return Err(Refused::Key("not an Ed25519 key".into()));
    };
    let v = Verifier::ed25519(&origin, k).map_err(|_| Refused::Malformed("origin"))?;
    let (cp, _) = verify_checkpoint(&PureBackend, note, &origin, &v, &[])
        .map_err(|e| Refused::Key(format!("note: {e}")))?;
    Ok(cp)
}
