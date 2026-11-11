//! What the witness checks before it looks at its base (§16.6 witness protocol, CR-58,
//! L2-CKP-3): the excerpt is signed by a binding key the witness holds for the domain, names
//! the domain, is an Ed25519 operational key with usage `checkpoint` whose window covers the
//! checkpoint's `issued_at`, and that key signed the note.

use access_kernel::codec::Canonical as _;
use access_kernel::verify::key_scope::{
    EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage, MAX_WINDOW_MS, thumbprint,
};
use suiss_crypto::cose::{PublicKey, verify_sign1};
use suiss_crypto::note::{Checkpoint, Verifier, parse_note, verify_checkpoint};
use suiss_crypto::sig::PureBackend;

use crate::config::{Log, origin};

/// Why a checkpoint is not the domain's.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Malformed note or extension.
    Malformed,
    /// Not signed by an operational key of the binding the witness holds.
    Key,
}

/// The checkpoint's `issued_at`, milliseconds.
pub(crate) fn issued_at(cp: &Checkpoint) -> Result<u64, Refused> {
    cp.extensions
        .iter()
        .find_map(|l| l.strip_prefix("issued_at "))
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or(Refused::Malformed)
}

/// Verifies `note` as a checkpoint of `log` signed by the key `excerpt` declares; the
/// checkpoint and the kid of the binding key that signed the excerpt.
pub(crate) fn checkpoint(
    log: &Log,
    note: &str,
    excerpt: &[u8],
) -> Result<(Checkpoint, [u8; 32]), Refused> {
    let parsed = parse_note(note).map_err(|_| Refused::Malformed)?;
    let cp = Checkpoint::parse(&parsed.body).map_err(|_| Refused::Malformed)?;
    let origin = origin(&log.domain);
    if cp.origin != origin {
        return Err(Refused::Malformed);
    }
    let at = issued_at(&cp)?;
    let verified = verify_sign1(&PureBackend, excerpt, &log.bindings, EXCERPT_CONTENT_TYPE)
        .map_err(|_| Refused::Key)?;
    let KeyExcerpt { domain, key } =
        KeyExcerpt::from_bytes(&verified.payload).map_err(|_| Refused::Key)?;
    let width = key
        .valid_until
        .checked_sub(key.valid_from)
        .ok_or(Refused::Key)?;
    let usable = domain == log.domain
        && key.kid == thumbprint(&key.key)
        && key.usage.contains(&KeyUsage::Checkpoint)
        && width <= MAX_WINDOW_MS
        && (key.valid_from..=key.valid_until).contains(&at);
    let (true, PublicKey::Ed25519(k)) = (usable, key.key) else {
        return Err(Refused::Key);
    };
    let v = Verifier::ed25519(&origin, k).map_err(|_| Refused::Malformed)?;
    let (cp, _) =
        verify_checkpoint(&PureBackend, note, &origin, &v, &[]).map_err(|_| Refused::Key)?;
    Ok((cp, verified.kid))
}
