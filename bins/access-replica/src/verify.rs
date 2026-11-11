//! What the replica checks of a mirrored checkpoint before it accepts it (CR-58, L2-CKP-3):
//! its key excerpt is signed by a binding key the replica holds for the domain and declares an
//! Ed25519 operational key with usage `checkpoint` whose window covers the checkpoint's
//! `issued_at`, and that key signed the note for the domain's log.

use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::{
    EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage, MAX_WINDOW_MS, thumbprint,
};
use suiss_crypto::cose::{KeySet, PublicKey, verify_sign1};
use suiss_crypto::note::{Checkpoint, Verifier, verify_checkpoint};
use suiss_crypto::sig::PureBackend;

/// The checkpoint's `issued_at`, milliseconds.
fn issued_at(cp: &Checkpoint) -> Option<u64> {
    cp.extensions
        .iter()
        .find_map(|l| l.strip_prefix("issued_at "))
        .and_then(|n| n.parse::<u64>().ok())
}

/// The verified checkpoint `note` of `domain`'s log, signed by the key `excerpt` declares under
/// one of `bindings`.
pub(crate) fn checkpoint(
    domain: &Digest,
    bindings: &KeySet,
    note: &str,
    excerpt: &[u8],
) -> Result<Checkpoint, String> {
    let origin = format!("sha-256:{}", access_kernel::json::b64url_encode(&domain.0));
    let verified = verify_sign1(&PureBackend, excerpt, bindings, EXCERPT_CONTENT_TYPE)
        .map_err(|e| format!("excerpt: {e}"))?;
    let KeyExcerpt { domain: of, key } =
        KeyExcerpt::from_bytes(&verified.payload).map_err(|e| format!("excerpt: {e}"))?;
    let width = key
        .valid_until
        .checked_sub(key.valid_from)
        .ok_or("excerpt: window")?;
    let usable = of == *domain
        && key.kid == thumbprint(&key.key)
        && key.usage.contains(&KeyUsage::Checkpoint)
        && width <= MAX_WINDOW_MS;
    let (true, PublicKey::Ed25519(k)) = (usable, key.key) else {
        return Err("excerpt: not a checkpoint key of this domain".into());
    };
    let v = Verifier::ed25519(&origin, k).map_err(|e| e.to_string())?;
    let (cp, _) = verify_checkpoint(&PureBackend, note, &origin, &v, &[])
        .map_err(|e| format!("checkpoint: {e}"))?;
    let at = issued_at(&cp).ok_or("checkpoint: no issued_at")?;
    if !(key.valid_from..=key.valid_until).contains(&at) {
        return Err("checkpoint: outside its key's window".into());
    }
    Ok(cp)
}
