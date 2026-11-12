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

/// How a binding change moved the binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Moved {
    /// `domain_handover` (§16.6 HO-7).
    Handover,
    /// `domain_recover` citing the checkpoint `(size, root)` (§16.6 FR-5).
    Recover(u64, [u8; 32]),
}

/// The new binding keys and how a decision record writes the provider binding, read from the
/// record alone (its place in a checkpoint is [`binding_change`]'s).
pub(crate) fn moved(
    record: &access_kernel::record::RecordEnvelope,
) -> Result<(Vec<[u8; 32]>, Moved), Refused> {
    let effects = access_kernel::fold::effects(record).map_err(|_| Refused::Key)?;
    let key = access_kernel::recovery::binding_key();
    let Some((_, Some(value))) = effects.iter().find(|(k, _)| *k == key) else {
        return Err(Refused::Key);
    };
    let how = match value.get("how") {
        Some(suiss_crypto::dcbor::Value::Text(t)) if t == "handover" => Moved::Handover,
        // FR-5, OP-158 m.3 (m)
        Some(suiss_crypto::dcbor::Value::Text(t)) if t == "recover" => {
            let cited = value
                .get("cited")
                .and_then(|c| access_kernel::recovery::CheckpointRef::from_value(c).ok())
                .ok_or(Refused::Key)?;
            Moved::Recover(cited.size, cited.root.0)
        }
        _ => return Err(Refused::Key),
    };
    let Some(suiss_crypto::dcbor::Value::Array(keys)) = value.get("binding") else {
        return Err(Refused::Key);
    };
    let mut out = Vec::new();
    for k in keys {
        let b = access_kernel::verify::key_scope::BindingKey::from_value(k)
            .map_err(|_| Refused::Key)?;
        match b.key {
            PublicKey::Ed25519(pk) if b.superseded.is_none() => out.push(pk),
            _ => return Err(Refused::Key),
        }
    }
    if out.is_empty() {
        return Err(Refused::Key);
    }
    Ok((out, how))
}

/// The binding a handover or recovery record moves the domain to (§16.6 HO-7, FR-5, U11): the
/// record sits at its position in `cp`, which ends right after it, is a decision of `domain`
/// whose effects write the provider binding by `domain_handover` or `domain_recover`, and every
/// new binding key is Ed25519. The new keys and how they were bound.
pub(crate) fn binding_change(
    domain: &access_kernel::digest::Digest,
    cp: &Checkpoint,
    change: &suiss_ledger::checkpoint::witness::BindingChange,
) -> Result<(Vec<[u8; 32]>, Moved), Refused> {
    use access_kernel::record::{RecordEnvelope, RecordKind};
    let record = RecordEnvelope::from_bytes(&change.record).map_err(|_| Refused::Malformed)?;
    let ends_here = change.position.checked_add(1) == Some(cp.size);
    if record.header.pos != change.position
        || record.header.kind != RecordKind::Decision
        || record.header.domain != Some(*domain)
        || !ends_here
        || record.leaf_hash().map_or(true, |leaf| {
            suiss_crypto::digest::verify_inclusion(
                change.position,
                cp.size,
                &leaf,
                &change.inclusion,
                &cp.root,
            )
            .is_err()
        })
    {
        return Err(Refused::Key);
    }
    moved(&record)
}

/// Verifies a post-quantum re-anchor checkpoint of `log` (CR-45 RA-2, RA-3, OP-159 m.3 (g)):
/// `body` is a checkpoint of the domain, `excerpt` is signed by a binding key the witness holds
/// and declares an ML-DSA key with usage `checkpoint` whose window covers `now` (the re-anchor
/// signs an earlier checkpoint's body later), and that key's `COSE_Sign1` carries `body` byte
/// for byte.
pub(crate) fn pq_checkpoint(
    log: &Log,
    (body, sign1, excerpt): (&str, &[u8], &[u8]),
    now: u64,
) -> Result<Checkpoint, Refused> {
    let cp = Checkpoint::parse(body).map_err(|_| Refused::Malformed)?;
    if cp.origin != origin(&log.domain) || cp.to_body().ok().as_deref() != Some(body) {
        return Err(Refused::Malformed);
    }
    issued_at(&cp)?;
    let at = now;
    let verified = verify_sign1(&PureBackend, excerpt, &log.bindings, EXCERPT_CONTENT_TYPE)
        .map_err(|_| Refused::Key)?;
    let KeyExcerpt { domain, key } =
        KeyExcerpt::from_bytes(&verified.payload).map_err(|_| Refused::Key)?;
    let width = key
        .valid_until
        .checked_sub(key.valid_from)
        .ok_or(Refused::Key)?;
    let usable = domain == log.domain
        && access_kernel::verify::ml_dsa::is_ml_dsa(key.alg)
        && key.kid == thumbprint(&key.key)
        && key.usage.contains(&KeyUsage::Checkpoint)
        && width <= MAX_WINDOW_MS
        && (key.valid_from..=key.valid_until).contains(&at);
    if !usable {
        return Err(Refused::Key);
    }
    let signed = access_kernel::verify::cose::verify_sign1(
        &suiss_crypto::aws::AwsLcBackend,
        sign1,
        &key.key_set(),
        access_kernel::verify::reanchor::CHECKPOINT_CONTENT_TYPE,
    )
    .map_err(|_| Refused::Key)?;
    if signed.payload != body.as_bytes() {
        return Err(Refused::Key);
    }
    Ok(cp)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use access_kernel::record::{Header, Opened, RecordEnvelope, RecordKind};
    use suiss_crypto::dcbor::Value;
    use suiss_ledger::checkpoint::witness::BindingChange;

    use super::*;

    fn cp(size: u64, root: [u8; 32]) -> Checkpoint {
        Checkpoint {
            origin: String::from("o"),
            size,
            root,
            extensions: Vec::new(),
        }
    }

    // U11, §16.6 HO-7, OP-158 m.3 (l)
    #[test]
    fn only_a_handover_record_the_checkpoint_ends_with_moves_the_binding() {
        let genesis = RecordEnvelope {
            header: Header {
                domain: None,
                pos: 0,
                kind: RecordKind::Genesis,
                recorded_at: 1,
                prev: None,
            },
            fields: std::collections::BTreeMap::from([(
                String::from("versions"),
                Opened {
                    value: Value::Map(Vec::new()),
                    salt: [3; 32],
                },
            )]),
        };
        let domain = genesis.domain().unwrap();
        let leaf = genesis.leaf_hash().unwrap();
        let change = BindingChange {
            position: 0,
            record: genesis.to_bytes().unwrap(),
            inclusion: Vec::new(),
        };
        assert_eq!(
            binding_change(&domain, &cp(1, leaf), &change),
            Err(Refused::Key)
        );
        assert_eq!(
            binding_change(&domain, &cp(2, leaf), &change),
            Err(Refused::Key)
        );
        let garbage = BindingChange {
            record: vec![0xa0],
            ..change
        };
        assert_eq!(
            binding_change(&domain, &cp(1, leaf), &garbage),
            Err(Refused::Malformed)
        );
    }
}
