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

/// The binding a handover record moves the domain to (§16.6 HO-7, U11): the record sits at
/// its position in `cp`, which ends right after it, is a decision of `domain` whose effects
/// write the provider binding by `domain_handover`, and every new binding key is Ed25519. The
/// new keys.
pub(crate) fn binding_change(
    domain: &access_kernel::digest::Digest,
    cp: &Checkpoint,
    change: &suiss_ledger::checkpoint::witness::BindingChange,
) -> Result<Vec<[u8; 32]>, Refused> {
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
    let effects = access_kernel::fold::effects(&record).map_err(|_| Refused::Key)?;
    let key = access_kernel::recovery::binding_key();
    let Some((_, Some(value))) = effects.iter().find(|(k, _)| *k == key) else {
        return Err(Refused::Key);
    };
    if !matches!(value.get("how"), Some(suiss_crypto::dcbor::Value::Text(t)) if t == "handover")
    {
        return Err(Refused::Key);
    }
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
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test code")]
mod tests {
    use access_kernel::codec::Canonical as _;
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
