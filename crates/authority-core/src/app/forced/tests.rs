use std::collections::BTreeSet;
use std::hash::BuildHasher as _;

use access_kernel::digest::Digest;
use access_kernel::meta::InstanceState;
use access_kernel::model::Id;
use access_kernel::recovery::{KeyHolding, RECOVER, RecoveryEntry};
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use ed25519_dalek::Signer as _;
use suiss_crypto::note::{Checkpoint, Verifier, base64_encode, cosigned_message};

use super::{WitnessHead, WitnessHeadError, entry_contributors, witness_party};

fn runtime_key() -> ed25519_dalek::SigningKey {
    let bytes: Vec<u8> = (0..4_u64)
        .flat_map(|i| {
            std::collections::hash_map::RandomState::new()
                .hash_one(i)
                .to_le_bytes()
        })
        .collect();
    let seed: [u8; 32] = bytes.try_into().unwrap();
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

/// `name`'s cosigned note over `size` and `root` of `origin`, at `seconds`.
pub(super) fn cosigned(
    key: &ed25519_dalek::SigningKey,
    name: &str,
    (origin, size, root): (&str, u64, [u8; 32]),
    seconds: u64,
) -> (String, String) {
    let v = Verifier::cosigner(name, key.verifying_key().to_bytes()).unwrap();
    let body = Checkpoint {
        origin: origin.to_owned(),
        size,
        root,
        extensions: Vec::new(),
    }
    .to_body()
    .unwrap();
    let sig = key.sign(&cosigned_message(seconds, &body)).to_bytes();
    let mut raw = v.id().to_be_bytes().to_vec();
    raw.extend_from_slice(&seconds.to_be_bytes());
    raw.extend_from_slice(&sig);
    (
        format!("{body}\n\u{2014} {name} {}\n", base64_encode(&raw)),
        v.to_vkey(),
    )
}

// FR-2, SEC22, OP-158 m.3 (m), Ek B 6023
#[test]
fn a_witness_head_is_recorded_only_under_its_own_cosignature() {
    let d = Digest(suiss_crypto::digest::sha256(b"domain"));
    let origin = access_authority_sequencer::checkpoint::origin(&d);
    let root = suiss_crypto::digest::sha256(b"tree");
    let key = runtime_key();
    let (note, vkey) = cosigned(&key, "w1.example", (&origin, 9, root), 1_700_000_000);
    let h = WitnessHead::verified(&d, &note, &vkey).unwrap();
    assert_eq!((h.head().size, h.head().root.0), (9, root));
    assert_eq!(h.at(), 1_700_000_000_000);
    assert_eq!(h.party(), witness_party(&vkey));
    assert_eq!(
        h.claim(),
        WitnessHead::verified(&d, &note, &vkey).unwrap().claim()
    );

    let other = runtime_key();
    let (_, stranger) = cosigned(&other, "w1.example", (&origin, 9, root), 1_700_000_000);
    assert_eq!(
        WitnessHead::verified(&d, &note, &stranger),
        Err(WitnessHeadError::Cosignature)
    );
    let elsewhere = Digest(suiss_crypto::digest::sha256(b"another domain"));
    assert_eq!(
        WitnessHead::verified(&elsewhere, &note, &vkey),
        Err(WitnessHeadError::Checkpoint)
    );
    assert_ne!(witness_party(&vkey), witness_party(&stranger));
}

fn instance(key: &ed25519_dalek::SigningKey) -> InstanceState {
    InstanceState {
        party: Id([1; 16]),
        key: PublicKey::Ed25519(key.verifying_key().to_bytes()),
        since: 1,
        successor: None,
        ended: None,
    }
}

// SEC20, U16, OP-158 m.7 (c), Ek B 5908, 6022
#[test]
fn only_contributions_from_the_entry_keys_count() {
    let (a, b, c, outsider) = (runtime_key(), runtime_key(), runtime_key(), runtime_key());
    let kid = |k: &ed25519_dalek::SigningKey| {
        thumbprint(&PublicKey::Ed25519(k.verifying_key().to_bytes()))
    };
    let entry = RecoveryEntry::new(
        2,
        [kid(&a), kid(&b), kid(&c)].into_iter().collect(),
        2,
        KeyHolding::Device,
        BTreeSet::from([Id([1; 16])]),
    );
    let target = Digest([7; 32]);
    let given = |k: &ed25519_dalek::SigningKey, n: u8, class: &str, t: Digest| {
        (Id([n; 16]), instance(k), class.to_owned(), t)
    };
    let two = [given(&a, 1, RECOVER, target), given(&b, 2, RECOVER, target)];
    assert_eq!(entry_contributors(&entry, &target, &two), 2);
    let outside = [
        given(&a, 1, RECOVER, target),
        given(&outsider, 3, RECOVER, target),
    ];
    assert_eq!(entry_contributors(&entry, &target, &outside), 1);
    let same = [given(&a, 1, RECOVER, target), given(&a, 1, RECOVER, target)];
    assert_eq!(entry_contributors(&entry, &target, &same), 1);
    let wrong = [
        given(&a, 1, "approve", target),
        given(&b, 2, RECOVER, Digest([8; 32])),
    ];
    assert_eq!(entry_contributors(&entry, &target, &wrong), 0);
}
