#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use core::cell::RefCell;

use access_kernel::intent::{ContextRefs, intent_digest};
use access_kernel::model::{ActionRef, Window};

use super::*;

struct At(u64);

impl Clock for At {
    fn now(&self) -> Option<TrustedTime> {
        Some(self.0)
    }
}

#[derive(Default)]
struct Spent {
    seen: RefCell<BTreeSet<[u8; 32]>>,
    down: bool,
}

impl ReplayStore for &Spent {
    fn record(&self, key: &[u8; 32], _: TrustedTime) -> Replay {
        if self.down {
            return Replay::Unavailable;
        }
        if self.seen.borrow_mut().insert(*key) {
            Replay::Fresh
        } else {
            Replay::Seen
        }
    }
}

fn secret(path: &str) -> SecretRef {
    SecretRef {
        mount: String::from("kv"),
        path: vec![String::from("payroll"), String::from(path)],
    }
}

fn envelope(action: &str, of: &SecretRef) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: ActionRef {
            namespace: String::from(NAMESPACE),
            name: String::from(action),
            major: 1,
            schema: Digest([7; 32]),
        },
        resources: vec![of.resource()],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 1_000,
            until: 2_000,
        },
    }
}

fn allowed(e: &IntentEnvelope, nonce: u8) -> (Authorized<(), ()>, Intent<(), ()>) {
    let intent = Intent::named(e.clone()).unwrap();
    let digest = intent_digest(e).unwrap();
    (
        Authorized::new(Digest([nonce; 32]), digest, 42, None),
        intent,
    )
}

// E36, §7.9.12.4, OP-156 m.3 (x)
#[test]
fn a_secret_leaves_once_and_only_for_its_own_release_exercise() {
    let spent = Spent::default();
    let gate = Releases::new(&spent);
    let db = secret("db");
    let (a, i) = allowed(&envelope(ACTION, &db), 1);
    let out = gate.release(a, &i, &db, &At(1_500), |_| 7_u32).unwrap();
    assert_eq!(out.value, 7);
    assert_eq!(out.exercise, Digest([1; 32]));
    assert_eq!(out.until, 2_000);
    let (again, i) = allowed(&envelope(ACTION, &db), 1);
    assert_eq!(
        gate.release(again, &i, &db, &At(1_500), |_| ()),
        Err(Refused::AlreadyUsed)
    );
    let (other, i) = allowed(&envelope(ACTION, &db), 2);
    assert_eq!(
        gate.release(other, &i, &secret("api"), &At(1_500), |_| ()),
        Err(Refused::OtherSecret)
    );
    let (read, i) = allowed(&envelope("read", &db), 3);
    assert_eq!(
        gate.release(read, &i, &db, &At(1_500), |_| ()),
        Err(Refused::OtherSecret)
    );
}

// E36, MD-8
#[test]
fn a_release_outside_its_window_or_unrecorded_does_not_happen() {
    let db = secret("db");
    let spent = Spent::default();
    let gate = Releases::new(&spent);
    let (late, i) = allowed(&envelope(ACTION, &db), 1);
    assert_eq!(
        gate.release(late, &i, &db, &At(2_001), |_| ()),
        Err(Refused::OutsideValidity)
    );
    let down = Spent {
        down: true,
        ..Spent::default()
    };
    let (a, i) = allowed(&envelope(ACTION, &db), 2);
    let mut ran = false;
    assert_eq!(
        Releases::new(&down).release(a, &i, &db, &At(1_500), |_| ran = true),
        Err(Refused::StoreUnavailable)
    );
    assert!(!ran);
    let e = envelope(ACTION, &db);
    let digest = intent_digest(&e).unwrap();
    let only_digest = Intent::<(), ()>::approved(digest, Some(e.action.clone()));
    let a = Authorized::new(Digest([3; 32]), digest, 1, None);
    assert_eq!(
        gate.release(a, &only_digest, &db, &At(1_500), |_| ()),
        Err(Refused::Unknown)
    );
    let mut wider = envelope(ACTION, &db);
    wider.resources.push(secret("api").resource());
    let (a, i) = allowed(&wider, 4);
    assert_eq!(
        gate.release(a, &i, &db, &At(1_500), |_| ()),
        Err(Refused::OtherSecret)
    );
}
