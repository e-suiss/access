//! Local break-glass over the offline verifier (OP-156 m.3 (p), Ek B 5207): the reserved
//! break-glass Grant's PAP admits one console sign-in for the named user, and its one-use
//! slice cannot be drawn twice, not even after a restart over the same counter.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "../../../sdks/rust/verifier/tests/support/mod.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use access_kernel::algebra::Catalog;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::model::{
    ActionSet, AuthoritySet, Bound, ResourceRef, ResourceSelector, Structural, Window,
};
use access_kernel::pap::{Pap, PapError};
use access_kernel::validity::OfflineSlice;
use access_kernel::verify::key_scope::KeyUsage;
use access_linux_client::breakglass::{self, ACTION, FileCounter, NAMESPACE, PRINCIPAL, Refused};
use access_verifier::metadata::MetadataView;
use access_verifier::offline::{Denial, Identity, OfflineVerifier, Use};
use access_verifier::testing::EmulatedClock;
use access_verifier::time::{ClockGuard, DEFAULT_TOLERANCE_MS};
use support::{
    HOUR, LOG, NOW, SIGNED_METADATA, VERIFIER, action, checkpoint, d, excerpt, list, log_verifier,
    metadata, present, profile, signed, term, witness_verifier,
};

type Device = OfflineVerifier<EmulatedClock, FileCounter>;

fn catalog() -> Catalog {
    Catalog {
        catalogs: BTreeMap::from([(d(20), BTreeSet::from([action(NAMESPACE, ACTION)]))]),
        ..Catalog::default()
    }
}

fn bounds() -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::new(),
            prefix: BTreeSet::from([(NAMESPACE.to_owned(), d(20))]),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: "ssh".to_owned(),
            prefix: vec!["host-group".to_owned()],
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::from([(
            PRINCIPAL.to_owned(),
            Bound::Enum(BTreeSet::from(["ayse".to_owned()])),
        )]),
        recipient: None,
        purpose: None,
    }
}

/// The reserved break-glass Grant's PAP: one use, `count`.
fn pap() -> Pap {
    support::pap_with(|p| {
        p.bounds = bounds();
        p.validity.bounds = bounds();
        p.validity.offline_slice = BTreeSet::from([OfflineSlice {
            budget_term: d(6),
            amount: 1,
            unit: "count".to_owned(),
        }]);
    })
}

fn intent(user: &str) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: action(NAMESPACE, ACTION),
        resources: vec![ResourceRef {
            namespace: "ssh".to_owned(),
            path: vec!["host-group".to_owned(), "prod-web".to_owned()],
            incarnation: 0,
        }],
        params: BTreeMap::from([(PRINCIPAL.to_owned(), ParamValue::Enum(user.to_owned()))]),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 11 * HOUR,
            until: 13 * HOUR,
        },
    }
}

fn device(p: &Pap, counter: &std::path::Path) -> Device {
    let mut view = MetadataView::new(metadata(), SIGNED_METADATA);
    view.witness(
        &checkpoint(Some(NOW / 1_000 - 60)),
        LOG,
        &log_verifier(),
        &[witness_verifier()],
    )
    .unwrap();
    let status = access_verifier::status::StatusList::verify(
        view.metadata(),
        &list(&[], NOW - 60_000),
        &excerpt(KeyUsage::StatusList),
    )
    .unwrap();
    let me = Identity {
        audience: VERIFIER.to_owned(),
        instance: None,
        domain: d(1),
        profile: profile(),
        catalog: catalog(),
        understood: BTreeSet::new(),
    };
    let mut v = OfflineVerifier::new(
        me,
        view,
        EmulatedClock::new(NOW),
        ClockGuard::new(DEFAULT_TOLERANCE_MS),
    );
    v.install_list(status);
    let c = FileCounter::open(counter, [7; 16]).unwrap();
    v.provision(p.projection_exercise, d(6), 1, c).unwrap();
    v
}

fn runtime_nonce() -> Vec<u8> {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    suiss_crypto::digest::sha256(&t.to_le_bytes())[..16].to_vec()
}

fn breakglass_mark(dir: &std::path::Path, p: &Pap) {
    let name = p
        .projection_exercise
        .0
        .iter()
        .fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        });
    std::fs::create_dir_all(dir.join("spent")).unwrap();
    std::fs::write(dir.join("spent").join(name), b"").unwrap();
}

fn scratch() -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("q13-break-glass-{n}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn admit(
    v: &mut Device,
    dir: &std::path::Path,
    user: &str,
    i: &IntentEnvelope,
) -> Result<(), Refused> {
    let p = pap();
    let s = signed(&p);
    let nonce = runtime_nonce();
    let presentation = present(&s, i, &nonce, NOW);
    let pap_excerpt = excerpt(KeyUsage::Pap);
    let satisfied = BTreeSet::from([term("phishing_resistant")]);
    breakglass::admit(
        v,
        dir,
        user,
        &Use::new((&s, &pap_excerpt), &presentation, i, &nonce, &satisfied),
    )
}

// OP-156 m.3 (p), Ek B 5207, U2
#[test]
fn the_break_glass_slice_cannot_be_used_twice() {
    let dir = scratch();
    let counter = dir.join("counter");
    let p = pap();
    let mut v = device(&p, &counter);
    admit(&mut v, &dir, "ayse", &intent("ayse")).unwrap();
    assert!(breakglass::take(&dir, "ayse", NOW + 1));
    assert!(!breakglass::take(&dir, "ayse", NOW + 2));
    assert_eq!(
        admit(&mut v, &dir, "ayse", &intent("ayse")),
        Err(Refused::Spent)
    );
    std::fs::remove_dir_all(dir.join("spent")).unwrap();
    assert_eq!(
        admit(&mut v, &dir, "ayse", &intent("ayse")),
        Err(Refused::Verifier(Denial::Pap(PapError::Slice)))
    );
    breakglass_mark(&dir, &p);
    let mut again = device(&p, &counter);
    assert_eq!(
        admit(&mut again, &dir, "ayse", &intent("ayse")),
        Err(Refused::Spent)
    );
    assert!(!breakglass::take(&dir, "ayse", NOW + 3));
    let _ = std::fs::remove_dir_all(&dir);
}

// OP-156 m.3 (p)
#[test]
fn break_glass_names_one_user_and_its_allowance_expires() {
    let dir = scratch();
    let p = pap();
    let mut v = device(&p, &dir.join("counter"));
    assert_eq!(
        admit(&mut v, &dir, "mert", &intent("ayse")),
        Err(Refused::Intent)
    );
    assert!(admit(&mut v, &dir, "mert", &intent("mert")).is_err());
    admit(&mut v, &dir, "ayse", &intent("ayse")).unwrap();
    assert!(!breakglass::take(
        &dir,
        "ayse",
        NOW + breakglass::ALLOWANCE_MS
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
