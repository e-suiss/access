//! Domain-scope meta-actions: `domain_handover`, `domain_recover`, `version_activate` and
//! `algorithm_retire` (§9.13.7, §9.15, §13.6, §15.4, §15.16, PI-15, SEC20–SEC22, OP-158 m.3 (b)),
//! with the `handover/1/meta.json` and `recovery/1/meta.json` vectors.

use alloc::format;
use alloc::string::String;

use super::*;
use crate::recovery::{
    CheckpointRef, HandoverInput, KeyHolding, LostSuffix, RecoverInput, RecoveryEntry,
};
use crate::vector_rules::golden_in;

fn binding_of(seed: u8) -> BTreeMap<[u8; 32], crate::verify::key_scope::BindingKey> {
    let key = PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    );
    let b = crate::verify::key_scope::BindingKey {
        kid: crate::verify::key_scope::thumbprint(&key),
        alg: crate::verify::cose::Algorithm::Ed25519,
        key,
        scope: crate::verify::key_scope::BindingScope::Domain,
        superseded: None,
    };
    BTreeMap::from([(b.kid, b)])
}

fn binding_set(seed: u8) -> Value {
    set_value(binding_of(seed).values().map(Canonical::to_value))
}

fn entry(holders: &[Id], keys: &[u8]) -> RecoveryEntry {
    RecoveryEntry::new(
        2,
        keys.iter().map(|k| [*k; 32]).collect(),
        2,
        KeyHolding::Device,
        holders.iter().copied().collect(),
    )
}

fn domain_genesis(recovery: Option<&RecoveryEntry>) -> Result<Mem, MetaError> {
    let mut fields = BTreeMap::new();
    fields.insert(
        "meta_anchor".to_string(),
        map([
            (
                "root",
                Some(root_value(&Root::Joint {
                    parties: BTreeSet::from([ROOT, BOB]),
                    k: 2,
                })),
            ),
            ("recovery", recovery.map(Canonical::to_value)),
        ]),
    );
    fields.insert(
        "anchors".to_string(),
        set_value([map([
            (
                "scope",
                Some(scope_value(&AnchorScope::Resource(shop(&[])))),
            ),
            ("root", Some(root_value(&Root::Sole(ROOT)))),
        ])]),
    );
    fields.insert("binding".to_string(), binding_set(6));
    let mut m = Mem(BTreeMap::new());
    m.apply(&genesis_effects(&DOMAIN, &fields)?);
    Ok(m)
}

fn run_with(recovery: Option<&RecoveryEntry>) -> Recorder {
    let mut run = Run::new();
    run.state = domain_genesis(recovery).unwrap();
    run.now = 10_000_000;
    Recorder {
        run,
        cases: Vec::new(),
    }
}

fn meta() -> ExerciseBasis {
    ExerciseBasis::Anchor(meta_anchor(&DOMAIN))
}

fn json(track: &str, cases: &[String]) -> String {
    format!(
        "{{\n \"rule\": \"OP-158\",\n \"track\": \"{track}\",\n \"version\": 1,\n \"operation\": \"meta.apply\",\n \"cases\": [\n{}\n ]\n}}\n",
        cases.join(",\n")
    )
}

// SEC20, U16, Ek B 6132
#[test]
fn a_genesis_refuses_a_recovery_entry_the_provider_holds() {
    assert!(domain_genesis(Some(&entry(&[ROOT], &[1, 2, 3]))).is_ok());
    assert_eq!(
        domain_genesis(Some(&entry(&[ROOT, CAROL], &[1, 2, 3]))).err(),
        Some(MetaError::NotWithin)
    );
    let provider = *binding_of(6).keys().next().unwrap();
    let mut held = entry(&[ROOT], &[1, 2]);
    held.keys.insert(provider);
    assert_eq!(
        domain_genesis(Some(&held)).err(),
        Some(MetaError::NotWithin)
    );
}

// §9.13.7, PI-15, SI-18, §15.16, Ek B 6117, 6118, 6131, 6132, 6141, 6142
#[test]
#[allow(clippy::too_many_lines, reason = "one scripted run")]
fn handover_vectors_match() {
    let mut r = run_with(None);
    let c = CheckpointRef::new(40, Digest([0x40; 32]));
    let handover = Payload::DomainHandover(HandoverInput::new(binding_of(5), c, false));
    r.step(
        "handover-from-a-carved-anchor-is-refused",
        &["L0-META-36"],
        (ROOT, ROOT),
        ExerciseBasis::Anchor(shop_anchor()),
        &handover,
    );
    r.step(
        "handover-by-a-non-root-is-refused",
        &["L0-META-36"],
        (CAROL, CAROL),
        meta(),
        &handover,
    );
    let amended = r.step(
        "anchor-amend-leaves-the-binding",
        &["L0-META-36", "L0-META-20"],
        (ROOT, ROOT),
        meta(),
        &Payload::AnchorAmend {
            anchor: meta_anchor(&DOMAIN),
            root: None,
            root_terms: Some(BTreeSet::new()),
            sets: None,
        },
    );
    assert!(amended.is_some());
    let before = r.run.state.get(&crate::recovery::binding_key());
    r.step(
        "handover-by-the-meta-anchor-root",
        &["L0-META-36"],
        (ROOT, ROOT),
        meta(),
        &handover,
    );
    let after = r.run.state.get(&crate::recovery::binding_key());
    assert_ne!(before, after);
    let old = *binding_of(6).keys().next().unwrap();
    assert!(
        r.run
            .state
            .get(&crate::recovery::superseded_key(&old))
            .is_some()
    );
    let v = |core| crate::verify::key_scope::SpecVersions {
        core,
        meta_schema: 1,
        ..crate::verify::key_scope::SpecVersions::default()
    };
    for (id, versions) in [
        ("version-activate-raises-the-minimum", v(2)),
        ("version-activate-keeps-the-minimum", v(2)),
        ("version-activate-lowers-the-minimum-widens", v(1)),
    ] {
        r.step(
            id,
            &["L0-META-37"],
            (ROOT, ROOT),
            meta(),
            &Payload::VersionActivate { versions },
        );
    }
    r.step(
        "version-activate-by-a-non-root-is-refused",
        &["L0-META-37"],
        (CAROL, CAROL),
        meta(),
        &Payload::VersionActivate { versions: v(3) },
    );
    let retire = Payload::AlgorithmRetire {
        algorithm: crate::verify::cose::Algorithm::Es256,
    };
    r.step(
        "algorithm-retire-narrows",
        &["L0-META-38"],
        (ROOT, ROOT),
        meta(),
        &retire,
    );
    r.step(
        "algorithm-retire-by-the-provider-is-refused",
        &["L0-META-38"],
        (CAROL, CAROL),
        meta(),
        &retire,
    );
    golden_in(
        "handover/1",
        "meta.json",
        include_str!("../../../../../conformance/vectors/handover/1/meta.json"),
        &json("handover", &r.cases),
    );
}

fn checkpoint_claim(r: &mut Recorder, id: u8, size: u64, root: u8, age: u64) -> Id {
    let cid = Id([id; 16]);
    r.run.state.0.insert(
        crate::recovery::witness_head_key(&cid),
        CheckpointRef::new(size, Digest([root; 32])).to_value(),
    );
    let state = crate::claim::ClaimState {
        statement: crate::claim::Statement {
            domain: DOMAIN,
            issuer: Id([0x77; 16]),
            subject: Id([0x77; 16]),
            class: String::from(crate::claim::CHECKPOINT),
            value: Some(EqValue::Bytes(alloc::vec![0xcd; 32])),
            issued_at: r.run.now.checked_sub(age).unwrap(),
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            assurance: BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        instance: None,
        since: 1,
        ended: None,
    };
    r.run
        .state
        .0
        .insert(key(kind::CLAIM, &cid), state.to_value());
    cid
}

fn recover(
    n: u64,
    root: u8,
    claims: &[Id],
    replica: Option<u64>,
    lost: Option<(u64, u64)>,
) -> Payload {
    let mut p = RecoverInput::new(n, CheckpointRef::new(n, Digest([root; 32])), binding_of(5));
    p.witness_claims = claims.iter().copied().collect();
    p.replica_head = replica.map(|s| CheckpointRef::new(s, Digest([0x55; 32])));
    p.lost_suffix = lost.map(|(f, t)| LostSuffix::new(f, t));
    Payload::DomainRecover(p)
}

// SEC20, SEC21, SEC22, TI-RT3, Ek B 6117, 6121, 6132
#[test]
#[allow(clippy::too_many_lines, reason = "one scripted run")]
fn recovery_vectors_match() {
    let mut bare = run_with(None);
    let w = checkpoint_claim(&mut bare, 0x61, 100, 1, 60_000);
    bare.step(
        "recover-without-an-entry-is-refused",
        &["L0-META-36"],
        (ROOT, ROOT),
        meta(),
        &recover(100, 1, &[w], Some(100), None),
    );
    let mut r = run_with(Some(&entry(&[ROOT], &[1, 2, 3])));
    r.cases = bare.cases;
    let w1 = checkpoint_claim(&mut r, 0x61, 100, 1, 60_000);
    let w2 = checkpoint_claim(&mut r, 0x62, 100, 1, 120_000);
    let w3 = checkpoint_claim(&mut r, 0x63, 80, 2, 60_000);
    let stale = checkpoint_claim(&mut r, 0x64, 100, 1, crate::fold::WITNESS_FRESHNESS_MS + 1);
    for (id, actor, basis, payload) in [
        (
            "recover-from-a-carved-anchor-is-refused",
            ROOT,
            ExerciseBasis::Anchor(shop_anchor()),
            recover(100, 1, &[w1, w2], Some(100), None),
        ),
        (
            "recover-by-a-non-root-is-refused",
            CAROL,
            meta(),
            recover(100, 1, &[w1, w2], Some(100), None),
        ),
        (
            "recover-below-r-star-is-denied",
            ROOT,
            meta(),
            recover(90, 9, &[w1, w2], Some(100), None),
        ),
        (
            "recover-lossy-without-the-declared-suffix-is-refused",
            ROOT,
            meta(),
            recover(80, 2, &[w1, w3], None, None),
        ),
        (
            "recover-with-a-stale-witness-asks-for-the-threshold",
            ROOT,
            meta(),
            recover(100, 1, &[w1, stale], Some(100), None),
        ),
        (
            "recover-lossy-declares-the-lost-suffix",
            ROOT,
            meta(),
            recover(80, 2, &[w1, w3], None, Some((80, 100))),
        ),
        (
            "recover-arm-i-needs-only-the-entry",
            ROOT,
            meta(),
            recover(100, 1, &[w1, w2], Some(100), None),
        ),
    ] {
        r.step(id, &["L0-META-36"], (actor, actor), basis, &payload);
    }
    assert!(r.run.state.get(&crate::recovery::recovered_key()).is_some());
    // L0-EVAL-26a, SEC20, OP-158 m.19 (c)
    let device = PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[0x31; 32])
            .verifying_key()
            .to_bytes(),
    );
    let other = PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[0x32; 32])
            .verifying_key()
            .to_bytes(),
    );
    let mut keyed = entry(&[ROOT], &[1, 2]);
    keyed
        .keys
        .insert(crate::verify::key_scope::thumbprint(&device));
    let mut k = run_with(Some(&keyed));
    k.cases = r.cases;
    let (inside, outside) = (Id([0x41; 16]), Id([0x42; 16]));
    for (id, key) in [(inside, &device), (outside, &other)] {
        k.run.state.apply(&[(
            super::key(kind::INSTANCE, &id),
            Some(
                InstanceState {
                    party: ROOT,
                    key: key.clone(),
                    since: 1,
                    successor: None,
                    ended: None,
                }
                .to_value(),
            ),
        )]);
    }
    let give = Payload::Contribute {
        target: Digest([0x99; 32]),
        class: String::from(crate::recovery::RECOVER),
    };
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant: Id([0x51; 16]),
        holder: ROOT,
        since: 0,
    });
    k.step(
        "recover-contribution-from-an-entry-key",
        &["L0-EVAL-26a", "L0-META-30"],
        (ROOT, inside),
        holding,
        &give,
    );
    k.step(
        "recover-contribution-from-another-key-is-refused",
        &["L0-EVAL-26a", "L0-META-30"],
        (ROOT, outside),
        holding,
        &give,
    );
    let r = k;
    golden_in(
        "recovery/1",
        "meta.json",
        include_str!("../../../../../conformance/vectors/recovery/1/meta.json"),
        &json("recovery", &r.cases),
    );
}
