//! Root-term witness and replica sets on the meta-anchor (OP-158 m.11 5984, OP-159 m.3 (j)),
//! with the `core/1/meta-root-sets.json` vectors.

use alloc::format;

use super::*;
use crate::vector_rules::{field, golden};
use crate::verify::cose::{Algorithm, PublicKey};
use crate::verify::key_scope::{Replica, Witness};

const R: &[&str] = &["L0-META-20", "L0-META-28"];

fn ed(seed: u8) -> PublicKey {
    PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn witness(name: &str, seed: u8) -> Witness {
    Witness::new(
        name.into(),
        ed(seed),
        Algorithm::Ed25519,
        "northwind".into(),
        true,
    )
}

fn replica(name: &str, seed: u8) -> Replica {
    Replica::new(name.into(), ed(seed), "acme".into(), true)
}

fn amend(anchor: Id, sets: RootSets) -> Payload {
    let p = Payload::AnchorAmend {
        anchor,
        root: None,
        root_terms: None,
        sets: Some(sets),
    };
    Payload::from_value(&p.to_value()).unwrap()
}

fn canonical(sets: RootSets) -> RootSets {
    match amend(Id([0; 16]), sets) {
        Payload::AnchorAmend { sets: Some(s), .. } => s,
        _ => RootSets::default(),
    }
}

// TI-RT12, OP-158 m.11, OP-159 m.3 (j)
#[test]
fn meta_root_sets_vectors_match() {
    let mut r = Recorder {
        run: Run::new(),
        cases: Vec::new(),
    };
    let meta = meta_anchor(&DOMAIN);
    let basis = ExerciseBasis::Anchor(meta);
    let one = RootSets::new(
        vec![witness("w1.example", 4)],
        vec![replica("r1.example", 5)],
    );
    let two = canonical(RootSets::new(
        vec![witness("w1.example", 4), witness("w2.example", 6)],
        vec![replica("r1.example", 5)],
    ));
    r.step(
        "adding-a-witness-and-a-replica-narrows",
        R,
        (ROOT, ROOT),
        basis,
        &amend(meta, one.clone()),
    );
    r.step(
        "adding-a-second-witness-narrows",
        R,
        (ROOT, ROOT),
        basis,
        &amend(meta, two.clone()),
    );
    r.step(
        "removing-a-witness-widens",
        R,
        (ROOT, ROOT),
        basis,
        &amend(meta, one.clone()),
    );
    r.step(
        "removing-every-replica-widens",
        R,
        (ROOT, ROOT),
        basis,
        &amend(
            meta,
            RootSets::new(vec![witness("w1.example", 4)], Vec::new()),
        ),
    );
    r.step(
        "a-non-root-cannot-amend-the-sets",
        R,
        (ALICE, ALICE),
        basis,
        &amend(meta, two.clone()),
    );
    let shop = shop_anchor();
    r.step(
        "a-resource-anchor-carries-no-sets",
        R,
        (ROOT, ROOT),
        ExerciseBasis::Anchor(shop),
        &amend(shop, two.clone()),
    );
    r.step(
        "anchor-create-carries-no-sets",
        R,
        (ROOT, ROOT),
        ExerciseBasis::Anchor(shop),
        &Payload::AnchorCreate {
            scope: AnchorScope::Resource(super::shop(&["eu"])),
            root: Root::Sole(BOB),
            root_terms: BTreeSet::new(),
            sets: two,
        },
    );
    assert_eq!(r.cases.len(), 7);
    let json = format!(
        "{{\n \"rule\": \"OP-159\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"meta.apply\",\n {},\n \"cases\": [\n{}\n ]\n}}\n",
        field(&["L0-META-20"]),
        r.cases.join(",\n")
    );
    golden(
        "meta-root-sets.json",
        include_str!("../../../../../conformance/vectors/core/1/meta-root-sets.json"),
        &json,
    );
}

// SEC23, TI-13, OP-159 m.3 (j)
#[test]
fn only_the_canonical_sets_acknowledge() {
    use crate::verify::key_scope::Declarations;
    let w = witness("w1.example", 4);
    let rep = replica("r1.example", 5);
    let declared = Declarations {
        witnesses: vec![w.clone()],
        replicas: vec![rep.clone()],
        ..Declarations::default()
    };
    assert!(declared.acknowledges());
    assert!(!declared.acknowledges_with(&RootSets::default()));
    assert!(!declared.acknowledges_with(&RootSets::new(vec![w.clone()], Vec::new())));
    assert!(!declared.acknowledges_with(&RootSets::new(Vec::new(), vec![rep.clone()])));
    assert!(declared.acknowledges_with(&RootSets::new(vec![w], vec![rep.clone()])));
    let operator_only = Declarations {
        witnesses: vec![witness("w9.example", 9)],
        replicas: vec![rep.clone()],
        ..Declarations::default()
    };
    assert!(
        !operator_only.acknowledges_with(&RootSets::new(vec![witness("w1.example", 4)], vec![rep]))
    );
}

// CR-44, L0-SIG-82, OP-159 m.3 (r)
#[test]
fn a_fips_domain_cannot_add_ml_dsa() {
    use crate::verify::key_scope::{CryptoProfile, Declarations};
    let fips = Declarations {
        crypto_profile: Some(CryptoProfile::Fips),
        ..Declarations::default()
    };
    assert_eq!(
        admit_algorithm(&fips, Algorithm::MlDsa65),
        Err(MetaError::AlgorithmProfileConflict)
    );
    assert_eq!(admit_algorithm(&fips, Algorithm::Es256), Ok(()));
    assert_eq!(
        admit_algorithm(&Declarations::default(), Algorithm::MlDsa87),
        Ok(())
    );
}
