//! `version/1/downgrade.json` and `version/1/transition.json`: downgrade is expansion and a
//! raised minimum binds after its transition window (SI-18, CR-8, §15.4, §13.7.8, OP-158 m.3 (b)).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::*;
use crate::codec::{Canonical as _, set_value};
use crate::vector_rules::{field, golden_in, hex};
use suiss_crypto::dcbor::{self, Limits, Value};

fn algs(list: &[Algorithm]) -> BTreeSet<Algorithm> {
    list.iter().copied().collect()
}

fn algs_hex(set: &BTreeSet<Algorithm>) -> String {
    hex(&dcbor::encode(
        &set_value(set.iter().map(|a| Value::int(a.cose()))),
        Limits::CEILING,
    )
    .unwrap())
}

type Change = (
    &'static str,
    SpecVersions,
    SpecVersions,
    &'static [Algorithm],
    &'static [Algorithm],
    bool,
);

// SI-18, CR-8, §15.4, Ek B 6119, 6131, 6142
#[test]
#[allow(clippy::too_many_lines, reason = "one table of cases")]
fn downgrade_vectors_match() {
    use Algorithm::{Ed25519, Es256, MlDsa65};
    let base = v(1, 1, &[("authzen", 2)]);
    let cases: Vec<Change> = alloc::vec![
        (
            "unchanged-narrows",
            base.clone(),
            base.clone(),
            &[Ed25519],
            &[Ed25519],
            false
        ),
        (
            "raise-core-narrows",
            base.clone(),
            v(2, 1, &[("authzen", 2)]),
            &[Ed25519],
            &[Ed25519],
            false
        ),
        (
            "lower-core-widens",
            v(2, 1, &[]),
            v(1, 1, &[]),
            &[Ed25519],
            &[Ed25519],
            true
        ),
        (
            "lower-meta-schema-widens",
            v(1, 2, &[]),
            v(1, 1, &[]),
            &[Ed25519],
            &[Ed25519],
            true
        ),
        (
            "lower-profile-widens",
            base.clone(),
            v(1, 1, &[("authzen", 1)]),
            &[Ed25519],
            &[Ed25519],
            true
        ),
        (
            "drop-profile-floor-widens",
            base.clone(),
            v(1, 1, &[]),
            &[Ed25519],
            &[Ed25519],
            true
        ),
        (
            "add-profile-floor-narrows",
            v(1, 1, &[]),
            base.clone(),
            &[Ed25519],
            &[Ed25519],
            false
        ),
        (
            "remove-algorithm-narrows",
            base.clone(),
            base.clone(),
            &[Ed25519, Es256],
            &[Ed25519],
            false
        ),
        (
            "add-weak-algorithm-widens",
            base.clone(),
            base.clone(),
            &[Ed25519],
            &[Ed25519, Es256],
            true
        ),
        (
            "add-pq-algorithm-widens",
            base.clone(),
            base.clone(),
            &[Ed25519],
            &[Ed25519, MlDsa65],
            true
        ),
    ];
    let mut lines = Vec::new();
    for (id, old_min, new_min, old_algs, new_algs, widens) in cases {
        let (oa, na) = (algs(old_algs), algs(new_algs));
        assert_eq!(downgrades((&old_min, &new_min), (&oa, &na)), widens, "{id}");
        lines.push(format!(
            "  {{\"id\": \"{id}\", {}, \"old_minimum\": \"{}\", \"new_minimum\": \"{}\", \"old_algorithms\": \"{}\", \"new_algorithms\": \"{}\", \"expansion\": {widens}}}",
            field(&["L0-META-37"]),
            hex(&old_min.to_bytes().unwrap()),
            hex(&new_min.to_bytes().unwrap()),
            algs_hex(&oa),
            algs_hex(&na),
        ));
    }
    let json = format!(
        "{{\n \"rule\": \"OP-158\",\n \"track\": \"version\",\n \"version\": 1,\n \"operation\": \"version.downgrade\",\n \"delay_ms\": {DOWNGRADE_DELAY_MS},\n \"cases\": [\n{}\n ]\n}}\n",
        lines.join(",\n")
    );
    golden_in(
        "version/1",
        "downgrade.json",
        include_str!("../../../../../conformance/vectors/version/1/downgrade.json"),
        &json,
    );
}

// §15.4, §13.7.8, Ek B 6143
#[test]
fn transition_vectors_match() {
    let current = v(1, 1, &[("authzen", 1)]);
    let activated = v(2, 1, &[("authzen", 2), ("oid4vp", 1)]);
    let t = 1_000;
    let cases = [
        (
            "before-the-window-the-old-minimum-binds",
            current.clone(),
            t,
        ),
        (
            "last-instant-of-the-window",
            current.clone(),
            t + TRANSITION_MS - 1,
        ),
        (
            "after-the-window-the-activated-binds",
            current.clone(),
            t + TRANSITION_MS,
        ),
        (
            "never-lowers",
            v(3, 1, &[("authzen", 3)]),
            t + TRANSITION_MS,
        ),
    ];
    let mut lines = Vec::new();
    for (id, current, now) in cases {
        let got = minimum_at(&current, &activated, t, now);
        lines.push(format!(
            "  {{\"id\": \"{id}\", {}, \"current\": \"{}\", \"activated\": \"{}\", \"activated_at\": {t}, \"now\": {now}, \"minimum\": \"{}\"}}",
            field(&["L0-META-37"]),
            hex(&current.to_bytes().unwrap()),
            hex(&activated.to_bytes().unwrap()),
            hex(&got.to_bytes().unwrap()),
        ));
    }
    assert_eq!(
        minimum_at(&current, &activated, t, t + TRANSITION_MS),
        v(2, 1, &[("authzen", 2), ("oid4vp", 1)])
    );
    let json = format!(
        "{{\n \"rule\": \"OP-158\",\n \"track\": \"version\",\n \"version\": 1,\n \"operation\": \"version.transition\",\n \"window_ms\": {TRANSITION_MS},\n \"cases\": [\n{}\n ]\n}}\n",
        lines.join(",\n")
    );
    golden_in(
        "version/1",
        "transition.json",
        include_str!("../../../../../conformance/vectors/version/1/transition.json"),
        &json,
    );
}
