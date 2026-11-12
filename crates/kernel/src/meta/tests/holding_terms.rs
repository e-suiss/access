//! Holding terms on meta-actions (L0-META-13, OP-157 m.22 (f), OP-159 m.3 (k)), with the
//! `core/1/meta-holding-terms.json` vectors.

use alloc::format;

use super::*;
use crate::vector_rules::{field, golden};

const ALICE_I: Id = Id([0x22; 16]);
const CAROL_I: Id = Id([0x44; 16]);
const R: &[&str] = &["L0-META-13"];

fn terms_issue(holder: Id, basis: GrantBasis, depth: u64, count: u64) -> Payload {
    let mut a = authority(&["eu"], depth, 100);
    a.requirements = BTreeSet::from([term(1), term(count)]);
    Payload::GrantIssue(GrantContent {
        basis,
        holder: SubjectSelector::Party(holder),
        authority: a,
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    })
}

fn narrowed(grant: Id, count: u64) -> Payload {
    let mut a = authority(&["eu", "x"], 0, 100);
    a.requirements = BTreeSet::from([term(1), term(count)]);
    Payload::GrantAmend {
        grant,
        authority: a,
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    }
}

fn pin_mandate(r: &mut Recorder, instance: Id, pin: HoldingRef) {
    let m = Id([0x6d; 16]);
    let state = MandateState {
        instance,
        envelope: envelope(&["eu"], BTreeSet::new(), Some(pin)),
        since: 0,
        ended: None,
    };
    r.run
        .state
        .0
        .insert(key(kind::MANDATE, &m), state.to_value());
    r.run
        .state
        .0
        .insert(key(kind::MANDATES, &instance), set_value([m.to_value()]));
}

// TI-RT12, L0-META-13, OP-159 m.3 (k)
#[test]
#[allow(clippy::too_many_lines, reason = "one scripted run")]
fn meta_holding_terms_vectors_match() {
    let mut r = Recorder {
        run: Run::new(),
        cases: Vec::new(),
    };
    let a = shop_anchor();
    let g1_ex = r
        .step(
            "root-issues-with-terms",
            R,
            (ROOT, ROOT),
            ExerciseBasis::Anchor(a),
            &terms_issue(ALICE, GrantBasis::Anchor(a), 2, 1),
        )
        .unwrap();
    let g1 = object_id(&g1_ex, kind::GRANT, 0);
    let h1 = HoldingRef {
        grant: g1,
        holder: ALICE,
        since: 1,
    };
    let g2_ex = r
        .step(
            "redelegation-adds-the-holding-terms",
            R,
            (ALICE, ALICE_I),
            ExerciseBasis::Holding(h1),
            &terms_issue(CAROL, GrantBasis::Holding(h1), 1, 2),
        )
        .unwrap();
    let g2 = object_id(&g2_ex, kind::GRANT, 0);
    let h2 = HoldingRef {
        grant: g2,
        holder: CAROL,
        since: 2,
    };
    let g3_ex = r
        .step(
            "deeper-holding-adds-the-whole-lineage",
            R,
            (CAROL, CAROL_I),
            ExerciseBasis::Holding(h2),
            &terms_issue(BOB, GrantBasis::Holding(h2), 0, 2),
        )
        .unwrap();
    let g3 = object_id(&g3_ex, kind::GRANT, 0);
    r.step(
        "lineage-power-amend-adds-the-holding-terms",
        R,
        (ALICE, ALICE_I),
        ExerciseBasis::Holding(h1),
        &narrowed(g2, 2),
    );
    r.step(
        "anchor-basis-adds-no-holding-terms",
        R,
        (ROOT, ROOT),
        ExerciseBasis::Anchor(a),
        &narrowed(g2, 2),
    );
    r.run.now = 101;
    r.step(
        "outside-the-holding-window-is-refused",
        R,
        (ALICE, ALICE_I),
        ExerciseBasis::Holding(h1),
        &narrowed(g2, 2),
    );
    r.run.now = 0;
    let other = HoldingRef {
        grant: g2,
        holder: ALICE,
        since: 2,
    };
    pin_mandate(&mut r, ALICE_I, other);
    r.step(
        "a-mandate-pinned-elsewhere-is-refused",
        R,
        (ALICE, ALICE_I),
        ExerciseBasis::Holding(h1),
        &narrowed(g2, 2),
    );
    pin_mandate(&mut r, ALICE_I, h1);
    r.step(
        "a-mandate-pinned-to-the-holding-passes",
        R,
        (ALICE, ALICE_I),
        ExerciseBasis::Holding(h1),
        &narrowed(g2, 2),
    );
    r.step(
        "root-revokes-the-top-grant",
        R,
        (ROOT, ROOT),
        ExerciseBasis::Anchor(a),
        &Payload::GrantRevoke { grant: g1 },
    );
    r.step(
        "an-ended-grant-in-the-lineage-is-refused",
        R,
        (CAROL, CAROL_I),
        ExerciseBasis::Holding(h2),
        &Payload::GrantRevoke { grant: g3 },
    );
    let json = format!(
        "{{\n \"rule\": \"OP-159\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"meta.apply\",\n {},\n \"cases\": [\n{}\n ]\n}}\n",
        field(&["L0-META-13"]),
        r.cases.join(",\n")
    );
    golden(
        "meta-holding-terms.json",
        include_str!("../../../../../conformance/vectors/core/1/meta-holding-terms.json"),
        &json,
    );
}
