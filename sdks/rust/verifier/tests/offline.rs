//! The offline verifier end to end over the emulator (§9.10, §9.12, §13.7.2, EP-7).

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical;
use access_kernel::model::Id;
use access_kernel::pap::{Pap, PapError};
use access_kernel::report::{self, LocalOutcome};
use access_kernel::schema::EffectClass;
use access_kernel::tier::Tier;
use access_kernel::validity::{ProfileVariant, ValidityError};
use access_kernel::verify::key_scope::{KeyUsage, VerifierCaps};
use access_verifier::caps::{self, HOUR_MS};
use access_verifier::counter::{CounterError, CounterId};
use access_verifier::offline::{Denial, Verdict, basis_position, contract_digest};
use access_verifier::profile::ProfileError;
use access_verifier::status::{ListError, StatusList};
use access_verifier::testing::EmulatedCounter;
use access_verifier::time::ClockError;
use support::{
    Device, HOUR, IAT, Inputs, LOG, NOW, contract, d, device, device_with, excerpt, intent, list,
    log_verifier, metadata, pap_with, schema, witness_verifier,
};

fn run(v: &mut Device, p: &Pap, amount: i64) -> Verdict {
    let inputs = Inputs::new(p, intent(amount, "eur"), NOW);
    v.verify(&inputs.use_())
}

fn denial(verdict: &Verdict) -> &'static str {
    match verdict {
        Verdict::Allow(_) => "allow",
        Verdict::Deny(d) => d.code(),
    }
}

fn base() -> Pap {
    pap_with(|_| {})
}

// L2-PAP-3, U2, PI-20, PI-11
#[test]
fn a_use_within_the_projection_is_allowed_and_drawn() {
    // G25
    let p = base();
    let mut v = device(&p);
    let Verdict::Allow(a) = run(&mut v, &p, 40) else {
        panic!("expected allow");
    };
    assert_eq!(a.seq, 0);
    let drawn: BTreeMap<_, _> = a.drawn.iter().map(|s| (s.budget_term, s.amount)).collect();
    assert_eq!(drawn, BTreeMap::from([(d(5), 40), (d(6), 1)]));
    let unused: BTreeMap<_, _> = v
        .slice_unused(&d(3))
        .iter()
        .map(|s| (s.budget_term, s.amount))
        .collect();
    assert_eq!(unused, BTreeMap::from([(d(5), 60), (d(6), 2)]));
}

// U2, PI-20, SEC13
#[test]
fn the_slice_is_never_overdrawn() {
    let p = base();
    let mut v = device(&p);
    assert!(matches!(run(&mut v, &p, 60), Verdict::Allow(_)));
    assert_eq!(denial(&run(&mut v, &p, 41)), "pap-slice");
    assert!(matches!(run(&mut v, &p, 40), Verdict::Allow(_)));
    assert!(matches!(run(&mut v, &p, 0), Verdict::Allow(_)));
    assert_eq!(denial(&run(&mut v, &p, 0)), "pap-slice");
}

// U2, T25
#[test]
fn a_clock_that_jumps_or_is_missing_denies() {
    let p = base();
    let mut v = device(&p);
    assert!(matches!(run(&mut v, &p, 1), Verdict::Allow(_)));
    v.clock().jump(-10 * 60_000);
    assert_eq!(
        run(&mut v, &p, 1),
        Verdict::Deny(Denial::Clock(ClockError::WentBack))
    );
    v.clock().jump(10 * 60_000);
    v.clock().set_unavailable(true);
    assert_eq!(
        run(&mut v, &p, 1),
        Verdict::Deny(Denial::Clock(ClockError::Unavailable))
    );
}

// U2, INV-24, EP-7
#[test]
fn past_the_horizon_or_the_class_ceiling_denies() {
    let p = pap_with(|p| p.validity.horizon = IAT + HOUR);
    let mut v = device(&p);
    assert_eq!(denial(&run(&mut v, &p, 1)), "pap-validity");
}

// U25, T20, CR-K1
#[test]
fn the_verifier_ceiling_wins_over_the_artefact() {
    let p = pap_with(|p| p.validity.horizon = 40 * HOUR);
    let mut md = metadata();
    md.caps = Some(VerifierCaps {
        horizon: BTreeMap::from([(1, HOUR)]),
        slice_max: BTreeMap::new(),
    });
    let mut v = device_with(md, &p);
    assert_eq!(
        run(&mut v, &p, 1),
        Verdict::Deny(Denial::Pap(PapError::Validity(ValidityError::Expired)))
    );
}

// PI-12, U25
#[test]
fn a_contract_for_another_profile_or_variant_denies() {
    let p = pap_with(|p| p.validity.verifier_profile_ref = d(99));
    let mut v = device(&p);
    assert_eq!(
        run(&mut v, &p, 1),
        Verdict::Deny(Denial::Profile(ProfileError::Reference))
    );
    let p = pap_with(|p| p.validity.clock_source = "ntp".to_owned());
    let mut v = device(&p);
    assert_eq!(
        run(&mut v, &p, 1),
        Verdict::Deny(Denial::Profile(ProfileError::Clock))
    );
}

// §13.7.2, EP-7
#[test]
fn class_ceilings_follow_the_tier() {
    let p = base();
    let mut v = device(&p);
    let mut ct2 = Inputs::new(&p, intent(1, "eur"), NOW);
    ct2.schema = Some(schema(EffectClass::Irreversible, false));
    assert_eq!(
        v.verify(&ct2.use_()),
        Verdict::Deny(Denial::Profile(ProfileError::ClassCap))
    );
    let mut ct3 = Inputs::new(&p, intent(1, "eur"), NOW);
    ct3.schema = Some(schema(EffectClass::Reversible, true));
    assert_eq!(
        v.verify(&ct3.use_()),
        Verdict::Deny(Denial::Profile(ProfileError::ClassCap))
    );
    let Verdict::Allow(a) = run(&mut v, &p, 1) else {
        panic!("CT1 is within the class ceiling");
    };
    assert_eq!(a.tier, Tier::Ct1);
}

// §13.7.2
#[test]
fn a_ct2_offline_extension_needs_metadata_and_one_verifier() {
    let p = pap_with(|p| {
        p.validity.offline_slice.clear();
        p.validity.horizon = IAT + 3 * HOUR;
    });
    let mut md = metadata();
    md.caps = Some(VerifierCaps {
        horizon: BTreeMap::from([(2, 8 * HOUR)]),
        slice_max: BTreeMap::new(),
    });
    let mut v = device_with(md, &p);
    let mut ct2 = Inputs::new(&p, intent(1, "eur"), NOW);
    ct2.schema = Some(schema(EffectClass::Irreversible, false));
    assert!(matches!(v.verify(&ct2.use_()), Verdict::Allow(_)));
    let wide = pap_with(|p| {
        p.validity.offline_slice.clear();
        p.validity.audience.insert("other.example".to_owned());
    });
    let mut ct2 = Inputs::new(&wide, intent(1, "eur"), NOW);
    ct2.schema = Some(schema(EffectClass::Irreversible, false));
    assert_eq!(
        v.verify(&ct2.use_()),
        Verdict::Deny(Denial::Profile(ProfileError::Audience))
    );
}

// EP-7, SEC27, INV-26
#[test]
fn online_strict_is_never_accepted_offline() {
    let p = pap_with(|p| {
        p.validity.variant = ProfileVariant::OnlineStrict;
        p.validity.class = ProfileVariant::OnlineStrict.class();
        p.validity.offline_slice.clear();
    });
    let mut v = device(&p);
    let verdict = run(&mut v, &p, 1);
    assert_eq!(
        verdict,
        Verdict::Deny(Denial::Pap(PapError::Validity(
            ValidityError::OnlineRequired
        )))
    );
    assert!(matches!(verdict, Verdict::Deny(d) if d.online_may_allow()));
}

// U19, INV-24
#[test]
fn bounded_staleness_runs_on_the_status_list_age() {
    let p = pap_with(|p| {
        p.validity.variant = ProfileVariant::BoundedStaleness;
        p.validity.class = ProfileVariant::BoundedStaleness.class();
        p.validity.offline_slice.clear();
        p.validity.max_staleness_ms = Some(5 * 60_000);
    });
    let mut v = device(&p);
    assert!(matches!(run(&mut v, &p, 1), Verdict::Allow(_)));
    let p = pap_with(|p| {
        p.validity.variant = ProfileVariant::BoundedStaleness;
        p.validity.class = ProfileVariant::BoundedStaleness.class();
        p.validity.offline_slice.clear();
        p.validity.max_staleness_ms = Some(30_000);
    });
    let mut v = device(&p);
    assert_eq!(
        run(&mut v, &p, 1),
        Verdict::Deny(Denial::Pap(PapError::Validity(ValidityError::Stale)))
    );
    let p = pap_with(|p| {
        p.validity.variant = ProfileVariant::BoundedStaleness;
        p.validity.class = ProfileVariant::BoundedStaleness.class();
        p.validity.offline_slice.clear();
        p.validity.max_staleness_ms = Some(20 * 60_000);
    });
    let mut v = device(&p);
    assert_eq!(
        run(&mut v, &p, 1),
        Verdict::Deny(Denial::Profile(ProfileError::Parameter))
    );
}

// U2, PI-9, L2-STL-3
#[test]
fn a_set_status_bit_denies_and_a_missing_list_falls_back_to_the_horizon() {
    let p = base();
    let mut v = device(&p);
    let revoked = StatusList::verify(
        &metadata(),
        &list(&[9], NOW - 30_000),
        &excerpt(KeyUsage::StatusList),
    )
    .unwrap();
    v.install_list(revoked);
    assert_eq!(run(&mut v, &p, 1), Verdict::Deny(Denial::Revoked));
    let older = StatusList::verify(
        &metadata(),
        &list(&[], NOW - 20 * 60_000),
        &excerpt(KeyUsage::StatusList),
    )
    .unwrap();
    v.install_list(older);
    assert_eq!(run(&mut v, &p, 1), Verdict::Deny(Denial::Revoked));
    let p = pap_with(|p| p.validity.status = None);
    let mut v = device(&p);
    assert!(matches!(run(&mut v, &p, 1), Verdict::Allow(_)));
}

// L2-STL-2, OP-150 m.6 (d)
#[test]
fn a_list_under_another_key_or_with_bad_zlib_is_refused() {
    let bad = list(&[], NOW - 30_000);
    assert!(matches!(
        StatusList::verify(&metadata(), &bad, &excerpt(KeyUsage::Pap)),
        Err(ListError::Key(_))
    ));
    assert_eq!(
        access_verifier::status::inflate(&[0x78, 0x9c, 1, 2, 3]),
        Err(ListError::Compression)
    );
    let bomb = support::zlib(&vec![0_u8; access_verifier::status::MAX_LIST_BYTES + 1]);
    assert_eq!(
        access_verifier::status::inflate(&bomb),
        Err(ListError::Compression)
    );
}

// TI-RT5
#[test]
fn metadata_freshness_comes_from_a_witness() {
    let p = base();
    let mut v = device(&p);
    let view = v.metadata_mut();
    assert!(view.fresh(NOW, None));
    assert!(!view.fresh(NOW + 2 * HOUR_MS, None));
    let mut fresh =
        access_verifier::metadata::MetadataView::new(metadata(), support::SIGNED_METADATA);
    assert!(!fresh.fresh(NOW, None));
    // OP-152 m.5 (h)
    for other in [
        support::checkpoint_of(Some(b"older metadata"), Some(NOW / 1_000 - 60)),
        support::checkpoint_of(None, Some(NOW / 1_000 - 60)),
    ] {
        assert_eq!(
            fresh.witness(&other, LOG, &log_verifier(), &[witness_verifier()]),
            Err(access_verifier::metadata::WitnessError::OtherMetadata)
        );
    }
    assert!(!fresh.fresh(NOW, None));
    assert_eq!(
        fresh.witness(
            &support::checkpoint(None),
            LOG,
            &log_verifier(),
            &[witness_verifier()]
        ),
        Err(access_verifier::metadata::WitnessError::Unwitnessed)
    );
    fresh
        .witness(
            &support::checkpoint(Some(NOW / 1_000 - 7_200)),
            LOG,
            &log_verifier(),
            &[witness_verifier()],
        )
        .unwrap();
    assert!(!fresh.fresh(NOW, None));
    assert!(fresh.fresh(NOW, Some(3 * HOUR_MS)));
    let mut stale = device_with(metadata(), &p);
    *stale.metadata_mut() = fresh;
    assert_eq!(
        run(&mut stale, &p, 1),
        Verdict::Deny(Denial::Pap(PapError::Stale))
    );
}

// INV-41, U60
#[test]
fn content_written_after_the_basis_denies_when_the_profile_checks_it() {
    let p = base();
    assert_eq!(basis_position(&p.validity), Some(41));
    let mut v = device(&p);
    let mut inputs = Inputs::new(&p, intent(1, "eur"), NOW);
    inputs.content_position = Some(41);
    assert!(matches!(v.verify(&inputs.use_()), Verdict::Allow(_)));
    inputs.content_position = Some(42);
    let verdict = v.verify(&inputs.use_());
    assert_eq!(verdict, Verdict::Deny(Denial::ContentPosition));
}

// TI-RT6, PI-12
#[test]
fn another_domain_or_an_unknown_extension_denies() {
    let p = pap_with(|p| p.domain = d(2));
    let mut v = device(&p);
    assert_eq!(denial(&run(&mut v, &p, 1)), "pap-key");
    let p = pap_with(|p| {
        p.validity.must_understand.insert("future_ext".to_owned());
    });
    let mut v = device(&p);
    assert_eq!(
        run(&mut v, &p, 1),
        Verdict::Deny(Denial::Pap(PapError::Validity(
            ValidityError::MustUnderstand
        )))
    );
}

// U3, SEC13
#[test]
fn a_missing_or_wiped_counter_denies() {
    let p = base();
    let mut v = device(&p);
    let other = pap_with(|p| p.projection_exercise = d(33));
    assert_eq!(denial(&run(&mut v, &other, 1)), "pap-slice");
    let mut v = device(&base());
    let shared = EmulatedCounter::new(CounterId([50; 16]));
    v.provision(d(3), d(5), 100, shared.share()).unwrap();
    assert!(matches!(run(&mut v, &p, 1), Verdict::Allow(_)));
    shared.wipe(CounterId([51; 16])).unwrap();
    assert_eq!(
        run(&mut v, &p, 1),
        Verdict::Deny(Denial::Counter(CounterError::Wiped))
    );
}

// U3, SEC13
#[test]
fn a_group_counter_bounds_the_whole_group() {
    let p = base();
    let group = EmulatedCounter::new(CounterId([60; 16]));
    let count = EmulatedCounter::new(CounterId([61; 16]));
    let mut a = device(&p);
    let mut b = device(&p);
    for v in [&mut a, &mut b] {
        v.provision(d(3), d(5), 100, group.share()).unwrap();
        v.provision(d(3), d(6), 3, count.share()).unwrap();
    }
    assert!(matches!(run(&mut a, &p, 70), Verdict::Allow(_)));
    assert_eq!(denial(&run(&mut b, &p, 40)), "pap-slice");
    assert!(matches!(run(&mut b, &p, 30), Verdict::Allow(_)));
}

// U4, L2-RPT-2, L2-RPT-3, P27
#[test]
fn uses_are_chained_into_a_report_that_verifies_and_continues() {
    let p = base();
    let mut v = device(&p);
    assert!(matches!(run(&mut v, &p, 30), Verdict::Allow(_)));
    assert_eq!(denial(&run(&mut v, &p, 90)), "pap-slice");
    assert!(matches!(run(&mut v, &p, 10), Verdict::Allow(_)));
    let forged = pap_with(|p| p.validity.horizon = 99 * HOUR);
    let mut bad = Inputs::new(&forged, intent(1, "eur"), NOW);
    bad.pap = support::sign1(
        9,
        access_kernel::pap::CONTENT_TYPE,
        &forged.to_bytes().unwrap(),
    );
    assert_eq!(denial(&v.verify(&bad.use_())), "pap-signature");
    assert_eq!(v.unreported(), vec![d(3)]);
    let cut = v.report(&d(3)).unwrap().unwrap();
    let (decoded, summary) = report::verify_bytes(&cut.body).unwrap();
    assert_eq!(decoded, cut.report);
    assert_eq!(summary.next_seq, 3);
    assert_eq!(
        cut.report
            .entries
            .iter()
            .map(|e| e.outcome)
            .collect::<Vec<_>>(),
        vec![LocalOutcome::Allow, LocalOutcome::Deny, LocalOutcome::Allow]
    );
    assert_eq!(summary.drawn.get(&d(5)), Some(&40));
    assert_eq!(cut.report.contract, contract_digest(&contract()).unwrap());
    assert_eq!(cut.report.verifier_instance, Some(Id([8; 16])));
    let unused: BTreeSet<_> = cut
        .report
        .slice_unused
        .iter()
        .map(|s| (s.budget_term, s.amount))
        .collect();
    assert_eq!(unused, BTreeSet::from([(d(5), 60), (d(6), 1)]));
    assert!(matches!(run(&mut v, &p, 1), Verdict::Allow(_)));
    let next = v.report(&d(3)).unwrap().unwrap();
    let (_, s2) = report::verify_bytes(&next.body).unwrap();
    assert!(report::continues(&summary, &next.report));
    assert_eq!(s2.next_seq, 4);
    let mut hidden = next.report.clone();
    hidden.entries.clear();
    assert!(report::verify(&hidden).is_err());
}

// §13.7.2
#[test]
fn report_deadline_is_horizon_plus_a_day() {
    assert_eq!(caps::report_deadline(10), 10 + 24 * HOUR_MS);
    assert_eq!(caps::report_deadline(u64::MAX), u64::MAX);
}

// §13.7.2
#[test]
fn the_class_table_matches_the_policy_defaults() {
    let day = 24 * HOUR_MS;
    let row = |v, t| caps::policy(v, t).map(|c| (c.horizon_ms, c.staleness_ms, c.hardware));
    assert_eq!(
        row(ProfileVariant::BoundedStaleness, Tier::Ct0),
        Some((day, Some(15 * 60_000), false))
    );
    assert_eq!(
        row(ProfileVariant::BoundedStaleness, Tier::Ct1),
        Some((8 * HOUR_MS, Some(5 * 60_000), false))
    );
    assert_eq!(row(ProfileVariant::BoundedStaleness, Tier::Ct2), None);
    assert_eq!(
        row(ProfileVariant::CheckpointedOffline, Tier::Ct0),
        Some((3 * day, None, false))
    );
    assert_eq!(
        row(ProfileVariant::CheckpointedOffline, Tier::Ct1),
        Some((day, None, true))
    );
    assert_eq!(row(ProfileVariant::CheckpointedOffline, Tier::Ct2), None);
    assert_eq!(
        row(ProfileVariant::OnlineStrict, Tier::Ct2),
        Some((5 * 60_000, None, false))
    );
    for v in [
        ProfileVariant::OnlineStrict,
        ProfileVariant::BoundedStaleness,
        ProfileVariant::RevalidateOnReconnect,
        ProfileVariant::CheckpointedOffline,
        ProfileVariant::CheckpointContinuation,
    ] {
        assert_eq!(caps::policy(v, Tier::Ct3), None);
    }
    assert_eq!(
        caps::policy(ProfileVariant::CheckpointContinuation, Tier::Ct2)
            .and_then(|c| c.checkpoint_ms),
        Some(0)
    );
    assert_eq!(
        caps::ct2_offline_extension(8 * HOUR_MS).horizon_ms,
        4 * HOUR_MS
    );
    assert_eq!(caps::skew_ms(Tier::Ct1), 120_000);
    assert_eq!(caps::skew_ms(Tier::Ct2), 60_000);
}
