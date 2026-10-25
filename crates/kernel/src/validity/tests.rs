use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::model::{ActionRef, ActionSet, ResourceSelector, Structural};

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn contract(variant: ProfileVariant) -> ValidityContract {
    ValidityContract {
        issuing_exercise: d(1),
        basis_ref: vec![9, 9],
        holder: d(2),
        audience: ["pep:shop".to_string()].into_iter().collect(),
        bounds: AuthoritySet {
            actions: ActionSet {
                exact: [ActionRef {
                    namespace: "pay".to_string(),
                    name: "refund".to_string(),
                    major: 1,
                    schema: d(3),
                }]
                .into_iter()
                .collect(),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: "shop".to_string(),
                prefix: vec![],
                kind: None,
                attrs: BTreeMap::new(),
            }),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        class: variant.class(),
        variant,
        profile_version: 1,
        params: BTreeMap::new(),
        horizon: 10_000,
        max_staleness_ms: (variant == ProfileVariant::BoundedStaleness).then_some(1_000),
        freshness_sources: BTreeSet::new(),
        revalidation: Revalidation::default(),
        offline_slice: BTreeSet::new(),
        local_requirements: BTreeSet::new(),
        verifier_profile_ref: d(4),
        clock_source: "ntp".to_string(),
        clock_skew_ms: 60_000,
        must_understand: BTreeSet::new(),
    }
}

fn ctx(
    now: u64,
    understood: &BTreeSet<String>,
    online: bool,
    last_refresh: Option<u64>,
) -> VerifierContext<'_> {
    VerifierContext {
        now,
        audience: "pep:shop",
        understood,
        last_refresh,
        online,
        skew_ms: 60_000,
        iat: 0,
        horizon_cap_ms: u64::MAX,
    }
}

// OP-117 m.12, m.13: the horizon is closed and the verifier's class skew caps the artefact's
#[test]
fn horizon_is_closed_and_skew_is_the_smaller_one() {
    let vc = contract(ProfileVariant::OnlineStrict);
    let none = BTreeSet::new();
    let edge = vc.horizon + vc.clock_skew_ms;
    assert_eq!(check(&vc, &ctx(edge, &none, true, None)), Ok(()));
    assert_eq!(
        check(&vc, &ctx(edge + 1, &none, true, None)),
        Err(ValidityError::Expired)
    );
    let mut tight = ctx(vc.horizon + 1_000, &none, true, None);
    tight.skew_ms = 999;
    assert_eq!(check(&vc, &tight), Err(ValidityError::Expired));
    tight.skew_ms = 1_000;
    assert_eq!(check(&vc, &tight), Ok(()));
}

#[test]
fn round_trips_and_class_must_match_variant() {
    let mut vc = contract(ProfileVariant::BoundedStaleness);
    vc.revalidation.every_uses = Some(5);
    vc.offline_slice.insert(OfflineSlice {
        budget_term: d(5),
        amount: 3,
        unit: "count".to_string(),
    });
    vc.must_understand.insert("geo".to_string());
    let bytes = vc.to_bytes().unwrap();
    assert_eq!(ValidityContract::from_bytes(&bytes), Ok(vc.clone()));
    // OP-120 m.8
    let Value::Map(mut entries) = vc.to_value() else {
        panic!("contract is a map")
    };
    for (k, v) in &mut entries {
        if *k == Value::text("profile") {
            let Value::Map(p) = v else {
                panic!("profile is a map")
            };
            p.retain(|(pk, _)| *pk != Value::text("version"));
        }
    }
    let bytes =
        suiss_crypto::dcbor::encode(&Value::Map(entries), suiss_crypto::dcbor::Limits::CEILING)
            .unwrap();
    assert_eq!(
        ValidityContract::from_bytes(&bytes),
        Err(ModelError::Missing)
    );
    vc.class = ProfileClass::Offline;
    assert_eq!(
        ValidityContract::from_bytes(&vc.to_bytes().unwrap()),
        Err(ModelError::Range)
    );
}

// §9.12, OP-108 m.2, PI-12
#[test]
fn use_rules() {
    let none = BTreeSet::new();
    let vc = contract(ProfileVariant::CheckpointedOffline);
    assert_eq!(
        check(&vc, &ctx(10_000 + 60_000, &none, false, None)),
        Ok(())
    );
    assert_eq!(
        check(&vc, &ctx(10_000 + 60_001, &none, false, None)),
        Err(ValidityError::Expired)
    );
    let mut other = ctx(0, &none, false, None);
    other.audience = "pep:bank";
    assert_eq!(check(&vc, &other), Err(ValidityError::Audience));

    let mut mu = vc.clone();
    mu.must_understand.insert("geo".to_string());
    assert_eq!(
        check(&mu, &ctx(0, &none, false, None)),
        Err(ValidityError::MustUnderstand)
    );
    let geo: BTreeSet<String> = ["geo".to_string()].into_iter().collect();
    assert_eq!(check(&mu, &ctx(0, &geo, false, None)), Ok(()));

    let mut overflow = vc.clone();
    overflow.horizon = u64::MAX;
    assert_eq!(
        check(&overflow, &ctx(0, &none, false, None)),
        Err(ValidityError::Overflow)
    );

    let strict = contract(ProfileVariant::OnlineStrict);
    assert_eq!(
        check(&strict, &ctx(0, &none, false, None)),
        Err(ValidityError::OnlineRequired)
    );
    assert_eq!(check(&strict, &ctx(0, &none, true, None)), Ok(()));

    let stale = contract(ProfileVariant::BoundedStaleness);
    assert_eq!(
        check(&stale, &ctx(5_000, &none, false, Some(4_000))),
        Ok(())
    );
    assert_eq!(
        check(&stale, &ctx(5_001, &none, false, Some(4_000))),
        Err(ValidityError::Stale)
    );
    assert_eq!(
        check(&stale, &ctx(5_000, &none, false, None)),
        Err(ValidityError::Stale)
    );
}

#[test]
fn horizon_is_the_earliest_bound() {
    assert_eq!(horizon(100, &[500, 300], 1_000), Ok(300));
    assert_eq!(horizon(100, &[], 1_000), Ok(1_100));
    assert_eq!(horizon(100, &[5_000], 1_000), Ok(1_100));
    assert_eq!(horizon(u64::MAX, &[1], 1), Err(ValidityError::Overflow));
}

fn cap_scenarios() -> Vec<(&'static str, u64, u64, u64)> {
    vec![
        ("cap-later-than-horizon-edge", 0, 20_000, 11_000),
        ("cap-later-than-horizon-past", 0, 20_000, 11_001),
        ("cap-earlier-than-horizon-edge", 2_000, 5_000, 8_000),
        ("cap-earlier-than-horizon-past", 2_000, 5_000, 8_001),
        ("cap-equal-to-horizon", 4_000, 6_000, 11_000),
        ("cap-zero", 5_000, 0, 6_000),
        ("cap-zero-past", 5_000, 0, 6_001),
        ("cap-overflow", u64::MAX, 1, u64::MAX - 1_000),
        ("iat-future-edge", 6_000, 20_000, 5_000),
        ("iat-future-past", 6_001, 20_000, 5_000),
    ]
}

fn cap_check(iat: u64, cap: u64, now: u64) -> Result<(), ValidityError> {
    let none = BTreeSet::new();
    let mut c = ctx(now, &none, true, None);
    c.skew_ms = 1_000;
    c.iat = iat;
    c.horizon_cap_ms = cap;
    check(&contract(ProfileVariant::OnlineStrict), &c)
}

// OP-118 m.4, T20, U25, OP-117 m.13: acceptance ends at min(horizon, iat + cap), plus skew; iat at most now + skew
#[test]
fn acceptance_end_is_capped_by_the_effective_ceiling() {
    let all: BTreeMap<&str, Result<(), ValidityError>> = cap_scenarios()
        .into_iter()
        .map(|(id, iat, cap, now)| (id, cap_check(iat, cap, now)))
        .collect();
    for id in [
        "cap-later-than-horizon-edge",
        "cap-earlier-than-horizon-edge",
        "cap-equal-to-horizon",
        "cap-zero",
    ] {
        assert_eq!(all[id], Ok(()), "{id}");
    }
    for id in [
        "cap-later-than-horizon-past",
        "cap-earlier-than-horizon-past",
        "cap-zero-past",
    ] {
        assert_eq!(all[id], Err(ValidityError::Expired), "{id}");
    }
    assert_eq!(all["cap-overflow"], Err(ValidityError::Overflow));
    assert_eq!(all["iat-future-edge"], Ok(()));
    assert_eq!(all["iat-future-past"], Err(ValidityError::NotYetValid));
}

struct ProfileCase {
    id: &'static str,
    variant: ProfileVariant,
    online: bool,
    last_refresh: Option<u64>,
    now: u64,
}

// OP-122 m.6, m.7, L0-VAL-7
fn profile_scenarios() -> Vec<ProfileCase> {
    let case = |id, variant, online, last_refresh, now| ProfileCase {
        id,
        variant,
        online,
        last_refresh,
        now,
    };
    vec![
        case(
            "online-strict-offline",
            ProfileVariant::OnlineStrict,
            false,
            None,
            5_000,
        ),
        case(
            "reconnect-offline-accepted",
            ProfileVariant::RevalidateOnReconnect,
            false,
            None,
            5_000,
        ),
        case(
            "reconnect-offline-horizon-edge",
            ProfileVariant::RevalidateOnReconnect,
            false,
            None,
            11_000,
        ),
        case(
            "reconnect-offline-past-horizon",
            ProfileVariant::RevalidateOnReconnect,
            false,
            None,
            11_001,
        ),
        case(
            "bounded-fresh",
            ProfileVariant::BoundedStaleness,
            false,
            Some(4_000),
            5_000,
        ),
        case(
            "bounded-stale",
            ProfileVariant::BoundedStaleness,
            false,
            Some(3_999),
            5_000,
        ),
        case(
            "bounded-no-refresh",
            ProfileVariant::BoundedStaleness,
            false,
            None,
            5_000,
        ),
        case(
            "bounded-future-refresh",
            ProfileVariant::BoundedStaleness,
            false,
            Some(5_001),
            5_000,
        ),
        case(
            "bounded-online-ignores-refresh",
            ProfileVariant::BoundedStaleness,
            true,
            None,
            5_000,
        ),
        case(
            "checkpointed-offline-accepted",
            ProfileVariant::CheckpointedOffline,
            false,
            None,
            5_000,
        ),
    ]
}

fn profile_check(c: &ProfileCase) -> Result<(), ValidityError> {
    let none = BTreeSet::new();
    let mut ctx = ctx(c.now, &none, c.online, c.last_refresh);
    ctx.skew_ms = 1_000;
    ctx.horizon_cap_ms = 100_000;
    check(&contract(c.variant), &ctx)
}

// OP-122 m.6: `online` means the verifier obtains an online decision for this use
#[test]
fn offline_use_follows_the_variant() {
    let all: BTreeMap<&str, Result<(), ValidityError>> = profile_scenarios()
        .iter()
        .map(|c| (c.id, profile_check(c)))
        .collect();
    for id in [
        "reconnect-offline-accepted",
        "reconnect-offline-horizon-edge",
        "bounded-fresh",
        "bounded-online-ignores-refresh",
        "checkpointed-offline-accepted",
    ] {
        assert_eq!(all[id], Ok(()), "{id}");
    }
    for id in [
        "bounded-stale",
        "bounded-no-refresh",
        "bounded-future-refresh",
    ] {
        assert_eq!(all[id], Err(ValidityError::Stale), "{id}");
    }
    assert_eq!(
        all["online-strict-offline"],
        Err(ValidityError::OnlineRequired)
    );
    assert_eq!(
        all["reconnect-offline-past-horizon"],
        Err(ValidityError::Expired)
    );
}

// OP-118 m.4, OP-122 m.6, m.7, OP-106 m.24
#[test]
fn validity_vectors_match() {
    extern crate std;
    use core::fmt::Write as _;
    let hex = |b: &[u8]| {
        b.iter().fold(String::new(), |mut h, x| {
            let _ = write!(h, "{x:02x}");
            h
        })
    };
    let expect = |r: Result<(), ValidityError>| match r {
        Ok(()) => "\"valid\": true".to_string(),
        Err(e) => alloc::format!(
            "\"error\": \"{}\"",
            crate::binding::Error::Validity(e).name()
        ),
    };
    let strict = hex(&contract(ProfileVariant::OnlineStrict).to_bytes().unwrap());
    let mut json = alloc::format!(
        "{{\n \"rule\": \"OP-118\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"validity.check\",\n \"contract\": \"{strict}\",\n \"audience\": \"pep:shop\",\n \"online\": true,\n \"skew_ms\": 1000,\n \"cases\": [\n"
    );
    let mut lines = Vec::new();
    for (id, iat, cap, now) in cap_scenarios() {
        lines.push(alloc::format!(
            "  {{\"id\": \"{id}\", \"iat\": {iat}, \"horizon_cap_ms\": {cap}, \"now\": {now}, {}}}",
            expect(cap_check(iat, cap, now))
        ));
    }
    for c in profile_scenarios() {
        let mut fields = alloc::format!("\"id\": \"{}\"", c.id);
        if c.variant != ProfileVariant::OnlineStrict {
            let _ = write!(
                fields,
                ", \"contract\": \"{}\"",
                hex(&contract(c.variant).to_bytes().unwrap())
            );
        }
        if !c.online {
            fields.push_str(", \"online\": false");
        }
        if let Some(t) = c.last_refresh {
            let _ = write!(fields, ", \"last_refresh\": {t}");
        }
        lines.push(alloc::format!(
            "  {{{fields}, \"iat\": 0, \"horizon_cap_ms\": 100000, \"now\": {}, {}}}",
            c.now,
            expect(profile_check(&c))
        ));
    }
    json.push_str(&lines.join(",\n"));
    json.push_str("\n ]\n}\n");
    #[cfg(not(target_os = "wasi"))]
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../conformance/vectors/core/1/validity.json"
            ),
            &json,
        )
        .unwrap();
        return;
    }
    assert_eq!(
        include_str!("../../../../conformance/vectors/core/1/validity.json"),
        json
    );
}
