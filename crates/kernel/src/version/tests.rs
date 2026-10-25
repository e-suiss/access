use alloc::string::ToString;

use super::*;
use crate::digest::Digest;

fn domain(adopted: &SpecVersions, minimum: &SpecVersions) -> DomainMetadata {
    DomainMetadata {
        domain: Digest([1; 32]),
        genesis: Digest([2; 32]),
        issued_at: 0,
        binding: alloc::collections::BTreeMap::new(),
        algorithms: alloc::collections::BTreeSet::new(),
        operational_window_max_ms: 0,
        operational_keys: alloc::vec::Vec::new(),
        min_versions: minimum.clone(),
        adopted: adopted.clone(),
        caps: None,
        hybrid: None,
        discovery: None,
    }
}

fn v(core: u64, meta: u64, profiles: &[(&str, u64)]) -> SpecVersions {
    SpecVersions {
        core,
        meta_schema: meta,
        profiles: profiles.iter().map(|(n, x)| (n.to_string(), *x)).collect(),
        schemas: alloc::collections::BTreeSet::new(),
    }
}

// §9.17 compat k.5
#[test]
fn newer_verifier_accepts_older_versions_never_the_reverse() {
    let old = v(1, 1, &[("authzen", 1)]);
    let new = v(2, 1, &[("authzen", 2)]);
    assert_eq!(check_understood(&old, &new), Ok(()));
    assert_eq!(
        check_understood(&new, &old),
        Err(VersionError::NotUnderstood(Track::Core))
    );
    assert_eq!(
        check_understood(&v(1, 2, &[]), &old),
        Err(VersionError::NotUnderstood(Track::MetaSchema))
    );
    assert_eq!(
        check_understood(&v(1, 1, &[("authzen", 2)]), &old),
        Err(VersionError::NotUnderstood(Track::Profile))
    );
    assert_eq!(
        check_understood(&v(1, 1, &[("ssf", 1)]), &old),
        Err(VersionError::NotUnderstood(Track::Profile))
    );
}

// §9.17 compat k.2
#[test]
fn unadopted_version_has_no_effect() {
    let supported = v(2, 2, &[("authzen", 2), ("ssf", 1)]);
    let adopted = v(1, 1, &[("authzen", 1)]);
    let minimum = v(1, 1, &[]);
    assert_eq!(
        check_domain(
            &v(1, 1, &[("authzen", 1)]),
            &supported,
            &domain(&adopted, &minimum)
        ),
        Ok(())
    );
    assert_eq!(
        check_domain(&v(2, 1, &[]), &supported, &domain(&adopted, &minimum)),
        Err(VersionError::NotAdopted(Track::Core))
    );
    assert_eq!(
        check_domain(&v(1, 2, &[]), &supported, &domain(&adopted, &minimum)),
        Err(VersionError::NotAdopted(Track::MetaSchema))
    );
    assert_eq!(
        check_domain(
            &v(1, 1, &[("ssf", 1)]),
            &supported,
            &domain(&adopted, &minimum)
        ),
        Err(VersionError::NotAdopted(Track::Profile))
    );
}

// §9.17 compat k.4, PI-21
#[test]
fn below_the_domain_minimum_is_a_downgrade() {
    let supported = v(3, 3, &[("authzen", 3)]);
    let adopted = v(3, 3, &[("authzen", 3)]);
    let minimum = v(2, 2, &[("authzen", 2)]);
    assert_eq!(
        check_domain(&v(1, 2, &[]), &supported, &domain(&adopted, &minimum)),
        Err(VersionError::BelowMinimum(Track::Core))
    );
    assert_eq!(
        check_domain(&v(2, 1, &[]), &supported, &domain(&adopted, &minimum)),
        Err(VersionError::BelowMinimum(Track::MetaSchema))
    );
    assert_eq!(
        check_domain(
            &v(2, 2, &[("authzen", 1)]),
            &supported,
            &domain(&adopted, &minimum)
        ),
        Err(VersionError::BelowMinimum(Track::Profile))
    );
    assert_eq!(
        check_domain(&v(2, 2, &[]), &supported, &domain(&adopted, &minimum)),
        Ok(())
    );
}

// §9.17 compat k.6: a standard's new version moves only its own profile track
#[test]
fn profile_tracks_are_independent_of_core() {
    let supported = v(1, 1, &[("authzen", 2), ("oauth_rar", 1)]);
    let adopted = supported.clone();
    let minimum = v(1, 1, &[("authzen", 1)]);
    for authzen in [1, 2] {
        assert_eq!(
            check_domain(
                &v(1, 1, &[("authzen", authzen), ("oauth_rar", 1)]),
                &supported,
                &domain(&adopted, &minimum)
            ),
            Ok(())
        );
    }
}

#[test]
fn understanding_comes_before_adoption() {
    let old = v(1, 1, &[]);
    assert_eq!(
        check_domain(&v(2, 1, &[]), &old, &domain(&v(2, 1, &[]), &old)),
        Err(VersionError::NotUnderstood(Track::Core))
    );
    assert_eq!(CORE, 1);
}
