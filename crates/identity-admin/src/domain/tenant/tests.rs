#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

// TN-140, OP-159 m.47 (h)
#[test]
fn the_tenant_catalog_carries_its_tiers() {
    use access_kernel::tier::{Tier, of};
    let spp = catalog(Id([1; 16]));
    assert_eq!(spp.namespace, NAMESPACE);
    assert_eq!(spp.actions.len(), TenantAction::ALL.len());
    let tier = |a: TenantAction| {
        let change = TenantChange::AdminRemove { subject: [0; 16] };
        let mut intent = change
            .intent("acme-admin", Window { from: 0, until: 1 })
            .unwrap();
        intent.action = a.action_ref();
        of(&intent, None, false, Some(&a.schema()))
    };
    assert_eq!(tier(TenantAction::EnvironmentCreate), Tier::Ct2);
    assert_eq!(tier(TenantAction::AdminInvite), Tier::Ct2);
    assert_eq!(tier(TenantAction::AdminRemove), Tier::Ct1);
    assert_eq!(tier(TenantAction::OwnerAdd), Tier::Ct3);
    assert!(!TenantAction::ADMINISTERED.contains(&TenantAction::OwnerAdd));
}

// EI-25, TN-89 (4)
#[test]
fn a_tenant_change_binds_its_body_and_checks_its_fields() {
    let a = TenantChange::EnvironmentCreate(NewTenantEnvironment {
        slug: String::from("acme"),
        style: IssuerStyle::Path,
        sandbox: false,
        schemas: Vec::new(),
        acceptances: Vec::new(),
        issuer_predicate_input: Vec::new(),
    });
    let b = TenantChange::EnvironmentCreate(NewTenantEnvironment {
        slug: String::from("acme"),
        style: IssuerStyle::Path,
        sandbox: true,
        schemas: Vec::new(),
        acceptances: Vec::new(),
        issuer_predicate_input: Vec::new(),
    });
    assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    assert_eq!(
        a.resource("acme-admin").path,
        ["acme-admin", "tenant", "environment", "acme"]
    );
    assert!(a.check().is_ok());
    let bad = TenantChange::EnvironmentCreate(NewTenantEnvironment {
        slug: String::from("api"),
        style: IssuerStyle::Path,
        sandbox: false,
        schemas: Vec::new(),
        acceptances: Vec::new(),
        issuer_predicate_input: Vec::new(),
    });
    assert_eq!(
        bad.check(),
        Err(TenantInvalid::Provision(ProvisionInvalid::Slug))
    );
    assert_eq!(
        folded_email(" Ｂob@Example.COM ").as_deref(),
        Some("bob@example.com")
    );
    assert_eq!(folded_email("bob@localhost"), None);
    let invite = |email: &str, days| {
        TenantChange::AdminInvite(AdminInvite {
            email: String::from(email),
            days,
            inviter_name: None,
            environments: Vec::new(),
        })
    };
    assert!(invite("bob@example.com", 7).check().is_ok());
    assert_eq!(
        invite("Bob@example.com", 7).check(),
        Err(TenantInvalid::Email)
    );
    assert_eq!(
        invite("bob@example.com", 31).check(),
        Err(TenantInvalid::Lifetime)
    );
    assert_eq!(TenantInvalid::NotPrimary.code(), "primary-environment");
}

// OP-159 m.49 (d), TN-144
#[test]
fn an_invitation_scope_is_bound_sorted_and_distinct() {
    let invite = |environments: &[&str]| {
        TenantChange::AdminInvite(AdminInvite {
            email: String::from("bob@example.com"),
            days: 7,
            inviter_name: None,
            environments: environments.iter().map(|s| String::from(*s)).collect(),
        })
    };
    let whole = invite(&[]);
    let scoped = invite(&["acme", "acme-staging"]);
    assert!(scoped.check().is_ok());
    assert_ne!(whole.digest().unwrap(), scoped.digest().unwrap());
    assert_ne!(
        scoped.digest().unwrap(),
        invite(&["acme-staging"]).digest().unwrap()
    );
    for bad in [
        &["acme-staging", "acme"][..],
        &["acme", "acme"][..],
        &["Acme"][..],
    ] {
        assert_eq!(invite(bad).check(), Err(TenantInvalid::Scope), "{bad:?}");
    }
    let many: Vec<String> = (0..=MAX_SCOPE).map(|i| format!("env-{i:03}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(invite(&refs).check(), Err(TenantInvalid::Scope));
    assert_eq!(TenantInvalid::Scope.code(), "invalid-admin-scope");
}

// OP-159 m.47 (e)
#[test]
fn the_owners_root_every_environment_each_alone() {
    use access_kernel::meta::Root;
    assert_eq!(owners_root(&BTreeSet::new()), None);
    let one = BTreeSet::from([Id([1; 16])]);
    assert_eq!(owners_root(&one), Some(Root::Sole(Id([1; 16]))));
    let two = BTreeSet::from([Id([1; 16]), Id([2; 16])]);
    assert!(matches!(owners_root(&two), Some(Root::Joint { k: 1, .. })));
}
