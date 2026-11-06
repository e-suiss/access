#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_internal_api::idp::{GenesisOrder, IdpAction, NAMESPACES};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{Root, kind, object_id};
use access_kernel::model::{Id, ResourceRef, Window};
use access_kernel::tier::{Tier, of};

use super::*;

struct Fixed;

impl Salts for Fixed {
    fn salt(&mut self) -> Result<[u8; 32], CoreError> {
        Ok([4; 32])
    }
}

fn values(order: &GenesisOrder) -> BTreeMap<String, Value> {
    realm(order, &mut Fixed)
        .unwrap()
        .into_iter()
        .map(|(k, o)| (k, o.value))
        .collect()
}

fn order(root: Root) -> GenesisOrder {
    GenesisOrder {
        tenant: [1; 16],
        slug: String::from("acme"),
        root,
        ct3_delay_s: None,
        schemas: Vec::new(),
        issuer: None,
        acceptances: Vec::new(),
        issuer_predicate_input: Vec::new(),
    }
}

// TN-111, L0-META-7, OP-141 m.35 (d): the template is a valid Genesis whose `idp` Anchor is
// rooted in the founder and whose state accepts every `idp.*` catalog
#[test]
fn a_realm_genesis_roots_idp_and_accepts_its_catalogs() {
    // INV-2, INV-29, E34, MD-14
    let d = Digest([7; 32]);
    let founder = Id([2; 16]);
    let effects = meta::genesis_effects(&d, &values(&order(Root::Sole(founder)))).unwrap();
    let keys: BTreeSet<Vec<u8>> = effects.iter().map(|(k, _)| k.clone()).collect();
    assert!(keys.contains(&meta::key(kind::ANCHOR, &meta::meta_anchor(&d))));
    assert!(keys.contains(&meta::key(
        kind::ANCHOR,
        &object_id(&d, kind::ANCHOR, IDP_ANCHOR)
    )));
    for ns in NAMESPACES {
        assert!(
            keys.contains(&access_kernel::schema::schemas_key(ns)),
            "{ns}"
        );
    }
    assert!(!values(&order(Root::Sole(founder))).contains_key("policy"));
}

// §12.5.1: a joint founding root is kept as it is, and the time-lock default can be set
#[test]
fn a_joint_root_and_a_time_lock_are_carried() {
    // TN-111, OP-141 m.34 (d)
    let root = Root::Joint {
        parties: BTreeSet::from([Id([3; 16]), Id([2; 16])]),
        k: 2,
    };
    let mut o = order(root);
    o.ct3_delay_s = Some(0);
    let v = values(&o);
    assert!(meta::genesis_effects(&Digest([7; 32]), &v).is_ok());
    assert!(v.contains_key("policy"));
}

fn intent(action: IdpAction) -> IntentEnvelope {
    IntentEnvelope {
        action: action.action_ref(),
        resources: vec![ResourceRef {
            namespace: String::from("idp"),
            path: vec![String::from("acme"), String::from("realm")],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window { from: 0, until: 1 },
    }
}

// OP-141 m.34 (a), m.35 (g): the tier of each `idp.*` action follows from its schema; the RP
// ID change is reserved and irreversible, so CT3 (IDP-5, IDI-4)
#[test]
fn idp_actions_carry_their_consequence_tiers() {
    // IDP-5, IDI-4, TN-95, TN-117, §13.7.1
    let tier = |a: IdpAction| of(&intent(a), None, false, Some(&a.schema()));
    assert_eq!(tier(IdpAction::RealmRpId), Tier::Ct3);
    assert_eq!(tier(IdpAction::RealmRehome), Tier::Ct3);
    assert_eq!(tier(IdpAction::UpstreamRegister), Tier::Ct3);
    assert_eq!(tier(IdpAction::UpstreamMapping), Tier::Ct3);
    assert_eq!(tier(IdpAction::ClientRegister), Tier::Ct2);
    assert_eq!(tier(IdpAction::ClientUpdate), Tier::Ct2);
    assert_eq!(tier(IdpAction::CimdPolicy), Tier::Ct2);
    assert_eq!(tier(IdpAction::RealmJoseAlg), Tier::Ct2);
    assert_eq!(tier(IdpAction::MapperSet), Tier::Ct2);
    assert_eq!(tier(IdpAction::ClientRetire), Tier::Ct1);
    assert_eq!(tier(IdpAction::RealmArgon2), Tier::Ct1);
    // TN-118, TN-106, §13.2, §13.7.1, OP-73
    assert_eq!(tier(IdpAction::RealmKeyPolicy), Tier::Ct3);
    assert_eq!(tier(IdpAction::RealmKeyRotate), Tier::Ct3);
    assert_eq!(tier(IdpAction::AccountDelete), Tier::Ct3);
    assert_eq!(tier(IdpAction::RealmBranding), Tier::Ct2);
    assert_eq!(tier(IdpAction::RealmKeyDrop), Tier::Ct1);
    for a in IdpAction::ALL {
        assert_eq!(IdpAction::from_label(&a.label()), Some(a));
    }
}

fn catalog(publisher: Id, namespace: &str) -> access_kernel::schema::Spp {
    access_kernel::schema::Spp {
        publisher,
        namespace: String::from(namespace),
        catalog_version: 1,
        actions: vec![access_kernel::schema::ActionSchema {
            name: String::from("approve"),
            major: 1,
            effect: access_kernel::schema::EffectClass::Reversible,
            reserved: false,
            consumption_bearing: false,
            params: BTreeMap::new(),
            resource_types: BTreeSet::new(),
            render: None,
        }],
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

// OP-141 m.35 (c), OP-149 m.10, SEC8: a Genesis may publish further catalogs of the founder in
// namespaces of their own; one by another publisher, or in a namespace Access publishes, is
// refused
#[test]
fn a_genesis_publishes_the_founders_further_catalogs() {
    let d = Digest([7; 32]);
    let founder = Id([2; 16]);
    let mut o = order(Root::Sole(founder));
    o.schemas = vec![catalog(founder, "work")];
    let effects = meta::genesis_effects(&d, &values(&o)).unwrap();
    let keys: BTreeSet<Vec<u8>> = effects.iter().map(|(k, _)| k.clone()).collect();
    assert!(keys.contains(&access_kernel::schema::schemas_key("work")));
    assert!(keys.contains(&access_kernel::schema::schemas_key("idp.client")));
    for bad in [
        catalog(Id([3; 16]), "work"),
        catalog(founder, "idp.client"),
        catalog(founder, "access"),
    ] {
        o.schemas = vec![bad];
        assert!(matches!(
            realm(&o, &mut Fixed),
            Err(CoreError::Protocol("genesis-schema"))
        ));
    }
    o.schemas = vec![catalog(founder, "work"), catalog(founder, "work")];
    assert!(realm(&o, &mut Fixed).is_err());
}

// §10.1.4 rule 3, E18, OP-142, first-party neutrality (§9.13.2): a domain is born accepting its
// realm's issuer for actor-binding only; predicate input and subject selection are not implied
#[test]
fn the_realm_issuer_is_accepted_for_actor_binding_only() {
    let d = Digest([7; 32]);
    let issuer = Id([9; 16]);
    let mut o = order(Root::Sole(Id([2; 16])));
    let without = meta::genesis_effects(&d, &values(&o)).unwrap();
    assert!(
        !without
            .iter()
            .any(|(k, _)| *k == meta::key(kind::ACCEPTANCES, &issuer))
    );
    o.issuer = Some(issuer);
    let effects = meta::genesis_effects(&d, &values(&o)).unwrap();
    let gates: Vec<access_kernel::claim::Gate> = effects
        .iter()
        .filter_map(|(_, v)| v.as_ref())
        .filter_map(|v| access_kernel::meta::ContentState::from_value(v).ok())
        .filter_map(|c| access_kernel::claim::Gate::of(&c.content).ok())
        .filter(|g| g.issuer == Some(issuer))
        .collect();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].use_, access_kernel::claim::ACTOR_BINDING);
    assert_eq!(
        gates[0].classes,
        REALM_ISSUER_CLASSES.map(String::from).to_vec()
    );
}

// MD-5a, TN-1, INV-37: the `idp` Anchor covers only its own realm's resources, so the domain
// governs that realm alone; a Genesis without a slug is refused
#[test]
fn the_idp_anchor_covers_its_realm_only() {
    let o = order(Root::Sole(Id([2; 16])));
    let Value::Array(anchors) = values(&o).remove("anchors").unwrap() else {
        panic!("anchors");
    };
    let scope = anchors
        .iter()
        .find_map(|a| match a {
            Value::Map(m) => m
                .iter()
                .find(|(k, _)| *k == Value::text("scope"))
                .map(|(_, v)| v.clone()),
            _ => None,
        })
        .unwrap();
    let Value::Map(scope) = scope else {
        panic!("scope");
    };
    let resource = ResourceSelector::from_value(&scope[0].1).unwrap();
    let ResourceSelector::Structural(s) = resource else {
        panic!("{resource:?}");
    };
    assert_eq!(
        (s.namespace.as_str(), s.prefix),
        ("idp", vec![String::from("acme")])
    );
    let mut bad = order(Root::Sole(Id([2; 16])));
    bad.slug = String::new();
    assert!(matches!(
        realm(&bad, &mut Fixed),
        Err(CoreError::Protocol("genesis-slug"))
    ));
}
