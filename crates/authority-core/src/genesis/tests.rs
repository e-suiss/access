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
        root,
        ct3_delay_s: None,
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
    for a in IdpAction::ALL {
        assert_eq!(IdpAction::from_label(&a.label()), Some(a));
    }
}
