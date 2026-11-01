use alloc::collections::BTreeMap;
use alloc::string::ToString;

use super::*;
use crate::model::{ActionRef, Id, ResourceRef, Window};

fn intent(amount: Option<(i64, &str)>) -> IntentEnvelope {
    let mut params = BTreeMap::new();
    if let Some((value, unit)) = amount {
        params.insert(
            "amount".to_string(),
            ParamValue::Amount {
                value,
                unit: unit.to_string(),
            },
        );
    }
    IntentEnvelope {
        action: ActionRef {
            namespace: "shop".to_string(),
            name: "refund".to_string(),
            major: 1,
            schema: crate::digest::Digest([9; 32]),
        },
        resources: alloc::vec![ResourceRef {
            namespace: "shop".to_string(),
            path: alloc::vec![],
            incarnation: 0,
        }],
        params,
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: crate::intent::ContextRefs::default(),
        validity: Window { from: 0, until: 1 },
    }
}

// §13.7.1, OP-141 m.34: amounts by the EUR thresholds, other units CT2, no amount CT1
#[test]
fn a_domain_action_is_tiered_by_its_amount() {
    assert_eq!(of(&intent(None), None, false), Tier::Ct1);
    assert_eq!(of(&intent(Some((CT1_MAX, "eur"))), None, false), Tier::Ct1);
    assert_eq!(
        of(&intent(Some((CT1_MAX + 1, "eur"))), None, false),
        Tier::Ct2
    );
    assert_eq!(
        of(&intent(Some((CT2_MAX + 1, "eur"))), None, false),
        Tier::Ct3
    );
    assert_eq!(of(&intent(Some((1, "try"))), None, false), Tier::Ct2);
}

// §13.7.1, SI-4, OP-141 m.34: narrowing meta-actions are CT1, expansion-class ones CT3,
// other widening ones CT2
#[test]
fn a_meta_action_is_tiered_by_its_class() {
    let i = intent(None);
    let revoke = Payload::GrantRevoke { grant: Id([1; 16]) };
    assert_eq!(of(&i, Some(&revoke), false), Tier::Ct1);
    let retire = Payload::PolicyRetire {
        policy: Id([1; 16]),
    };
    assert_eq!(of(&i, Some(&retire), true), Tier::Ct3);
    let rebind = Payload::MandateRevoke {
        mandate: Id([1; 16]),
    };
    assert_eq!(of(&i, Some(&rebind), true), Tier::Ct2);
    assert_eq!(validity_ceiling(Tier::Ct3), 259_200_000);
    assert_eq!(validity_ceiling(Tier::Ct1), 86_400_000);
}
