use alloc::collections::BTreeMap;
use alloc::string::ToString;
use alloc::vec::Vec;

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
        provenance: BTreeMap::new(),
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

// §13.7.1, OP-141 m.34
#[test]
fn a_domain_action_is_tiered_by_its_amount() {
    assert_eq!(of(&intent(None), None, false, None), Tier::Ct1);
    assert_eq!(
        of(&intent(Some((CT1_MAX, "eur"))), None, false, None),
        Tier::Ct1
    );
    assert_eq!(
        of(&intent(Some((CT1_MAX + 1, "eur"))), None, false, None),
        Tier::Ct2
    );
    assert_eq!(
        of(&intent(Some((CT2_MAX + 1, "eur"))), None, false, None),
        Tier::Ct3
    );
    assert_eq!(of(&intent(Some((1, "try"))), None, false, None), Tier::Ct2);
}

// §13.7.1, SI-4, OP-141 m.34
#[test]
fn a_meta_action_is_tiered_by_its_class() {
    let i = intent(None);
    let revoke = Payload::GrantRevoke { grant: Id([1; 16]) };
    assert_eq!(of(&i, Some(&revoke), false, None), Tier::Ct1);
    let retire = Payload::PolicyRetire {
        policy: Id([1; 16]),
    };
    assert_eq!(of(&i, Some(&retire), true, None), Tier::Ct3);
    let rebind = Payload::MandateRevoke {
        mandate: Id([1; 16]),
    };
    assert_eq!(of(&i, Some(&rebind), true, None), Tier::Ct2);
    assert_eq!(validity_ceiling(Tier::Ct3), 259_200_000);
    assert_eq!(validity_ceiling(Tier::Ct1), 86_400_000);
}

// §13.7.1, OP-141 m.34
#[test]
fn an_amount_at_the_ct2_threshold_stays_ct2() {
    assert_eq!(
        of(&intent(Some((CT2_MAX, "eur"))), None, false, None),
        Tier::Ct2
    );
}

// OP-143 m.7
#[test]
fn contribute_and_projection_issue_are_ct1_when_widening() {
    let i = intent(None);
    let contribute = Payload::Contribute {
        target: crate::digest::Digest([1; 32]),
        class: "approve".to_string(),
    };
    assert_eq!(of(&i, Some(&contribute), true, None), Tier::Ct1);
    assert_eq!(meta_tier(&contribute, true), Tier::Ct1);
}

// OP-141 m.35 (g)
#[test]
fn a_reversible_action_is_ct1() {
    let mut s = crate::schema::tests::refund();
    s.effect = EffectClass::Reversible;
    assert_eq!(of(&intent(None), None, false, Some(&s)), Tier::Ct1);
}

// OP-141 m.35 (g)
#[test]
fn the_action_schema_raises_the_tier() {
    let mut s = crate::schema::tests::refund();
    assert_eq!(of(&intent(None), None, false, Some(&s)), Tier::Ct2);
    assert_eq!(
        of(&intent(Some((CT2_MAX + 1, "eur"))), None, false, Some(&s)),
        Tier::Ct3
    );
    s.effect = EffectClass::None;
    assert_eq!(of(&intent(None), None, false, Some(&s)), Tier::Ct0);
    s.reserved = true;
    assert_eq!(of(&intent(None), None, false, Some(&s)), Tier::Ct3);
}

// §9.13.7, OP-141 m.39 (a)
#[test]
fn read_actions_are_tiered_by_name() {
    let mut i = intent(Some((CT2_MAX + 1, "eur")));
    i.action.namespace = "access".to_string();
    i.action.name = "read".to_string();
    assert_eq!(of(&i, None, false, None), Tier::Ct0);
    i.action.name = "audit_export".to_string();
    assert_eq!(of(&i, None, false, None), Tier::Ct1);
    i.action.name = "audit.export".to_string();
    assert!(!crate::meta::is_read("access", "audit.export"));
    assert!(crate::meta::is_read("access", "read") && !crate::meta::is_read("shop", "read"));
    assert!(!crate::meta::is_read("access", "audit"));
}

// OP-159 m.3 (l): `audit_export` is a read and stays CT1 whatever its amounts
#[test]
fn audit_export_is_a_read_at_ct1() {
    let mut i = intent(Some((CT2_MAX + 1, "eur")));
    i.action.namespace = "access".to_string();
    i.action.name = "audit_export".to_string();
    assert!(crate::meta::is_read("access", "audit_export"));
    assert_eq!(of(&i, None, false, None), AUDIT_EXPORT_TIER);
    assert_eq!(AUDIT_EXPORT_TIER, Tier::Ct1);
}

// OP-159 m.3 (m), SEC10, §13.7.2: a first payment to a payee is CT2, a seen payee keeps its tier
#[test]
fn a_new_payee_is_ct2() {
    let mut i = intent(Some((100, "eur")));
    assert_eq!(payee(&i, None), None);
    assert_eq!(payee_floor(&i, None, false), Tier::Ct0);
    i.recipient = Some(Id([7; 16]));
    let p = payee(&i, None);
    assert!(p.is_some());
    assert_eq!(payee_floor(&i, None, false), Tier::Ct2);
    assert_eq!(payee_floor(&i, None, true), Tier::Ct0);
    assert_eq!(
        of(&i, None, false, None).max(payee_floor(&i, None, false)),
        Tier::Ct2
    );
    assert_eq!(
        of(&i, None, false, None).max(payee_floor(&i, None, true)),
        Tier::Ct1
    );
    let mut other = i.clone();
    other.recipient = Some(Id([8; 16]));
    assert_ne!(payee(&other, None), p);
    i.params.clear();
    assert_eq!(payee(&i, None), None);
}

fn tier_word(t: Tier) -> &'static str {
    match t {
        Tier::Ct0 => "ct0",
        Tier::Ct1 => "ct1",
        Tier::Ct2 => "ct2",
        Tier::Ct3 => "ct3",
    }
}

struct TierCase {
    id: &'static str,
    rule: &'static str,
    intent: IntentEnvelope,
    payload: Option<Payload>,
    schema: Option<ActionSchema>,
    seen: bool,
}

fn tier_case(
    id: &'static str,
    rule: &'static str,
    mut intent: IntentEnvelope,
    payload: Option<Payload>,
    schema: Option<ActionSchema>,
    seen: bool,
) -> TierCase {
    intent.resources[0].path = alloc::vec!["orders".to_string()];
    TierCase {
        id,
        rule,
        intent,
        payload,
        schema,
        seen,
    }
}

fn read_cases() -> Vec<TierCase> {
    let access = |name: &str| {
        let mut i = intent(Some((CT2_MAX + 1, "eur")));
        i.action.namespace = "access".to_string();
        i.action.name = name.to_string();
        i
    };
    let r = "L0-EVAL-70";
    alloc::vec![
        tier_case("read-is-ct0", r, access("read"), None, None, false),
        tier_case(
            "audit-export-is-ct1",
            r,
            access("audit_export"),
            None,
            None,
            false
        ),
        tier_case(
            "other-access-action-by-amount",
            r,
            access("export"),
            None,
            None,
            false
        ),
    ]
}

fn tier_cases() -> Vec<TierCase> {
    let paid = |amount: i64, unit: &str| {
        let mut i = intent(Some((amount, unit)));
        i.recipient = Some(Id([7; 16]));
        i
    };
    let mut no_amount = intent(None);
    no_amount.recipient = Some(Id([7; 16]));
    let irreversible = crate::schema::tests::refund();
    let mut reserved = crate::schema::tests::refund();
    reserved.reserved = true;
    let mut none = crate::schema::tests::refund();
    none.effect = EffectClass::None;
    let revoke = Payload::GrantRevoke { grant: Id([3; 16]) };
    let p = "L0-EVAL-71";
    let mut out = read_cases();
    out.extend([
        tier_case(
            "payment-without-recipient",
            p,
            intent(Some((100, "eur"))),
            None,
            None,
            false,
        ),
        tier_case("new-payee-is-ct2", p, paid(100, "eur"), None, None, false),
        tier_case(
            "seen-payee-keeps-ct1",
            p,
            paid(100, "eur"),
            None,
            None,
            true,
        ),
        tier_case(
            "seen-payee-above-ct1",
            p,
            paid(CT1_MAX + 1, "eur"),
            None,
            None,
            true,
        ),
        tier_case(
            "new-payee-above-ct2",
            p,
            paid(CT2_MAX + 1, "eur"),
            None,
            None,
            false,
        ),
        tier_case("new-payee-other-unit", p, paid(1, "usd"), None, None, false),
        tier_case("recipient-without-amount", p, no_amount, None, None, false),
        tier_case(
            "meta-action-is-no-payment",
            p,
            paid(100, "eur"),
            Some(revoke),
            None,
            false,
        ),
        tier_case(
            "new-payee-irreversible",
            p,
            paid(100, "eur"),
            None,
            Some(irreversible),
            false,
        ),
        tier_case(
            "seen-payee-no-effect",
            p,
            paid(100, "eur"),
            None,
            Some(none.clone()),
            true,
        ),
        tier_case(
            "new-payee-no-effect",
            p,
            paid(100, "eur"),
            None,
            Some(none),
            false,
        ),
        tier_case(
            "new-payee-reserved",
            p,
            paid(100, "eur"),
            None,
            Some(reserved),
            false,
        ),
    ]);
    out
}

fn tier_line(c: &TierCase) -> alloc::string::String {
    use crate::codec::Canonical as _;
    use crate::vector_rules::{field, hex};
    use core::fmt::Write as _;
    let (i, payload, schema) = (&c.intent, c.payload.as_ref(), c.schema.as_ref());
    let tier = of(i, payload, false, schema).max(payee_floor(i, payload, c.seen));
    let mut line = alloc::format!(
        "  {{\"id\": \"{}\", {}, \"intent\": \"{}\"",
        c.id,
        field(&[c.rule]),
        hex(&i.to_bytes().unwrap())
    );
    if let Some(p) = payload {
        let _ = write!(line, ", \"payload\": \"{}\"", hex(&p.to_bytes().unwrap()));
    }
    line.push_str(", \"expansion\": false");
    if let Some(s) = schema {
        let _ = write!(line, ", \"schema\": \"{}\"", hex(&s.to_bytes().unwrap()));
    }
    let _ = write!(
        line,
        ", \"payee_seen\": {}, \"tier\": \"{}\"",
        c.seen,
        tier_word(tier)
    );
    if let Some(p) = payee(i, payload) {
        let _ = write!(line, ", \"payee\": \"{}\"", hex(&p.0));
    }
    line.push('}');
    line
}

// TI-RT12, OP-159 m.3 (l), (m): the tier of reads and the new-payee floor, as vectors
#[test]
fn tier_vectors_match() {
    use crate::vector_rules::{field, golden};
    let lines: Vec<_> = tier_cases().iter().map(tier_line).collect();
    let json = alloc::format!(
        "{{\n \"rule\": \"§13.7.1\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"tier.of\",\n {},\n \"cases\": [\n{}\n ]\n}}\n",
        field(&["L0-EVAL-70", "L0-EVAL-71"]),
        lines.join(",\n")
    );
    golden(
        "tier.json",
        include_str!("../../../../conformance/vectors/core/1/tier.json"),
        &json,
    );
}
