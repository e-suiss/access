//! Signal sources on the real server path (OP-156 m.3 (r), E38, CI-2, IDP-34, TN-46, F11,
//! OP-153 m.3 (gg)). A KYC provider, an MDM, a fraud engine and a DLP system are each a twin of
//! `access-product-twin` with its own Party and issuer key, paired beside the product whose
//! decisions they inform. Each signs its own Claims with the body beside them through Claim
//! Ingest; nothing it says counts until the domain's root accepts it, and then only as the
//! domain's own requirement terms and forbid-only restriction policies read it.

use access_product_twin::{Signed, TwinError};
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::digest::context_digest;

use super::*;

/// A payments product: a `transfer` of an amount.
const PAY: &str = r#"
product = "Seam Pay"
namespace = "seampay"
catalog_version = 1
truth = ["transfer"]

[[actions]]
name = "transfer"
major = 1
effect_class = "irreversible"
reversibility = "compensable"
consumption_bearing = true
params = { amount = "amount" }
classes = { amount = "amount" }
resource_types = ["account"]
"#;

/// A files product: `disclose` a file to someone.
const FILES: &str = r#"
product = "Seam Files"
namespace = "seamfiles"
catalog_version = 1
truth = ["file"]

[[actions]]
name = "disclose"
major = 1
effect_class = "irreversible"
reversibility = "irreversible"
resource_types = ["file"]
"#;

/// `SHA-256("access/claim-body/v1" ‖ 0x00 ‖ dCBOR([class, body]))` and the body's dCBOR, as
/// the source computes them with the public crates (L2-CLB-1).
fn body(class: &str, members: Vec<(&str, Value)>) -> (Vec<u8>, Vec<u8>) {
    let body = Value::Map(
        members
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    );
    let tagged = dcbor::encode(
        &Value::Array(vec![Value::text(class), body.clone()]),
        Limits::CEILING,
    )
    .unwrap();
    (
        context_digest("access/claim-body/v1", &tagged).0.to_vec(),
        dcbor::encode(&body, Limits::CEILING).unwrap(),
    )
}

fn proofing(ial: u64) -> (Vec<u8>, Vec<u8>) {
    body(
        "identity_proofing",
        vec![
            ("provider", Value::text("idv.example")),
            ("method", Value::text("document")),
            ("ial", Value::Unsigned(ial)),
            ("verified_at", Value::Unsigned(now_ms())),
        ],
    )
}

fn posture(compliant: bool) -> (Vec<u8>, Vec<u8>) {
    body(
        "posture_mdm",
        vec![
            ("managed", Value::Bool(true)),
            ("compliant", Value::Bool(compliant)),
            ("provider", Value::text("acme-mdm")),
            ("statement", Value::text("Disk encrypted, OS current")),
        ],
    )
}

fn risk(level: &str, reason: &str) -> (Vec<u8>, Vec<u8>) {
    body(
        "risk_external",
        vec![
            ("level", Value::text(level)),
            ("reason_class", Value::text(reason)),
        ],
    )
}

fn label(name: &str) -> (Vec<u8>, Vec<u8>) {
    body(
        "data_label",
        vec![
            ("label", Value::text(name)),
            ("scheme", Value::text("acme-dlp")),
        ],
    )
}

/// The source's Claim of `class` about `subject` carrying `(value, body)`.
fn signal(subject: Id, class: &str, (value, bytes): (Vec<u8>, Vec<u8>)) -> Signed {
    Signed::with_body(
        Issue {
            subject,
            class: String::from(class),
            value: Some(EqValue::Bytes(value)),
            for_ms: 3_600_000,
            resource: None,
        },
        bytes,
    )
}

fn claim_term(class: &str, source: Id, binding: Binding) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: String::from(class),
        count: 1,
        binding,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: Some(SubjectSelector::Party(source)),
        assurance: BTreeMap::new(),
    }
}

fn denied(r: &Result<access_sdk::authorize::Authorized<(), ()>, Denied>) -> bool {
    refused(r, Refusal::Deny)
}

impl Seam {
    /// The root accepts `issuer`'s Claims of `classes` as `predicate-input`; the Acceptance's id.
    async fn accept_inputs(&self, issuer: Id, classes: &[&str]) -> Id {
        let mut classes = classes.to_vec();
        classes.sort_by_key(|c| (c.len(), *c));
        let (exercise, _) = self
            .root(Payload::AcceptanceEstablish(Value::Map(vec![
                (Value::text("issuer"), issuer.to_value()),
                (
                    Value::text("use"),
                    Value::text(access_kernel::claim::PREDICATE_INPUT),
                ),
                (
                    Value::text("classes"),
                    Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
                ),
                (Value::text("subject"), SubjectSelector::Public.to_value()),
                (
                    Value::text("validity"),
                    Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
                ),
            ])))
            .await;
        meta::object_id(&exercise, kind::ACCEPTANCE, 0)
    }

    /// The root's domain-wide restriction policy of `source` with the requirement sets `sets`.
    async fn restrict(&self, source: &str, sets: Vec<(&str, RequirementTerm)>) {
        let mut content = vec![
            (Value::text("schema"), Value::text(meta::RESTRICTION_SCHEMA)),
            (Value::text("source"), Value::text(source)),
            (Value::text("target"), Value::text("domain")),
        ];
        if !sets.is_empty() {
            content.push((
                Value::text("requirements"),
                Value::Map(
                    sets.into_iter()
                        .map(|(k, t)| (Value::text(k), Value::Array(vec![t.to_value()])))
                        .collect(),
                ),
            ));
        }
        let content = dcbor::decode(
            &dcbor::encode(&Value::Map(content), Limits::CEILING).unwrap(),
            Limits::CEILING,
        )
        .unwrap();
        self.root(Payload::PolicySet {
            policy: None,
            content,
        })
        .await;
    }
}

/// `amount` minor units of TRY.
fn amount(minor: i64) -> BTreeMap<String, ParamValue> {
    BTreeMap::from([(
        String::from("amount"),
        ParamValue::Amount {
            value: minor,
            unit: String::from("try"),
        },
    )])
}

fn up_to(min: i64, max: i64) -> BTreeMap<String, Bound> {
    BTreeMap::from([(
        String::from("amount"),
        Bound::Range {
            min: Some(min),
            max: Some(max),
            unit: String::from("try"),
        },
    )])
}

// IDP-34, §10.3.1, §10.9.1, OP-156 m.3 (r), Ek B 5142, 5282, 5368
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_external_proofing_is_a_requirement_input_above_an_amount() {
    let (s, mut others) = Seam::open_many("signals-kyc", &["pay", "idv"]).await;
    let (idv, idv_party) = others.remove(0);
    let pay = Schema::parse(PAY).unwrap();
    s.twin.publish_schema(&s.domain, &pay).await.unwrap();
    s.accept_schema(&pay).await;
    let transfer = pay.action("transfer").unwrap();
    let customer = s.actor().await;
    let accounts = || structural("seampay.account", &[]);
    let mut ial2 = claim_term("identity_proofing", idv_party, Binding::None);
    ial2.assurance = BTreeMap::from([(String::from("loa_eidas"), 2)]);
    let (small, small_since) = s
        .grant(
            SubjectSelector::Party(customer.party),
            canonical(
                std::slice::from_ref(&transfer),
                accounts(),
                up_to(0, 100_000),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    let (large, large_since) = s
        .grant(
            SubjectSelector::Party(customer.party),
            canonical(
                std::slice::from_ref(&transfer),
                accounts(),
                up_to(100_001, 10_000_000),
                BTreeSet::new(),
                BTreeSet::from([ial2]),
            ),
        )
        .await;
    let big = || {
        envelope(
            transfer.clone(),
            ("seampay.account", &["a-1"]),
            amount(500_000),
        )
    };
    let ask = |grant, since, e, proofs| {
        s.request(&customer, e, holding(grant, customer.party, since), proofs)
    };

    // IDP-34
    let r = s
        .twin
        .ask(&s.domain, &ask(large, large_since, big(), Vec::new()))
        .await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    let with_level = |ial: u64, stated: u64| Signed {
        assurance: BTreeMap::from([(String::from("loa_eidas"), stated)]),
        ..signal(customer.party, "identity_proofing", proofing(ial))
    };
    let unaccepted = idv.issue_signed(&s.domain, with_level(2, 2)).await.unwrap();
    assert_eq!(unaccepted.disposition, "quarantine", "{unaccepted:?}");
    s.accept_inputs(idv_party, &["identity_proofing"]).await;

    // OP-156 m.3 (r)
    let overstated = idv.issue_signed(&s.domain, with_level(1, 2)).await;
    assert!(
        matches!(&overstated, Err(TwinError::Refused { status: 400, .. })),
        "{overstated:?}"
    );
    let ial1 = idv.issue_signed(&s.domain, with_level(1, 1)).await.unwrap();
    assert_eq!(ial1.disposition, "admit", "{ial1:?}");
    schedule(&s.signer);
    let r = s
        .twin
        .ask(
            &s.domain,
            &ask(large, large_since, big(), vec![Proof::Recorded(ial1.claim)]),
        )
        .await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");

    let verified = idv
        .issue_signed(
            &s.domain,
            Signed {
                supersedes: Some(ial1.claim),
                ..with_level(2, 2)
            },
        )
        .await
        .unwrap();
    assert_eq!(verified.disposition, "admit", "{verified:?}");
    schedule(&s.signer);
    let e = big();
    let allowed = s
        .twin
        .ask(
            &s.domain,
            &ask(
                large,
                large_since,
                e.clone(),
                vec![Proof::Recorded(verified.claim)],
            ),
        )
        .await
        .unwrap();
    let mut sent = Vec::new();
    ProductTwin::enforce(allowed, &e, || sent.push("a-1")).unwrap();
    assert_eq!(sent, ["a-1"]);
    let low = envelope(
        transfer.clone(),
        ("seampay.account", &["a-2"]),
        amount(5_000),
    );
    s.twin
        .ask(&s.domain, &ask(small, small_since, low, Vec::new()))
        .await
        .unwrap();

    s.only_public();
}

// §2.5, §2.6, §7.6, §7.9.12.2, §8.10, OP-156 m.3 (r), Ek B 5278, 5279, 5280
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_mdm_posture_counts_only_once_the_domain_accepts_it() {
    let (s, mut others) = Seam::open_many("signals-mdm", &["shop", "acme-mdm"]).await;
    let (mdm, mdm_party) = others.remove(0);
    let shop = Schema::parse(SHOP).unwrap();
    s.twin.publish_schema(&s.domain, &shop).await.unwrap();
    s.accept_schema(&shop).await;
    let refund = shop.action("refund").unwrap();
    let agent = s.actor().await;
    let (grant, since) = s
        .grant(
            SubjectSelector::Party(agent.party),
            canonical(
                std::slice::from_ref(&refund),
                structural("seamshop.order", &[]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    s.restrict(
        r#"@id("mdm-missing") @require("rs-mdm") forbid(principal, action, resource) when { context.action == "seamshop:refund" && context.posture == "none" };
@id("mdm-failing") forbid(principal, action, resource) when { context.action == "seamshop:refund" && (context.posture == "noncompliant" || context.posture == "unmanaged") };"#,
        vec![("rs-mdm", claim_term("posture_mdm", mdm_party, Binding::None))],
    )
    .await;
    let refund_it = || {
        envelope(
            refund.clone(),
            ("seamshop.order", &["o-1"]),
            BTreeMap::new(),
        )
    };
    let ask = |proofs| {
        s.request(
            &agent,
            refund_it(),
            holding(grant, agent.party, since),
            proofs,
        )
    };

    // §2.6
    let r = s.twin.ask(&s.domain, &ask(Vec::new())).await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    let compliant = mdm
        .issue_signed(&s.domain, signal(agent.party, "posture_mdm", posture(true)))
        .await
        .unwrap();
    assert_eq!(compliant.disposition, "quarantine", "{compliant:?}");
    schedule(&s.signer);
    let r = s
        .twin
        .ask(
            &s.domain,
            &ask(vec![Proof::Carried(compliant.sign1.clone())]),
        )
        .await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");

    // E38
    s.accept_inputs(mdm_party, &["posture_mdm"]).await;
    let compliant = mdm
        .issue_signed(&s.domain, signal(agent.party, "posture_mdm", posture(true)))
        .await
        .unwrap();
    assert_eq!(compliant.disposition, "admit", "{compliant:?}");
    schedule(&s.signer);
    let e = refund_it();
    let allowed = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &agent,
                e.clone(),
                holding(grant, agent.party, since),
                Vec::new(),
            ),
        )
        .await
        .unwrap();
    let mut refunded = Vec::new();
    ProductTwin::enforce(allowed, &e, || refunded.push("o-1")).unwrap();
    assert_eq!(refunded, ["o-1"]);

    let failing = mdm
        .issue_signed(
            &s.domain,
            Signed {
                supersedes: Some(compliant.claim),
                ..signal(agent.party, "posture_mdm", posture(false))
            },
        )
        .await
        .unwrap();
    assert_eq!(failing.disposition, "admit", "{failing:?}");
    schedule(&s.signer);
    let r = s.twin.ask(&s.domain, &ask(Vec::new())).await;
    assert!(denied(&r), "{r:?}");
    s.only_public();
}

// §7.9.12.1, CI-2, E38, IDP-39, TN-46, OP-156 m.3 (r), Ek B 5281, 5374, 5280
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_external_risk_only_narrows_and_never_holds_for_good() {
    let (s, mut others) = Seam::open_many("signals-risk", &["shop", "fraud"]).await;
    let (fraud, fraud_party) = others.remove(0);
    let shop = Schema::parse(SHOP).unwrap();
    s.twin.publish_schema(&s.domain, &shop).await.unwrap();
    s.accept_schema(&shop).await;
    let refund = shop.action("refund").unwrap();
    let agent = s.actor().await;
    let (grant, since) = s
        .grant(
            SubjectSelector::Party(agent.party),
            canonical(
                std::slice::from_ref(&refund),
                structural("seamshop.order", &["o-1"]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    s.restrict(
        r#"@id("risk") forbid(principal, action, resource) when { context.action == "seamshop:refund" && (context.risk == "high" || context.risk == "critical") };
@id("risk-known") forbid(principal, action, resource) when { context.action == "seamshop:refund" && resource == Resource::"seamshop.order/o-1/known" && context.risk != "low" };"#,
        Vec::new(),
    )
    .await;
    let order = |path: &[&str]| envelope(refund.clone(), ("seamshop.order", path), BTreeMap::new());
    let ask = |e| s.request(&agent, e, holding(grant, agent.party, since), Vec::new());
    let acceptance = s.accept_inputs(fraud_party, &["risk_external"]).await;

    // CI-2: without a signal the Grant alone decides, and a domain that needs a known level
    // gets no ALLOW from a missing one
    s.twin.ask(&s.domain, &ask(order(&["o-1"]))).await.unwrap();
    let r = s.twin.ask(&s.domain, &ask(order(&["o-1", "known"]))).await;
    assert!(denied(&r), "{r:?}");

    let low = fraud
        .issue_signed(
            &s.domain,
            signal(agent.party, "risk_external", risk("low", "none")),
        )
        .await
        .unwrap();
    assert_eq!(low.disposition, "admit", "{low:?}");
    schedule(&s.signer);
    s.twin
        .ask(&s.domain, &ask(order(&["o-1", "known"])))
        .await
        .unwrap();
    // CI-2: low never turns a DENY into an ALLOW
    let r = s.twin.ask(&s.domain, &ask(order(&["o-2"]))).await;
    assert!(denied(&r), "{r:?}");

    // E38: a bot management engine's verdict is a risk_external like any other
    let high = fraud
        .issue_signed(
            &s.domain,
            Signed {
                supersedes: Some(low.claim),
                ..signal(agent.party, "risk_external", risk("high", "bot-detected"))
            },
        )
        .await
        .unwrap();
    assert_eq!(high.disposition, "admit", "{high:?}");
    schedule(&s.signer);
    let r = s.twin.ask(&s.domain, &ask(order(&["o-1"]))).await;
    assert!(denied(&r), "{r:?}");

    // CI-2: a risk Claim that would qualify is refused
    let qualifying = fraud
        .issue_signed(
            &s.domain,
            Signed {
                assurance: BTreeMap::from([(String::from("aal"), 2)]),
                ..signal(agent.party, "risk_external", risk("low", "none"))
            },
        )
        .await;
    assert!(qualifying.is_err(), "{qualifying:?}");

    // TN-46: a verdict counts for a day after its issue, whatever validity it declares
    let stale = s.actor().await;
    let (stale_grant, stale_since) = s
        .grant(
            SubjectSelector::Party(stale.party),
            canonical(
                std::slice::from_ref(&refund),
                structural("seamshop.order", &["o-1"]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    let old = fraud
        .issue_signed(
            &s.domain,
            Signed {
                issued_ago_ms: access_internal_api::signals::RISK_HORIZON_MS + 60_000,
                issue: Issue {
                    for_ms: 365 * 86_400_000,
                    ..signal(stale.party, "risk_external", risk("critical", "fraud-ring")).issue
                },
                ..signal(stale.party, "risk_external", risk("critical", "fraud-ring"))
            },
        )
        .await
        .unwrap();
    assert_eq!(old.disposition, "admit", "{old:?}");
    schedule(&s.signer);
    s.twin
        .ask(
            &s.domain,
            &s.request(
                &stale,
                order(&["o-1"]),
                holding(stale_grant, stale.party, stale_since),
                Vec::new(),
            ),
        )
        .await
        .unwrap();

    // TN-46: the domain lifts a hold sooner by its own attributable Exercise
    s.root(Payload::AcceptanceRevoke { acceptance }).await;
    let e = order(&["o-1"]);
    let allowed = s.twin.ask(&s.domain, &ask(e.clone())).await.unwrap();
    let mut refunded = Vec::new();
    ProductTwin::enforce(allowed, &e, || refunded.push("o-1")).unwrap();
    assert_eq!(refunded, ["o-1"]);
    s.only_public();
}

// §7.1, §7.6, F11, OP-156 m.3 (r), Ek B 5283
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_data_label_is_an_input_to_disclose_and_access_decides() {
    let (s, mut others) = Seam::open_many("signals-dlp", &["files", "acme-dlp"]).await;
    let (dlp, dlp_party) = others.remove(0);
    let files = Schema::parse(FILES).unwrap();
    s.twin.publish_schema(&s.domain, &files).await.unwrap();
    s.accept_schema(&files).await;
    let disclose = files.action("disclose").unwrap();
    let agent = s.actor().await;
    let (grant, since) = s
        .grant(
            SubjectSelector::Party(agent.party),
            canonical(
                std::slice::from_ref(&disclose),
                structural("seamfiles.file", &[]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    s.restrict(
        r#"@id("dlp-unlabelled") @require("rs-label") forbid(principal, action, resource) when { context.action == "seamfiles:disclose" && context.labels.isEmpty() };
@id("dlp-confidential") forbid(principal, action, resource) when { context.action == "seamfiles:disclose" && (context.labels.contains("acme-dlp:confidential") || context.labels.contains("unreadable")) };"#,
        vec![("rs-label", claim_term("data_label", dlp_party, Binding::Resource))],
    )
    .await;
    s.accept_inputs(dlp_party, &["data_label"]).await;
    let file = |f: &str| ResourceRef {
        namespace: String::from("seamfiles.file"),
        path: vec![String::from(f)],
        incarnation: 0,
    };
    let disclose_it =
        |f: &str| envelope(disclose.clone(), ("seamfiles.file", &[f]), BTreeMap::new());
    let ask = |f: &str, proofs| {
        s.request(
            &agent,
            disclose_it(f),
            holding(grant, agent.party, since),
            proofs,
        )
    };
    let labelled = |f: &str, name: &str| Signed {
        issue: Issue {
            resource: Some(file(f)),
            ..signal(agent.party, "data_label", label(name)).issue
        },
        ..signal(agent.party, "data_label", label(name))
    };

    // F11
    let r = s.twin.ask(&s.domain, &ask("f-1", Vec::new())).await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    let public = dlp
        .issue_signed(&s.domain, labelled("f-1", "public"))
        .await
        .unwrap();
    assert_eq!(public.disposition, "admit", "{public:?}");
    let secret = dlp
        .issue_signed(&s.domain, labelled("f-2", "confidential"))
        .await
        .unwrap();
    assert_eq!(secret.disposition, "admit", "{secret:?}");
    schedule(&s.signer);
    let e = disclose_it("f-1");
    let allowed = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &agent,
                e.clone(),
                holding(grant, agent.party, since),
                vec![Proof::Recorded(public.claim)],
            ),
        )
        .await
        .unwrap();
    let mut shared = Vec::new();
    ProductTwin::enforce(allowed, &e, || shared.push("f-1")).unwrap();
    assert_eq!(shared, ["f-1"]);
    let r = s
        .twin
        .ask(&s.domain, &ask("f-2", vec![Proof::Recorded(secret.claim)]))
        .await;
    assert!(denied(&r), "{r:?}");
    // F11: a label carried without its body reads as unreadable
    let r = s
        .twin
        .ask(
            &s.domain,
            &ask("f-2", vec![Proof::Carried(secret.sign1.clone())]),
        )
        .await;
    assert!(denied(&r), "{r:?}");
    s.only_public();
}
