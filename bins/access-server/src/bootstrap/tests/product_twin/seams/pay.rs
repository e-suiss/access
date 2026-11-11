//! The Pay seam (§7.9.9, E21, F9, X28, U62, MUST-NEVER-7, OP-156 m.3 (u)): Pay is the PEP of
//! its payments and asks Access for each one; Access holds the authority, its limit as a
//! `BudgetTerm` and the payment envelope (amount, recipient, purpose). Pay holds the money: its
//! holds, its own financial limit, its execution and its scheme artefacts, which name the
//! `GrantID` and `ExerciseID` they rest on. An effect attestation is a Claim and never changes a
//! decision.

use access_authority_core::app::templates::{Install, Template};
use access_kernel::claim::PREDICATE_INPUT;
use access_kernel::claim::body::{
    AuthMethod, Authentication, EffectAttestation, EffectOutcome, EvidenceKind,
};
use access_kernel::model::PurposeRef;

use super::*;

/// What Pay keeps on its side and Access never sees: holds, settled payments, its financial
/// limit per transaction and the scheme artefacts its payments rest on.
#[derive(Default)]
struct Ledger {
    held: i64,
    settled: Vec<i64>,
    limit_per_transaction: i64,
    artefacts: Vec<Artefact>,
}

/// A scheme artefact (a merchant-initiated transaction record, a payment mandate): Pay's own,
/// referring to the authority it rests on (§7.9.9.3).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Artefact {
    grant: Id,
    exercise: Digest,
}

impl Ledger {
    /// Pay's own execution after an ALLOW: its limit, not Access's, decides whether the money
    /// moves.
    fn settle(&mut self, amount: i64) -> EffectOutcome {
        if amount > self.limit_per_transaction {
            return EffectOutcome::NotDone;
        }
        self.settled.push(amount);
        EffectOutcome::Done
    }
}

fn payment(
    p: &Product,
    action: &str,
    resource: (&str, &[&str]),
    kurus: i64,
    recipient: Option<Id>,
    purpose: Option<&str>,
) -> IntentEnvelope {
    let mut e = envelope(p.action(action), resource, amount(kurus));
    e.recipient = recipient;
    e.purpose = purpose.map(|c| PurposeRef::Code(String::from(c)));
    e
}

/// The authority over `actions` on `resource`, at most `max` per use, `total` in all, to
/// `recipient` for `purpose`.
fn payment_authority(
    p: &Product,
    actions: &[&str],
    resource: ResourceSelector,
    (max, total): (i64, u64),
    recipient: Option<Id>,
    purpose: Option<&str>,
) -> CanonicalAuthority {
    let refs: Vec<ActionRef> = actions.iter().map(|a| p.action(a)).collect();
    let mut a = canonical(
        &refs,
        resource,
        at_most(max),
        budget(total),
        BTreeSet::new(),
    );
    a.authority.recipient = recipient.map(SubjectSelector::Party);
    a.authority.purpose = purpose.map(|c| BTreeSet::from([PurposeRef::Code(String::from(c))]));
    a
}

/// Pay's `effect_attestation` of one allowed payment (E64): a Claim about its effect, bound to
/// the intent it executed.
async fn attest(p: &Product, exercise: Digest, intent: &IntentEnvelope, outcome: EffectOutcome) {
    let paired = p.s.twin.paired(&p.s.domain).unwrap();
    let digest = intent_digest(intent).unwrap();
    let step = Digest(context_digest("access/pay-step/v1", b"settle").0);
    let mut key = exercise.0.to_vec();
    key.extend_from_slice(&step.0);
    let body = Body::EffectAttestation(EffectAttestation {
        exercise,
        step,
        idempotency_key: Digest(context_digest("access/effect-key/v1", &key).0),
        action: intent.action.clone(),
        params: digest,
        outcome,
        evidence: if outcome == EffectOutcome::Done {
            BTreeSet::from([EvidenceKind::UpstreamConfirmation])
        } else {
            BTreeSet::new()
        },
        refs: BTreeSet::new(),
        at: now_ms(),
        executor: paired.instance,
        environment: None,
    });
    let claim = Signed {
        intent: Some(digest),
        instance: Some(paired.instance),
        ..signed(
            paired.party,
            "effect_attestation",
            tabled_body(&body),
            3_600_000,
        )
    };
    let issued = p.s.twin.issue_signed(&p.s.domain, claim).await.unwrap();
    assert_eq!(issued.disposition, "admit", "{issued:?}");
    schedule(&p.s.signer);
}

/// Pay's `pay_limit` Claim: its financial limit and what it holds, a fact apart from authority
/// (XI-14).
async fn pay_limit(p: &Product, subject: Id, limit: u64, held: u64) {
    let body = seam_body(
        "pay_limit",
        &Value::Map(vec![
            (Value::text("currency"), Value::text("TRY")),
            (Value::text("held_minor"), Value::Unsigned(held)),
            (Value::text("limit_minor"), Value::Unsigned(limit)),
            (Value::text("period"), Value::text("transaction")),
        ]),
    );
    let issued =
        p.s.twin
            .issue_signed(&p.s.domain, signed(subject, "pay_limit", body, 3_600_000))
            .await
            .unwrap();
    assert_eq!(issued.disposition, "admit", "{issued:?}");
    schedule(&p.s.signer);
}

// §7.9.9.1, §7.9.9.2, §7.9.9.4, E21, F9, X28, MUST-NEVER-7, OP-156 m.3 (u), Ek B 5187, 5198, 5265
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one payer's authority, Pay's ledger beside it, from the first hold to the budget's end"
)]
async fn pay_asks_for_each_payment_and_keeps_the_money_itself() {
    let p = Product::open("q17-pay", "pay").await;
    p.s.accept_claims(PREDICATE_INPUT, &["effect_attestation", "pay_limit"])
        .await;
    let payer = p.s.actor().await;
    let merchant = p.s.actor().await;
    let mut ledger = Ledger {
        limit_per_transaction: 25_000,
        ..Ledger::default()
    };
    let (grant, since) =
        p.s.grant(
            SubjectSelector::Party(payer.party),
            payment_authority(
                &p,
                &["initiate"],
                structural("pay.instrument", &[]),
                (30_000, 70_000),
                Some(merchant.party),
                Some("groceries"),
            ),
        )
        .await;
    let basis = holding(grant, payer.party, since);
    let (hold_grant, hold_since) =
        p.s.grant(
            SubjectSelector::Party(payer.party),
            canonical(
                &[p.action("hold_create")],
                structural("pay.instrument", &[]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    let card = ("pay.instrument", &["card-1"][..]);
    let pay = |kurus| {
        payment(
            &p,
            "initiate",
            card,
            kurus,
            Some(merchant.party),
            Some("groceries"),
        )
    };

    // F9
    let hold = payment(&p, "hold_create", card, 30_000, None, None);
    let allowed =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &payer,
                    hold.clone(),
                    holding(hold_grant, payer.party, hold_since),
                    Vec::new(),
                ),
            )
            .await
            .unwrap();
    ProductTwin::enforce(allowed, &hold, || ledger.held += 30_000).unwrap();
    pay_limit(&p, payer.party, 25_000, 30_000).await;

    // E21, §7.9.9.4
    let mut paid = 0_u64;
    for kurus in [20_000, 30_000, 20_000] {
        let intent = pay(kurus);
        let allowed =
            p.s.twin
                .ask(
                    &p.s.domain,
                    &p.s.request(&payer, intent.clone(), basis, Vec::new()),
                )
                .await
                .unwrap();
        let exercise = *allowed.exercise();
        let outcome = ProductTwin::enforce(allowed, &intent, || ledger.settle(kurus)).unwrap();
        ledger.artefacts.push(Artefact { grant, exercise });
        attest(&p, exercise, &intent, outcome).await;
        paid += u64::try_from(kurus).unwrap();
    }
    assert_eq!(paid, 70_000);
    assert_eq!(ledger.settled, [20_000, 20_000]);

    // L0-EVAL-15, E64
    let over = p.evaluate(&payer, &pay(10_000), basis, Vec::new()).await;
    let (outcome, classes) = blocked(&over);
    assert_eq!(outcome, "deny", "{over}");
    assert!(classes.iter().any(|c| c == "budget-exhausted"), "{over}");

    // MUST-NEVER-7, F9
    assert_eq!(ledger.held, 30_000);
    assert!(ledger.artefacts.iter().all(|a| a.grant == grant));
    let mut exercises: Vec<Digest> = ledger.artefacts.iter().map(|a| a.exercise).collect();
    exercises.dedup();
    assert_eq!(exercises.len(), 3);
    s_only_public(&p);
}

// §2.7, §7.9.9.3, E21, OP-156 m.3 (u), Ek B 5188, 5198, 5367
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one customer's merchant Grant through every bound of the payment envelope"
)]
async fn a_merchant_charges_only_itself_within_the_customers_grant() {
    let p = Product::open("q17-merchant", "pay").await;
    let customer = p.s.actor().await;
    let merchant = p.s.actor().await;
    let other = p.s.actor().await;
    let card = hex(&customer.party);
    // §7.9.9.3
    let (exercise, since) =
        p.s.own_commit(
            &customer,
            ExerciseBasis::Anchor(customer.anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(customer.anchor),
                holder: SubjectSelector::Party(merchant.party),
                authority: payment_authority(
                    &p,
                    &["initiate"],
                    structural("access.party", &[&card, "instrument"]),
                    (15_000, 30_000),
                    Some(merchant.party),
                    Some("subscription"),
                ),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        )
        .await;
    let grant = meta::object_id(&exercise, kind::GRANT, 0);
    let basis = holding(grant, merchant.party, since);
    let on_card = ("access.party", &[card.as_str(), "instrument", "card-1"][..]);
    let charge =
        |kurus, to: Id, purpose| payment(&p, "initiate", on_card, kurus, Some(to), Some(purpose));

    let intent = charge(10_000, merchant.party, "subscription");
    let allowed =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(&merchant, intent.clone(), basis, Vec::new()),
            )
            .await
            .unwrap();
    let mut mit = Vec::new();
    let exercise = *allowed.exercise();
    ProductTwin::enforce(allowed, &intent, || {
        mit.push(Artefact { grant, exercise });
    })
    .unwrap();
    assert_eq!(mit, [Artefact { grant, exercise }]);

    // §2.7
    for (kurus, to, purpose) in [
        (10_000, other.party, "subscription"),
        (20_000, merchant.party, "subscription"),
        (10_000, merchant.party, "travel"),
    ] {
        let v = p
            .evaluate(&merchant, &charge(kurus, to, purpose), basis, Vec::new())
            .await;
        assert_eq!(blocked(&v).0, "deny", "{kurus} {purpose}: {v}");
    }

    // §7.9.9.3
    let token_holder =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &other,
                    charge(10_000, other.party, "subscription"),
                    holding(grant, other.party, since),
                    Vec::new(),
                ),
            )
            .await;
    assert!(
        matches!(token_holder, Err(Denied::Refused(Refusal::Deny))),
        "{token_holder:?}"
    );

    // E21
    p.s.own_commit(
        &customer,
        ExerciseBasis::Anchor(customer.anchor),
        Payload::GrantRevoke { grant },
    )
    .await;
    let r =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &merchant,
                    charge(5_000, merchant.party, "subscription"),
                    basis,
                    Vec::new(),
                ),
            )
            .await;
    assert!(matches!(r, Err(Denied::Refused(_))), "{r:?}");
    s_only_public(&p);
}

/// The realm authenticator's `authentication` Claim for `intent`, carried whole: bound to that
/// one intent (dynamic linking) with the assurance `levels`.
fn authentication(
    p: &Product,
    authenticator: &Actor,
    payer: &Actor,
    intent: &IntentEnvelope,
    levels: &[(&str, u64)],
) -> Proof {
    let now = now_ms();
    let body = Body::Authentication(Authentication {
        method: AuthMethod::DeviceKey,
        auth_time: now,
        statement: None,
        evidence: None,
        webauthn: None,
        upstream: None,
    });
    let (value, _) = tabled_body(&body);
    let mut st = statement(payer.party, "authentication", Some(value), 300_000);
    st.domain = p.s.domain;
    st.issuer = authenticator.party;
    st.bound_intent = Some(intent_digest(intent).unwrap());
    st.assurance = levels.iter().map(|(d, l)| (String::from(*d), *l)).collect();
    Proof::Carried(
        sign_sign1(
            &authenticator.key,
            thumbprint(&authenticator.key.public_key()),
            access_kernel::claim::CONTENT_TYPE,
            &st.to_bytes().unwrap(),
        )
        .unwrap(),
    )
}

// U62, MD-11, IDP-9, §10.3.4, N-52, OP-156 m.3 (u), Ek B 5266
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one domain under PSD2 SCA and then under the TR payment template"
)]
async fn a_regulatory_template_is_enforced_on_the_decision_path() {
    let p = Product::open("q17-template", "pay").await;
    let payer = p.s.actor().await;
    let merchant = p.s.actor().await;
    let authenticator = p.s.actor().await;
    p.accept_from(authenticator.party, PREDICATE_INPUT, &["authentication"])
        .await;
    let (grant, since) =
        p.s.grant(
            SubjectSelector::Party(payer.party),
            payment_authority(
                &p,
                &["initiate"],
                structural("pay.instrument", &[]),
                (100_000, 1_000_000),
                Some(merchant.party),
                None,
            ),
        )
        .await;
    let basis = holding(grant, payer.party, since);
    let card = ("pay.instrument", &["card-1"][..]);
    let pay = |kurus| payment(&p, "initiate", card, kurus, Some(merchant.party), None);
    let ask = async |intent: IntentEnvelope, proofs: Vec<Proof>| {
        p.s.twin
            .ask(&p.s.domain, &p.s.request(&payer, intent, basis, proofs))
            .await
    };
    let install = Install {
        issuer: SubjectSelector::Party(authenticator.party),
        actions: BTreeSet::from([String::from("pay:initiate"), String::from("pay:payout")]),
    };
    assert!(ask(pay(1_000), Vec::new()).await.is_ok());

    // §10.3.4
    let (sca, _) =
        p.s.root(Payload::PolicySet {
            defaults: None,
            policy: None,
            content: Template::Psd2Sca.content(&install).unwrap(),
        })
        .await;
    let r = ask(pay(1_001), Vec::new()).await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    let one = pay(1_002);
    let single = authentication(&p, &authenticator, &payer, &one, &[("aal", 1)]);
    let r = ask(one.clone(), vec![single]).await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    let two = authentication(&p, &authenticator, &payer, &one, &[("aal", 2)]);
    assert!(ask(one.clone(), vec![two.clone()]).await.is_ok());
    let r = ask(pay(1_003), vec![two]).await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    p.s.root(Payload::PolicyRetire {
        policy: meta::object_id(&sca, kind::POLICY, 0),
    })
    .await;

    // U62, MD-11
    p.s.root(Payload::PolicySet {
        defaults: None,
        policy: None,
        content: Template::TrGkd.content(&install).unwrap(),
    })
    .await;
    let r = ask(pay(1_004), Vec::new()).await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    let biometric = pay(1_005);
    let without_app = authentication(
        &p,
        &authenticator,
        &payer,
        &biometric,
        &[
            ("aal", 2),
            ("phishing_resistant", 1),
            ("app_controlled_factor", 0),
        ],
    );
    let r = ask(biometric.clone(), vec![without_app]).await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    let gkd = authentication(
        &p,
        &authenticator,
        &payer,
        &biometric,
        &[
            ("aal", 2),
            ("phishing_resistant", 1),
            ("app_controlled_factor", 1),
        ],
    );
    let allowed = ask(biometric.clone(), vec![gkd]).await.unwrap();
    let mut settled = Vec::new();
    ProductTwin::enforce(allowed, &biometric, || settled.push(1_005)).unwrap();
    assert_eq!(settled, [1_005]);
    s_only_public(&p);
}

fn s_only_public(p: &Product) {
    p.s.only_public();
}
