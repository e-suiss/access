//! The Serve seam (§7.9.10.2, §7.9.4, §2.7 Serve, §8.17.5.8, X17, OP-156 m.3 (b), (u)): the
//! store's owner is the root of the store's Anchor and grants the store admin and the cashiers'
//! void and drawer authority from it. Who is on shift is Serve's short-lived `on_shift` Claim
//! and the role its `serve_staff` Claim; the cashiers' Grant holds only while the shift does.
//! Offline, the POS terminal is the verifier: a projection with a void count and amount slice,
//! checked with `esuiss-access-verifier` and nothing else, refuses once the slice is spent.

use access_kernel::claim::body::{VerifierId, VerifierProfile};
use access_kernel::claim::{PREDICATE_INPUT, SUBJECT_SELECTION};
use access_kernel::model::WhileCondition;
use access_kernel::validity::{ProfileClass, ProfileVariant};
use access_kernel::verify::cose::parse_sign1;
use access_kernel::verify::key_scope::DomainMetadata;
use access_verifier::counter::CounterId;
use access_verifier::offline::{Identity, OfflineVerifier, Use, Verdict, peek};
use access_verifier::profile::LocalProfile;
use access_verifier::testing::{EmulatedClock, EmulatedCounter};
use access_verifier::time::{ClockGuard, DEFAULT_TOLERANCE_MS};

use super::*;

/// The POS terminal's audience.
const POS: &str = "pos-store-1";

/// The unit of the POS amounts: the default tier thresholds are in it, so a small void is CT1
/// and may be projected offline (§13.7.2).
const UNIT: &str = "eur";

fn cents(value: i64) -> BTreeMap<String, ParamValue> {
    BTreeMap::from([(
        String::from("amount"),
        ParamValue::Amount {
            value,
            unit: String::from(UNIT),
        },
    )])
}

fn void_of(p: &Product, order: &str, value: i64) -> IntentEnvelope {
    envelope(
        p.action("void"),
        ("serve.store", &["store-1", "orders", order]),
        cents(value),
    )
}

/// Serve's `on_shift` Claim: `subject` is on shift at store 1 for `for_ms`.
async fn on_shift(p: &Product, subject: Id, for_ms: u64) -> u64 {
    let until = now_ms() + for_ms;
    let body = seam_body(
        "on_shift",
        &Value::Map(vec![
            (Value::text("until"), Value::Unsigned(until)),
            (Value::text("location"), Value::text("store-1")),
            (Value::text("on_shift"), Value::Bool(true)),
        ]),
    );
    let issued =
        p.s.twin
            .issue_signed(&p.s.domain, signed(subject, "on_shift", body, for_ms))
            .await
            .unwrap();
    assert_eq!(issued.disposition, "admit", "{issued:?}");
    schedule(&p.s.signer);
    until
}

/// Serve's `serve_staff` role Claim; the position its episode starts at.
async fn staff(p: &Product, subject: Id, role: &str) -> u64 {
    let issued =
        p.s.twin
            .issue_claim(
                &p.s.domain,
                Issue {
                    subject,
                    class: String::from("serve_staff"),
                    value: Some(EqValue::Text(String::from(role))),
                    for_ms: 3_600_000,
                    resource: None,
                },
            )
            .await
            .unwrap();
    assert_eq!(issued.disposition, "admit", "{issued:?}");
    schedule(&p.s.signer);
    issued.position.unwrap()
}

/// The store's Anchor, its owner as root.
async fn store(p: &Product, owner: &Actor) -> Id {
    let (created, _) =
        p.s.root(Payload::AnchorCreate {
            scope: meta::AnchorScope::Resource(structural("serve.store", &["store-1"])),
            root: Root::Sole(owner.party),
            root_terms: BTreeSet::new(),
        })
        .await;
    meta::object_id(&created, kind::ANCHOR, 0)
}

async fn from_store(
    p: &Product,
    owner: &Actor,
    anchor: Id,
    holder: SubjectSelector,
    authority: CanonicalAuthority,
) -> (Id, u64) {
    let (e, since) =
        p.s.own_commit(
            owner,
            ExerciseBasis::Anchor(anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(anchor),
                holder,
                authority,
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        )
        .await;
    (meta::object_id(&e, kind::GRANT, 0), since)
}

fn cash(p: &Product, names: &[&str], max: i64) -> CanonicalAuthority {
    let actions: Vec<ActionRef> = names.iter().map(|n| p.action(n)).collect();
    canonical(
        &actions,
        structural("serve.store", &["store-1"]),
        BTreeMap::from([(
            String::from("amount"),
            Bound::Range {
                min: Some(0),
                max: Some(max),
                unit: String::from(UNIT),
            },
        )]),
        BTreeSet::new(),
        BTreeSet::new(),
    )
}

// §7.9.10.2, X17, OP-156 m.3 (u), Ek B 5268
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one store's admin and cashier authority across a shift"
)]
async fn serve_staff_act_only_while_on_shift() {
    let p = Product::open("q17-serve", "serve").await;
    let shifts = p
        .accept_from(p.s.party, PREDICATE_INPUT, &["on_shift"])
        .await;
    p.s.accept_claims(SUBJECT_SELECTION, &["serve_staff"]).await;
    let owner = p.s.actor().await;
    let manager = p.s.actor().await;
    let bob = p.s.actor().await;
    let anchor = store(&p, &owner).await;

    // §7.9.10.2
    let (admin, admin_since) = from_store(
        &p,
        &owner,
        anchor,
        SubjectSelector::Party(manager.party),
        canonical(
            &[
                p.action("void"),
                p.action("refund"),
                p.action("menu_edit"),
                p.action("drawer_open"),
            ],
            structural("serve.store", &["store-1"]),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        ),
    )
    .await;
    let menu = envelope(
        p.action("menu_edit"),
        ("serve.store", &["store-1", "menu"]),
        BTreeMap::new(),
    );
    let allowed =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &manager,
                    menu.clone(),
                    holding(admin, manager.party, admin_since),
                    Vec::new(),
                ),
            )
            .await
            .unwrap();
    let mut edits = 0;
    ProductTwin::enforce(allowed, &menu, || edits += 1).unwrap();
    assert_eq!(edits, 1);
    let drawer = envelope(
        p.action("drawer_open"),
        ("serve.store", &["store-1", "drawer-1"]),
        BTreeMap::new(),
    );
    let allowed =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(
                    &manager,
                    drawer.clone(),
                    holding(admin, manager.party, admin_since),
                    Vec::new(),
                ),
            )
            .await
            .unwrap();
    let mut opened = 0;
    ProductTwin::enforce(allowed, &drawer, || opened += 1).unwrap();
    assert_eq!(opened, 1);

    let mut cashier = cash(&p, &["void"], 5_000);
    cashier.constraints.conditions = BTreeSet::from([WhileCondition::ClaimHeld {
        class: String::from("on_shift"),
        subject: SubjectSelector::Public,
        acceptance: shifts,
    }]);
    let (grant, _) = from_store(
        &p,
        &owner,
        anchor,
        pred(
            "serve_staff",
            EqValue::Text(String::from("store-1:cashier")),
        ),
        cashier,
    )
    .await;
    let since = staff(&p, bob.party, "store-1:cashier").await;
    let basis = holding(grant, bob.party, since);
    let r =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(&bob, void_of(&p, "o-1", 1_000), basis, Vec::new()),
            )
            .await;
    assert!(matches!(r, Err(Denied::Refused(_))), "{r:?}");

    let until = on_shift(&p, bob.party, 4_000).await;
    let void = void_of(&p, "o-1", 1_000);
    let allowed =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(&bob, void.clone(), basis, Vec::new()),
            )
            .await
            .unwrap();
    let mut voided = Vec::new();
    ProductTwin::enforce(allowed, &void, || voided.push("o-1")).unwrap();
    let r =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(&bob, menu.clone(), basis, Vec::new()),
            )
            .await;
    assert!(matches!(r, Err(Denied::Refused(Refusal::Deny))), "{r:?}");

    // §7.9.10.2
    while server_time(&p.s.w.db.app).await.unwrap() <= until + 1_000 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let r =
        p.s.twin
            .ask(
                &p.s.domain,
                &p.s.request(&bob, void_of(&p, "o-2", 1_000), basis, Vec::new()),
            )
            .await;
    assert!(matches!(r, Err(Denied::Refused(_))), "{r:?}");
    assert_eq!(voided, ["o-1"]);
    p.s.only_public();
}

/// The POS terminal's Verifier Profile (§9.12.1): checkpointed offline with a hardware-backed
/// counter, a secure clock, attestation and offline reports; its slice at most 5 voids and
/// 200 EUR.
fn pos_profile() -> VerifierProfile {
    VerifierProfile {
        verifier: VerifierId::Workload(String::from(POS)),
        profiles: BTreeMap::from([
            (ProfileVariant::CheckpointedOffline, BTreeMap::new()),
            (ProfileVariant::OnlineStrict, BTreeMap::new()),
        ]),
        versions: access_kernel::verify::key_scope::SpecVersions::default(),
        clock_source: access_verifier::caps::SECURE_CLOCK_CLASS.to_owned(),
        clock_skew_ms: 60_000,
        tamper_evident_counter: true,
        offline_report: true,
        content_position_check: false,
        status_access: BTreeSet::new(),
        refresh_interval_ms: None,
        attestation: Some(Digest(access_crypto::random::bytes::<32>().unwrap())),
        cap_horizon: BTreeMap::new(),
        slice_max: BTreeMap::from([(String::from("count"), 5), (String::from(UNIT), 20_000)]),
        conformance: BTreeSet::new(),
    }
}

/// Domain Metadata as the POS holds it, witnessed now (TI-RT5): the terminal trusts this log
/// and witness.
fn witnessed(signed: &[u8], now: u64) -> access_verifier::metadata::MetadataView {
    use ed25519_dalek::{Signer as _, SigningKey};
    use suiss_crypto::note::{self, Verifier};
    const LOG: &str = "pos.example/log";
    const WITNESS: &str = "pos.example/w1";
    let metadata = parse_sign1(signed)
        .ok()
        .and_then(|s| s.payload)
        .and_then(|b| DomainMetadata::from_bytes(&b).ok())
        .unwrap();
    let log_key = SigningKey::from_bytes(&access_crypto::random::bytes::<32>().unwrap());
    let witness_key = SigningKey::from_bytes(&access_crypto::random::bytes::<32>().unwrap());
    let log = Verifier::ed25519(LOG, log_key.verifying_key().to_bytes()).unwrap();
    let witness = Verifier::cosigner(WITNESS, witness_key.verifying_key().to_bytes()).unwrap();
    let body = format!(
        "{LOG}\n7\n{}\nmetadata sha-256:{}\n",
        note::base64_encode(&access_crypto::random::bytes::<32>().unwrap()),
        b64url_encode(&access_verifier::metadata::metadata_digest(signed)),
    );
    let mut sig = log.id().to_be_bytes().to_vec();
    sig.extend(log_key.sign(body.as_bytes()).to_bytes());
    let mut checkpoint = format!("{body}\n\u{2014} {LOG} {}\n", note::base64_encode(&sig));
    let ts = now / 1_000;
    let mut sig = witness.id().to_be_bytes().to_vec();
    sig.extend(ts.to_be_bytes());
    sig.extend(
        witness_key
            .sign(&note::cosigned_message(ts, &body))
            .to_bytes(),
    );
    checkpoint = format!(
        "{checkpoint}\u{2014} {WITNESS} {}\n",
        note::base64_encode(&sig)
    );
    let mut view = access_verifier::metadata::MetadataView::new(metadata, signed);
    view.witness(&checkpoint, LOG, &log, &[witness]).unwrap();
    view
}

/// `actor`'s commit of the meta-action `payload` on `basis` with the twin as PEP: the decision
/// body.
async fn meta_through_twin(
    p: &Product,
    actor: &Actor,
    basis: ExerciseBasis,
    payload: &Payload,
) -> Json {
    let now = server_time(&p.s.w.db.app).await.unwrap();
    let intent = access_product_twin::twin::meta_intent(
        payload,
        actor.party,
        Window {
            from: now - 60_000,
            until: now + 600_000,
        },
    )
    .unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let digest = intent_digest(&intent).unwrap();
    let ais = Seam::ais(
        &actor.key,
        &Statement {
            domain: p.s.domain,
            nonce: nonce.clone(),
            intent: digest,
            mode: Mode::Commit,
            pep: String::from(TWIN_PEP),
            capacity: Capacity::Own,
            basis,
            iat: now,
            exercise: None,
        },
    );
    let mut body: Json = serde_json::from_str(
        &adp_body(&ExerciseRequest {
            domain: &p.s.domain,
            mode: Mode::Commit,
            nonce: &nonce,
            intent: &digest,
            envelope: Some(&intent),
            actor: &SdkActor::Statement(ais),
            basis: &basis,
            capacity: Capacity::Own,
            pep: TWIN_PEP,
            exercise: None,
        })
        .unwrap(),
    )
    .unwrap();
    body["context"]["payload"] = Json::String(b64url_encode(&payload.to_bytes().unwrap()));
    let Answer::Response(r) =
        p.s.listener
            .send(
                access_product_twin::wire::call(
                    access_product_twin::Method::Post,
                    access_product_twin::wire::EVALUATION,
                    &[],
                    body.to_string().into_bytes(),
                )
                .unwrap(),
            )
            .await
    else {
        panic!("no answer");
    };
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    schedule(&p.s.signer);
    serde_json::from_slice(&r.body).unwrap()
}

// §2.7, §8.17.5.8, §7.9.4, §9.10, §9.12, X17, OP-156 m.3 (u), Ek B 5211, 5268
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one POS terminal from its profile to the end of its slice"
)]
async fn a_pos_terminal_refuses_offline_once_its_slice_is_spent() {
    let p = Product::open("q17-pos", "serve").await;
    p.s.accept_claims(
        PREDICATE_INPUT,
        &["verifier_profile", "offline_exercise_report"],
    )
    .await;
    let owner = p.s.actor().await;
    let bob = p.s.actor().await;
    let anchor = store(&p, &owner).await;
    let mut voids = cash(&p, &["void"], 5_000);
    voids.constraints.budget = BTreeSet::from([
        BudgetTerm {
            dimension: BudgetDimension::Count,
            capacity: 20,
            window: BudgetWindow::Total,
        },
        BudgetTerm {
            dimension: BudgetDimension::Amount(String::from(UNIT)),
            capacity: 100_000,
            window: BudgetWindow::Total,
        },
    ]);
    let (grant, since) = from_store(
        &p,
        &owner,
        anchor,
        SubjectSelector::Party(bob.party),
        voids.clone(),
    )
    .await;
    let basis = holding(grant, bob.party, since);

    // §9.12.1, PI-12
    let profile = pos_profile();
    let claim = signed(
        p.s.party,
        "verifier_profile",
        tabled_body(&Body::VerifierProfile(profile.clone())),
        3_600_000,
    );
    let issued = p.s.twin.issue_signed(&p.s.domain, claim).await.unwrap();
    assert_eq!(issued.disposition, "admit", "{issued:?}");
    schedule(&p.s.signer);

    // §7.9.4.1
    let now = server_time(&p.s.w.db.app).await.unwrap();
    let mut bounds = voids;
    bounds.constraints.budget = BTreeSet::new();
    bounds.constraints.validity = Window {
        from: now - 1_000,
        until: now + 3_600_000,
    };
    let projection = Payload::ProjectionIssue {
        bounds,
        audience: BTreeSet::from([String::from(POS)]),
        class: ProfileClass::Offline,
        variant: ProfileVariant::CheckpointedOffline,
        max_staleness_ms: None,
        offline_slice: Some(meta::SliceRequest {
            count: Some(2),
            amounts: BTreeMap::from([(String::from(UNIT), 10_000)]),
        }),
    };
    let answer = meta_through_twin(&p, &bob, basis, &projection).await;
    assert_eq!(answer["decision"], true, "{answer}");
    let pap_sign1 =
        access_kernel::json::b64url_decode(answer["context"]["pap"]["sign1"].as_str().unwrap())
            .unwrap();
    let excerpt =
        access_kernel::json::b64url_decode(answer["context"]["pap"]["excerpt"].as_str().unwrap())
            .unwrap();
    let pap = peek(&pap_sign1).unwrap();
    let local = LocalProfile::new(profile).unwrap();
    assert_eq!(pap.validity.verifier_profile_ref, *local.digest());

    // §9.10, EP-7
    let named = format!("sha-256:{}", b64url_encode(&p.s.domain.0));
    let path = access_product_twin::wire::DOMAIN_METADATA.replace("{domain}", &named);
    let Answer::Response(m) = p.s.listener.raw("GET", &path, Vec::new()).await else {
        panic!("no metadata");
    };
    assert_eq!(m.status, 200);
    let now = server_time(&p.s.w.db.app).await.unwrap();
    let mut pos = OfflineVerifier::new(
        Identity {
            audience: String::from(POS),
            instance: None,
            domain: p.s.domain,
            profile: local,
            catalog: access_kernel::algebra::Catalog::default(),
            understood: BTreeSet::new(),
        },
        witnessed(&m.body, now),
        EmulatedClock::new(now),
        ClockGuard::new(DEFAULT_TOLERANCE_MS),
    );
    for s in &pap.validity.offline_slice {
        pos.provision(
            pap.projection_exercise,
            s.budget_term,
            s.amount,
            EmulatedCounter::new(CounterId(access_crypto::random::bytes::<16>().unwrap())),
        )
        .unwrap();
    }
    let void_schema = p
        .schema
        .actions
        .iter()
        .find(|a| a.name == "void")
        .unwrap()
        .clone();
    let mut voided = Vec::new();
    for (order, expect) in [("o-1", true), ("o-2", true), ("o-3", false)] {
        let intent = void_of(&p, order, 4_000);
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let presentation = sign_sign1(
            &bob.key,
            thumbprint(&bob.key.public_key()),
            access_kernel::pap::PRESENTATION_CONTENT_TYPE,
            &access_kernel::pap::Presentation {
                pap: access_kernel::pap::pap_digest(&pap_sign1),
                intent: intent_digest(&intent).unwrap(),
                audience: String::from(POS),
                nonce: nonce.to_vec(),
                iat: now,
            }
            .to_bytes()
            .unwrap(),
        )
        .unwrap();
        let verdict = pos.verify(&Use {
            pap: &pap_sign1,
            excerpt: &excerpt,
            presentation: &presentation,
            intent: &intent,
            nonce: &nonce,
            satisfied: &BTreeSet::new(),
            schema: Some(&void_schema),
            content_position: None,
        });
        match (verdict, expect) {
            (Verdict::Allow(_), true) => voided.push(order),
            (Verdict::Deny(d), false) => assert_eq!(d.code(), "pap-slice"),
            (v, _) => panic!("{order}: {v:?}"),
        }
    }
    assert_eq!(voided, ["o-1", "o-2"]);
    p.s.only_public();
}
