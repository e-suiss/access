//! The end customer's payment surfaces on the real server path with Pay's own seam schema
//! (§8.17.5.11, §8.11, XI-14, R8, X8, INV-20, OP-156 m.3 (v), m.24 (b), (g)): "save my card" is
//! the customer's own `grant.issue` from their self-anchor to the merchant (agency OWN,
//! recipient the merchant, bounded per order and in all); the hub, read by the experience
//! service with the customer's own signed reads, shows it as a merchant that can charge them with
//! Access's limit and Pay's limit as two rows; a one-time payment is the customer's own
//! `pay:initiate` Exercise and leaves the merchant no Grant; Stop charges is `grant.revoke`.

use access_experience::adapters::{Beacon, router as experience_router};
use access_experience::app::Experience;
use access_experience::contract::{Hub, Kind, Owner, Plan};
use access_experience::ports::{Clock, Random, Upstream};
use access_kernel::json::b64url_decode;
use access_kernel::model::PurposeRef;

use super::*;

/// The public listener as the experience service, which authenticates as the twin's PEP here.
#[derive(Clone)]
struct Reads(Listener);

impl Upstream for Reads {
    async fn search(&self, _domain: &str, kind: Kind, body: Vec<u8>) -> Answer {
        self.0
            .raw(
                "POST",
                &format!("/access/v1/search/{}", kind.search()),
                body,
            )
            .await
    }
}

struct Now;

impl Clock for Now {
    fn now(&self) -> u64 {
        now_ms()
    }
}

impl Random for Now {
    fn nonce(&self) -> Option<[u8; 16]> {
        access_crypto::random::bytes().ok()
    }
}

async fn post(app: &axum::Router, path: &str, body: &Json) -> Json {
    let r = app
        .clone()
        .oneshot(
            HttpRequestOf::post(path)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    serde_json::from_slice(&to_bytes(r.into_body(), 1 << 22).await.unwrap()).unwrap()
}

/// The hub of `viewer`, its reads signed with the viewer's own key, with Pay's `financial`
/// statements as the viewer's device read them from Pay.
async fn hub(p: &Product, app: &axum::Router, viewer: &Actor, financial: &Json) -> Hub {
    let party = b64url_encode(&viewer.party.0);
    let domain = b64url_encode(&p.s.domain.0);
    let plan: Plan = serde_json::from_value(
        post(
            app,
            "/experience/v1/hub/plan",
            &serde_json::json!({ "viewer": party, "domains": [{ "domain": domain }], "kinds": ["inventory"] }),
        )
        .await,
    )
    .unwrap();
    let reads: Vec<Json> = plan
        .reads
        .iter()
        .map(|r| {
            let digest =
                Digest(<[u8; 32]>::try_from(b64url_decode(&r.intent_digest).unwrap()).unwrap());
            let ais = Seam::ais(
                &viewer.key,
                &Statement {
                    domain: p.s.domain,
                    nonce: b64url_decode(&r.nonce).unwrap(),
                    intent: digest,
                    mode: Mode::Check,
                    pep: plan.pep.clone(),
                    capacity: Capacity::Own,
                    basis: ExerciseBasis::Anchor(meta::meta_anchor(&p.s.domain)),
                    iat: now_ms(),
                    exercise: None,
                },
            );
            let mut body = r.body.clone();
            body["context"]["ais"] = Json::from(b64url_encode(&ais));
            serde_json::json!({ "domain": r.domain, "kind": r.kind, "body": body })
        })
        .collect();
    serde_json::from_value(
        post(
            app,
            "/experience/v1/hub",
            &serde_json::json!({ "viewer": party, "reads": reads, "financial": financial }),
        )
        .await,
    )
    .unwrap()
}

/// The customer's commit of a drafted meta write through the public evaluation route, signed
/// with their own key on the draft's basis: its Exercise.
async fn commit_drafted(
    p: &Product,
    actor: &Actor,
    drafted: &access_http::console::drafts::Drafted,
    answer: &Json,
) -> Digest {
    let anchor = Id(<[u8; 16]>::try_from(
        b64url_decode(answer["basis"]["anchor"].as_str().unwrap()).unwrap(),
    )
    .unwrap());
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let basis = ExerciseBasis::Anchor(anchor);
    let ais = Seam::ais(
        &actor.key,
        &Statement {
            domain: p.s.domain,
            nonce: nonce.to_vec(),
            intent: intent_digest(&drafted.envelope).unwrap(),
            mode: Mode::Commit,
            pep: String::from(TWIN_PEP),
            capacity: Capacity::Own,
            basis,
            iat: now_ms(),
            exercise: None,
        },
    );
    let resource = &answer["intent"]["resources"][0];
    let body = serde_json::json!({
        "subject": { "type": "access_party", "id": b64url_encode(&actor.party.0) },
        "action": { "name": "grant_issue" },
        "resource": { "type": resource["namespace"], "id": resource["path"][0] },
        "context": {
            "domain": b64url_encode(&p.s.domain.0),
            "mode": "commit",
            "nonce": b64url_encode(&nonce),
            "intent": answer["intent"],
            "payload": answer["payload"],
            "basis": answer["basis"],
            "capacity": "own",
            "ais": b64url_encode(&ais),
        },
    });
    let Answer::Response(r) =
        p.s.listener
            .raw(
                "POST",
                "/access/v1/evaluation",
                body.to_string().into_bytes(),
            )
            .await
    else {
        panic!("no answer");
    };
    let v: Json = serde_json::from_slice(&r.body).unwrap();
    assert_eq!((r.status, &v["decision"]), (200, &Json::Bool(true)), "{v}");
    schedule(&p.s.signer);
    Digest(
        <[u8; 32]>::try_from(b64url_decode(v["context"]["exercise"].as_str().unwrap()).unwrap())
            .unwrap(),
    )
}

// §8.17.5.11, §7.9.9.3, XI-14, R8, X8, INV-20, E21, F9, OP-156 m.3 (u), (v), m.24 (b), (g),
// OP-153 m.3 (gg), Ek B 5165, 5166, 5167, 5168
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one customer from saving a card to paying once and stopping charges"
)]
async fn saving_a_card_paying_once_and_stopping_charges_on_the_real_server() {
    let p = Product::open("q18-customer", "pay").await;
    let customer = p.s.actor().await;
    let merchant = p.s.actor().await;
    let card = hex(&customer.party);
    let initiate = p.action("initiate");
    let app = experience_router(
        Experience::new(
            Reads(p.s.listener.clone()),
            Now,
            Now,
            String::from(TWIN_PEP),
        ),
        Beacon::default(),
    );

    // §8.17.5.11, Ek B 5167
    let mut authority = canonical(
        std::slice::from_ref(&initiate),
        structural("access.party", &[&card, "instrument"]),
        at_most(15_000),
        budget(50_000),
        BTreeSet::new(),
    );
    authority.authority.recipient = Some(SubjectSelector::Party(merchant.party));
    authority.authority.purpose = Some(BTreeSet::from([PurposeRef::Code(String::from("orders"))]));
    // S1, TN-110
    let page = serde_json::json!({
        "action": { "namespace": "access", "name": "grant_issue", "major": 1 },
        "mode": "commit",
        "payload": { "grant_issue": {
            "basis": { "anchor": b64url_encode(&customer.anchor.0) },
            "holder": { "party": b64url_encode(&merchant.party.0) },
            "authority": access_http::adp::payload::canonical_authority_to_json(&authority).unwrap(),
            "agency": ["own"],
        } },
    });
    let drafted = access_http::console::drafts::draft(page.to_string().as_bytes(), SLUG, now_ms())
        .unwrap_or_else(|e| panic!("{e:?}: {page}"));
    let answer = drafted.answer(&p.s.domain);
    assert_eq!(
        answer["basis"]["anchor"],
        b64url_encode(&customer.anchor.0),
        "the Grant rests on the customer's self-anchor"
    );
    let saved = commit_drafted(&p, &customer, &drafted, &answer).await;
    let grant = meta::object_id(&saved, kind::GRANT, 0);
    let grant_text = b64url_encode(&grant.0);

    // S2, XI-14
    let pay_limit =
        serde_json::json!({ "currency": "TRY", "limit_minor": 500_000, "period": "day" });
    let seen = hub(
        &p,
        &app,
        &customer,
        &serde_json::json!([{ "grant": grant_text, "pay_limit": pay_limit, "as_of": 1 }]),
    )
    .await;
    let row = seen
        .shared_from_you
        .iter()
        .find(|r| r.grant == grant_text)
        .unwrap_or_else(|| panic!("{seen:?}"));
    assert_eq!(
        row.who.party.as_deref(),
        Some(b64url_encode(&merchant.party.0).as_str())
    );
    assert_eq!(row.what, ["pay:initiate"]);
    let owners: Vec<(&str, Owner)> = row
        .limits
        .iter()
        .map(|l| (l.kind.as_str(), l.owner))
        .collect();
    assert_eq!(
        owners,
        [("authority", Owner::Access), ("financial", Owner::Pay)]
    );
    assert_eq!(row.limits[0].term["capacity"], 50_000);
    assert_eq!(row.limits[1].term, pay_limit);
    assert!(
        row.offers
            .iter()
            .any(|o| o.action == "revoke" && o.available)
    );

    // §8.17.5.11, R8, X8, INV-20, Ek B 5166
    let on_card = ("access.party", &[card.as_str(), "instrument", "card-1"][..]);
    let mut once = envelope(initiate.clone(), on_card, amount(30_000));
    once.recipient = Some(merchant.party);
    once.purpose = Some(PurposeRef::Code(String::from("order_1182")));
    assert!(once.validity.until - once.validity.from <= 86_400_000);
    let paid = p
        .evaluate(
            &customer,
            &once,
            ExerciseBasis::Anchor(customer.anchor),
            Vec::new(),
        )
        .await;
    assert_eq!(paid["decision"], true, "{paid}");
    let exercise = Digest(
        <[u8; 32]>::try_from(b64url_decode(paid["context"]["exercise"].as_str().unwrap()).unwrap())
            .unwrap(),
    );
    let after = hub(&p, &app, &customer, &serde_json::json!([])).await;
    let to_merchant: Vec<&str> = after
        .shared_from_you
        .iter()
        .filter(|r| r.who.party.as_deref() == Some(b64url_encode(&merchant.party.0).as_str()))
        .map(|r| r.grant.as_str())
        .collect();
    assert_eq!(
        to_merchant,
        [grant_text.as_str()],
        "paying once adds no merchant Grant"
    );
    let phantom = meta::object_id(&exercise, kind::GRANT, 0);
    let again = p
        .evaluate(
            &merchant,
            &{
                let mut e = envelope(initiate.clone(), on_card, amount(30_000));
                e.recipient = Some(merchant.party);
                e.purpose = Some(PurposeRef::Code(String::from("order_1182")));
                e
            },
            holding(phantom, merchant.party, 1),
            Vec::new(),
        )
        .await;
    assert_ne!(
        again["decision"], true,
        "the one-time payment left nothing to charge with: {again}"
    );

    // S2, Ek B 5168
    p.s.own_commit(
        &customer,
        ExerciseBasis::Anchor(customer.anchor),
        Payload::GrantRevoke { grant },
    )
    .await;
    let stopped = hub(&p, &app, &customer, &serde_json::json!([])).await;
    assert!(
        stopped
            .shared_from_you
            .iter()
            .all(|r| r.grant != grant_text),
        "{stopped:?}"
    );
    p.s.only_public();
}
