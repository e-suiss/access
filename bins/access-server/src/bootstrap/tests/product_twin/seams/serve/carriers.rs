//! Post-quantum PAP carriers on the real server path (CR-41 m.2, CR-43, L2-BUD-1, OP-159 m.3
//! (p), (q), m.21 (f)): the POS terminal's offline projection in the smallest offline carrier
//! that holds it, refused over every one of them, signed under ML-DSA-44 by a key that signs
//! only offline PAPs; a projection over the header budget served by reference through the real
//! fetch route, and shredded at its horizon.

use access_kernel::json::b64url_decode;
use access_kernel::verify::hybrid::{self, Component, Expected, HybridError};
use access_kernel::verify::key_scope::{Hybrid, KeyExcerpt, KeyUsage};
use axum::http::Request;
use suiss_crypto::aws::AwsLcBackend;
use suiss_crypto::cose::Algorithm;

use super::*;

fn wall() -> u64 {
    access_authority_signer::adapters::now_ms()
}

fn after_lock() -> u64 {
    wall() + crate::algorithms::LOCK_MS + 1_000
}

struct NoDecision;

impl access_http::adp::ports::Pdp for NoDecision {
    fn evaluate(
        &self,
        _: access_authority_core::app::Incoming,
    ) -> impl std::future::Future<
        Output = Result<access_authority_core::app::Response, access_authority_core::CoreError>,
    > + Send {
        std::future::ready(Err(access_authority_core::CoreError::Protocol(
            "not-reached",
        )))
    }
}

async fn send(router: axum::Router, req: Request<axum::body::Body>, pep: &str) -> (u16, Vec<u8>) {
    let mut req = req;
    req.extensions_mut()
        .insert(access_http::adp::adapters::Pep(pep.to_owned()));
    let r = router.oneshot(req).await.unwrap();
    let status = r.status().as_u16();
    let body = axum::body::to_bytes(r.into_body(), 1 << 22).await.unwrap();
    (status, body.to_vec())
}

/// `alg` admitted to the product's domain through the algorithm route behind its CT3
/// time-lock (OP-159 m.16 (a)).
async fn admit(p: &Product, label: &str, alg: Algorithm) {
    let socket = std::env::temp_dir()
        .join(format!("abs-auth-{label}-{}", std::process::id()))
        .join("a.sock");
    let router = |now: fn() -> u64| {
        access_http::algorithms::router(
            crate::algorithms::PgAlgorithms {
                socket: socket.clone(),
                app: p.s.w.db.app.clone(),
                sequencer: p.s.w.db.sequencer.clone(),
                targets: Vec::new(),
                notify: None,
            },
            NoDecision,
            now,
        )
    };
    let uri = format!(
        "/access/v1/domains/{}/algorithms",
        access_authority_sequencer::checkpoint::origin(&p.s.domain)
    );
    let body = format!(r#"{{"alg":{}}}"#, alg.cose());
    let post = || {
        Request::post(uri.as_str())
            .body(axum::body::Body::from(body.clone()))
            .unwrap()
    };
    let (s, b) = send(router(wall), post(), "pep-j3b").await;
    assert_eq!(s, 202, "{}", String::from_utf8_lossy(&b));
    let (s, b) = send(router(after_lock), post(), "pep-j3b").await;
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&b));
}

/// The commit of `payload` by `actor` on `basis` with the twin as PEP: the status and body.
async fn through_twin(
    p: &Product,
    actor: &Actor,
    basis: ExerciseBasis,
    payload: &Payload,
) -> (u16, Json) {
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
    schedule(&p.s.signer);
    (
        r.status,
        serde_json::from_slice(&r.body).unwrap_or_default(),
    )
}

/// A projection of the voids under `extra` more resource path segments than the Grant names
/// (narrower, and larger), for the POS terminal, `variant`, living `life_ms`.
fn projection(
    p: &Product,
    extra: usize,
    variant: ProfileVariant,
    now: u64,
    life_ms: u64,
) -> Payload {
    let segments: Vec<String> = (0..extra)
        .map(|i| format!("lane-{i:02}-{}", "x".repeat(112)))
        .collect();
    let mut path = vec!["store-1"];
    path.extend(segments.iter().map(String::as_str));
    let mut bounds = canonical(
        &[p.action("void")],
        structural("serve.store", &path),
        BTreeMap::from([(
            String::from("amount"),
            Bound::Range {
                min: Some(0),
                max: Some(5_000),
                unit: String::from(UNIT),
            },
        )]),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    bounds.constraints.validity = Window {
        from: now - 1_000,
        until: now + life_ms,
    };
    let offline_slice = (variant.class() == ProfileClass::Offline).then(|| meta::SliceRequest {
        count: Some(1),
        amounts: BTreeMap::from([(String::from(UNIT), 1_000)]),
    });
    Payload::ProjectionIssue {
        bounds,
        audience: BTreeSet::from([String::from(POS)]),
        class: variant.class(),
        variant,
        max_staleness_ms: None,
        offline_slice,
    }
}

fn member(answer: &Json, artefact: &str, k: &str) -> Vec<u8> {
    b64url_decode(answer["context"][artefact][k].as_str().unwrap_or_default()).unwrap()
}

fn excerpted(excerpt: &[u8]) -> access_kernel::verify::key_scope::OperationalKey {
    let payload = parse_sign1(excerpt).unwrap().payload.unwrap();
    KeyExcerpt::from_bytes(&payload).unwrap().key
}

/// The PAP carrier verified under `metadata` with both excerpts, and refused without the
/// ML-DSA one (L0-SIG-75a).
fn verify_pap(metadata: &DomainMetadata, carrier: &[u8], excerpt: &[u8], pq_excerpt: &[u8]) {
    let (classic, pq) = hybrid::decode_carrier(carrier).unwrap();
    let pap = peek(&classic).unwrap();
    let expected = Expected::new(
        &metadata.domain,
        KeyUsage::Pap,
        pap.iat,
        access_kernel::pap::CONTENT_TYPE,
    );
    let verified = hybrid::verify(
        &AwsLcBackend,
        metadata,
        Some(Component::new(&classic, excerpt)),
        Some(Component::new(&pq, pq_excerpt)),
        &expected,
    )
    .unwrap();
    assert_eq!(peek(&classic).unwrap(), pap);
    assert_ne!(verified.payload.len(), 0);
    assert!(matches!(
        hybrid::verify(
            &AwsLcBackend,
            metadata,
            Some(Component::new(&classic, excerpt)),
            None,
            &expected,
        ),
        Err(HybridError::Missing)
    ));
}

// CR-41 m.2, CR-43, L0-SIG-75a, L2-BUD-1, L2-PAP-2, OP-73, OP-159 m.3 (p), (q), m.21 (f)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::too_many_lines,
    reason = "one domain's PAPs through every carrier from classic to ML-DSA-44"
)]
async fn pq_paps_take_the_carrier_that_holds_them_and_ml_dsa_44_signs_only_offline_paps() {
    let label = "j3b-carriers";
    let p = Product::open(label, "serve").await;
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
    let claim = signed(
        p.s.party,
        "verifier_profile",
        tabled_body(&Body::VerifierProfile(pos_profile())),
        3_600_000,
    );
    let issued = p.s.twin.issue_signed(&p.s.domain, claim).await.unwrap();
    assert_eq!(issued.disposition, "admit", "{issued:?}");
    schedule(&p.s.signer);
    let offline = ProfileVariant::CheckpointedOffline;
    let now = || server_time(&p.s.w.db.app);

    // L2-BUD-1
    let (s, classic) = through_twin(
        &p,
        &bob,
        basis,
        &projection(&p, 0, offline, now().await.unwrap(), 3_600_000),
    )
    .await;
    assert_eq!(
        (s, &classic["decision"]),
        (200, &Json::Bool(true)),
        "{classic}"
    );
    assert_eq!(classic["context"]["pap"]["carrier"], "qr", "{classic}");
    assert!(classic["context"]["pap"]["pq_excerpt"].is_null());

    // L2-BUD-1, OP-159 m.3 (p)
    admit(&p, label, Algorithm::MlDsa65).await;
    let (s, over) = through_twin(
        &p,
        &bob,
        basis,
        &projection(&p, 14, offline, now().await.unwrap(), 3_600_000),
    )
    .await;
    assert_eq!(s, 422, "{over}");
    assert_eq!(over["code"], "projection-over-budget", "{over}");

    // CR-41 m.2, OP-159 m.21 (f)
    admit(&p, label, Algorithm::MlDsa44).await;
    let signed_metadata = p.s.w.domains.metadata(p.s.domain).await.unwrap();
    let metadata =
        DomainMetadata::from_bytes(&parse_sign1(&signed_metadata).unwrap().payload.unwrap())
            .unwrap();
    assert_eq!(metadata.hybrid, Some(Hybrid::Both));
    assert!(metadata.algorithms.contains(&Algorithm::MlDsa44));
    let (s, small) = through_twin(
        &p,
        &bob,
        basis,
        &projection(&p, 0, offline, now().await.unwrap(), 3_600_000),
    )
    .await;
    assert_eq!((s, &small["decision"]), (200, &Json::Bool(true)), "{small}");
    assert_eq!(small["context"]["pap"]["carrier"], "nfc", "{small}");
    let carrier = member(&small, "pap", "sign1");
    let pap_key = excerpted(&member(&small, "pap", "pq_excerpt"));
    assert_eq!(pap_key.alg, Algorithm::MlDsa44);
    assert_eq!(pap_key.usage, BTreeSet::from([KeyUsage::Pap]));
    let (_, pq) = hybrid::decode_carrier(&carrier).unwrap();
    assert_eq!(
        access_kernel::verify::ml_dsa::algorithm_of(&pq).unwrap(),
        Algorithm::MlDsa44
    );
    verify_pap(
        &metadata,
        &carrier,
        &member(&small, "pap", "excerpt"),
        &member(&small, "pap", "pq_excerpt"),
    );
    let receipt_key = excerpted(&member(&small, "receipt", "pq_excerpt"));
    assert_eq!(receipt_key.alg, Algorithm::MlDsa65);
    assert_ne!(receipt_key.kid, pap_key.kid);
    assert!(
        metadata
            .operational_keys
            .iter()
            .filter(|k| k.alg == Algorithm::MlDsa44)
            .all(|k| k.usage == BTreeSet::from([KeyUsage::Pap]))
    );

    // OP-159 m.3 (q)
    let life_ms = 15_000;
    let (s, large) = through_twin(
        &p,
        &bob,
        basis,
        &projection(
            &p,
            14,
            ProfileVariant::OnlineStrict,
            now().await.unwrap(),
            life_ms,
        ),
    )
    .await;
    assert_eq!((s, &large["decision"]), (200, &Json::Bool(true)), "{large}");
    let reference = &large["context"]["pap"]["projection_ref"];
    assert!(large["context"]["pap"]["sign1"].is_null(), "{large}");
    let digest = b64url_decode(reference["digest"].as_str().unwrap()).unwrap();
    let fetch = reference["fetch"].as_str().unwrap().to_owned();
    assert_eq!(
        fetch,
        access_authority_core::app::carry::fetch_path(
            &p.s.domain,
            &<[u8; 32]>::try_from(digest.as_slice()).unwrap()
        )
    );
    let router = || access_http::projections::router(p.s.w.domains.clone());
    let get = || {
        Request::get(fetch.as_str())
            .body(axum::body::Body::empty())
            .unwrap()
    };
    let (s, bytes) = send(router(), get(), POS).await;
    assert_eq!(s, 200, "{}", String::from_utf8_lossy(&bytes));
    assert_eq!(reference["size"], bytes.len());
    assert!(
        access_crypto::budget::Carrier::Header
            .check(b64url_encode(&bytes).len())
            .is_err()
    );
    assert_eq!(suiss_crypto::digest::sha256(&bytes).as_slice(), digest);
    let (classic_part, pq_part) = hybrid::decode_carrier(&bytes).unwrap();
    assert_eq!(
        access_kernel::verify::ml_dsa::algorithm_of(&pq_part).unwrap(),
        Algorithm::MlDsa65
    );
    assert_eq!(
        peek(&classic_part).unwrap().validity.class,
        ProfileClass::Online
    );
    verify_pap(
        &metadata,
        &bytes,
        &member(&large, "pap", "excerpt"),
        &member(&large, "pap", "pq_excerpt"),
    );
    let (s, _) = send(router(), get(), "pos-store-2").await;
    assert_eq!(s, 404);

    // OP-73
    let d = access_store::scope::DomainId::from_bytes(p.s.domain.0);
    let key = <[u8; 32]>::try_from(digest.as_slice()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let (s, body) = send(router(), get(), POS).await;
        if s == 410 {
            let problem: Json = serde_json::from_slice(&body).unwrap();
            assert_eq!(problem["code"], "projection-ref-expired");
            break;
        }
        assert_eq!(s, 200);
        assert!(std::time::Instant::now() < deadline, "never expired");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let row = access_store::projection_blobs::get(&p.s.w.db.sequencer, &d, &key)
        .await
        .unwrap()
        .unwrap();
    assert!(row.sealed.is_none());
    assert_eq!(row.size, u64::try_from(bytes.len()).unwrap());
    p.s.only_public();
}
