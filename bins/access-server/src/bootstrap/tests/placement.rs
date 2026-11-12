//! Cells, placement, residency and rehome on the real server path (OP-158 m.3 (o), (p), OP-153
//! m.3 (gg)): the Placement Directory routes through the real ADP router and never decides; a
//! single-node cell publishes `durability: single-node` and acknowledges no revocation without a
//! replica and an independent witness; a silo move takes a tenant's domains to a dedicated cell
//! of its own; a realm rehome needs a committed Exercise in both governing domains.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;

use access_authority_core::app::placement::{CellDb, silo};
use access_http::adp::adapters::Pep;
use access_identity_admin::AdminError;
use access_identity_admin::domain::Invalid;
use access_identity_admin::domain::resilience::Rehome;
use access_kernel::combinator::Mode;
use access_kernel::verify::key_scope::{DrClass, Durability, Residency};
use access_store::placement::{self, CellProfile, Subject};
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Request as HttpRequest, StatusCode, header};
use serde_json::Value as Json;
use tower::ServiceExt as _;

use super::authzen::{PEP, Pdp, pdp};
use super::*;

fn socket(label: &str) -> PathBuf {
    std::env::temp_dir()
        .join(format!("abs-auth-{label}-{}", std::process::id()))
        .join("a.sock")
}

fn profile(cell: &str, durability: &str, dedicated_to: Option<[u8; 16]>) -> CellProfile {
    CellProfile {
        cell: String::from(cell),
        region: Some(String::from("eu-central")),
        class: String::from("regional"),
        durability: String::from(durability),
        dedicated_to,
    }
}

async fn post(router: &axum::Router, path: &str, body: &Json) -> (StatusCode, HeaderMap, Json) {
    let mut req = HttpRequest::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    req.extensions_mut().insert(Pep(String::from(PEP)));
    let r = router.clone().oneshot(req).await.unwrap();
    let (status, headers) = (r.status(), r.headers().clone());
    let bytes = to_bytes(r.into_body(), 1 << 22).await.unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Json::Null),
    )
}

/// The root's revocation: `idp.org` `invite_revoke`, in the SEC23 class by its name.
async fn revoke(p: &Pdp) -> Json {
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let intent = p
        .idp_intent(access_internal_api::idp::IdpAction::OrgInviteRevoke, "org")
        .await;
    let body = p
        .body(Mode::Commit, &nonce, &intent, p.idp_basis(), PEP)
        .await;
    let a = p.post("/access/v1/evaluation", &body).await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::OK, "{v}");
    assert_eq!(v["decision"], true, "{v}");
    v
}

// HL-40, SEC23, OP-48, T36, OP-158 m.3 (p), Ek B 5887, 5968
#[tokio::test(flavor = "multi_thread")]
async fn hl_40_a_single_node_cell_publishes_it_and_acknowledges_no_revocation_without_a_replica() {
    let label = "w9-single";
    let p = pdp(label).await;
    let small = profile("small-provider", "single-node", None);
    crate::cells::declare(&p.w.db.app, &small).await.unwrap();
    assert_eq!(
        placement::cell_profile(&p.w.db.app).await.unwrap(),
        Some(small.clone())
    );
    assert!(
        crate::cells::declare_domain(&socket(label), p.domain, &small)
            .await
            .unwrap()
    );
    assert!(
        !crate::cells::declare_domain(&socket(label), p.domain, &small)
            .await
            .unwrap(),
        "a declared cell declares nothing again"
    );
    let declared = p.w.domains.declared(p.domain).await;
    // HL-40
    assert_eq!(declared.durability, Some(Durability::SingleNode));
    // T28
    assert_eq!(
        declared.residency,
        Some(Residency::new(
            String::from("eu-central"),
            DrClass::Regional
        ))
    );
    assert!(declared.mmd.is_some(), "the other declarations stay");
    assert!(!declared.acknowledges());
    // SEC23, HL-40
    let v = revoke(&p).await;
    assert_eq!(v["context"]["ack"], "pending", "{v}");
}

// TI-17, CMP-26, OP-158 m.3 (o), Ek B 5717, 5973, 6107
#[tokio::test(flavor = "multi_thread")]
async fn ti_17_the_directory_routes_a_misdirected_request_and_the_commit_path_runs_without_it() {
    let p = pdp("w9-route").await;
    let app = &p.w.db.app;
    let id = DomainId::from_bytes(p.domain.0);
    let tenant = placement::domain_tenant(app, &id).await.unwrap().unwrap();
    let now = p.now().await;
    placement::place_tenant(
        app,
        tenant,
        &Subject::Domain(p.domain.0),
        ("cell-b", false),
        now,
    )
    .await
    .unwrap();
    let routed = access_http::placement::route(
        p.adp.clone(),
        Arc::new(crate::cells::PgDirectory::of(
            app.clone(),
            "cell-a",
            &[("cell-b", "https://b.access.test")],
        )),
    );
    let before = p.w.domains.head(p.domain).await.unwrap().0;
    let (status, headers, body) = post(
        &routed,
        "/access/v1/evaluation",
        &p.allowed(Mode::Commit).await,
    )
    .await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST, "{body}");
    assert_eq!(body["code"], "placement-mismatch");
    assert_eq!(headers["access-cell"], "cell-b");
    assert_eq!(
        headers["location"],
        "https://b.access.test/access/v1/evaluation"
    );
    assert_eq!(p.w.domains.head(p.domain).await.unwrap().0, before);

    // TI-17
    let down = p.w.db.deriver.clone();
    let blind = access_http::placement::route(
        p.adp.clone(),
        Arc::new(crate::cells::PgDirectory::of(down, "cell-a", &[])),
    );
    let (status, _, body) = post(
        &blind,
        "/access/v1/evaluation",
        &p.allowed(Mode::Commit).await,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["decision"], true, "{body}");
    assert!(p.w.domains.head(p.domain).await.unwrap().0 > before);

    // TI-17
    placement::place_tenant(
        app,
        tenant,
        &Subject::Domain(p.domain.0),
        ("cell-a", false),
        now,
    )
    .await
    .unwrap();
    p.w.domains.release().await;
    access_authority_sequencer::cell::seal(&p.w.db.sequencer, app, p.domain, "mover")
        .await
        .unwrap();
    let sealed = p.w.domains.head(p.domain).await.unwrap().0;
    let (status, _, body) = post(
        &routed,
        "/access/v1/evaluation",
        &p.allowed(Mode::Commit).await,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_ne!(status, StatusCode::MISDIRECTED_REQUEST, "{body}");
    assert_eq!(p.w.domains.head(p.domain).await.unwrap().0, sealed);
}

// TN-9, OP-12, OP-48, OP-30, T28, OP-158 m.3 (o), Ek B 5718, 5719, 5958
#[tokio::test(flavor = "multi_thread")]
async fn tn_9_a_silo_move_takes_the_tenants_domains_to_a_dedicated_cell_and_no_other_tenant_lands_there()
 {
    let p = pdp("w9-silo").await;
    let target = fresh().await.unwrap();
    let id = DomainId::from_bytes(p.domain.0);
    let tenant = placement::domain_tenant(&p.w.db.app, &id)
        .await
        .unwrap()
        .unwrap();
    placement::declare_cell(
        &target.app,
        &profile("cell-acme", "replicated", Some(tenant)),
    )
    .await
    .unwrap();
    // OP-12, OP-48
    assert!(create_tenant(&target.app, "cell-acme").await.is_err());
    p.w.domains.release().await;
    let now = p.now().await;
    let source = CellDb {
        name: "pool-default",
        sequencer: &p.w.db.sequencer,
        app: &p.w.db.app,
    };
    let to = CellDb {
        name: "cell-acme",
        sequencer: &target.sequencer,
        app: &target.app,
    };
    let moved = silo(source, to, tenant, ("mover", now)).await.unwrap();
    assert!(
        moved.domains.iter().any(|(d, _)| *d == p.domain),
        "{moved:?}"
    );
    for app in [&p.w.db.app, &target.app] {
        let placed = placement::cell_of(app, &Subject::Domain(p.domain.0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (placed.cell.as_str(), placed.dedicated),
            ("cell-acme", true)
        );
        let t = placement::cell_of(app, &Subject::Tenant(tenant))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(t.cell, "cell-acme");
    }
    let head = access_store::cells::cell_head(&target.sequencer, &id)
        .await
        .unwrap()
        .unwrap();
    assert!(head.accepted_epoch.is_some());
    // OP-30
    let sealed = p.w.domains.head(p.domain).await.unwrap().0;
    let (status, _, body) = post(
        &p.adp,
        "/access/v1/evaluation",
        &p.allowed(Mode::Commit).await,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(p.w.domains.head(p.domain).await.unwrap().0, sealed);
    let again = silo(source, to, tenant, ("mover", now)).await.unwrap();
    assert!(
        again.domains.is_empty(),
        "a moved domain is not moved twice"
    );
    let routed = access_http::placement::route(
        p.adp.clone(),
        Arc::new(crate::cells::PgDirectory::of(
            p.w.db.app.clone(),
            "pool-default",
            &[("cell-acme", "https://acme.access.test")],
        )),
    );
    let (status, headers, _) = post(
        &routed,
        "/access/v1/evaluation",
        &p.allowed(Mode::Commit).await,
    )
    .await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(headers["access-cell"], "cell-acme");
}

/// The root's rehome proposal of `realm` in `tenant` to `to`, on `from`'s IDP anchor.
async fn rehome_proposal(
    w: &World,
    (tenant, realm): (TenantId, RealmId),
    from: Digest,
    to: Digest,
) -> (Proposal, Moment) {
    let at = Moment::at(server_time(&w.db.app).await.unwrap());
    let proposal = Proposal {
        tenant,
        realm,
        change: Change::Rehome(Rehome { domain: to.0 }),
        nonce: access_crypto::random::bytes::<16>().unwrap().to_vec(),
        validity: at.validity,
        basis: ExerciseBasis::Anchor(meta::object_id(&from, kind::ANCHOR, IDP_ANCHOR)),
        capacity: Capacity::Own,
        subject: None,
    };
    (proposal, at)
}

// E14, MD-5a, §5.16, §12.1.1 2a, OP-158 m.3 (o), m.18 (e), Ek B 5725
#[tokio::test(flavor = "multi_thread")]
async fn e14_a_rehome_moves_the_realm_only_with_an_exercise_in_both_governing_domains() {
    let w = World::new("w9-rehome").await;
    w.run(&plan()).await;
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let declared = DeclaredTargets::default();
    let b = Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &declared,
        console: None,
    };
    let admin = b.admin(&ids, None);
    let root = root_key(&w.keys).unwrap();
    let party = root_party(&root.public_key());
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let from = Digest(
        *idp::governance(&mut t)
            .await
            .unwrap()
            .unwrap()
            .domain
            .as_bytes(),
    );
    t.commit().await.unwrap();
    placement::declare_cell(&w.db.app, &profile("cell-a", "replicated", None))
        .await
        .unwrap();
    let other = admin
        .create_realm(&NewRealm {
            tenant: route.tenant,
            slug: "acme-two",
            style: IssuerStyle::Path,
            placement: PLACEMENT,
            root: Root::Sole(party),
            ct3_delay_s: Some(0),
            causal_binding: false,
            schemas: Vec::new(),
            acceptances: Vec::new(),
            issuer_predicate_input: Vec::new(),
            provisioned_by: None,
        })
        .await
        .unwrap();
    let to = other.domain;
    b.onboard(route.tenant, other.realm, to, &root, party)
        .await
        .unwrap();
    // E14
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    b.commit_meta(
        to,
        &root,
        &nonce,
        Payload::AnchorCreate {
            scope: meta::AnchorScope::Resource(access_kernel::model::ResourceSelector::Structural(
                access_kernel::model::Structural {
                    namespace: String::from(access_internal_api::idp::RESOURCE_NAMESPACE),
                    prefix: vec![String::from("acme")],
                    kind: None,
                    attrs: BTreeMap::new(),
                },
            )),
            root: Root::Sole(party),
            root_terms: BTreeSet::new(),
            sets: access_kernel::meta::RootSets::default(),
        },
        party,
    )
    .await
    .unwrap();
    let covering = meta::object_id(&meta::exercise_id(&to, &nonce).unwrap(), kind::ANCHOR, 0);
    b.lead(from).await.unwrap();
    b.lead(to).await.unwrap();
    let governing = || async {
        let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let g = idp::governance(&mut t).await.unwrap().unwrap().domain;
        let open = placement::open_ends(&mut t).await.unwrap();
        t.commit().await.unwrap();
        (Digest(*g.as_bytes()), open.len())
    };

    // E14
    let (p, at) = rehome_proposal(&w, (route.tenant, route.realm), from, to).await;
    let prepared = admin.prepare(&p).await.unwrap();
    assert_eq!(prepared.domain, from);
    let ais = sign(
        &root,
        &at.statement(from, &p.nonce, prepared.digest, p.basis),
    )
    .unwrap();
    let one = Box::pin(admin.rehome(&p, ais, None)).await;
    assert!(
        matches!(one, Err(AdminError::Invalid(Invalid::RehomeIncomplete))),
        "{one:?}"
    );
    assert_eq!(governing().await, (from, 1));
    // OP-158 m.18 (e)
    access_store::testing::age_rehome_ends(&w.db, 25)
        .await
        .unwrap();
    assert_eq!(
        governing().await,
        (from, 0),
        "an unused end expires 24 h after it was recorded"
    );

    // E14
    let (p, at) = rehome_proposal(&w, (route.tenant, route.realm), from, to).await;
    let prepared = admin.prepare(&p).await.unwrap();
    let ais = sign(
        &root,
        &at.statement(from, &p.nonce, prepared.digest, p.basis),
    )
    .unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let wrong = sign(
        &root,
        &at.statement(
            from,
            &nonce,
            prepared.digest,
            ExerciseBasis::Anchor(meta::object_id(&from, kind::ANCHOR, IDP_ANCHOR)),
        ),
    )
    .unwrap();
    let unbound = Box::pin(admin.rehome(&p, ais, Some(wrong))).await;
    assert!(matches!(unbound, Err(AdminError::Unbound)), "{unbound:?}");
    assert_eq!(governing().await.0, from);

    // E14
    let (p, at) = rehome_proposal(&w, (route.tenant, route.realm), from, to).await;
    let prepared = admin.prepare(&p).await.unwrap();
    let ais = sign(
        &root,
        &at.statement(from, &p.nonce, prepared.digest, p.basis),
    )
    .unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let target = sign(
        &root,
        &at.statement(to, &nonce, prepared.digest, ExerciseBasis::Anchor(covering)),
    )
    .unwrap();
    let moved = Box::pin(admin.rehome(&p, ais, Some(target))).await.unwrap();
    assert!(matches!(moved, Applied::Written { .. }), "{moved:?}");
    let (now, open) = governing().await;
    assert_eq!(now, to);
    assert_eq!(
        open, 1,
        "the expired end completes nothing; the second attempt's from end is used and the third's stays unused"
    );
    let placed = placement::cell_of(&w.db.app, &Subject::Realm(*route.realm.as_bytes()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(placed.cell, "cell-a");
    // MD-5a
    let after = b
        .change_as(
            &admin,
            (route.tenant, route.realm),
            (&root, ExerciseBasis::Anchor(covering)),
            (
                Change::DrProfile(Some(access_identity_admin::domain::resilience::DrProfile {
                    rpo_s: 60,
                })),
                None,
            ),
        )
        .await;
    assert!(after.is_ok(), "{after:?}");
    w.domains.release().await;
}

fn public_key() -> suiss_crypto::cose::PublicKey {
    let (signer, _) = suiss_crypto::signer::SoftSigner::generate_ed25519().unwrap();
    suiss_crypto::signer::Signer::public_key(&signer)
}

// SEC23, RR-35, HL-34, OP-158 m.11, OP-159 m.3 (g), (j), Ek B 5984, 6201
#[tokio::test(flavor = "multi_thread")]
async fn a_witness_only_the_provider_declared_is_a_proposal_and_no_anchor_is_claimed_before_one() {
    use access_authority_signer::protocol::{Request as SignRequest, Response as SignResponse};
    use access_kernel::verify::key_scope::{Replica, Witness};
    let label = "j2-canonical";
    let p = pdp(label).await;
    let mut declared = access_authority_signer::domain::declared_default();
    declared.witnesses.push(Witness::new(
        String::from("w-proposed"),
        public_key(),
        suiss_crypto::cose::Algorithm::Ed25519,
        String::from("Example Witness Ltd"),
        true,
    ));
    declared.replicas.push(Replica::new(
        String::from("r-proposed"),
        public_key(),
        String::from("Example Replica Ltd"),
        true,
    ));
    let answer = access_authority_signer::adapters::call(
        &socket(label),
        &SignRequest::Declare {
            domain: p.domain,
            declared: Box::new(declared),
        },
    )
    .await
    .unwrap();
    assert_eq!(answer, SignResponse::Opened);
    let published = p.w.domains.declared(p.domain).await;
    assert!(published.acknowledges(), "the operator's own statement");
    let canonical = crate::admin::realm::canonical_sets(&p.w.db.app, p.domain).await;
    assert!(canonical.is_empty(), "the Genesis root approved no set");
    let view = crate::admin::realm::declared_view(&published, &canonical);
    // OP-159 m.3 (j)
    assert_eq!(view["witnesses"][0]["canonical"], false, "{view:?}");
    assert_eq!(view["replicas"][0]["canonical"], false, "{view:?}");
    assert_eq!(view["acknowledges"], false);
    // RR-35, HL-34
    assert_eq!(view["pq_reanchor"], Json::Null);
    let approved =
        access_kernel::meta::RootSets::new(published.witnesses.clone(), published.replicas.clone());
    let view = crate::admin::realm::declared_view(&published, &approved);
    assert_eq!(view["acknowledges"], true);
    assert_eq!(view["witnesses"][0]["canonical"], true);
    // SEC23
    let v = revoke(&p).await;
    assert_eq!(v["context"]["ack"], "pending", "{v}");
}
