//! The console of a tenant administrator against the real BFF, admin surface, sequencer and store
//! (OP-159 m.47 (g), TN-142, TNI-14): the founder signs in once to the management environment,
//! registers the browser's key in the domain of an environment the tenant administers, and reads
//! that environment's management surface with a token its own authorization server issued to that
//! Instance; an environment it has no Instance in stays closed.

use crate::bootstrap::tenants::TenantPlan;

use super::*;

const FOUNDER: &str = "admin@acme.example";

fn tenant_plan() -> Plan {
    Plan {
        tenants: Vec::new(),
        managed: vec![TenantPlan {
            name: String::from("Acme"),
            management: String::from("acme-admin"),
            environments: vec![String::from("acme")],
            identifier: String::from(FOUNDER),
            password: Secret::new(String::from("founder horse battery staple")),
            totp: None,
        }],
        ..plan()
    }
}

// OP-159 m.47 (d), (g), (i), TN-142, TNI-14, TN-130
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one sign-in from the management environment to an administered environment's read"
)]
async fn the_founder_reads_its_environment_through_its_own_instance_there() {
    let plan = tenant_plan();
    let c = console_as(
        "mgmt-tenant",
        true,
        &plan,
        DeclaredTargets::default(),
        ("acme-admin", Some(FOUNDER)),
    )
    .await;
    let acme = route_by_slug(&c.w.db.router, "acme")
        .await
        .unwrap()
        .unwrap();
    assert!(acme.tenant == c.route.tenant);
    let mut t = TenantTx::begin(&c.w.db.app, acme.tenant, acme.environment)
        .await
        .unwrap();
    let acme_domain = Digest(
        *idp::governance(&mut t)
            .await
            .unwrap()
            .unwrap()
            .domain
            .as_bytes(),
    );
    t.commit().await.unwrap();
    // TNI-14
    assert!(subject_in_environment(&c.w, &acme, FOUNDER).await.is_none());

    let read = |c: &Console, domain: Digest, path: &str| {
        let proof = c.browser.ais(
            domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::GET, &format!("/admin/v1/{path}")),
            Mode::Check,
            ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR)),
        );
        c.browser
            .request(
                &Method::GET,
                &format!("/console/api/proxy/admin/{path}"),
                "",
            )
            .header("x-access-ais", proof)
            .body(Body::empty())
            .unwrap()
    };
    let (r, _) = send(&c.management, read(&c, acme_domain, "envs/acme/settings")).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // TN-142
    let key = b64url_encode(&cose_key(&c.browser.key.public_key()));
    let (r, body) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                "/console/api/environments/acme/instances/challenge",
                "x",
            )
            .body(Body::from(serde_json::json!({ "key": key }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let ch: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ch["domain"], b64url_encode(&acme_domain.0));
    assert!(ch.get("register").is_none(), "{ch}");
    let grant =
        <[u8; 16]>::try_from(b64url_decode(ch["basis"].as_str().unwrap()).unwrap()).unwrap();
    let challenge = b64url_decode(ch["challenge"].as_str().unwrap()).unwrap();
    let create = c.browser.ais(
        acme_domain,
        &challenge,
        envelope_digest(ch["create"].as_str().unwrap()),
        Mode::Commit,
        ExerciseBasis::Public(access_kernel::model::Id(grant)),
    );
    let (r, body) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                "/console/api/environments/acme/instances",
                "x",
            )
            .body(Body::from(
                serde_json::json!({
                    "challenge": ch["challenge"],
                    "party": ch["party"],
                    "key": key,
                    "valid_from": ch["valid_from"],
                    "valid_until": ch["valid_until"],
                    "ais": create,
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    c.w.domains.release().await;
    let (_, body) = send(
        &c.management,
        c.browser
            .request(&Method::GET, "/console/api/session", "")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let session: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(session["environments"], serde_json::json!(["acme"]));

    // OP-159 m.47 (f): the line is stated, then the environment's own AS issues the read token
    administer(&c.w).await;
    let (r, body) = send(&c.management, read(&c, acme_domain, "envs/acme/settings")).await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let (r, body) = send(
        &c.management,
        read(&c, c.domain, "envs/acme-admin/settings"),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    // a proof over the management domain does not read the administered environment
    let (r, _) = send(&c.management, read(&c, c.domain, "envs/acme/settings")).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // an environment it has no Instance in stays closed
    let (r, _) = send(&c.management, read(&c, acme_domain, "envs/globex/settings")).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let (r, _) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                "/console/api/environments/platform/instances/challenge",
                "x",
            )
            .body(Body::from(serde_json::json!({ "key": key }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

/// The account `identifier` of the environment `route`, if it has one.
async fn subject_in_environment(
    w: &World,
    route: &access_store::tenancy::EnvironmentRoute,
    identifier: &str,
) -> Option<[u8; 16]> {
    use access_identity_account::adapters::pg::PgAccounts;
    use access_identity_account::ports::{AccountDb as _, AccountTx as _};
    let keks = crate::login::EnvironmentKeks::new(w.keys.clone());
    let accounts = PgAccounts::sealed(w.db.app.clone(), keks.vault(route.environment).unwrap());
    let mut tx = accounts
        .begin(route.tenant, route.environment)
        .await
        .unwrap();
    let subject = tx.subject_by_identifier(identifier).await.unwrap();
    tx.commit().await.unwrap();
    subject
}
