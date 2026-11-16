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
    assert_eq!(session["kind"], "management");

    // OP-159 m.47 (f)
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
    let (r, _) = send(&c.management, read(&c, c.domain, "envs/acme/settings")).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
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

    // OP-159 m.47 (f)
    let ids = cell_ids(&c.w.db.app, &c.w.keys).await.unwrap();
    let account = ids
        .encode(access_identity_account::app::SUBJECT_PREFIX, c.subject)
        .unwrap();
    open_ingest_day(&c.w).await;
    let (s, body) = tenant_write(
        &c,
        &Method::POST,
        &format!("/admin/v1/envs/acme-admin/accounts/{account}/suspend"),
        ("suspendAccount", Some(&account)),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.environment)
        .await
        .unwrap();
    let lines = access_store::tenant_admin::lines(&mut t, Some(&c.subject))
        .await
        .unwrap();
    t.commit().await.unwrap();
    let line = lines
        .iter()
        .find(|l| l.domain.as_bytes() == &acme_domain.0)
        .unwrap();
    assert!(line.ended_ms.is_some() && line.ended_claim.is_some());
    let declared = DeclaredTargets::default();
    let admin = Admin {
        app: &c.w.db.app,
        ids: &ids,
        decider: &c.w.plane,
        governance: &c.w.plane,
        pep: access_identity_ui::domain::frontend::IDENTITY_PEP,
        base: &c.w.base,
        keys: &c.w.keyring,
        platform_tenant: None,
        declared,
        vault: None,
    };
    assert!(matches!(
        admin
            .standing(
                (acme.tenant, acme.environment),
                acme_domain,
                &[],
                Some(access_kernel::model::Id(line.party)),
            )
            .await,
        Err(access_identity_admin::AdminError::Refused(code)) if code == "actor-binding"
    ));
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

/// Drafts the write `operation` on `slug`'s surface, signs it in the browser on the console's
/// domain and sends it with `method` to `target`.
async fn tenant_write(
    c: &Console,
    method: &Method,
    target: &str,
    (operation, key): (&str, Option<&str>),
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let slug = &c.route.slug;
    let drafts = format!("/admin/v1/envs/{slug}/intents");
    let proof = c.browser.ais(
        c.domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::POST, &drafts),
        Mode::Check,
        c.idp_anchor(),
    );
    let ask = serde_json::json!({ "operation": operation, "key": key, "body": body });
    let (r, out) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                &drafts.replacen("/admin/v1/", "/console/api/proxy/admin/", 1),
                "x",
            )
            .header("x-access-ais", proof)
            .body(Body::from(ask.to_string()))
            .unwrap(),
    )
    .await;
    let draft: serde_json::Value = serde_json::from_slice(&out).unwrap_or_default();
    if r.status() != StatusCode::OK {
        return (r.status(), draft);
    }
    let digest = Digest(
        <[u8; 32]>::try_from(b64url_decode(draft["intent_digest"].as_str().unwrap()).unwrap())
            .unwrap(),
    );
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let ais = c
        .browser
        .ais(c.domain, &nonce, digest, Mode::Commit, c.idp_anchor());
    let (r, out) = send(
        &c.management,
        c.browser
            .request(
                method,
                &target.replacen("/admin/v1/", "/console/api/proxy/admin/", 1),
                "x",
            )
            .header("x-access-ais", ais)
            .header("idempotency-key", b64url_encode(&nonce))
            .body(Body::from(draft["body"].to_string()))
            .unwrap(),
    )
    .await;
    c.w.domains.release().await;
    (
        r.status(),
        serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null),
    )
}

/// Reads `path` under `/admin/v1/` through the BFF with a read proof on the console's domain.
async fn tenant_read(c: &Console, path: &str) -> (StatusCode, serde_json::Value) {
    let proof = c.browser.ais(
        c.domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::GET, &format!("/admin/v1/{path}")),
        Mode::Check,
        c.idp_anchor(),
    );
    let (r, body) = send(
        &c.management,
        c.browser
            .request(
                &Method::GET,
                &format!("/console/api/proxy/admin/{path}"),
                "",
            )
            .header("x-access-ais", proof)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    (
        r.status(),
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

// OP-159 m.47 (a), (e), (f), (h), TN-89 (3), (5), (8), TN-109, TN-140, TNI-14
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one tenant's administration from its management environment, end to end"
)]
async fn a_tenant_administers_its_environments_and_administrators_from_its_management_environment()
{
    use access_identity_account::domain::invitation::{code_hash, token_hash};
    let plan = tenant_plan();
    let c = console_as(
        "mgmt-tenant-admins",
        true,
        &plan,
        DeclaredTargets::default(),
        ("acme-admin", Some(FOUNDER)),
    )
    .await;
    let ids = cell_ids(&c.w.db.app, &c.w.keys).await.unwrap();

    // OP-159 m.47 (a)
    let (s, list) = tenant_read(&c, "envs/acme-admin/tenant/environments").await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let slugs: Vec<(&str, &str, bool)> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["slug"].as_str().unwrap(),
                e["kind"].as_str().unwrap(),
                e["sandbox"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        slugs,
        vec![
            ("acme", "standard", false),
            ("acme-admin", "management", false)
        ]
    );
    assert!(list["items"][0]["issuer"].is_string() && list["items"][0]["created_at"].is_string());

    // OP-159 m.47 (h), TN-140
    let (s, made) = tenant_write(
        &c,
        &Method::POST,
        "/admin/v1/envs/acme-admin/tenant/environments",
        ("createTenantEnvironment", None),
        serde_json::json!({ "slug": "acme-play", "sandbox": true, "issuer_style": "path" }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{made}");
    assert_eq!(made["resource"]["slug"], "acme-play");
    assert_eq!(made["resource"]["kind"], "standard");
    assert_eq!(made["resource"]["sandbox"], true);
    let (s, taken) = tenant_write(
        &c,
        &Method::POST,
        "/admin/v1/envs/acme-admin/tenant/environments",
        ("createTenantEnvironment", None),
        serde_json::json!({ "slug": "acme-play", "sandbox": false }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{taken}");
    assert_eq!(taken["code"], "slug-taken");

    // OP-159 m.47 (e)
    let (s, admins) = tenant_read(&c, "envs/acme-admin/tenant/admins").await;
    assert_eq!(s, StatusCode::OK, "{admins}");
    let founder = &admins["items"][0];
    assert_eq!(founder["identifier"], FOUNDER);
    assert_eq!(founder["role"], "owner");
    assert_eq!(founder["status"], "active");
    let founder_id = founder["id"].as_str().unwrap().to_owned();
    assert_eq!(
        founder_id,
        ids.encode(access_identity_account::app::SUBJECT_PREFIX, c.subject)
            .unwrap()
    );
    let (s, last_owner) = tenant_write(
        &c,
        &Method::POST,
        &format!("/admin/v1/envs/acme-admin/tenant/admins/{founder_id}/remove"),
        ("removeTenantAdmin", Some(&founder_id)),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{last_owner}");
    assert_eq!(last_owner["code"], "last-tenant-owner");

    // OP-159 m.47 (f), TN-89 (1), (4)
    let (s, invited) = tenant_write(
        &c,
        &Method::POST,
        "/admin/v1/envs/acme-admin/tenant/admins",
        ("inviteTenantAdmin", None),
        serde_json::json!({ "email": "Helper@Globex.example" }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{invited}");
    let (_, admins) = tenant_read(&c, "envs/acme-admin/tenant/admins").await;
    let pending: Vec<&serde_json::Value> = admins["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["status"] == "invited")
        .collect();
    assert_eq!(pending.len(), 1, "{admins}");
    assert_eq!(pending[0]["identifier"], "@globex.example");
    assert_eq!(pending[0]["role"], "admin");
    assert!(pending[0]["id"].as_str().unwrap().starts_with("inv"));
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.environment)
        .await
        .unwrap();
    let rows = access_store::tenant_admin::invitations(&mut t, None)
        .await
        .unwrap();
    t.commit().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].cross_domain);
    assert_eq!(rows[0].inviter, c.subject);

    // TN-89 (5), (7), (8)
    let keks = crate::login::EnvironmentKeks::new(c.w.keys.clone());
    let index = keks
        .vault(c.route.environment)
        .unwrap()
        .index_of(
            c.route.tenant.as_bytes(),
            c.route.environment.as_bytes(),
            "helper@globex.example",
        )
        .unwrap();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.environment)
        .await
        .unwrap();
    access_store::tenant_admin::insert_invitation(
        &mut t,
        &access_store::tenant_admin::NewInvitation {
            token_hash: &token_hash("helper-token"),
            code_hash: &code_hash("ABCDEFGH"),
            invitee_index: &index,
            invitee_domain: "globex.example",
            inviter: &c.subject,
            cross_domain: true,
            exercise: &[7; 32],
            ttl_s: 86_400,
        },
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let routes = crate::founding::router(crate::founding::Founding {
        app: c.w.db.app.clone(),
        router: c.w.db.router.clone(),
        ids: Arc::new(crate::ids::CellIds::new(c.w.keys.clone())),
        plane: c.w.plane.clone(),
        base: c.w.base.clone(),
        keys: Arc::new(EnvironmentKeyring::new(
            SignerKeys::new(c.w.identity_signer.clone()),
            c.w.keys.clone(),
        )),
        keks: crate::login::EnvironmentKeks::new(c.w.keys.clone()),
    });
    let call = |method: Method, path: String, body: serde_json::Value| {
        let routes = routes.clone();
        async move {
            let r = routes
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from(if body.is_null() {
                            String::new()
                        } else {
                            body.to_string()
                        }))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = r.status();
            let referrer = r.headers().get("referrer-policy").cloned();
            let bytes = to_bytes(r.into_body(), 1 << 16).await.unwrap();
            (
                status,
                referrer,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
            )
        }
    };
    let base = "/env/acme-admin/v1/admin-invites/helper-token";
    let (s, referrer, view) = call(Method::GET, String::from(base), serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{view}");
    assert_eq!(referrer.unwrap(), "no-referrer");
    assert_eq!(
        view,
        serde_json::json!({ "tenant": "Acme", "environment": "acme-admin", "state": "pending" })
    );
    let (s, _, _) = call(
        Method::GET,
        String::from("/env/acme/v1/admin-invites/helper-token"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, wrong) = call(
        Method::POST,
        format!("{base}/verify"),
        serde_json::json!({ "email": "helper@globex.example", "code": "AAAAAAAA" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{wrong}");
    assert_eq!(wrong["code"], "invalid-code");
    let (s, _, early) = call(
        Method::POST,
        format!("{base}/accept"),
        serde_json::json!({ "email": "helper@globex.example", "code": "AAAAAAAA",
                            "password": "helper horse battery staple",
                            "device_key": b64url_encode(&cose_key(&SoftSigner::generate_p256().unwrap().0.public_key())) }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{early}");
    let (s, _, _) = call(
        Method::POST,
        format!("{base}/verify"),
        serde_json::json!({ "email": "helper@globex.example", "code": "abcdefgh" }),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let device = SoftSigner::generate_p256().unwrap().0;
    let (s, _, accepted) = call(
        Method::POST,
        format!("{base}/accept"),
        serde_json::json!({
            "email": "helper@globex.example",
            "code": "ABCDEFGH",
            "password": "helper horse battery staple",
            "device_key": b64url_encode(&cose_key(&device.public_key())),
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{accepted}");
    assert_eq!(accepted["environment"]["kind"], "management");
    let (s, _, again) = call(
        Method::POST,
        format!("{base}/accept"),
        serde_json::json!({ "email": "helper@globex.example", "code": "ABCDEFGH",
                            "password": "helper horse battery staple",
                            "device_key": b64url_encode(&cose_key(&SoftSigner::generate_p256().unwrap().0.public_key())) }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{again}");
    assert_eq!(again["code"], "invite-state");
    let (_, _, view) = call(Method::GET, String::from(base), serde_json::Value::Null).await;
    assert_eq!(view["state"], "accepted");

    // OP-159 m.47 (f)
    let helper = subject_in_environment(&c.w, &c.route, "helper@globex.example")
        .await
        .unwrap();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.environment)
        .await
        .unwrap();
    let row = access_store::tenant_admin::admin(&mut t, &helper)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    assert!(!row.owner && row.party.is_none() && row.ended_ms.is_none());
    assert!(row.cooling_until_ms.unwrap() > row.added_ms + 23 * 3_600_000);
    let (_, admins) = tenant_read(&c, "envs/acme-admin/tenant/admins").await;
    let helper_id = ids
        .encode(access_identity_account::app::SUBJECT_PREFIX, helper)
        .unwrap();
    let listed = admins["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == helper_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(listed["identifier"], "helper@globex.example");
    assert_eq!(listed["role"], "admin");
    assert_eq!(listed["status"], "active");

    // OP-159 m.47 (e)
    let (s, owner) = tenant_write(
        &c,
        &Method::POST,
        &format!("/admin/v1/envs/acme-admin/tenant/admins/{helper_id}/owner"),
        ("addTenantOwner", Some(&helper_id)),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{owner}");

    // OP-159 m.47 (f)
    let (s, removed) = tenant_write(
        &c,
        &Method::POST,
        &format!("/admin/v1/envs/acme-admin/tenant/admins/{helper_id}/remove"),
        ("removeTenantAdmin", Some(&helper_id)),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{removed}");
    let (_, admins) = tenant_read(&c, "envs/acme-admin/tenant/admins").await;
    assert!(
        admins["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["id"] == helper_id.as_str() && a["status"] == "removed"),
        "{admins}"
    );
}
