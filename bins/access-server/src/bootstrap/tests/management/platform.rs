//! The console's Platform section against the real BFF, admin surface, sequencer and store
//! (OP-159 m.41, TN-119, INV-29, IA-5): the bootstrapped platform administrator signs in to the
//! platform realm, its `idp.platform.*` probes are eligible on its Grant alone, its session reads
//! the platform surface with a `platform.read` token, and a tenant creation is drafted, signed on
//! that Grant and committed as one Exercise.

use crate::bootstrap::platform_admin::PlatformAdminPlan;

use super::*;

const ADMIN: &str = "admin@platform.local";

fn admin_plan() -> Plan {
    Plan {
        platform_admin: Some(PlatformAdminPlan {
            identifier: String::from(ADMIN),
            password: Secret::new(String::from("platform horse battery staple")),
            totp: None,
            realms: Vec::new(),
        }),
        ..plan()
    }
}

fn read(c: &Console, path: &str) -> Request<Body> {
    let proof = c.browser.ais(
        c.domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::GET, &format!("/admin/v1/{path}")),
        Mode::Check,
        c.idp_anchor(),
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
}

// OP-159 m.41 (a), (b), (c), TN-119, INV-29, IA-5, XI-11, TN-110, TN-130
#[tokio::test]
async fn the_platform_admin_reads_and_provisions_through_the_console() {
    let plan = admin_plan();
    let c = console_as(
        "mgmt-platform",
        true,
        &plan,
        DeclaredTargets::default(),
        ("platform", Some(ADMIN)),
    )
    .await;
    let summary = c.w.run(&plan).await;
    let out = summary.platform_admin.unwrap();
    let holding = holding_of(&out.basis);
    let party = b64url_decode(&out.party).unwrap();

    // IA-5, XI-11
    for name in ["tenant_create", "realm_create", "sandbox_create"] {
        let ask = serde_json::json!({
            "action": { "namespace": "idp.platform", "name": name, "major": 1 },
            "resources": [{ "namespace": "idp", "path": ["platform"] }],
            "mode": "check",
        })
        .to_string();
        let proof = c.browser.ais(
            c.domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::POST, "/console/api/intents"),
            Mode::Check,
            c.idp_anchor(),
        );
        let (r, body) = send(
            &c.management,
            c.browser
                .request(&Method::POST, "/console/api/intents", "x")
                .header("x-access-ais", proof)
                .body(Body::from(ask))
                .unwrap(),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "{name}: {}",
            String::from_utf8_lossy(&body)
        );
        let draft: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mut set = draft["probe"].clone();
        set["intent"] = draft["intent"].clone();
        let mut on_grant = set.clone();
        on_grant["basis"] = out.basis.clone();
        for (set, eligible) in [(set, false), (on_grant, true)] {
            let body = serde_json::json!({ "subject": b64url_encode(&party), "set": set });
            let (r, answer) = send(
                &c.management,
                c.browser
                    .request(
                        &Method::POST,
                        "/console/api/proxy/adp/eligibility:check",
                        "x",
                    )
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await;
            assert_eq!(r.status(), StatusCode::OK, "{name}");
            let answer: serde_json::Value = serde_json::from_slice(&answer).unwrap();
            assert_eq!(answer["eligible"], eligible, "{name}: {answer}");
        }
    }

    // TN-130, OP-151 m.3 (a)
    for path in [
        "platform/tenants",
        "platform/operator/health",
        "platform/realms/acme",
    ] {
        let (r, body) = send(&c.management, read(&c, path)).await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "{path}: {}",
            String::from_utf8_lossy(&body)
        );
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // TN-119, X31
        for field in ["email", "redirect_uris", "grant", "claims"] {
            assert!(
                !body.windows(field.len()).any(|w| w == field.as_bytes()),
                "{path}: {v}"
            );
        }
    }
    let (_, body) = send(&c.management, read(&c, "platform/tenants")).await;
    let before = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["items"]
        .as_array()
        .unwrap()
        .len();

    // TN-110, OP-151 m.11 (a)
    let drafts = "/admin/v1/platform/intents";
    let proof = c.browser.ais(
        c.domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::POST, drafts),
        Mode::Check,
        c.idp_anchor(),
    );
    let (r, body) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                "/console/api/proxy/admin/platform/intents",
                "x",
            )
            .header("x-access-ais", proof)
            .body(Body::from(
                serde_json::json!({ "operation": "createTenant", "body": {} }).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let draft: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(draft["domain"], b64url_encode(&c.domain.0));
    let digest = Digest(
        <[u8; 32]>::try_from(b64url_decode(draft["intent_digest"].as_str().unwrap()).unwrap())
            .unwrap(),
    );
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let ais = c.browser.ais(
        c.domain,
        &nonce,
        digest,
        Mode::Commit,
        ExerciseBasis::Holding(holding),
    );
    let (r, body) = send(
        &c.management,
        c.browser
            .request(
                &Method::POST,
                "/console/api/proxy/admin/platform/tenants",
                "x",
            )
            .header("x-access-ais", ais)
            .header("idempotency-key", b64url_encode(&nonce))
            .body(Body::from(draft["body"].to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let written: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(written["exercise_id"].is_string());
    assert_eq!(written["resource"]["tenant_id"], draft["body"]["tenant_id"]);
    let (_, body) = send(&c.management, read(&c, "platform/tenants")).await;
    let after = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["items"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(after, before + 1);

    // TN-119, X31
    let (r, _) = send(&c.management, read(&c, "realms/acme")).await;
    assert_ne!(r.status(), StatusCode::OK);
}

/// The account of `identifier` in the realm `route` names, if it has one.
async fn subject_in(
    w: &World,
    route: &access_store::tenancy::RealmRoute,
    identifier: &str,
) -> Option<[u8; 16]> {
    use access_identity_account::adapters::pg::PgAccounts;
    use access_identity_account::ports::{AccountDb as _, AccountTx as _};
    let keks = crate::login::RealmKeks::new(w.keys.clone());
    let accounts = PgAccounts::sealed(w.db.app.clone(), keks.vault(route.realm).unwrap());
    let mut tx = accounts.begin(route.tenant, route.realm).await.unwrap();
    let subject = tx.subject_by_identifier(identifier).await.unwrap();
    tx.commit().await.unwrap();
    subject
}

/// The probe `(namespace, name, resource)` drafted in the console session's realm `realm`.
async fn drafted(
    c: &Console,
    realm: &str,
    (namespace, name, resource): (&str, &str, &str),
) -> Option<serde_json::Value> {
    let ask = serde_json::json!({
        "action": { "namespace": namespace, "name": name, "major": 1 },
        "resources": [{ "namespace": resource, "path": [realm] }],
        "mode": "check",
    })
    .to_string();
    let proof = c.browser.ais(
        c.domain,
        &access_crypto::random::bytes::<16>().unwrap(),
        read_intent(&Method::POST, "/console/api/intents"),
        Mode::Check,
        c.idp_anchor(),
    );
    let (r, body) = send(
        &c.management,
        c.browser
            .request(&Method::POST, "/console/api/intents", "x")
            .header("x-access-ais", proof)
            .body(Body::from(ask))
            .unwrap(),
    )
    .await;
    (r.status() == StatusCode::OK).then(|| serde_json::from_slice(&body).unwrap())
}

/// Whether `party` is eligible for the drafted probe on one of `bases` or, with `root`, on its
/// root basis, as the console asks (IA-5, OP-152 m.7 (b)).
async fn eligible_on(
    c: &Console,
    party: &[u8],
    draft: &serde_json::Value,
    bases: &[serde_json::Value],
    root: bool,
) -> bool {
    let mut set = draft["probe"].clone();
    set["intent"] = draft["intent"].clone();
    let mut sets = Vec::new();
    if root {
        sets.push(set.clone());
    }
    for b in bases {
        let mut on = set.clone();
        on["basis"] = b.clone();
        sets.push(on);
    }
    for set in sets {
        let body = serde_json::json!({ "subject": b64url_encode(party), "set": set });
        let (r, answer) = send(
            &c.management,
            c.browser
                .request(
                    &Method::POST,
                    "/console/api/proxy/adp/eligibility:check",
                    "x",
                )
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(
            r.status(),
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&answer)
        );
        let answer: serde_json::Value = serde_json::from_slice(&answer).unwrap();
        if answer["eligible"] == true {
            return true;
        }
    }
    false
}

// OP-159 m.43 (c), TN-119, INV-29, IA-5, XI-11, TN-114
#[tokio::test]
async fn the_platform_admin_administers_acme_on_acmes_root_grants_alone() {
    let mut plan = admin_plan();
    plan.tenants = vec![String::from("acme"), String::from("globex")];
    if let Some(p) = plan.platform_admin.as_mut() {
        p.realms = vec![String::from("acme")];
    }
    let c = console_as(
        "mgmt-realm-admin",
        true,
        &plan,
        DeclaredTargets::default(),
        ("acme", Some(ADMIN)),
    )
    .await;
    let summary = c.w.run(&plan).await;
    let out = summary.platform_admin.unwrap();
    let [acme] = out.realms.as_slice() else {
        panic!("one realm: {:?}", out.realms);
    };
    assert_eq!(acme.realm, "acme");
    assert!(!acme.created, "the second run makes nothing");
    assert!(!acme.delegated_admin_opened);
    assert_ne!(acme.subject, out.subject);
    assert_ne!(acme.party, out.party);
    let party = b64url_decode(&acme.party).unwrap();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let bound = idp::subject_party(&mut t, &c.subject).await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(bound.map(Vec::from), Some(party.clone()));
    assert!(
        acme.grants
            .iter()
            .flat_map(|g| &g.actions)
            .all(|a| !a.starts_with("idp.platform.")),
        "{:?}",
        acme.grants
    );
    // §13.7.4
    let on_grant = |(namespace, name, resource): (&str, &str, &str)| {
        let label = format!("{namespace}.{name}");
        acme.grants
            .iter()
            .find(|g| g.resource == resource && g.actions.contains(&label))
            .map_or_else(
                || panic!("no Grant names {label} on {resource}"),
                |g| g.basis.clone(),
            )
    };

    // IA-5, XI-11
    let probes = [
        ("access", "authority_set_define", "access.domain"),
        ("access", "grant_issue", "access.domain"),
        ("access", "policy_set", "access.domain"),
        ("access", "acceptance_establish", "access.domain"),
        ("access", "party_depart", "access.domain"),
        ("access", "anchor_amend", "access.domain"),
        ("access", "grant_revoke", "access.domain"),
        ("access", "read", "access.audit"),
        ("idp.account", "suspend", "idp"),
        ("idp.realm", "delegated_admin", "idp"),
        ("idp.realm", "signin_policy", "idp"),
        ("idp.org", "create", "idp"),
        ("idp.agent", "register", "idp"),
        ("idp.review", "schedule", "idp"),
        ("idp.realm", "rate_limit", "idp"),
        ("idp.client", "register", "idp"),
        ("idp.client", "update", "idp"),
    ];
    for (i, probe) in probes.into_iter().enumerate() {
        let draft = drafted(&c, "acme", probe).await.unwrap();
        assert!(
            eligible_on(&c, &party, &draft, &[on_grant(probe)], false).await,
            "{probe:?}"
        );
        if i % 8 == 0 {
            assert!(
                !eligible_on(&c, &party, &draft, &[], true).await,
                "{probe:?}: not root"
            );
            // TN-119, INV-29
            assert!(
                !eligible_on(&c, &party, &draft, std::slice::from_ref(&out.basis), false).await,
                "{probe:?}"
            );
        }
    }
    // INV-29
    let bases: Vec<serde_json::Value> = acme.grants.iter().map(|g| g.basis.clone()).collect();
    if let Some(draft) = drafted(&c, "acme", ("idp.platform", "realm_create", "idp")).await {
        assert!(!eligible_on(&c, &party, &draft, &bases[..1], false).await);
    }

    // TN-119
    let globex = route_by_slug(&c.w.db.router, "globex")
        .await
        .unwrap()
        .unwrap();
    assert!(subject_in(&c.w, &globex, ADMIN).await.is_none());
}
