//! The console's Platform section against the real BFF, admin surface, sequencer and store
//! (OP-159 m.41, m.47 (d), TN-119, INV-29, IA-5): the bootstrapped platform administrator signs in
//! to the platform environment, its `idp.platform.*` probes are eligible on the administrator rule
//! alone, its session reads the platform surface with a `platform.read` token, and a tenant creation
//! is drafted, signed on that rule and committed as one Exercise.

use crate::bootstrap::platform_admin::PlatformAdminPlan;

use super::*;

const ADMIN: &str = "admin@platform.local";

fn admin_plan() -> Plan {
    Plan {
        platform_admin: Some(PlatformAdminPlan {
            identifier: String::from(ADMIN),
            password: Secret::new(String::from("platform horse battery staple")),
            totp: None,
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
    let party = b64url_decode(&out.party).unwrap();
    // OP-159 m.47 (f)
    administer(&c.w).await;
    let basis = rule_basis(
        &c.w,
        "platform",
        Id(<[u8; 16]>::try_from(party.as_slice()).unwrap()),
        ("idp.platform", "tenant_create"),
    )
    .await;
    let holding = holding_of(&basis);

    // IA-5, XI-11
    for name in ["tenant_create", "tenant_suspend", "tenant_reactivate"] {
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
        on_grant["basis"] = basis.clone();
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
        "platform/envs/acme",
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
                serde_json::json!({ "operation": "createTenant", "body": {
                    "display_name": "Globex",
                    "management_slug": "globex-admin",
                    "founder_email": "admin@globex.example",
                } })
                .to_string(),
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
    let (r, _) = send(&c.management, read(&c, "envs/acme")).await;
    assert_ne!(r.status(), StatusCode::OK);
}
