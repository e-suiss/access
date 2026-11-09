//! Cross-app connections through the console's BFF against the real admin surface (AG-28,
//! OP-154 m.3 (a), (n), OP-153 m.3 (gg), Ek B 4191): a connection is recorded by REST as
//! `idp.client.cross_app_connection` for a registered client, a second live one by the same
//! name or one out of shape is refused, and retiring it is `cross_app_connection_retire` and
//! keeps both rows (OP-73).

use super::*;

// AG-28, MD-14, OP-73, OP-154 m.3 (n), Ek B 4191
#[tokio::test]
async fn a_cross_app_connection_is_recorded_and_retired_by_rest() {
    let c = console("mgmt-cross-app", true).await;
    let clients = c.admin_get("/admin/v1/realms/acme/clients").await;
    assert_eq!(clients.status, StatusCode::OK, "{}", clients.body);
    let client = clients.body["items"][0]["client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let create = |body: serde_json::Value| {
        let c = &c;
        async move {
            c.rest_write(
                &Method::POST,
                "/admin/v1/realms/acme/cross-app-connections",
                ("createCrossAppConnection", None),
                body,
                None,
            )
            .await
        }
    };
    let body = serde_json::json!({
        "connection": "crm",
        "client_id": client,
        "audience": "https://as.crm.example",
        "resource": "https://api.crm.example/mcp",
        "scopes": ["contacts.read"],
    });
    let w = create(body.clone()).await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let again = create(body.clone()).await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    // OP-154 m.3 (n)
    for (member, value) in [
        ("audience", serde_json::json!("http://as.crm.example")),
        (
            "resource",
            serde_json::json!("https://api.crm.example/mcp/"),
        ),
        ("connection", serde_json::json!("Not A Slug")),
        ("subject_policy", serde_json::json!("public")),
        ("scopes", serde_json::json!(["two words"])),
    ] {
        let mut bad = body.clone();
        bad["connection"] = serde_json::json!("other");
        bad[member] = value;
        let w = create(bad).await;
        assert_eq!(w.status, StatusCode::BAD_REQUEST, "{member}: {}", w.body);
        assert_eq!(w.body["code"], "invalid-cross-app-connection", "{}", w.body);
    }
    let mut stranger = body.clone();
    stranger["connection"] = serde_json::json!("stranger");
    stranger["client_id"] = serde_json::json!("no-such-client");
    let w = create(stranger).await;
    assert_eq!(w.status, StatusCode::NOT_FOUND, "{}", w.body);

    let retire = || {
        let c = &c;
        async move {
            c.rest_write(
                &Method::POST,
                "/admin/v1/realms/acme/cross-app-connections/crm/retire",
                ("retireCrossAppConnection", Some("crm")),
                serde_json::json!({}),
                None,
            )
            .await
        }
    };
    let w = retire().await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let w = retire().await;
    assert_eq!(w.status, StatusCode::NOT_FOUND, "{}", w.body);

    // OP-73
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let row = t.cross_app_connection("crm").await.unwrap().unwrap();
    assert_eq!((row.version, row.state.as_str()), (2, "retired"));
    assert!(
        !t.cross_app_connected(
            &client,
            "https://as.crm.example",
            "https://api.crm.example/mcp"
        )
        .await
        .unwrap()
    );
    t.commit().await.unwrap();
    let w = create(body).await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    assert!(
        t.cross_app_connected(
            &client,
            "https://as.crm.example",
            "https://api.crm.example/mcp"
        )
        .await
        .unwrap()
    );
    t.commit().await.unwrap();
    c.w.domains.release().await;
}
