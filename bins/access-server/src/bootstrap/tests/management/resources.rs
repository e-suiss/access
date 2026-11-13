//! Protected resources through the console's BFF against the real admin surface (AG-8,
//! OP-154 m.3 (a), OP-153 m.3 (gg), Ek B 4187, 4425): a resource is registered by REST as
//! `idp.client.resource_register`, read back, and a second registration or a URI that is not
//! canonical is refused before any decision.

use super::*;

// AG-8, MD-14, OP-154 m.3 (a), Ek B 4187, 4425
#[tokio::test]
async fn a_protected_resource_is_registered_and_listed_by_rest() {
    let c = console("mgmt-resources", true).await;
    let body = serde_json::json!({
        "resource": "https://mcp.example.com/mcp",
        "display_name": "Example MCP server",
    });
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/resources",
            ("registerProtectedResource", None),
            body.clone(),
            None,
        )
        .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let list = c.admin_get("/admin/v1/realms/acme/resources").await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    let item = &list.body["items"][0];
    assert_eq!(item["resource"], "https://mcp.example.com/mcp");
    assert_eq!(item["display_name"], "Example MCP server");

    // AG-8
    let again = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/resources",
            ("registerProtectedResource", None),
            body,
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    // RFC 8707 §2
    for resource in [
        "http://mcp.example.com/mcp",
        "https://MCP.example.com/mcp",
        "https://mcp.example.com/mcp/",
        "https://mcp.example.com/mcp?x=1",
    ] {
        let w = c
            .rest_write(
                &Method::POST,
                "/admin/v1/realms/acme/resources",
                ("registerProtectedResource", None),
                serde_json::json!({ "resource": resource, "display_name": "Bad" }),
                None,
            )
            .await;
        assert_eq!(w.status, StatusCode::BAD_REQUEST, "{resource}: {}", w.body);
        assert_eq!(w.body["code"], "invalid-protected-resource", "{}", w.body);
    }
    c.w.domains.release().await;
}

// CR-41, MD-6, OP-159 m.21 (b), (g)
#[tokio::test]
async fn a_resource_takes_ml_dsa_access_tokens_only_while_the_realm_profile_holds_it() {
    let c = console("mgmt-resources-pq", true).await;
    let register = |resource: &'static str, alg: &'static str| {
        let c = &c;
        async move {
            c.rest_write(
                &Method::POST,
                "/admin/v1/realms/acme/resources",
                ("registerProtectedResource", None),
                serde_json::json!({
                    "resource": resource,
                    "display_name": "Quantum tools",
                    "access_token_signed_response_alg": alg,
                }),
                None,
            )
            .await
        }
    };
    let w = register("https://pq.example.com/api", "ML-DSA-65").await;
    assert_eq!(w.status, StatusCode::CONFLICT, "{}", w.body);
    assert_eq!(w.body["code"], "algorithm-profile-conflict", "{}", w.body);
    let w = register("https://pq.example.com/api", "RS256").await;
    assert_eq!(w.status, StatusCode::BAD_REQUEST, "{}", w.body);
    assert_eq!(w.body["code"], "invalid-protected-resource", "{}", w.body);

    let w = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/settings/signing-profile",
            ("putSigningProfile", None),
            serde_json::json!({"profile": "ml-dsa-65"}),
            None,
        )
        .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let w = register("https://pq.example.com/api", "ML-DSA-87").await;
    assert_eq!(w.status, StatusCode::CONFLICT, "{}", w.body);
    let w = register("https://pq.example.com/api", "ML-DSA-65").await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let list = c.admin_get("/admin/v1/realms/acme/resources").await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    assert_eq!(
        list.body["items"][0]["access_token_signed_response_alg"],
        "ML-DSA-65"
    );
    c.w.domains.release().await;
}
