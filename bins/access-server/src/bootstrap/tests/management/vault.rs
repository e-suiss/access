//! Vault Resources through the console's BFF against the real admin surface (OP-154 m.3 (a),
//! (t), OP-153 m.3 (gg), Ek B 4413, 4487): a catalog upstream is enabled by REST as
//! `idp.vault.resource_enable`, read back with its secret reference only, disabled, and the
//! release mode is opened; a malformed Resource is refused before any decision.

use super::*;

fn resource() -> serde_json::Value {
    serde_json::json!({
        "upstream": "github",
        "client_id": "Iv1.vault-test",
        "client_secret_ref": "secret://vault/github",
        "scopes": ["repo"],
        "actions": [{
            "namespace": "work",
            "name": "open_issue",
            "major": 1,
            "schema": b64url_encode(&[7; 32]),
            "scopes": ["repo"],
        }],
        "executors": [b64url_encode(&[9; 32])],
    })
}

// AG-39, E36, MD-14, OP-154 m.3 (t), Ek B 4413, 4487
#[tokio::test]
async fn a_catalog_upstream_is_enabled_read_and_disabled_by_rest() {
    let c = console("mgmt-vault", true).await;
    let w = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/vault/resources/github",
            ("putVaultResource", Some("github")),
            resource(),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    let list = c.admin_get("/admin/v1/realms/acme/vault/resources").await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    let item = &list.body["items"][0];
    assert_eq!(item["resource"], "github");
    assert_eq!(item["origin"], "catalog");
    assert_eq!(item["status"], "enabled");
    assert_eq!(item["client_secret_ref"], "secret://vault/github");
    assert_eq!(item["release_mode"], "closed");
    assert!(item.get("client_secret").is_none());

    // AG-39
    let mut bad = resource();
    bad["upstream"] = serde_json::json!("nowhere");
    let w = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/vault/resources/nowhere",
            ("putVaultResource", Some("nowhere")),
            bad,
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::BAD_REQUEST, "{}", w.body);
    assert_eq!(w.body["code"], "invalid-vault-resource", "{}", w.body);

    let w = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/settings/vault-release-mode",
            ("putVaultReleaseMode", None),
            serde_json::json!({ "mode": "open" }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/vault/resources/github/disable",
            ("disableVaultResource", Some("github")),
            serde_json::json!({}),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    let list = c.admin_get("/admin/v1/realms/acme/vault/resources").await;
    assert_eq!(list.body["items"][0]["status"], "disabled", "{}", list.body);
    assert_eq!(list.body["items"][0]["release_mode"], "open");
    c.w.domains.release().await;
}
