//! The account actions of catalog 3 through the admin REST surface end to end (OP-153 m.25 (b),
//! m.3 (gg)): drafted, signed by the browser's Instance, decided by the real decision point and
//! written by the identity plane.

use super::*;

/// An import file's body members: its content, SHA-256 and line count (TN-85).
fn import_body(content: &str) -> serde_json::Value {
    let (file, accounts) = access_identity_account::app::import::file_of(content);
    serde_json::json!({
        "file": b64url_encode(&file),
        "accounts": accounts,
        "content": content,
    })
}

// TN-85, OP-153 m.19 (d), m.25 (b)
#[tokio::test]
async fn an_import_file_named_by_its_digest_imports_through_admin_rest() {
    let c = console("rest-import", false).await;
    let content = [
        r#"{"email":"imp.one@example.com","legacy_idp_reference":"u-1"}"#,
        "",
        r#"{"email":"imp.two@example.com","username":"imp_two","legacy_idp_reference":"u-2"}"#,
        r#"{"email":"imp.one@example.com","legacy_idp_reference":"u-3"}"#,
        "not json",
    ]
    .join("\n");
    let target = "/admin/v1/realms/acme/accounts/import";
    let mut wrong = import_body(&content);
    wrong["accounts"] = serde_json::json!(5);
    let refused = c
        .rest_write(&Method::POST, target, ("importAccounts", None), wrong, None)
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);

    let (_, before, _) = c.rest_read("/admin/v1/realms/acme/accounts").await;
    let done = c
        .rest_write(
            &Method::POST,
            target,
            ("importAccounts", None),
            import_body(&content),
            None,
        )
        .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.body);
    assert!(done.body["exercise_id"].is_string());
    let report = &done.body["resource"];
    assert_eq!(report["created"], 2, "{report}");
    assert_eq!(report["legacy"], 2);
    assert_eq!(
        report["skipped"],
        serde_json::json!([[4, "identifier already taken"], [5, "not an import line"]])
    );
    assert!(!done.body.to_string().contains("u-1"), "no line is echoed");
    let (_, after, _) = c.rest_read("/admin/v1/realms/acme/accounts").await;
    assert_eq!(
        after["items"].as_array().unwrap().len(),
        before["items"].as_array().unwrap().len() + 2
    );
}
