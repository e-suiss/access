//! Realm settings written through the admin REST surface end to end (OP-153 m.25 (b), m.22 (c),
//! (g), (k), m.3 (gg)): each write is drafted, signed by the browser's Instance, committed by the
//! real decision point and read back from the settings view and the hosted pages.

use super::writes::Written;
use super::*;

impl Console {
    /// A read of `target` (`/admin/v1/realms/acme/…`) through the BFF with a read proof: its
    /// status, body and `ETag`.
    pub(super) async fn rest_read(
        &self,
        target: &str,
    ) -> (StatusCode, serde_json::Value, Option<String>) {
        let proof = self.browser.ais(
            self.domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::GET, target),
            Mode::Check,
            self.idp_anchor(),
        );
        let (r, body) = send(
            &self.management,
            self.browser
                .request(
                    &Method::GET,
                    &target.replacen("/admin/v1/", "/console/api/proxy/admin/", 1),
                    "",
                )
                .header("x-access-ais", proof)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let etag = r
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        (
            r.status(),
            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
            etag,
        )
    }

    /// Drafts `operation` with `body` (and the path's natural `key`) through the BFF, signs its
    /// commit with the browser's Instance and sends it as `method` to `target`.
    pub(super) async fn rest_write(
        &self,
        method: &Method,
        target: &str,
        (operation, key): (&str, Option<&str>),
        body: serde_json::Value,
        if_match: Option<&str>,
    ) -> Written {
        let drafts = "/admin/v1/realms/acme/intents";
        let proof = self.browser.ais(
            self.domain,
            &access_crypto::random::bytes::<16>().unwrap(),
            read_intent(&Method::POST, drafts),
            Mode::Check,
            self.idp_anchor(),
        );
        let ask = serde_json::json!({ "operation": operation, "key": key, "body": body });
        let (r, out) = send(
            &self.management,
            self.browser
                .request(
                    &Method::POST,
                    "/console/api/proxy/admin/realms/acme/intents",
                    "x",
                )
                .header("x-access-ais", proof)
                .body(Body::from(ask.to_string()))
                .unwrap(),
        )
        .await;
        let draft: serde_json::Value = serde_json::from_slice(&out).unwrap_or_default();
        if r.status() != StatusCode::OK {
            return Written {
                status: r.status(),
                body: draft,
            };
        }
        let digest = Digest(
            <[u8; 32]>::try_from(b64url_decode(draft["intent_digest"].as_str().unwrap()).unwrap())
                .unwrap(),
        );
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let ais = self
            .browser
            .ais(self.domain, &nonce, digest, Mode::Commit, self.idp_anchor());
        let mut request = self
            .browser
            .request(
                method,
                &target.replacen("/admin/v1/", "/console/api/proxy/admin/", 1),
                "x",
            )
            .header("x-access-ais", ais)
            .header("idempotency-key", b64url_encode(&nonce));
        if let Some(tag) = if_match {
            request = request.header(header::IF_MATCH, tag);
        }
        let (r, out) = send(
            &self.management,
            request.body(Body::from(draft["body"].to_string())).unwrap(),
        )
        .await;
        Written {
            status: r.status(),
            body: serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null),
        }
    }

    /// Writes a settings section with `PUT` under the settings view's current `ETag`.
    pub(super) async fn put_setting(
        &self,
        section: &str,
        operation: &str,
        body: serde_json::Value,
    ) -> Written {
        let (_, _, etag) = self.rest_read("/admin/v1/realms/acme/settings").await;
        self.rest_write(
            &Method::PUT,
            &format!("/admin/v1/realms/acme/settings/{section}"),
            (operation, None),
            body,
            etag.as_deref(),
        )
        .await
    }
}

// OP-153 m.22 (g), m.25 (b), TN-106, Ek B 3668
#[tokio::test]
async fn the_csp_mode_moves_through_admin_rest_and_the_page_policy_follows_it() {
    let c = console("rest-csp", false).await;
    let report_only = || async {
        let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
            .await
            .unwrap();
        let stored = idp::branding(&mut t).await.unwrap();
        t.commit().await.unwrap();
        let theme = access_identity_ui::domain::branding::Theme::decode(stored.as_deref());
        theme.csp("/realms/acme").1.is_some()
    };
    assert!(!report_only().await);

    let loose = c
        .put_setting(
            "csp-mode",
            "putCspMode",
            serde_json::json!({ "csp_mode": "report_only" }),
        )
        .await;
    assert_eq!(loose.status, StatusCode::OK, "{}", loose.body);
    assert_eq!(loose.body["resource"]["csp_mode"], "report_only");
    assert!(report_only().await);

    let tight = c
        .put_setting(
            "csp-mode",
            "putCspMode",
            serde_json::json!({ "csp_mode": "enforce" }),
        )
        .await;
    assert_eq!(tight.status, StatusCode::OK, "{}", tight.body);
    assert_eq!(tight.body["resource"]["csp_mode"], "enforce");
    assert!(!report_only().await);

    let bad = c
        .put_setting(
            "csp-mode",
            "putCspMode",
            serde_json::json!({ "csp_mode": "off" }),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST, "{}", bad.body);
}

// X35, XI-25, OP-153 m.22 (k), m.25 (b), TN-18
#[tokio::test]
async fn related_origins_and_message_overrides_are_set_by_rest_and_the_pages_read_them() {
    let c = console("rest-texts", false).await;
    let app = super::super::recovery::hosted(&c, super::super::recovery::Recording::default());
    let set = c
        .put_setting(
            "locale-overrides",
            "putLocaleOverrides",
            serde_json::json!({ "overrides": { "tr": {
                "login-unavailable": "Giriş şu an kapalı; birazdan yeniden deneyin."
            } } }),
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{}", set.body);
    assert_eq!(
        set.body["resource"]["locale_overrides"]["tr"]["login-unavailable"],
        "Giriş şu an kapalı; birazdan yeniden deneyin."
    );
    let protected = c
        .put_setting(
            "locale-overrides",
            "putLocaleOverrides",
            serde_json::json!({ "overrides": { "en": { "login-failed": "Hep evet" } } }),
        )
        .await;
    assert_eq!(protected.status, StatusCode::BAD_REQUEST);
    assert_eq!(protected.body["code"], "invalid-locale-overrides");
    let (r, body) = send(
        &app,
        axum::http::Request::get("/realms/acme/v1/login/messages")
            .header(header::HOST, "access.test")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let read: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        read["overrides"],
        serde_json::json!({ "tr": {
            "login-unavailable": "Giriş şu an kapalı; birazdan yeniden deneyin."
        } })
    );

    // TN-18, OP-153 m.22 (j)
    let refused = c
        .put_setting(
            "related-origins",
            "putRelatedOrigins",
            serde_json::json!({ "origins": ["https://shop.acme-brand.example"] }),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert_eq!(refused.body["code"], "invalid-related-origins");
    let none = c
        .put_setting(
            "related-origins",
            "putRelatedOrigins",
            serde_json::json!({ "origins": [] }),
        )
        .await;
    assert_eq!(none.status, StatusCode::OK, "{}", none.body);
    assert_eq!(
        none.body["resource"]["related_origins"],
        serde_json::json!([])
    );
}

// TN-33, OP-153 m.22 (c), m.25 (b), Ek B 4103
#[tokio::test]
async fn a_realm_without_dbsc_offers_no_registration_and_with_it_does() {
    use super::super::recovery::{Page, Recording, account, hosted};
    let c = console("rest-dbsc", false).await;
    let app = hosted(&c, Recording::default());
    account(&c, "dee@example.com", true).await;
    let sign_in = |app: axum::Router| async move {
        let mut p = Page::default();
        let flow = p.call(&app, &Method::POST, "/v1/login/flows", None).await;
        let action = |g: &super::super::recovery::Got| {
            let a = g.json["action"].as_str().unwrap();
            a.strip_prefix("/realms/acme").unwrap_or(a).to_owned()
        };
        let id = p
            .call(
                &app,
                &Method::POST,
                &action(&flow),
                Some(serde_json::json!({"method": "identifier",
                    "fields": {"identifier": "dee@example.com"}})),
            )
            .await;
        p.call(
            &app,
            &Method::POST,
            &action(&id),
            Some(serde_json::json!({"method": "password",
                "fields": {"password": super::super::recovery::PW}})),
        )
        .await
    };
    let on = sign_in(app.clone()).await;
    assert_eq!(on.status, StatusCode::OK, "{}", on.json);
    assert!(
        on.headers.contains_key("secure-session-registration"),
        "a realm offers DBSC by default"
    );

    let (_, settings, _) = c.rest_read("/admin/v1/realms/acme/settings").await;
    let mut policy = settings["signin_policy"].clone();
    policy["dbsc"] = serde_json::Value::Bool(false);
    let off = c
        .put_setting("signin-policy", "putSigninPolicy", policy)
        .await;
    assert_eq!(off.status, StatusCode::OK, "{}", off.body);
    assert_eq!(off.body["resource"]["signin_policy"]["dbsc"], false);
    let without = sign_in(app.clone()).await;
    assert_eq!(without.status, StatusCode::OK, "{}", without.json);
    assert!(!without.headers.contains_key("secure-session-registration"));

    let (_, settings, _) = c.rest_read("/admin/v1/realms/acme/settings").await;
    let mut policy = settings["signin_policy"].clone();
    policy["dbsc"] = serde_json::Value::Bool(true);
    let back = c
        .put_setting("signin-policy", "putSigninPolicy", policy)
        .await;
    assert_eq!(back.status, StatusCode::OK, "{}", back.body);
    let with = sign_in(app).await;
    assert!(with.headers.contains_key("secure-session-registration"));
}
