//! The SCIM server on the real server path (OP-155 m.3 (g), OP-153 m.3 (gg), IDP-23): a client
//! registered by REST through `idp.scim.client_register` provisions Users and Groups of its
//! realm over the real router on real Postgres, the account use cases and the PII vault.

use access_identity_scim::domain::patch::PATCH_SCHEMA;
use access_identity_scim::domain::schema::{GROUP, USER};

use super::*;

const BASE: &str = "/realms/acme/scim/v2";

struct Scim {
    router: axum::Router,
}

fn scim_router(c: &Console) -> Scim {
    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    Scim {
        router: crate::scim::routes(
            c.w.db.router.clone(),
            c.w.db.app.clone(),
            crate::login::RealmKeks::new(c.w.keys.clone()),
            ids,
        )
        .unwrap(),
    }
}

impl Scim {
    async fn call(
        &self,
        method: Method,
        path: &str,
        secret: &str,
        body: Option<serde_json::Value>,
        extra: &[(&str, &str)],
    ) -> (StatusCode, HeaderMapLite, serde_json::Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("{BASE}{path}"))
            .header(header::HOST, HOST)
            .header(header::AUTHORIZATION, format!("Bearer {secret}"));
        let has_type = extra
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
        if body.is_some() && !has_type {
            b = b.header(header::CONTENT_TYPE, "application/scim+json");
        }
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        let req = b
            .body(body.map_or_else(Body::empty, |v| Body::from(v.to_string())))
            .unwrap();
        let (r, out) = send(&self.router, req).await;
        let headers = HeaderMapLite {
            etag: r
                .headers()
                .get(header::ETAG)
                .map(|v| v.to_str().unwrap().to_owned()),
            txn: r
                .headers()
                .get("set-txn")
                .map(|v| v.to_str().unwrap().to_owned()),
        };
        (
            r.status(),
            headers,
            serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null),
        )
    }
}

struct HeaderMapLite {
    etag: Option<String>,
    txn: Option<String>,
}

async fn register(c: &Console, name: &str, profile: Option<&str>) -> String {
    let mut body = serde_json::json!({ "name": name });
    if let Some(p) = profile {
        body["profile"] = serde_json::Value::from(p);
    }
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/scim-clients",
            ("registerScimClient", None),
            body,
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    w.body["client_secret"].as_str().unwrap().to_owned()
}

fn user(name: &str, external: &str) -> serde_json::Value {
    serde_json::json!({
        "schemas": [USER],
        "userName": name,
        "externalId": external,
        "name": { "givenName": "Ada", "familyName": "Lovelace" },
        "emails": [{ "value": name, "type": "work", "primary": true }],
        "active": true,
    })
}

async fn subject_of(c: &Console, client: &str, id: &str) -> [u8; 16] {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let id = access_identity_scim::app::parse_id(id).unwrap();
    let row = access_store::scim::resource(&mut t, client, "user", id, false)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    row.subject.unwrap()
}

async fn status_of(c: &Console, subject: [u8; 16]) -> (String, i64) {
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let row = t.subject(subject, false).await.unwrap().unwrap();
    t.commit().await.unwrap();
    (row.status, row.session_epoch)
}

// IDP-23, INV-32, TN-75, TN-76, OP-73, OP-155 m.3 (g), (gg), Ek B 4807, 4813, 4814, 4860, 5101
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one client's provisioning, deprovisioning and re-provisioning, read in order"
)]
async fn a_scim_client_provisions_deprovisions_and_never_reuses_an_id() {
    let c = console("scim-users", true).await;
    let s = scim_router(&c);
    let secret = register(&c, "entra", Some("scim.entra")).await;

    let (st, _, spc) = s
        .call(Method::GET, "/ServiceProviderConfig", &secret, None, &[])
        .await;
    assert_eq!(st, StatusCode::OK, "{spc}");
    assert_eq!(spc["bulk"]["supported"], false);
    assert_eq!(spc["patch"]["supported"], true);
    assert_eq!(spc["filter"]["supported"], true);
    assert_eq!(spc["filter"]["maxResults"], 1000);
    assert_eq!(spc["etag"]["supported"], true);
    assert_eq!(spc["sort"]["supported"], false);
    let (st, _, types) = s
        .call(Method::GET, "/ResourceTypes", &secret, None, &[])
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(types["totalResults"], 3);
    let (st, _, schemas) = s.call(Method::GET, "/Schemas", &secret, None, &[]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(schemas["Resources"].as_array().unwrap().len() >= 4);
    // IDP-23, Ek B 4928, 5037
    let (st, _, _) = s
        .call(
            Method::POST,
            "/Bulk",
            &secret,
            Some(serde_json::json!({})),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
    let (st, _, _) = s.call(Method::GET, "/Me", &secret, None, &[]).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = s
        .call(Method::GET, "/Users", "not-a-registered-secret", None, &[])
        .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let (st, h, created) = s
        .call(
            Method::POST,
            "/Users",
            &secret,
            Some(user("ada@contoso.example", "e-1")),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    assert!(h.txn.is_some());
    let first = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["meta"]["resourceType"], "User");
    assert!(created.get("password").is_none());
    let subject = subject_of(&c, "entra", &first).await;
    assert_eq!(status_of(&c, subject).await.0, "active");

    // IDP-23, Ek B 4814
    let (st, _, dup) = s
        .call(
            Method::POST,
            "/Users",
            &secret,
            Some(user("ADA@contoso.example", "e-2")),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::CONFLICT, "{dup}");
    assert_eq!(dup["scimType"], "uniqueness");
    let (st, _, stale) = s
        .call(
            Method::PUT,
            &format!("/Users/{first}"),
            &secret,
            Some(user("ada@contoso.example", "e-1")),
            &[("if-match", "W/\"99\"")],
        )
        .await;
    assert_eq!(st, StatusCode::PRECONDITION_FAILED, "{stale}");

    // TN-75, Ek B 4860
    let before = status_of(&c, subject).await.1;
    let entra_disable = serde_json::json!({ "schemas": [PATCH_SCHEMA], "Operations": [
        { "op": "Replace", "path": "active", "value": "False" },
    ]});
    let (st, _, patched) = s
        .call(
            Method::PATCH,
            &format!("/Users/{first}"),
            &secret,
            Some(entra_disable),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{patched}");
    assert_eq!(patched["active"], false);
    let (status, epoch) = status_of(&c, subject).await;
    assert_eq!(status, "deactivated");
    assert!(epoch > before);

    // INV-32, TN-76, Ek B 5101
    let (st, _, _) = s
        .call(
            Method::DELETE,
            &format!("/Users/{first}"),
            &secret,
            None,
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    let (st, _, gone) = s
        .call(Method::GET, &format!("/Users/{first}"), &secret, None, &[])
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND, "{gone}");
    let (st, _, again) = s
        .call(
            Method::POST,
            "/Users",
            &secret,
            Some(user("ada@contoso.example", "e-1")),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{again}");
    let second = again["id"].as_str().unwrap();
    assert_ne!(second, first);
    let (st, _, _) = s
        .call(Method::GET, &format!("/Users/{first}"), &secret, None, &[])
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = s
        .call(Method::GET, &format!("/Users/{second}"), &secret, None, &[])
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_ne!(subject_of(&c, "entra", second).await, subject);

    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/scim-clients/entra/secret/rotate",
            ("rotateScimSecret", Some("entra")),
            serde_json::json!({}),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    let rotated = w.body["client_secret"].as_str().unwrap().to_owned();
    let (st, _, _) = s.call(Method::GET, "/Users", &secret, None, &[]).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _, _) = s.call(Method::GET, "/Users", &rotated, None, &[]).await;
    assert_eq!(st, StatusCode::OK);
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/scim-clients/entra/retire",
            ("retireScimClient", Some("entra")),
            serde_json::json!({}),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    let (st, _, _) = s.call(Method::GET, "/Users", &rotated, None, &[]).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

// IDP-23, CR-10, CR-40, OP-155 m.3 (g), Ek B 4808, 4809, 4810, 4811, 4812, 4815
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "filters, both paging methods and an atomic PATCH over one client's users"
)]
async fn filters_pages_and_patches_hold_their_limits() {
    let c = console("scim-limits", true).await;
    let s = scim_router(&c);
    let secret = register(&c, "hr", None).await;
    let mut ids = Vec::new();
    for i in 0..3 {
        let (st, _, u) = s
            .call(
                Method::POST,
                "/Users",
                &secret,
                Some(user(&format!("u{i}@hr.example"), &format!("x-{i}"))),
                &[],
            )
            .await;
        assert_eq!(st, StatusCode::CREATED, "{u}");
        ids.push(u["id"].as_str().unwrap().to_owned());
    }

    // IDP-23, Ek B 4810
    let deep = format!("{}userName pr{}", "(".repeat(33), ")".repeat(33));
    for f in [deep.as_str(), "password pr", "title co \"x\""] {
        let q = format!("/Users?filter={}", form_encode(f));
        let (st, _, e) = s.call(Method::GET, &q, &secret, None, &[]).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{f}: {e}");
        assert_eq!(e["scimType"], "invalidFilter", "{f}");
    }
    let q = format!(
        "/Users?filter={}",
        form_encode("userName eq \"U1@hr.example\"")
    );
    let (st, _, found) = s.call(Method::GET, &q, &secret, None, &[]).await;
    assert_eq!(st, StatusCode::OK, "{found}");
    assert_eq!(found["totalResults"], 1);
    assert_eq!(found["Resources"][0]["id"], ids[1]);
    let q = format!("/Users?filter={}", form_encode("externalId eq \"x-2\""));
    let (_, _, found) = s.call(Method::GET, &q, &secret, None, &[]).await;
    assert_eq!(found["Resources"][0]["id"], ids[2]);

    // IDP-23, Ek B 4811
    let (st, _, page) = s
        .call(
            Method::GET,
            "/Users?startIndex=2&count=1",
            &secret,
            None,
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(page["totalResults"], 3);
    assert_eq!(page["startIndex"], 2);
    assert_eq!(page["itemsPerPage"], 1);
    // IDP-23, Ek B 4812
    let (st, _, p1) = s
        .call(Method::GET, "/Users?cursor=&count=2", &secret, None, &[])
        .await;
    assert_eq!(st, StatusCode::OK, "{p1}");
    assert_eq!(p1["Resources"].as_array().unwrap().len(), 2);
    let next = p1["nextCursor"].as_str().unwrap().to_owned();
    let (_, _, p2) = s
        .call(
            Method::GET,
            &format!("/Users?cursor={next}&count=2"),
            &secret,
            None,
            &[],
        )
        .await;
    assert_eq!(p2["Resources"].as_array().unwrap().len(), 1);
    assert!(p2.get("nextCursor").is_none());
    let mut bad = next.clone();
    bad.replace_range(..1, if next.starts_with('A') { "B" } else { "A" });
    let (st, _, e) = s
        .call(
            Method::GET,
            &format!("/Users?cursor={bad}&count=2"),
            &secret,
            None,
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(e["scimType"], "invalidCursor");
    let (st, _, _) = s
        .call(Method::GET, "/Users?count=500", &secret, None, &[])
        .await;
    assert_eq!(st, StatusCode::OK);

    // IDP-23, Ek B 4815
    let (_, _, one) = s
        .call(
            Method::GET,
            &format!("/Users/{}?attributes=name.givenName", ids[0]),
            &secret,
            None,
            &[],
        )
        .await;
    assert_eq!(one["id"], ids[0]);
    assert!(one.get("userName").is_none());
    assert_eq!(one["name"], serde_json::json!({ "givenName": "Ada" }));

    // IDP-23, Ek B 4808
    let (_, h0, _) = s
        .call(
            Method::GET,
            &format!("/Users/{}", ids[0]),
            &secret,
            None,
            &[],
        )
        .await;
    let bad_patch = serde_json::json!({ "schemas": [PATCH_SCHEMA], "Operations": [
        { "op": "replace", "path": "title", "value": "Changed" },
        { "op": "replace", "path": "id", "value": "mine" },
    ]});
    let (st, _, e) = s
        .call(
            Method::PATCH,
            &format!("/Users/{}", ids[0]),
            &secret,
            Some(bad_patch),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(e["scimType"], "mutability");
    let (_, h1, after) = s
        .call(
            Method::GET,
            &format!("/Users/{}", ids[0]),
            &secret,
            None,
            &[],
        )
        .await;
    assert!(after.get("title").is_none());
    assert_eq!(h0.etag, h1.etag);
    let noop = serde_json::json!({ "schemas": [PATCH_SCHEMA], "Operations": [
        { "op": "add", "path": "active", "value": true },
    ]});
    let (st, h2, same) = s
        .call(
            Method::PATCH,
            &format!("/Users/{}", ids[0]),
            &secret,
            Some(noop),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h2.etag, h0.etag);
    assert_eq!(same["meta"]["lastModified"], after["meta"]["lastModified"]);
}

fn members(q: &[access_store::identity::OutboxEvent]) -> usize {
    q.iter().filter(|e| e.kind == "scim_claim.member").count()
}

/// The identity outbox once `ready` holds; the watermark is cluster-wide, so another test's open
/// transaction delays an entry, never loses it.
async fn outbox_until(
    c: &Console,
    ready: impl Fn(&[access_store::identity::OutboxEvent]) -> bool,
) -> Vec<access_store::identity::OutboxEvent> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let queued = access_store::identity::poll(
            &c.w.db.reader,
            access_store::identity::Cursor::default(),
            1000,
        )
        .await
        .unwrap();
        if ready(&queued) {
            return queued;
        }
        assert!(std::time::Instant::now() < deadline, "outbox");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// IDP-23, IDP-35, §10.6.2, §10.1.2 k.1, INV-16, Ek B 4818, 4821, 4925, 4926, 5059
#[tokio::test]
async fn a_group_has_one_membership_issuer_and_its_members_become_member_claims() {
    let c = console("scim-groups", true).await;
    let s = scim_router(&c);
    let entra = register(&c, "entra", Some("scim.entra")).await;
    let okta = register(&c, "okta", Some("scim.okta")).await;
    let mut grace = user("grace@contoso.example", "g-1");
    grace["schemas"] = serde_json::json!([USER, access_identity_scim::domain::schema::ENTERPRISE]);
    grace[access_identity_scim::domain::schema::ENTERPRISE] =
        serde_json::json!({ "department": "Research" });
    let (_, _, u) = s
        .call(Method::POST, "/Users", &entra, Some(grace), &[])
        .await;
    let member = u["id"].as_str().unwrap().to_owned();
    let (st, _, g) = s
        .call(
            Method::POST,
            "/Groups",
            &entra,
            Some(serde_json::json!({
                "schemas": [GROUP], "displayName": "Engineering",
                "members": [{ "value": member }],
            })),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{g}");
    let group = g["id"].as_str().unwrap().to_owned();

    // IDP-23, Ek B 4818
    let (st, _, device) = s
        .call(
            Method::POST,
            "/Devices",
            &entra,
            Some(serde_json::json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Device"],
                "displayName": "Lab sensor 7", "active": true,
            })),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{device}");
    assert_eq!(device["meta"]["resourceType"], "Device");
    let (st, _, _) = s
        .call(
            Method::GET,
            &format!("/Devices/{}", device["id"].as_str().unwrap()),
            &entra,
            None,
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::OK);

    // §10.6.2
    let add = serde_json::json!({ "schemas": [PATCH_SCHEMA], "Operations": [
        { "op": "add", "path": "members", "value": [{ "value": member }] },
    ]});
    let (st, _, _) = s
        .call(
            Method::PATCH,
            &format!("/Groups/{group}"),
            &okta,
            Some(add),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    let (st, _, _) = s
        .call(Method::GET, &format!("/Groups/{group}"), &okta, None, &[])
        .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let queued = outbox_until(&c, |q| members(q) >= 1).await;
    let orders: Vec<_> = queued
        .iter()
        .filter(|e| e.kind == "scim_claim.member")
        .collect();
    assert_eq!(orders.len(), 1);
    assert!(!queued.iter().any(|e| e.kind.contains("grant")));
    // IDP-35, Ek B 4925
    assert!(queued.iter().any(|e| e.kind == "scim_claim.hr_department"));
    let (st, _, user_view) = s
        .call(Method::GET, &format!("/Users/{member}"), &entra, None, &[])
        .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(user_view["groups"][0]["value"], group);

    let remove = serde_json::json!({ "schemas": [PATCH_SCHEMA], "Operations": [
        { "op": "Remove", "path": "members", "value": [{ "value": member }] },
    ]});
    let (st, _, after) = s
        .call(
            Method::PATCH,
            &format!("/Groups/{group}"),
            &entra,
            Some(remove),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::OK, "{after}");
    assert!(after.get("members").is_none());
    let queued = outbox_until(&c, |q| members(q) >= 2).await;
    assert_eq!(members(&queued), 2);
}

#[tokio::test]
async fn okta_requests_pass_through_their_profile_and_the_strict_server_refuses_them() {
    let c = console("scim-okta", true).await;
    let s = scim_router(&c);
    let okta = register(&c, "okta", Some("scim.okta")).await;
    let strict = register(&c, "plain", None).await;
    let okta_create = serde_json::json!({
        "schemas": [USER], "userName": "linus@okta.example",
        "name": { "givenName": "Linus", "familyName": "T" },
        "emails": [{ "primary": true, "value": "linus@okta.example", "type": "work" }],
        "displayName": "Linus T", "locale": "en-US", "externalId": "00u1abcd",
        "groups": [], "active": true, "favoriteEditor": "vim",
    });
    let json = [("content-type", "application/json")];
    let (st, _, e) = s
        .call(
            Method::POST,
            "/Users",
            &strict,
            Some(okta_create.clone()),
            &json,
        )
        .await;
    assert_eq!(st, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{e}");
    let (st, _, e) = s
        .call(
            Method::POST,
            "/Users",
            &strict,
            Some(okta_create.clone()),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{e}");
    assert_eq!(e["scimType"], "invalidSyntax");
    let (st, head, created) = s
        .call(Method::POST, "/Users", &okta, Some(okta_create), &json)
        .await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    assert!(created.get("favoriteEditor").is_none());
    assert!(head.etag.is_none());
}

fn form_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// One push as sent: method, URL, secret and body.
type Sent = (String, String, Vec<u8>, Option<Vec<u8>>);

struct Recorder {
    calls: std::sync::Mutex<Vec<Sent>>,
    replies: std::sync::Mutex<Vec<access_identity_scim::app::outbound::Reply>>,
}

impl access_identity_scim::app::outbound::Sender for Recorder {
    fn send<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        secret: &'a [u8],
        body: Option<&'a [u8]>,
    ) -> access_identity_scim::app::outbound::Pending<
        'a,
        Option<access_identity_scim::app::outbound::Reply>,
    > {
        self.calls.lock().unwrap().push((
            method.to_owned(),
            url.to_owned(),
            secret.to_vec(),
            body.map(<[u8]>::to_vec),
        ));
        let reply = self.replies.lock().unwrap().pop();
        Box::pin(async move { reply })
    }
}

/// Steps `worker` until it pushed one order; the outbox watermark is cluster-wide, so another
/// test's open transaction delays an order, never loses it.
async fn drain<S, K, L>(worker: &access_identity_scim::app::outbound::Worker<S, K, L>)
where
    S: access_identity_scim::app::outbound::Sender,
    K: access_identity_scim::app::outbound::Secrets,
    L: access_identity_scim::app::outbound::Local,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while worker.step().await.unwrap() == 0 {
        assert!(std::time::Instant::now() < deadline, "no push");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// IDP-29, OP-155 m.3 (g), Ek B 4823, 5036
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one target from its registration through a push, a retry and a delete"
)]
async fn provisioned_users_are_pushed_to_a_registered_target_and_logged() {
    use access_identity_scim::app::outbound::{Reply, Worker};
    let c = console("scim-outbound", true).await;
    let s = scim_router(&c);
    let secret = register(&c, "entra", Some("scim.entra")).await;
    let bearer = b64url_encode(&access_crypto::random::bytes::<24>().unwrap());
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/scim-targets",
            ("registerScimTarget", None),
            serde_json::json!({
                "name": "crm",
                "base_url": "https://crm.example/scim/v2",
                "bearer": bearer,
            }),
            None,
        )
        .await;
    assert_eq!(w.status, StatusCode::OK, "{}", w.body);
    assert!(!w.body.to_string().contains(&bearer));
    let (st, _, created) = s
        .call(
            Method::POST,
            "/Users",
            &secret,
            Some(user("joan@contoso.example", "j-1")),
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::CREATED, "{created}");
    let local = created["id"].as_str().unwrap().to_owned();

    let ids = crate::ids::CellIds::new(c.w.keys.clone()).key().unwrap();
    let keks = crate::login::RealmKeks::new(c.w.keys.clone());
    let recorder = Recorder {
        calls: std::sync::Mutex::new(Vec::new()),
        replies: std::sync::Mutex::new(vec![Reply {
            status: 201,
            body: br#"{"id":"remote-1"}"#.to_vec(),
        }]),
    };
    let worker = Worker {
        app: c.w.db.app.clone(),
        reader: c.w.db.reader.clone(),
        sender: recorder,
        secrets: crate::scim::TargetSecrets(access_identity_events::adapters::KekSealer(
            keks.clone(),
        )),
        local: crate::scim::service(c.w.db.app.clone(), keks, ids).unwrap(),
    };
    drain(&worker).await;
    {
        let calls = worker.sender.calls.lock().unwrap();
        let (method, url, used, body) = &calls[0];
        assert_eq!(method, "POST");
        assert_eq!(url, "https://crm.example/scim/v2/Users");
        assert_eq!(used, bearer.as_bytes());
        let body: serde_json::Value = serde_json::from_slice(body.as_ref().unwrap()).unwrap();
        assert_eq!(body["userName"], "joan@contoso.example");
        assert_eq!(body["externalId"], local);
        assert!(body.get("id").is_none() && body.get("password").is_none());
    }
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let pushes = access_store::scim::pushes(&mut t, "crm", 10).await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(pushes[0].2, "create");
    assert_eq!(pushes[0].3, Some(201));
    assert_eq!(pushes[0].4, "done");

    worker.sender.replies.lock().unwrap().push(Reply {
        status: 503,
        body: Vec::new(),
    });
    let (st, _, _) = s
        .call(
            Method::DELETE,
            &format!("/Users/{local}"),
            &secret,
            None,
            &[],
        )
        .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    drain(&worker).await;
    worker.sender.replies.lock().unwrap().push(Reply {
        status: 204,
        body: Vec::new(),
    });
    drain(&worker).await;
    let calls = worker.sender.calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1].0, "DELETE");
    assert_eq!(calls[1].1, "https://crm.example/scim/v2/Users/remote-1");
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let pushes = access_store::scim::pushes(&mut t, "crm", 10).await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(pushes[0].4, "done");
    assert_eq!(pushes[0].5, 2);
    assert_eq!(pushes[1].4, "retry");
}
