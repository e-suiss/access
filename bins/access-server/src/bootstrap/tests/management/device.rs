//! The device authorization grant on the real server path (RFC 8628, OP-154 m.3 (p), (dd), TN-35,
//! CR-38, CR-39, OP-153 m.3 (gg)): off until `putDeviceCode` commits `idp.realm.device_code`; a
//! registered client asks, the signed-in person reads and approves the user code on the
//! verification routes, and the device's poll turns into a DPoP-bound token once.

use access_store::identity::TenantTx;

use super::*;

const TOKEN_URI: &str = "https://access.test/realms/acme/token";
const GRANT: &str = "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code";

fn xy(key: &access_kernel::verify::cose::PublicKey) -> (String, String) {
    let access_kernel::verify::cose::PublicKey::P256(sec1) = key else {
        panic!("not P-256");
    };
    (
        b64url_encode(sec1.get(1..33).unwrap()),
        b64url_encode(sec1.get(33..65).unwrap()),
    )
}

fn dpop(by: &SoftSigner, nonce: Option<&str>) -> String {
    let (x, y) = xy(&by.public_key());
    let mut claims = serde_json::json!({
        "jti": b64url_encode(&access_crypto::random::bytes::<16>().unwrap()),
        "htm": "POST",
        "htu": TOKEN_URI,
        "iat": now() / 1000,
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::Value::from(n);
    }
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y },
    });
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(claims.to_string().as_bytes())
    );
    let sig = by.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(&sig))
}

async fn form(
    c: &Console,
    path: &str,
    body: &str,
    proof: Option<String>,
) -> (StatusCode, serde_json::Value, Option<String>) {
    let mut b = Request::post(format!("/realms/acme{path}"))
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(p) = proof {
        b = b.header("dpop", p);
    }
    let (reply, bytes) = send(&c.oauth, b.body(Body::from(String::from(body))).unwrap()).await;
    let nonce = reply
        .headers()
        .get("dpop-nonce")
        .map(|h| h.to_str().unwrap().to_owned());
    (
        reply.status(),
        serde_json::from_slice(&bytes).unwrap_or_default(),
        nonce,
    )
}

/// One poll with a DPoP proof by `key`, retried once with the nonce the server hands out.
async fn poll(c: &Console, client: &str, code: &str, key: &SoftSigner) -> serde_json::Value {
    let body = format!("grant_type={GRANT}&client_id={client}&device_code={code}");
    let (_, answer, nonce) = form(c, "/token", &body, Some(dpop(key, None))).await;
    if answer["error"] != "use_dpop_nonce" {
        return answer;
    }
    form(c, "/token", &body, Some(dpop(key, nonce.as_deref())))
        .await
        .1
}

async fn session(c: &Console) -> String {
    let value: [u8; 32] = access_crypto::random::bytes().unwrap();
    let at = now();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    t.insert_session(&NewSession {
        cookie_hash: &cookie_digest(&value),
        subject: c.subject,
        session_epoch: 0,
        keep_signed_in: false,
        created_ms: i64::try_from(at).unwrap(),
        auth_time_ms: i64::try_from(at).unwrap(),
        idle_ms: 3_600_000,
        expires_ms: i64::try_from(at + 3_600_000).unwrap(),
        assurance: &serde_json::to_vec(&vector(&[Factor::password(at)])).unwrap(),
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    b64url_encode(&value)
}

async fn page(
    c: &Console,
    path: &str,
    cookie: Option<&str>,
    csrf: Option<&str>,
    body: &serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::post(format!("/realms/acme{path}"))
        .header(header::HOST, HOST)
        .header(header::ORIGIN, format!("https://{HOST}"))
        .header("sec-fetch-site", "same-origin")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(v) = cookie {
        b = b.header(header::COOKIE, format!("{SESSION}={v}"));
    }
    if let Some(t) = csrf {
        b = b.header("x-csrf-token", t);
    }
    let (reply, bytes) = send(&c.oauth, b.body(Body::from(body.to_string())).unwrap()).await;
    (
        reply.status(),
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn device_code(c: &Console, client: &str) -> (StatusCode, serde_json::Value) {
    let (status, body, _) = form(
        c,
        "/device_authorization",
        &format!("client_id={client}&scope=openid"),
        None,
    )
    .await;
    (status, body)
}

// TN-35, OP-154 m.3 (p), (dd), CR-38, CR-39, RFC 8628, Ek B 4649, 4650, 4651, 4655
#[tokio::test]
async fn a_device_code_is_off_until_decided_then_approved_once_into_a_dpop_bound_token() {
    let c = console("mgmt-device", true).await;
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/clients",
            ("createClient", None),
            serde_json::json!({
                "display_name": "Living room TV",
                "token_endpoint_auth_method": "none",
                "redirect_uris": ["https://tv.example/cb"],
            }),
            None,
        )
        .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let client = w.body["resource"]["client_id"].as_str().unwrap().to_owned();
    let key = SoftSigner::generate_p256().unwrap().0;

    // TN-35 OP-154 m.3 (dd)
    let (status, _) = device_code(&c, &client).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let answer = poll(&c, &client, "AAAA", &key).await;
    assert_eq!(answer["error"], "unsupported_grant_type", "{answer}");
    let w = c
        .rest_write(
            &Method::PUT,
            "/admin/v1/realms/acme/settings/device-code",
            ("putDeviceCode", None),
            serde_json::json!({ "enabled": true }),
            None,
        )
        .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);

    let (status, issued) = device_code(&c, &client).await;
    assert_eq!(status, StatusCode::OK, "{issued}");
    let user = issued["user_code"].as_str().unwrap().to_owned();
    let code = issued["device_code"].as_str().unwrap().to_owned();
    // OP-154 m.3 (p)
    assert_eq!(user.len(), 9);
    assert!(
        user.chars()
            .all(|ch| ch == '-' || "BCDFGHJKLMNPQRSTVWXZ".contains(ch))
    );
    assert_eq!(issued["expires_in"], 600);
    assert_eq!(issued["interval"], 5);
    assert_eq!(
        issued["verification_uri"],
        "https://access.test/realms/acme/device"
    );
    // CR-38
    let raw = b64url_decode(&code).unwrap();
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let digest = access_identity_oauth::domain::device::device_hash(&raw);
    assert!(t.device_code(&digest).await.unwrap().is_some());
    assert!(
        t.device_code(&<[u8; 32]>::try_from(raw.as_slice()).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    t.commit().await.unwrap();

    // RFC 8628 §3.5
    let answer = poll(&c, &client, &code, &key).await;
    assert_eq!(answer["error"], "authorization_pending", "{answer}");
    let answer = poll(&c, &client, &code, &key).await;
    assert_eq!(answer["error"], "slow_down", "{answer}");

    let cookie = session(&c).await;
    let (status, _) = page(
        &c,
        "/v1/device/preview",
        None,
        None,
        &serde_json::json!({ "user_code": user }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, view) = page(
        &c,
        "/v1/device/preview",
        Some(&cookie),
        None,
        &serde_json::json!({ "user_code": user.to_lowercase() }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["client"], "Living room TV");
    assert_eq!(view["scopes"], serde_json::json!(["openid"]));
    assert!(view["ip_prefix"].is_string());
    let csrf = view["csrf"].as_str().unwrap().to_owned();
    // §11.4.5
    let (status, _) = page(
        &c,
        "/v1/device/approval",
        Some(&cookie),
        None,
        &serde_json::json!({ "user_code": user, "approve": true }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, done) = page(
        &c,
        "/v1/device/approval",
        Some(&cookie),
        Some(&csrf),
        &serde_json::json!({ "user_code": user, "approve": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{done}");

    // OP-154 m.3 (p) m.10 (j)
    let answer = poll(&c, &client, &code, &key).await;
    assert_eq!(answer["token_type"], "DPoP", "{answer}");
    assert!(answer["access_token"].is_string());
    let again = poll(&c, &client, &code, &key).await;
    assert_eq!(again["error"], "invalid_grant", "{again}");

    // OP-154 m.3 (p) CR-39
    for _ in 0..5 {
        let (status, body) = page(
            &c,
            "/v1/device/preview",
            Some(&cookie),
            None,
            &serde_json::json!({ "user_code": "BCDF-BCDF" }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["code"], "device-code-invalid");
    }
    let (_, fresh) = device_code(&c, &client).await;
    let (status, body) = page(
        &c,
        "/v1/device/preview",
        Some(&cookie),
        None,
        &serde_json::json!({ "user_code": fresh["user_code"] }),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    c.w.domains.release().await;
}
