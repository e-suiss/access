//! Mutual TLS client authentication over the authorization server's HTTP routes (RFC 8705 §2,
//! TN-32, OP-155 m.3 (k)): the client certificate is the one the TLS layer put on the request;
//! a forwarded certificate header never stands in for it.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unused_async_trait_impl,
    clippy::type_complexity,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "../../identity-oauth/tests/support/mod.rs"]
mod support;

use std::sync::Arc;

use access_http::oauth::router;
use access_http::tls::MtlsChain;
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::ports::profile::CertificateNames;
use access_kernel::json::b64url_encode;
use access_store::client_profiles::ClientProfileRow;
use axum::body::Body;
use axum::http::{Request, header};
use http_body_util::BodyExt;
use serde_json::Value;
use support::{CB, Cluster, VERIFIER, location, now, query};
use tower::ServiceExt;

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            let mut out = format!("{k}=");
            access_identity_oauth::domain::issuer::form_encode(v, &mut out);
            out
        })
        .collect::<Vec<_>>()
        .join("&")
}

// RFC 8705 §2, TN-32, OP-155 m.3 (k), Ek B 4713
#[tokio::test]
async fn forwarded_certificate_headers_have_no_effect() {
    let c = Cluster::new(&["hdr-a"]).await;
    let a = c.at(0);
    let leaf = rcgen::generate_simple_self_signed(vec![String::from("svc.example")])
        .unwrap()
        .cert
        .der()
        .to_vec();
    a.c.oauth.env().certs.0.lock().unwrap().insert(
        leaf.clone(),
        Ok(CertificateNames {
            dns: vec![String::from("svc.example")],
            ..CertificateNames::default()
        }),
    );
    a.set_profile(
        'b',
        "idp.client.update",
        &ClientProfileRow {
            tls_auth: Some(String::from("tls_client_auth")),
            tls_name: Some((String::from("san_dns"), String::from("svc.example"))),
            ..ClientProfileRow::default()
        },
    )
    .await
    .unwrap();
    let app = router(OAuth::new(c.env()));
    let token = |chain: Option<Vec<u8>>, forwarded: bool| {
        let a = a.clone();
        let app = app.clone();
        let leaf = leaf.clone();
        async move {
            let cookie = a.sign_in(now() - 1000).await;
            let to = location(
                &a.authorize(&[("client_id", a.f.confidential.as_str())], Some(&cookie))
                    .await,
            );
            let code = query(&to, "code");
            let mut req = Request::post("/token")
                .header(header::HOST, &a.f.host)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            if forwarded {
                let pem = b64url_encode(&leaf);
                for name in [
                    "x-client-cert",
                    "x-forwarded-client-cert",
                    "ssl-client-cert",
                    "x-ssl-cert",
                    "client-cert",
                ] {
                    req = req.header(name, &pem);
                }
            }
            let mut req = req
                .body(Body::from(form(&[
                    ("grant_type", "authorization_code"),
                    ("client_id", a.f.confidential.as_str()),
                    ("code", &code),
                    ("redirect_uri", CB),
                    ("code_verifier", VERIFIER),
                ])))
                .unwrap();
            if let Some(leaf) = chain {
                req.extensions_mut()
                    .insert(MtlsChain(Arc::from(vec![leaf])));
            }
            let r = app.oneshot(req).await.unwrap();
            let status = r.status().as_u16();
            let body = r.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice::<Value>(&body).unwrap())
        }
    };
    let (status, body) = token(None, true).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_client");
    let (status, body) = token(Some(leaf.clone()), false).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["token_type"], "Bearer");
}
