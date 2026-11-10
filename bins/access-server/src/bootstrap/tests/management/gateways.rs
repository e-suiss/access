//! Edge gateway settings through the console's BFF against the real admin surface (OP-155
//! m.3 (c), (f), (o), OP-153 m.3 (gg)): a RADIUS gateway's `RadSec` client is registered by REST
//! as `idp.gateway.radius_client_register` and a Kerberos gateway's keytab policy as
//! `idp.gateway.keytab_policy`; a setting for a gateway of another kind, an unregistered gateway
//! or out of shape is refused.

use access_store::identity::TenantTx;

use super::*;

fn certificate(uri: Option<&str>) -> String {
    let mut p = rcgen::CertificateParams::new(vec![String::from("nas.acme.example")]).unwrap();
    if let Some(u) = uri {
        p.subject_alt_names = vec![rcgen::SanType::URI(u.try_into().unwrap())];
    }
    let key = rcgen::KeyPair::generate().unwrap();
    b64url_encode(p.self_signed(&key).unwrap().der())
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    })
}

async fn register(c: &Console, kind: &str, name: &str) {
    let w = c
        .rest_write(
            &Method::POST,
            "/admin/v1/realms/acme/gateways",
            ("registerGateway", None),
            serde_json::json!({
                "kind": kind,
                "name": name,
                "cert_sha256": hex(&suiss_crypto::digest::sha256(
                    &b64url_decode(&certificate(Some(&format!("urn:suiss:access:gw:{kind}:{name}"))))
                        .unwrap(),
                )),
            }),
            None,
        )
        .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
}

// OP-155 m.3 (f), (o), IDP-17, IDP-18
#[tokio::test]
async fn gateway_settings_are_committed_by_rest() {
    let c = console("mgmt-gateways", true).await;
    register(&c, "radius", "corp-radius").await;
    register(&c, "kerberos", "corp-krb").await;
    let nas = certificate(None);
    let client = |gateway: &'static str, body: serde_json::Value| {
        let c = &c;
        async move {
            c.rest_write(
                &Method::POST,
                &format!("/admin/v1/realms/acme/gateways/{gateway}/radius-clients"),
                ("registerRadiusClient", Some(gateway)),
                body,
                None,
            )
            .await
        }
    };
    let w = client(
        "radius:corp-radius",
        serde_json::json!({ "client": "vpn-1", "certificate": nas }),
    )
    .await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);
    let w = client(
        "radius:nowhere",
        serde_json::json!({ "client": "vpn-1", "certificate": nas }),
    )
    .await;
    assert_eq!(w.status, StatusCode::NOT_FOUND, "{}", w.body);
    for (gateway, body) in [
        (
            "kerberos:corp-krb",
            serde_json::json!({ "client": "vpn-1", "certificate": nas }),
        ),
        (
            "radius:corp-radius",
            serde_json::json!({ "client": "Not A Name", "certificate": nas }),
        ),
        (
            "radius:corp-radius",
            serde_json::json!({ "client": "vpn-2", "certificate": "AAAA" }),
        ),
    ] {
        let w = client(gateway, body).await;
        assert_eq!(w.status, StatusCode::BAD_REQUEST, "{gateway}: {}", w.body);
        assert_eq!(w.body["code"], "invalid-gateway", "{}", w.body);
    }

    let policy = |body: serde_json::Value| {
        let c = &c;
        async move {
            c.rest_write(
                &Method::PUT,
                "/admin/v1/realms/acme/gateways/kerberos:corp-krb/keytab-policy",
                ("putKeytabPolicy", Some("kerberos:corp-krb")),
                body,
                None,
            )
            .await
        }
    };
    for bad in [
        serde_json::json!({ "spn": "HTTP@ACME.EXAMPLE", "rotate_days": 30 }),
        serde_json::json!({ "spn": "HTTP/access.acme.example@ACME.EXAMPLE", "rotate_days": 0 }),
        serde_json::json!({ "spn": "HTTP/access.acme.example@ACME.EXAMPLE", "rotate_days": 366 }),
    ] {
        let w = policy(bad).await;
        assert_eq!(w.status, StatusCode::BAD_REQUEST, "{}", w.body);
    }
    let spn = "HTTP/access.acme.example@ACME.EXAMPLE";
    let w = policy(serde_json::json!({ "spn": spn, "rotate_days": 30 })).await;
    assert!(w.status.is_success(), "{} {}", w.status, w.body);

    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let registered = access_store::edge::radius_client_registered(
        &mut t,
        "corp-radius",
        &suiss_crypto::digest::sha256(&b64url_decode(&nas).unwrap()),
    )
    .await
    .unwrap();
    let kept = access_store::edge::keytab_policy(&mut t, "corp-krb")
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    assert!(registered);
    assert_eq!(
        (kept.spn.as_str(), kept.rotate_days, kept.kvno_floor),
        (spn, 30, 0)
    );
}
