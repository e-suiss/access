//! Admin API conformance (§9.7, TN-110, TN-130, OP-151 m.3 (s)): a management call without the
//! caller's actor proof changes nothing; there is no credential-setting route and no route that
//! acts as another user.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod admin;

use access_http::api::manifest::{Access, MANIFEST};
use access_kernel::combinator::Mode;
use access_kernel::json::b64url_encode;
use axum::body::Body;
use axum::http::{Request, StatusCode};

use admin::{Harness, ais, ais_with, platform_domain, proof, realm_domain, send, test_router};

const PATH: &str = "/admin/v1/realms/acme/probes";

fn write(key: &str, ais: Option<&str>, token: Option<&str>) -> Request<Body> {
    let mut b = Request::post(PATH)
        .header("content-type", "application/json")
        .header("idempotency-key", key);
    if let Some(a) = ais {
        b = b.header("x-access-ais", a);
    }
    if let Some(t) = token {
        b = b
            .header("authorization", format!("DPoP {t}"))
            .header("dpop", proof("POST", PATH));
    }
    b.body(Body::from(r#"{"name":"x"}"#)).unwrap()
}

// §9.7, TN-110, OP-151 m.3 (s), TNI-12: without AIS, with a wrong Instance, or with a read
// token only, the position of the domain's log does not move; with the caller's own AIS it does
#[tokio::test]
async fn a_write_without_actor_proof_changes_nothing() {
    let h = Harness::new();
    let router = test_router(&h);
    let nonce = [5; 16];
    let key = b64url_encode(&nonce);
    let reader = h.token(
        "reader",
        "access-admin:realm:acme",
        &["realm.read", "realm.write"],
        600_000,
    );
    let wrong = h.instance(platform_domain());
    let stranger = suiss_crypto::signer::SoftSigner::generate_ed25519()
        .unwrap()
        .0;
    let own = h.instance(realm_domain());
    let refused = [
        write(&key, None, None),
        write(&key, None, Some(&reader)),
        write(
            &key,
            Some(&ais(&wrong, realm_domain(), nonce, h.now())),
            None,
        ),
        write(
            &key,
            Some(&ais(&stranger, realm_domain(), nonce, h.now())),
            None,
        ),
        write(
            &key,
            Some(&ais_with(&own, realm_domain(), nonce, h.now(), Mode::Check)),
            None,
        ),
        write(
            &key,
            Some(&ais(&own, realm_domain(), nonce, h.now() + 120_000)),
            None,
        ),
    ];
    for (i, request) in refused.into_iter().enumerate() {
        let (r, body) = send(&router, request).await;
        assert!(
            matches!(r.status(), StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "case {i}: {} {body}",
            r.status()
        );
        assert_eq!(h.position(), 0, "case {i}");
        assert_eq!(h.proposals(), 0, "case {i}");
    }
    let (r, body) = send(
        &router,
        write(&key, Some(&ais(&own, realm_domain(), nonce, h.now())), None),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "{body}");
    assert_eq!(body["position"], "1");
    assert_eq!(h.position(), 1);
}

// TN-61, TN-130, MD-14, X24: no route sets a credential or acts as another user; reads never
// write and writes always carry an AIS
#[test]
fn no_credential_setting_or_acting_as_route_exists() {
    for row in MANIFEST {
        let text = format!("{} {} {}", row.path, row.operation_id, row.summary).to_lowercase();
        for banned in [
            "credential",
            "password",
            "set-secret",
            "impersonat",
            "log in as",
            "login-as",
            "act-as",
            "sudo",
            "token",
        ] {
            assert!(!text.contains(banned), "{}: {banned}", row.operation_id);
        }
        assert!(row.verb_fits(), "{}", row.operation_id);
        if row.verb.mutating() && row.access != Access::Write {
            assert!(
                matches!(row.operation_id, "draftIntent" | "draftPlatformIntent"),
                "{}",
                row.operation_id
            );
        }
    }
}

// IDI-1, MD-14, TN-110: every realm write route compiles into one idp.* change committed in the
// realm's governing domain, or is declared reserved and applies nothing; a bulk job runs each
// item as such a write; no route writes identity plane configuration another way
#[test]
fn every_realm_write_is_an_idp_exercise() {
    use access_http::api::domain::Surface;
    use access_identity_admin::app::rest::Op;
    let mut writes = 0;
    for row in MANIFEST
        .iter()
        .filter(|r| r.surface == Surface::Realm && r.changes_state())
    {
        assert_eq!(row.access, Access::Write, "{}", row.operation_id);
        if row.operation_id == "createJob" {
            continue;
        }
        assert!(
            Op::from_operation(row.operation_id).is_some(),
            "{} compiles to no idp.* change",
            row.operation_id
        );
        writes += 1;
    }
    assert!(writes > 30, "{writes}");
}
