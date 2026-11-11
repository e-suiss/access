//! Derived outage: commit goes on and status is never signed with a fresh `iat` (§16.7, G43).

use access_authority_core::status::adapters::{PgLists, SignerSocket, open_family};
use access_authority_core::status::{Publisher, set_entries};
use access_kernel::combinator::Mode;
use access_kernel::json::b64url_encode;
use access_store::projections::Family;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use tower::ServiceExt as _;

use super::super::authzen::pdp;
use super::signer_socket;

// FO-05, G43, TI-5, SI-7, §16.7, §17.7.1, OP-158 m.3 (t), Ek B 6145
#[tokio::test(flavor = "multi_thread")]
async fn fo_05_with_derived_down_commits_go_on_and_a_list_is_never_fresher_than_its_position() {
    let label = "fo-05-derived";
    let p = pdp(label).await;
    let family = Family {
        family: access_crypto::random::bytes().unwrap(),
        client_id: String::from("cli_fault"),
        holder: access_crypto::random::bytes().unwrap(),
        root_exercise: access_crypto::random::bytes().unwrap(),
        status: None,
        revoked_pos: None,
    };
    open_family(
        &p.w.db.sequencer,
        "https://api.access.test",
        p.domain,
        &family,
    )
    .await
    .unwrap()
    .unwrap();
    let publisher = Publisher::new(
        PgLists {
            app: p.w.db.app.clone(),
            sequencer: p.w.db.sequencer.clone(),
        },
        SignerSocket(signer_socket(label)),
    );
    assert_eq!(
        publisher
            .publish(p.domain, p.now().await)
            .await
            .unwrap()
            .len(),
        1
    );

    p.w.db.deriver.close().await;
    let a = p
        .post("/access/v1/evaluation", &p.allowed(Mode::Commit).await)
        .await;
    assert_eq!(a.status, StatusCode::OK, "commit goes on: {}", a.json());
    assert!(!p.w.domains.derive().await.is_empty(), "derived is down");

    // G43
    let (head, recorded_at) = p.w.domains.head(p.domain).await.unwrap();
    assert!(
        access_store::projections::revoke_family(
            &p.w.db.sequencer,
            &access_store::scope::DomainId::from_bytes(p.domain.0),
            &family.family,
            head,
        )
        .await
        .unwrap()
    );
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let later = p.now().await;
    let lists = publisher.publish(p.domain, later).await.unwrap();
    assert_eq!(lists.first().map(|l| l.as_of), Some(head));
    let r = crate::status::routes(p.w.db.app.clone())
        .oneshot(
            Request::get(format!(
                "/access/v1/status-lists/0?domain=sha-256:{}",
                b64url_encode(&p.domain.0)
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = to_bytes(r.into_body(), 1 << 20).await.unwrap();
    assert_eq!(set_entries(&body), Some(1));
    let payload = access_kernel::verify::cose::parse_sign1(&body)
        .unwrap()
        .payload
        .unwrap();
    let t = access_kernel::status::ListToken::from_bytes(&payload).unwrap();
    assert_eq!((t.as_of, t.iat), (head, recorded_at / 1_000));
    assert!(
        t.iat < later / 1_000,
        "signed later, never with the signing time"
    );
    p.w.domains.release().await;
}
