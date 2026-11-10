//! OP-155 m.3 (f), §10.6.5, IDP-18, IDP-33, IDI-11, OP-153 m.3 (gg): the RADIUS gateway against
//! access-server's real edge router over mutual TLS 1.3, on a real PostgreSQL. A `RadSec` client
//! speaks RADIUS/1.1 to the gateway's real listener. Keys, certificates and app passwords are
//! made at run time.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::expect_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::time::Duration;

use access_identity_account::ports::{AccountTx as _, Entropy as _};
use support::{ADMIN, USER_NAME, USER_PASSWORD, VENDOR_SPECIFIC, exchange, nas, packet, world};

const ACCESS_REQUEST: u8 = 1;
const ACCESS_ACCEPT: u8 = 2;
const ACCESS_REJECT: u8 = 3;
const STATUS_SERVER: u8 = 12;
const ALPN: &[u8] = b"radius/1.1";

// IDP-18, OP-155 m.3 (f), P-ID-5
#[tokio::test]
async fn a_radsec_pap_success_yields_an_authentication_claim() {
    let w = world(111).await;
    let ada = w.person("ada").await;
    w.person("bob").await;
    let token = w.app_password(ada).await;
    let mut c = w.connect(&w.nas, &[ALPN]).await.unwrap();
    let ok = exchange(
        &mut c,
        &packet(
            ACCESS_REQUEST,
            [1, 2, 3, 4],
            &[(USER_NAME, b"ada"), (USER_PASSWORD, token.as_bytes())],
        ),
    )
    .await
    .unwrap();
    assert_eq!(ok[0], ACCESS_ACCEPT);
    assert_eq!(&ok[4..8], &[1, 2, 3, 4]);
    let by_mail = exchange(
        &mut c,
        &packet(
            ACCESS_REQUEST,
            [1, 2, 3, 5],
            &[
                (USER_NAME, b"ada@corp.example"),
                (USER_PASSWORD, token.as_bytes()),
            ],
        ),
    )
    .await
    .unwrap();
    assert_eq!(by_mail[0], ACCESS_ACCEPT);
    for (name, secret) in [
        ("bob", token.as_str()),
        ("ada", "not-the-app-password"),
        ("nobody", token.as_str()),
    ] {
        let no = exchange(
            &mut c,
            &packet(
                ACCESS_REQUEST,
                [9, 9, 9, 9],
                &[
                    (USER_NAME, name.as_bytes()),
                    (USER_PASSWORD, secret.as_bytes()),
                ],
            ),
        )
        .await
        .unwrap();
        assert_eq!(no[0], ACCESS_REJECT, "{name}");
    }
    let status = exchange(&mut c, &packet(STATUS_SERVER, [7, 7, 7, 7], &[]))
        .await
        .unwrap();
    assert_eq!(status[0], ACCESS_ACCEPT);
    let (audit, outbox) = w.rows().await;
    assert!(
        audit.contains(&String::from("login.radius.succeeded")),
        "{audit:?}"
    );
    assert!(
        audit.contains(&String::from("login.radius.failed")),
        "{audit:?}"
    );
    assert!(
        audit.contains(&String::from("edge.claim_requested")),
        "{audit:?}"
    );
    assert_eq!(
        outbox
            .iter()
            .filter(|k| k.ends_with("authentication"))
            .count(),
        2,
        "{outbox:?}"
    );
}

// IDP-18, §10.6.5
#[tokio::test]
async fn ms_chapv2_and_other_methods_are_refused() {
    let w = world(112).await;
    let ada = w.person("ada").await;
    let token = w.app_password(ada).await;
    let mut c = w.connect(&w.nas, &[ALPN]).await.unwrap();
    let mut response = vec![0, 0, 1, 55, 25, 52];
    response.extend_from_slice(&[0; 50]);
    for attrs in [
        vec![
            (USER_NAME, b"ada".as_slice()),
            (VENDOR_SPECIFIC, response.as_slice()),
        ],
        vec![
            (USER_NAME, b"ada".as_slice()),
            (USER_PASSWORD, token.as_bytes()),
            (VENDOR_SPECIFIC, response.as_slice()),
        ],
        vec![(USER_NAME, b"ada".as_slice()), (3, b"chap".as_slice())],
        vec![(USER_NAME, b"ada".as_slice()), (79, b"eap".as_slice())],
    ] {
        let no = exchange(&mut c, &packet(ACCESS_REQUEST, [4, 4, 4, 4], &attrs))
            .await
            .unwrap();
        assert_eq!(no[0], ACCESS_REJECT);
    }
    let (audit, outbox) = w.rows().await;
    assert!(
        audit.contains(&String::from("edge.radius.mschap.refused")),
        "{audit:?}"
    );
    assert!(
        audit.contains(&String::from("edge.radius.method.refused")),
        "{audit:?}"
    );
    assert!(!audit.contains(&String::from("login.radius.succeeded")));
    assert!(!outbox.iter().any(|k| k.ends_with("authentication")));
}

// IDP-18, OP-155 m.3 (f)
#[tokio::test]
async fn a_radius_access_request_over_udp_gets_no_answer() {
    let w = world(113).await;
    let ada = w.person("ada").await;
    let token = w.app_password(ada).await;
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = packet(
        ACCESS_REQUEST,
        [1, 1, 1, 1],
        &[(USER_NAME, b"ada"), (USER_PASSWORD, token.as_bytes())],
    );
    let _ = udp.send_to(&request, w.radsec).await;
    let mut buf = [0_u8; 4096];
    let answer = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut buf)).await;
    assert!(!matches!(answer, Ok(Ok(_))), "a UDP datagram was answered");
    let (audit, outbox) = w.rows().await;
    assert!(!audit.contains(&String::from("login.radius.succeeded")));
    assert!(!outbox.iter().any(|k| k.ends_with("authentication")));
}

// OP-155 m.3 (f)
#[tokio::test]
async fn an_unregistered_client_or_another_protocol_is_never_answered() {
    let w = world(114).await;
    let ada = w.person("ada").await;
    let token = w.app_password(ada).await;
    let request = packet(
        ACCESS_REQUEST,
        [2, 2, 2, 2],
        &[(USER_NAME, b"ada"), (USER_PASSWORD, token.as_bytes())],
    );
    let stranger = nas("rogue.corp.example");
    if let Ok(mut c) = w.connect(&stranger, &[ALPN]).await {
        assert!(exchange(&mut c, &request).await.is_none());
    }
    let legacy = w.connect(&w.nas, &[b"radius/1.0"]).await;
    if let Ok(mut c) = legacy {
        assert!(exchange(&mut c, &request).await.is_none());
    }
    if let Ok(mut c) = w.connect(&w.nas, &[]).await {
        assert!(exchange(&mut c, &request).await.is_none());
    }
    let (audit, outbox) = w.rows().await;
    assert!(
        audit.contains(&String::from("edge.radius.client.refused")),
        "{audit:?}"
    );
    assert!(!outbox.iter().any(|k| k.ends_with("authentication")));
}

// IDP-18, IDP-16
#[tokio::test]
async fn a_primary_password_never_authenticates_over_radius() {
    let w = world(115).await;
    let ada = w.person("ada").await;
    let primary = String::from("correct horse battery staple 1");
    {
        let mut tx = w.tx().await;
        let salt = access_identity_account::adapters::system::SystemEntropy
            .salt()
            .unwrap();
        let phc = w
            .hasher
            .hash(
                &access_identity_account::domain::password::Password::new(&primary).unwrap(),
                salt,
            )
            .await
            .unwrap();
        access_identity_account::app::accounts::store_password(
            &mut tx,
            &w.realm(),
            ada,
            phc.expose(),
            &ADMIN,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let mut c = w.connect(&w.nas, &[ALPN]).await.unwrap();
    let no = exchange(
        &mut c,
        &packet(
            ACCESS_REQUEST,
            [3, 3, 3, 3],
            &[(USER_NAME, b"ada"), (USER_PASSWORD, primary.as_bytes())],
        ),
    )
    .await
    .unwrap();
    assert_eq!(no[0], ACCESS_REJECT);
}
