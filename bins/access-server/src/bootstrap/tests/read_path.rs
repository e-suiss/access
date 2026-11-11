//! The read path on the real ADP router, sequencer, store and authority signer (§9.7A, P45, U61,
//! G51, TI-RT3, OP-158 m.3 (u), m.5): the advisory cache, the `as_of` window, the watch stream and
//! the nonce archive.

use access_authority_core::CoreError;
use access_authority_core::app::cache::AS_OF_WINDOW_MS;
use access_authority_core::keys::AsOf;
use access_authority_core::ports::Keys as _;
use axum::http::StatusCode;
use serde_json::Value as Json;

use super::authzen::{PEP, Pdp, pdp};
use super::*;

const DAY_AND_AN_HOUR: u64 = AS_OF_WINDOW_MS + 3_600_000;

impl Pdp {
    async fn evaluate(&self, body: &Json) -> Json {
        let a = self.post("/access/v1/evaluation", body).await;
        assert_eq!(a.status, StatusCode::OK, "{}", a.json());
        a.json()
    }

    /// A consistency token of the head as the domain seals it, issued `ago` ms before now.
    async fn token_issued(&self, ago: u64) -> String {
        let head = self.w.domains.head(self.domain).await.unwrap().0;
        let mut b = head.to_be_bytes().to_vec();
        b.extend_from_slice(&(self.now().await - ago).to_be_bytes());
        self.w
            .keys
            .token_key(&self.domain)
            .unwrap()
            .seal(&self.domain.0, "consistency", &b)
            .unwrap()
    }
}

// U61, P45, TI-5, §9.7A.4, Ek B 6124, 6125, 6130
#[tokio::test]
async fn u61_a_repeated_check_is_answered_from_the_cache_and_a_commit_never_reads_it() {
    let p = pdp("rp-cache").await;
    let allow = p.allowed(Mode::Check).await;
    let deny = p.denied(Mode::Check).await;
    let start = p.w.domains.advisory_counts();
    assert_eq!(p.evaluate(&allow).await["decision"], true);
    assert_eq!(p.evaluate(&allow).await["decision"], true);
    assert_eq!(p.evaluate(&deny).await["decision"], false);
    let second = p.evaluate(&deny).await;
    assert_eq!(second["decision"], false, "{second}");
    assert_eq!(second["context"]["advisory"], true, "{second}");
    let cached = p.w.domains.advisory_counts();
    assert_eq!(cached.lookups - start.lookups, 4);
    assert_eq!(
        cached.hits - start.hits,
        2,
        "the ALLOW and the DENY were each answered once"
    );
    assert_eq!(cached.stored - start.stored, 2);

    // TI-5
    let before = p.w.domains.head(p.domain).await.unwrap().0;
    let committed = p.evaluate(&p.allowed(Mode::Commit).await).await;
    assert_eq!(committed["decision"], true, "{committed}");
    assert!(p.w.domains.head(p.domain).await.unwrap().0 > before);
    assert_eq!(p.w.domains.advisory_counts().lookups, cached.lookups);
    p.w.domains.release().await;
}

// G51, P45, MD-7, §9.7A.4, Ek B 6122
#[tokio::test]
async fn g51_an_answer_given_at_an_older_position_is_never_served_again() {
    let p = pdp("rp-position").await;
    let deny = p.denied(Mode::Check).await;
    assert_eq!(p.evaluate(&deny).await["decision"], false);
    let token = p.evaluate(&deny).await["context"]["consistency_token"].clone();
    assert!(token.is_string());
    let hits = p.w.domains.advisory_counts().hits;
    assert_eq!(
        p.evaluate(&p.allowed(Mode::Commit).await).await["decision"],
        true
    );
    let again = p.evaluate(&deny).await;
    assert_eq!(again["decision"], false);
    assert_eq!(
        p.w.domains.advisory_counts().hits,
        hits,
        "the commit moved applied_pos, so the canonical state answered"
    );
    assert_ne!(again["context"]["consistency_token"], token);
    p.w.domains.release().await;
}

// §9.7A.2 k.3, P36, OP-158 m.3 (u), Ek B 6123, 6128
#[tokio::test]
async fn a_consistency_token_older_than_the_history_window_is_as_of_expired() {
    let p = pdp("rp-as-of").await;
    let mut fresh = p.allowed(Mode::Check).await;
    fresh["context"]["consistency_token"] = Json::from(p.token_issued(60_000).await);
    assert_eq!(p.evaluate(&fresh).await["decision"], true);
    let mut old = p.allowed(Mode::Check).await;
    old["context"]["consistency_token"] = Json::from(p.token_issued(DAY_AND_AN_HOUR).await);
    let a = p.post("/access/v1/evaluation", &old).await;
    let v = a.json();
    assert_eq!(a.status, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "as-of-expired", "{v}");
    p.w.domains.release().await;
}

// §9.7A.2 k.3, OP-158 m.3 (u), Ek B 6123, 6128
#[tokio::test]
async fn a_lookup_as_of_a_position_or_time_past_24_hours_is_as_of_expired() {
    let p = pdp("rp-lookup").await;
    let kid = thumbprint(&p.root.public_key());
    let now = p.now().await;
    let at = |t| AsOf::Time(t);
    assert!(
        p.w.domains
            .lookup_keys(p.domain, &[kid], at(now), false)
            .await
            .is_ok()
    );
    assert!(matches!(
        p.w.domains
            .lookup_keys(p.domain, &[kid], at(now - DAY_AND_AN_HOUR), false)
            .await,
        Err(CoreError::Refused("as-of-expired"))
    ));
    let head = p.w.domains.head(p.domain).await.unwrap().0;
    assert!(
        p.w.domains
            .lookup_keys(p.domain, &[kid], AsOf::Position(head - 1), false)
            .await
            .is_ok()
    );
    access_store::testing::age_authority(&p.w.db, p.domain.0, DAY_AND_AN_HOUR)
        .await
        .unwrap();
    assert!(matches!(
        p.w.domains
            .lookup_keys(p.domain, &[kid], AsOf::Position(head - 1), false)
            .await,
        Err(CoreError::Refused("as-of-expired"))
    ));
    assert!(
        p.w.domains
            .lookup_keys(p.domain, &[kid], AsOf::Head, false)
            .await
            .is_ok(),
        "the reader falls back to head"
    );
    p.w.domains.release().await;
}

// §9.7A.2, §9.7A.4, OP-158 m.3 (u), Ek B 6127
#[tokio::test(flavor = "multi_thread")]
async fn watch_long_polls_for_the_next_record_with_witnessed_through() {
    let p = pdp("rp-watch").await;
    let domain = format!(
        "sha-256:{}",
        access_kernel::json::b64url_encode(&p.domain.0)
    );
    let head = p.w.domains.head(p.domain).await.unwrap().0;
    let path =
        |from: u64, wait: u64| format!("/access/v1/domains/{domain}/watch?from={from}&wait={wait}");
    let none = p.send(&path(head, 0), Vec::new(), &[], Some(PEP)).await;
    assert_eq!(none.status, StatusCode::OK);
    assert_eq!(
        none.headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let v = none.json();
    assert_eq!(v["changes"], Json::Array(Vec::new()), "{v}");
    assert_eq!(v["head"], head);
    assert_eq!(v["witnessed_through"], 0);
    assert_eq!(v["advisory"], true);

    let back = p
        .send(&path(head - 2, 0), Vec::new(), &[], Some(PEP))
        .await
        .json();
    let positions: Vec<u64> = back["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["position"].as_u64().unwrap())
        .collect();
    assert_eq!(positions, vec![head - 1, head]);
    assert_eq!(back["next"], head);

    let waiting = {
        let adp = p.adp.clone();
        let uri = path(head, 20_000);
        tokio::spawn(async move {
            let mut req = axum::http::Request::get(uri)
                .body(axum::body::Body::empty())
                .unwrap();
            req.extensions_mut()
                .insert(access_http::adp::adapters::Pep(String::from(PEP)));
            let r = tower::ServiceExt::oneshot(adp, req).await.unwrap();
            let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
            serde_json::from_slice::<Json>(&b).unwrap()
        })
    };
    let committed = p.evaluate(&p.allowed(Mode::Commit).await).await;
    assert_eq!(committed["decision"], true);
    let woke = tokio::time::timeout(std::time::Duration::from_secs(20), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(woke["changes"][0]["position"], head + 1, "{woke}");
    assert!(
        woke["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kinds"].as_array().is_some_and(|k| !k.is_empty())),
        "{woke}"
    );

    let unauthenticated = p.send(&path(head, 0), Vec::new(), &[], None).await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    let future = p
        .send(&path(head + 50, 0), Vec::new(), &[], Some(PEP))
        .await;
    assert_eq!(future.status, StatusCode::SERVICE_UNAVAILABLE);
    access_store::testing::age_authority(&p.w.db, p.domain.0, DAY_AND_AN_HOUR)
        .await
        .unwrap();
    let expired = p.send(&path(head - 2, 0), Vec::new(), &[], Some(PEP)).await;
    assert_eq!(expired.status, StatusCode::CONFLICT);
    assert_eq!(expired.json()["code"], "as-of-expired");
    p.w.domains.release().await;
}

// TI-RT3, OP-138, OP-73, Ek B 6134
#[tokio::test]
async fn an_archived_nonce_stays_in_the_lookup_and_is_never_opened_again() {
    let p = pdp("rp-nonce").await;
    let first = p.allowed(Mode::Commit).await;
    assert_eq!(p.evaluate(&first).await["decision"], true);
    let row = p.recorded(&first).await;
    let scope = DomainId::from_bytes(p.domain.0);
    let head = p.w.domains.head(p.domain).await.unwrap().0;
    let copied = access_store::authority::archive_nonces(&p.w.db.archive, &scope, head)
        .await
        .unwrap();
    assert!(copied >= 1);
    assert_eq!(
        access_store::authority::archive_nonces(&p.w.db.archive, &scope, head)
            .await
            .unwrap(),
        0,
        "archiving is idempotent"
    );

    let archived = access_crypto::random::bytes::<16>().unwrap();
    access_store::testing::archive_only_nonce(&p.w.db, p.domain.0, &row.nonce, &archived)
        .await
        .unwrap();
    let found = find_nonce(&p.w.db.app, &scope, &archived)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.decision_pos, row.decision_pos);
    let intent = p
        .idp_intent(access_internal_api::idp::IdpAction::ClientRegister, "other")
        .await;
    let reuse = p
        .body(Mode::Commit, &archived, &intent, p.idp_basis(), PEP)
        .await;
    let a = p.post("/access/v1/evaluation", &reuse).await;
    assert_eq!(a.status, StatusCode::UNPROCESSABLE_ENTITY, "{}", a.json());
    assert_eq!(a.json()["code"], "nonce-conflict");
    assert_eq!(
        p.w.domains.head(p.domain).await.unwrap().0,
        head,
        "nothing was recorded"
    );
    p.w.domains.release().await;
}
