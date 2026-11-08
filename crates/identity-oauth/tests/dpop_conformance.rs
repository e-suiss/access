//! DPoP replay conformance (§10.4.3 m.5, K19, TN-30): the authorization server and the
//! resource server each run their own replay check over the cell's PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::OnceLock;

use access_crypto::Secret;
use access_crypto::dpop::{MAX_STALE_MS, NonceKey, NoncePolicy, NonceRing, Role};
use access_identity_oauth::adapters::dpop::PgReplayCache;
use access_identity_oauth::app::dpop::{DpopChecker, DpopRequest};
use access_identity_oauth::domain::dpop::{DpopProfile, Failure, Step};
use access_identity_oauth::ports::dpop::{Clock, ClockUnavailable};
use access_kernel::json::b64url_encode;
use access_kernel::verify::dpop::ath;
use access_store::dpop::open_dpop_replay_day;
use access_store::identity::{RealmId, TenantId};
use access_store::testing::{TestDb, fresh};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};

const NOW: u64 = 1_800_000_000_000;
const DAY: u32 = 20_833;
const HOUR: u64 = 60 * 60 * 1000;
const T: TenantId = TenantId::from_bytes([1; 16]);
const R: RealmId = RealmId::from_bytes([2; 16]);
const TOKEN_URI: &str = "https://login.example.com/token";
const API_URI: &str = "https://api.example.com/v1/items";

struct Fixed(u64);

impl Clock for Fixed {
    fn now(&self) -> Result<u64, ClockUnavailable> {
        Ok(self.0)
    }
}

fn ring(realm: &RealmId, role: Role, key: u8) -> NonceRing {
    NonceRing::new(
        *realm.as_bytes(),
        role,
        NoncePolicy::new(HOUR, MAX_STALE_MS).unwrap(),
        1,
        NonceKey::new(Secret::new([key; 32])),
    )
}

fn signing_key() -> &'static EcdsaKeyPair {
    static KEY: OnceLock<EcdsaKeyPair> = OnceLock::new();
    KEY.get_or_init(|| EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap())
}

fn proof(method: &str, uri: &str, jti: &str, nonce: &str, extra: &str) -> String {
    let key = signing_key();
    let point = key.public_key().as_ref();
    let header = format!(
        r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}}}"#,
        b64url_encode(&point[1..33]),
        b64url_encode(&point[33..])
    );
    let payload = format!(
        r#"{{"jti":"{jti}","htm":"{method}","htu":"{uri}","iat":{},"nonce":"{nonce}"{extra}}}"#,
        NOW / 1000
    );
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

async fn db() -> TestDb {
    let db = fresh().await.unwrap();
    open_dpop_replay_day(&db.archive, DAY).await.unwrap();
    db
}

fn request<'a>(proofs: &'a [&'a str], method: &'a str, uri: &'a str) -> DpopRequest<'a> {
    DpopRequest {
        proofs,
        method,
        uri,
        access_token: None,
        bound: None,
    }
}

fn is_replay(r: &Result<impl std::fmt::Debug, Failure>) -> bool {
    matches!(
        r,
        Err(Failure::InvalidProof {
            step: Step::Jti,
            ..
        })
    )
}

// K19, TN-30, IDP-11 step 9
#[tokio::test]
async fn token_endpoint_rejects_a_replayed_proof() {
    let db = db().await;
    let profile = DpopProfile::default();
    let nonces = ring(&R, Role::AuthorizationServer, 1);
    let cache = PgReplayCache::new(db.app.clone(), T, R);
    let clock = Fixed(NOW);
    let checker = DpopChecker::new(&profile, &nonces, &cache, &clock);
    let nonce = checker.nonce().unwrap();
    let p = proof("POST", TOKEN_URI, "c-1", &nonce, "");
    assert!(
        checker
            .check(&request(&[&p], "POST", TOKEN_URI))
            .await
            .is_ok()
    );
    let again = checker.check(&request(&[&p], "POST", TOKEN_URI)).await;
    assert!(is_replay(&again), "{again:?}");
    let other = proof("POST", TOKEN_URI, "c-2", &nonce, "");
    assert!(
        checker
            .check(&request(&[&other], "POST", TOKEN_URI))
            .await
            .is_ok()
    );
}

// K19, TN-28, TN-30
#[tokio::test]
async fn uri_variants_of_a_replay_are_still_replays() {
    let db = db().await;
    let profile = DpopProfile::default();
    let nonces = ring(&R, Role::AuthorizationServer, 1);
    let cache = PgReplayCache::new(db.app.clone(), T, R);
    let clock = Fixed(NOW);
    let checker = DpopChecker::new(&profile, &nonces, &cache, &clock);
    let nonce = checker.nonce().unwrap();
    let p = proof("POST", TOKEN_URI, "v-1", &nonce, "");
    assert!(
        checker
            .check(&request(&[&p], "POST", TOKEN_URI))
            .await
            .is_ok()
    );
    for uri in [
        "https://login.example.com/token?retry=1",
        "https://LOGIN.example.com:443/token#x",
        "https://login.example.com/./token",
    ] {
        let again = checker.check(&request(&[&p], "POST", uri)).await;
        assert!(is_replay(&again), "{uri}: {again:?}");
    }
}

// K19, TN-30
#[tokio::test]
async fn concurrent_replays_across_nodes_have_one_winner() {
    let db = db().await;
    let profile = DpopProfile::default();
    let nonces = ring(&R, Role::AuthorizationServer, 1);
    let nonce = nonces.issue(NOW).unwrap();
    let p = proof("POST", TOKEN_URI, "race", &nonce, "");
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (pool, p, profile) = (db.app.clone(), p.clone(), profile.clone());
        tasks.push(tokio::spawn(async move {
            let nonces = ring(&R, Role::AuthorizationServer, 1);
            let cache = PgReplayCache::new(pool, T, R);
            let clock = Fixed(NOW);
            let checker = DpopChecker::new(&profile, &nonces, &cache, &clock);
            checker
                .check(&request(&[&p], "POST", TOKEN_URI))
                .await
                .is_ok()
        }));
    }
    let mut winners = 0;
    for t in tasks {
        if t.await.unwrap() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
}

// §10.4.3 m.5, K19
#[tokio::test]
async fn resource_server_runs_its_own_replay_check() {
    let db = db().await;
    let profile = DpopProfile::default();
    let rs_nonces = ring(&R, Role::ResourceServer, 2);
    let as_nonces = ring(&R, Role::AuthorizationServer, 1);
    let cache = PgReplayCache::new(db.app.clone(), T, R);
    let clock = Fixed(NOW);
    let rs = DpopChecker::new(&profile, &rs_nonces, &cache, &clock);
    let token = "eyJ0eXAiOiJhdCtqd3QifQ.e30.c2ln";
    let with_ath = format!(r#","ath":"{}""#, ath(token));
    let as_nonce = as_nonces.issue(NOW).unwrap();
    let foreign = proof("GET", API_URI, "rs-0", &as_nonce, &with_ath);
    let proofs = [foreign.as_str()];
    let err = rs
        .check(&DpopRequest {
            access_token: Some(token),
            ..request(&proofs, "GET", API_URI)
        })
        .await
        .unwrap_err();
    assert_eq!(err.error(), "use_dpop_nonce");
    assert_eq!(err.status(Role::ResourceServer), 401);
    let nonce = err.nonce().unwrap().to_owned();
    let p = proof("GET", API_URI, "rs-1", &nonce, &with_ath);
    let proofs = [p.as_str()];
    let at_rs = DpopRequest {
        access_token: Some(token),
        ..request(&proofs, "GET", API_URI)
    };
    assert!(rs.check(&at_rs).await.is_ok());
    let again = rs.check(&at_rs).await;
    assert!(is_replay(&again), "{again:?}");
}

// K19, TN-29, TN-30
#[tokio::test]
async fn realms_are_separate() {
    let db = db().await;
    let profile = DpopProfile::default();
    let other = RealmId::from_bytes([3; 16]);
    let nonces = ring(&R, Role::AuthorizationServer, 1);
    let other_nonces = ring(&other, Role::AuthorizationServer, 1);
    let clock = Fixed(NOW);
    let cache = PgReplayCache::new(db.app.clone(), T, R);
    let other_cache = PgReplayCache::new(db.app.clone(), T, other);
    let here = DpopChecker::new(&profile, &nonces, &cache, &clock);
    let there = DpopChecker::new(&profile, &other_nonces, &other_cache, &clock);
    let p = proof("POST", TOKEN_URI, "x-1", &here.nonce().unwrap(), "");
    assert!(here.check(&request(&[&p], "POST", TOKEN_URI)).await.is_ok());
    let err = there
        .check(&request(&[&p], "POST", TOKEN_URI))
        .await
        .unwrap_err();
    assert_eq!(err.error(), "use_dpop_nonce");
}

// TN-30, MD-8
#[tokio::test]
async fn cache_failure_rejects() {
    let db = fresh().await.unwrap();
    let profile = DpopProfile::default();
    let nonces = ring(&R, Role::AuthorizationServer, 1);
    let cache = PgReplayCache::new(db.app.clone(), T, R);
    let clock = Fixed(NOW);
    let checker = DpopChecker::new(&profile, &nonces, &cache, &clock);
    let p = proof("POST", TOKEN_URI, "f-1", &checker.nonce().unwrap(), "");
    assert_eq!(
        checker.check(&request(&[&p], "POST", TOKEN_URI)).await,
        Err(Failure::Unavailable)
    );
}
