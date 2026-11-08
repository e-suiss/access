//! TN-130, TN-27, OP-151 m.3 (a), (c): the management read token exchange at the realm's token
//! endpoint. Real PostgreSQL and identity signer; the authority plane's live Instance keys are
//! scripted.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "support/mod.rs"]
mod support;

use access_identity_oauth::domain::jwt::realm_key_set;
use access_identity_oauth::domain::management::{
    ACCESS_TOKEN_TYPE, AIS_TOKEN_TYPE, PLATFORM_AUDIENCE, PLATFORM_READ, READ_TTL_MS, REALM_READ,
    TOKEN_EXCHANGE, exchange_intent, read_claims,
};
use access_identity_oauth::ports::oauth::TokenSigner as _;
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Id;
use access_kernel::verify::key_scope::thumbprint;
use access_store::identity::TenantTx;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};
use support::{At, Cluster, body, error, now};

/// One Instance key, as the AIS signer and as the DPoP key.
struct Instance {
    signer: SoftSigner,
    pkcs8: Vec<u8>,
}

impl Instance {
    fn new() -> Self {
        let (signer, pkcs8) = SoftSigner::generate_p256().unwrap();
        Self {
            signer,
            pkcs8: pkcs8.expose().clone(),
        }
    }

    fn dpop(&self) -> EcdsaKeyPair {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &self.pkcs8).unwrap()
    }

    fn kid(&self) -> [u8; 32] {
        thumbprint(&self.signer.public_key())
    }

    fn ais(&self, domain: [u8; 32], intent: Digest, mode: Mode, nonce: u8) -> String {
        let s = Statement {
            domain: Digest(domain),
            nonce: vec![nonce; 16],
            intent,
            mode,
            pep: String::from("access-identity"),
            capacity: Capacity::Own,
            basis: ExerciseBasis::Public(Id([1; 16])),
            iat: now(),
            exercise: None,
        };
        let payload = dcbor::encode(&s.to_value(), Limits::CEILING).unwrap();
        let sign1 = sign_sign1(
            &self.signer as &dyn Signer,
            self.kid(),
            CONTENT_TYPE,
            &payload,
        )
        .unwrap();
        b64url_encode(&sign1)
    }
}

async fn governing(c: &Cluster, at: &At<'_>) -> [u8; 32] {
    let mut t = TenantTx::begin(&c.db.app, at.f.realm.tenant, at.f.realm.realm)
        .await
        .unwrap();
    let g = access_store::idp::governance(&mut t)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    *g.domain.as_bytes()
}

fn live(c: &Cluster, domain: [u8; 32], i: &Instance) {
    c.env()
        .management
        .keys
        .lock()
        .unwrap()
        .insert((domain, i.kid()), i.signer.public_key());
}

async fn exchange(
    at: &At<'_>,
    audience: &str,
    scope: &str,
    ais: &str,
) -> access_identity_oauth::app::oauth::Reply {
    at.token(
        &[
            ("grant_type", TOKEN_EXCHANGE),
            ("subject_token_type", AIS_TOKEN_TYPE),
            ("subject_token", ais),
            ("audience", audience),
            ("scope", scope),
        ],
        None,
    )
    .await
}

// TN-130, TN-27, OP-151 m.3 (c)
#[tokio::test]
async fn tn_130_an_instance_exchanges_its_statement_for_a_bound_read_token() {
    let c = Cluster::new(&["mgmtread"]).await;
    let at = c.at(0);
    let domain = governing(&c, &at).await;
    let i = Instance::new();
    live(&c, domain, &i);
    let at = at.with_key(i.dpop());
    let audience = "access-admin:realm:mgmtread";
    let ais = i.ais(
        domain,
        exchange_intent(audience, REALM_READ),
        Mode::Check,
        1,
    );
    let t = body(&exchange(&at, audience, REALM_READ, &ais).await, 200);
    assert_eq!(t["issued_token_type"], ACCESS_TOKEN_TYPE);
    assert_eq!(t["token_type"], "DPoP");
    assert_eq!(t["scope"], REALM_READ);
    assert_eq!(t["expires_in"], READ_TTL_MS / 1000);
    let jwks = c.env().signer.jwks(at.f.realm.realm).await.unwrap();
    let keys = realm_key_set(jwks.as_bytes()).unwrap();
    let claims = read_claims(t["access_token"].as_str().unwrap(), &keys, at.issuer()).unwrap();
    assert_eq!(claims.aud, audience);
    assert_eq!(claims.scopes, [REALM_READ]);
    assert_eq!(claims.jkt, i.kid());
    assert_eq!(claims.instance, i.kid());
    assert!(claims.exp_ms - claims.iat_ms <= 3_600_000);
    // TN-130
    assert_eq!(
        error(&exchange(&at, audience, REALM_READ, &ais).await),
        "invalid_grant"
    );
}

// TN-130, TN-27
#[tokio::test]
async fn tn_130_the_exchange_refuses_everything_but_the_instances_own_read() {
    let c = Cluster::new(&["mgmtrefuse"]).await;
    let base = c.at(0);
    let domain = governing(&c, &base).await;
    let audience = "access-admin:realm:mgmtrefuse";
    let intent = exchange_intent(audience, REALM_READ);
    let stranger = Instance::new();
    let at = base.with_key(Instance::new().dpop());
    let ais = stranger.ais(domain, intent, Mode::Check, 2);
    assert_eq!(
        error(&exchange(&at, audience, REALM_READ, &ais).await),
        "invalid_grant"
    );
    let unknown = Instance::new();
    let ais = unknown.ais(domain, intent, Mode::Check, 3);
    let at = base.with_key(unknown.dpop());
    assert_eq!(
        error(&exchange(&at, audience, REALM_READ, &ais).await),
        "invalid_grant"
    );
    let i = Instance::new();
    live(&c, domain, &i);
    let commit = i.ais(domain, intent, Mode::Commit, 4);
    let wrong = i.ais(
        domain,
        exchange_intent(audience, PLATFORM_READ),
        Mode::Check,
        5,
    );
    let foreign = i.ais([1; 32], intent, Mode::Check, 6);
    let ok = i.ais(domain, intent, Mode::Check, 7);
    let platform = i.ais(
        domain,
        exchange_intent(PLATFORM_AUDIENCE, PLATFORM_READ),
        Mode::Check,
        8,
    );
    let at = base.with_key(i.dpop());
    for ais in [&commit, &wrong, &foreign] {
        assert_eq!(
            error(&exchange(&at, audience, REALM_READ, ais).await),
            "invalid_grant"
        );
    }
    assert_eq!(
        error(&exchange(&at, "access-admin:realm:other", REALM_READ, &ok).await),
        "invalid_target"
    );
    assert_eq!(
        error(&exchange(&at, PLATFORM_AUDIENCE, PLATFORM_READ, &platform).await),
        "invalid_target"
    );
    assert_eq!(
        error(&exchange(&at, audience, "realm.write", &ok).await),
        "invalid_scope"
    );
    let with_client = at
        .token(
            &[
                ("grant_type", TOKEN_EXCHANGE),
                ("subject_token_type", AIS_TOKEN_TYPE),
                ("subject_token", &ok),
                ("audience", audience),
                ("client_id", &at.f.public),
                ("client_assertion", "x"),
            ],
            None,
        )
        .await;
    assert_eq!(error(&with_client), "invalid_request");
    let bearer = at
        .token_with(
            &[
                ("grant_type", TOKEN_EXCHANGE),
                ("subject_token_type", AIS_TOKEN_TYPE),
                ("subject_token", &ok),
                ("audience", audience),
            ],
            None,
            &[],
        )
        .await;
    assert_eq!(error(&bearer), "invalid_dpop_proof");
    *c.env().management.platform.lock().unwrap() = Some(at.f.realm.realm);
    let t = body(
        &exchange(&at, PLATFORM_AUDIENCE, PLATFORM_READ, &platform).await,
        200,
    );
    assert_eq!(t["scope"], PLATFORM_READ);
}
