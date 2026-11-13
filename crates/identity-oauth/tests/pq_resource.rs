//! A protected resource's access tokens in the algorithm its registration names (CR-41, CR-43,
//! OP-159 m.3 (o), m.21 (b), (g), OP-153 m.3 (gg)): real PostgreSQL and a real identity signer.
//! While the realm's signing profile holds ML-DSA-65 the token is ML-DSA-65 and verifies with the
//! realm's `AKP` keys; once the profile closes the token is refused, never signed classically.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "support/mod.rs"]
mod support;

use access_identity_oauth::app::oauth::Reply;
use access_identity_oauth::ports::oauth::TokenSigner as _;
use access_kernel::verify::jws::{Origin, verify_compact};
use access_store::clients::NewConsentRecord;
use access_store::identity::TenantTx;
use support::{At, Cluster, VERIFIER, body, header, location, now, query};

const APP: &str = "https://app.example/client.json";
const MCP: &str = "https://mcp.example/mcp";
const TOOLS: &str = "https://tools.example/api";
const CB: &str = "https://app.example/cb";
const GRANT: [u8; 16] = [7; 16];

async fn consent(a: &At<'_>, resource: &str) {
    let mut tx = TenantTx::begin(&a.c.db.app, a.f.realm.tenant, a.f.realm.realm)
        .await
        .unwrap();
    let client = tx.cimd_client(APP).await.unwrap().unwrap().client_uuid;
    tx.put_consent_record(&NewConsentRecord {
        subject: a.f.subject,
        client,
        source: "cimd",
        resource,
        scopes: &[String::from("openid")],
        metadata_hash: [1; 32],
        grant_domain: a.f.domain,
        grant_ref: GRANT,
        exercise: [2; 32],
        now_ms: now(),
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// The CIMD client's access token for `resource`, or the token endpoint's answer.
async fn token_for(a: &At<'_>, resource: &str) -> Reply {
    let p = [
        ("client_id", APP),
        ("redirect_uri", CB),
        ("resource", resource),
    ];
    let ok = location(&a.authorize(&p, Some(&a.f.cookie)).await);
    assert!(ok.starts_with(CB), "{ok}");
    let code = query(&ok, "code");
    a.token(
        &[
            ("grant_type", "authorization_code"),
            ("client_id", APP),
            ("code", &code),
            ("redirect_uri", CB),
            ("code_verifier", VERIFIER),
        ],
        None,
    )
    .await
}

// CR-41, CR-43, MD-8, OP-159 m.3 (o), (p), m.21 (b), (g)
#[tokio::test]
async fn a_resource_registered_for_ml_dsa_gets_ml_dsa_access_tokens_or_none() {
    let c = Cluster::new_pq(&["pq-rs"], access_crypto::jose::JwsAlg::MlDsa65).await;
    let a = c.at(0);
    a.cimd_policy(true, &["app.example"]).await;
    a.register_resource_with(MCP, Some("ML-DSA-65")).await;
    a.register_resource(TOOLS).await;
    a.signing_profile(Some("ml-dsa-65")).await;
    let docs = &c.oauth.env().documents;
    docs.serve(
        APP,
        200,
        Some(3_600),
        &format!(r#"{{"client_id":"{APP}","client_name":"App","redirect_uris":["{CB}"]}}"#),
    );
    let _ = a
        .authorize(
            &[("client_id", APP), ("redirect_uri", CB), ("resource", MCP)],
            Some(&a.f.cookie),
        )
        .await;
    consent(&a, MCP).await;
    consent(&a, TOOLS).await;
    c.oauth
        .env()
        .standing
        .live
        .lock()
        .unwrap()
        .push((a.f.domain, GRANT));

    let t = body(&token_for(&a, MCP).await, 200);
    let token = t["access_token"].as_str().unwrap();
    assert_eq!(header(token)["alg"], "ML-DSA-65");
    assert!(
        access_crypto::budget::Carrier::Header
            .check(token.len())
            .is_ok()
    );
    let jwks = c.oauth.env().signer.jwks(a.f.realm.realm).await.unwrap();
    let keys = access_identity_oauth::domain::jwt::realm_key_set(jwks.as_bytes()).unwrap();
    let v = verify_compact(
        &suiss_crypto::aws::AwsLcBackend,
        token,
        &keys,
        "at+jwt",
        Origin::Native,
    )
    .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&v.payload).unwrap();
    assert_eq!(claims["aud"], MCP);

    let t = body(&token_for(&a, TOOLS).await, 200);
    assert_ne!(
        header(t["access_token"].as_str().unwrap())["alg"],
        "ML-DSA-65",
        "a resource without its own algorithm takes the realm's"
    );

    // OP-159 m.21 (b)
    a.signing_profile(None).await;
    let refused = token_for(&a, MCP).await;
    assert!(
        !matches!(&refused, Reply::Json { status: 200, .. }),
        "{refused:?}"
    );
}
