//! CIMD clients, the MCP authorization server profile and the consent record on the real
//! authorization server (OP-154 m.3 (i), (k), OP-153 m.3 (gg)): real PostgreSQL, a real
//! identity signer, documents served in process behind the same SSRF rules for address
//! literals, and the Grants that stand scripted.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "support/mod.rs"]
mod support;

use access_identity_oauth::app::oauth::{NotApproved, Reply};
use access_identity_oauth::ports::oauth::IssuedGrant;
use access_store::clients::NewConsentRecord;
use access_store::identity::TenantTx;
use support::{At, CHALLENGE, Cluster, VERIFIER, body, claims, location, now, query, query_opt};

const APP: &str = "https://app.example/client.json";
const MCP: &str = "https://mcp.example/mcp";
const CB: &str = "https://app.example/cb";
const GRANT: [u8; 16] = [7; 16];

fn doc(extra: &str) -> String {
    format!(r#"{{"client_id":"{APP}","client_name":"App","redirect_uris":["{CB}"]{extra}}}"#)
}

async fn mcp_realm(slug: &str) -> Cluster {
    let c = Cluster::new(&[slug]).await;
    let a = c.at(0);
    a.cimd_policy(true, &["app.example"]).await;
    a.register_resource(MCP).await;
    c
}

async fn ask(a: &At<'_>, client_id: &str, extra: &[(&str, &str)]) -> Reply {
    let mut p = vec![
        ("client_id", client_id),
        ("redirect_uri", CB),
        ("resource", MCP),
    ];
    p.extend_from_slice(extra);
    a.authorize(&p, Some(&a.f.cookie)).await
}

fn problem(r: &Reply) -> &'static str {
    match r {
        Reply::Problem { code, .. } => code,
        other => panic!("not a problem: {other:?}"),
    }
}

async fn cimd_uuid(a: &At<'_>, url: &str) -> Option<[u8; 16]> {
    let mut tx = TenantTx::begin(&a.c.db.app, a.f.realm.tenant, a.f.realm.realm)
        .await
        .unwrap();
    let row = tx.cimd_client(url).await.unwrap();
    tx.commit().await.unwrap();
    row.map(|r| r.client_uuid)
}

/// The person's consent record for the CIMD client, naming a Grant that stands.
async fn consent(a: &At<'_>, scopes: &[&str]) -> [u8; 16] {
    let client = cimd_uuid(a, APP).await.unwrap();
    let scopes: Vec<String> = scopes.iter().map(|s| String::from(*s)).collect();
    let mut tx = TenantTx::begin(&a.c.db.app, a.f.realm.tenant, a.f.realm.realm)
        .await
        .unwrap();
    tx.put_consent_record(&NewConsentRecord {
        subject: a.f.subject,
        client,
        source: "cimd",
        resource: MCP,
        scopes: &scopes,
        metadata_hash: [1; 32],
        grant_domain: a.f.domain,
        grant_ref: GRANT,
        exercise: [2; 32],
        now_ms: now(),
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();
    a.c.oauth
        .env()
        .standing
        .live
        .lock()
        .unwrap()
        .push((a.f.domain, GRANT));
    client
}

async fn live_record(a: &At<'_>, client: [u8; 16]) -> bool {
    let mut tx = TenantTx::begin(&a.c.db.app, a.f.realm.tenant, a.f.realm.realm)
        .await
        .unwrap();
    let r = tx.consent_record(a.f.subject, client, MCP).await.unwrap();
    tx.commit().await.unwrap();
    r.is_some()
}

// IDI-10, IDP-1, Ek B 4180, 4179
#[tokio::test]
async fn a_url_client_id_resolves_only_through_its_document() {
    let c = Cluster::new(&["cimd-idi"]).await;
    let a = c.at(0);
    let docs = &c.oauth.env().documents;
    docs.serve(APP, 200, None, &doc(""));
    // IDI-10
    let off = ask(&a, APP, &[]).await;
    assert_eq!(problem(&off), "invalid-client");
    assert_eq!(docs.fetched(APP), 0, "a realm without CIMD fetches nothing");
    let as_url = format!("https://app.example/{}", a.f.public);
    a.cimd_policy(true, &["app.example"]).await;
    let local_named = ask(&a, &as_url, &[]).await;
    assert_eq!(problem(&local_named), "invalid-client");
    assert!(
        cimd_uuid(&a, &as_url).await.is_none(),
        "a URL never falls back to the registry, whatever its path names"
    );
    let federated = ask(&a, APP, &[("trust_chain", "eyJ")]).await;
    assert_eq!(
        problem(&federated),
        "invalid-client",
        "federation refuses until its resolver"
    );
    assert_eq!(docs.fetched(APP), 0);
    let other = ask(&a, "https://other.example/client.json", &[]).await;
    assert_eq!(problem(&other), "invalid-client", "AS-A2 domain policy");
}

// AG-4, §11.3.6, RFC 6890, Ek B 4535, 4171, 4181
#[tokio::test]
async fn special_purpose_addresses_cancel_the_request() {
    let c = mcp_realm("cimd-ssrf").await;
    let a = c.at(0);
    a.cimd_policy(true, &["app.example", "internal.example"]).await;
    let docs = &c.oauth.env().documents;
    docs.private_hosts
        .lock()
        .unwrap()
        .push(String::from("internal.example"));
    let internal = "https://internal.example/client.json";
    docs.serve(internal, 200, None, &doc("").replace(APP, internal));
    assert_eq!(problem(&ask(&a, internal, &[]).await), "invalid-client");
    assert_eq!(docs.fetched(internal), 0, "never fetched");
    for jwks in [
        "https://10.0.0.1/jwks",
        "https://169.254.169.254/jwks",
        "https://[::ffff:127.0.0.1]/jwks",
    ] {
        docs.serve(
            APP,
            200,
            None,
            &doc(&format!(
                r#","token_endpoint_auth_method":"private_key_jwt","jwks_uri":"{jwks}""#
            )),
        );
        assert_eq!(problem(&ask(&a, APP, &[]).await), "invalid-client", "{jwks}");
        assert!(cimd_uuid(&a, APP).await.is_none(), "nothing kept: {jwks}");
    }
}

// §11.3.1, §11.4.5 #14, AG-4, Ek B 4537, 4624, 4169, 4170, 4536
#[tokio::test]
async fn refused_documents_and_answers_cancel_and_are_never_cached() {
    let c = mcp_realm("cimd-bad").await;
    let a = c.at(0);
    let docs = &c.oauth.env().documents;
    for (status, body) in [
        (200, doc(r#","client_secret":"s3cret""#)),
        (200, doc(r#","token_endpoint_auth_method":"client_secret_basic""#)),
        (200, doc("").replace(APP, "https://app.example/other.json")),
        (200, String::from("not json")),
        (302, doc("")),
        (404, doc("")),
        (200, doc(&format!(r#","pad":"{}""#, "x".repeat(6 * 1024)))),
    ] {
        docs.serve(APP, status, Some(3_600), &body);
        let before = docs.fetched(APP);
        assert_eq!(problem(&ask(&a, APP, &[]).await), "invalid-client", "{status} {body}");
        assert_eq!(docs.fetched(APP), before + 1);
        assert!(cimd_uuid(&a, APP).await.is_none());
    }
    assert_eq!(problem(&ask(&a, APP, &[]).await), "invalid-client");
    assert_eq!(docs.fetched(APP), 8, "a refusal is not cached: fetched again");
}

// §11.6, P58, EI-18, AG-7, AG-8, §11.4.5 #4, #7, #21, Ek B 4246, 4251, 4187, 4425
#[tokio::test]
async fn a_cimd_client_waits_on_a_consent_record_whose_grant_stands() {
    let c = mcp_realm("cimd-flow").await;
    let a = c.at(0);
    let docs = &c.oauth.env().documents;
    docs.serve(APP, 200, Some(3_600), &doc(""));
    let asked = location(&ask(&a, APP, &[]).await);
    assert!(asked.contains("/login?"), "{asked}");
    assert_eq!(query(&asked, "reason"), "approve");
    let silent = location(&ask(&a, APP, &[("prompt", "none")]).await);
    assert_eq!(query(&silent, "error"), "consent_required");
    assert_eq!(query(&silent, "iss"), a.issuer(), "AG-7 on errors too");
    assert_eq!(docs.fetched(APP), 1, "the snapshot is the cache within its bounds");
    let client = consent(&a, &["openid"]).await;
    let ok = location(&ask(&a, APP, &[]).await);
    assert!(ok.starts_with(CB), "{ok}");
    assert_eq!(query(&ok, "iss"), a.issuer());
    let code = query(&ok, "code");
    let t = body(
        &a.token(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", APP),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            None,
        )
        .await,
        200,
    );
    let at = claims(t["access_token"].as_str().unwrap());
    assert_eq!(at["aud"], MCP, "one audience: the registered resource");
    assert_eq!(at["client_id"], APP);
    let wider = location(&ask(&a, APP, &[("scope", "openid email")]).await);
    assert_eq!(
        query(&wider, "reason"),
        "approve",
        "the record covers its scopes only"
    );
    a.c.oauth.env().standing.live.lock().unwrap().clear();
    let lapsed = location(&ask(&a, APP, &[]).await);
    assert_eq!(query(&lapsed, "reason"), "approve", "no standing Grant, no code");
    assert!(!live_record(&a, client).await, "the record ends with its Grant");
    assert!(query_opt(&lapsed, "code").is_none());
    let _ = CHALLENGE;
}

// AG-8, §11.4.3, Ek B 4161
#[tokio::test]
async fn a_cimd_client_names_one_registered_resource() {
    let c = mcp_realm("cimd-res").await;
    let a = c.at(0);
    c.oauth.env().documents.serve(APP, 200, None, &doc(""));
    for resource in ["", "https://unknown.example/mcp", "https://mcp.example/mcp#x"] {
        let r = location(&ask(&a, APP, &[("resource", resource)]).await);
        assert_eq!(query(&r, "error"), "invalid_target", "{resource:?}");
        assert_eq!(query(&r, "iss"), a.issuer());
    }
    consent(&a, &["openid"]).await;
    let upper = location(&ask(&a, APP, &[("resource", "https://MCP.example/mcp/")]).await);
    assert!(
        query_opt(&upper, "code").is_some(),
        "the canonical form is accepted: {upper}"
    );
}

// AG-5, Ek B 4175, 4250
#[tokio::test]
async fn an_authority_change_asks_again_and_a_visual_one_only_warns() {
    let c = mcp_realm("cimd-change").await;
    let a = c.at(0);
    let docs = &c.oauth.env().documents;
    docs.serve(APP, 200, Some(0), &doc(""));
    ask(&a, APP, &[]).await;
    let client = consent(&a, &["openid"]).await;
    let expire = || async {
        let mut tx = TenantTx::begin(&a.c.db.app, a.f.realm.tenant, a.f.realm.realm)
            .await
            .unwrap();
        sqlx_expire(&mut tx, client).await;
        tx.commit().await.unwrap();
    };
    expire().await;
    docs.serve(APP, 200, None, &doc("").replace("\"App\"", "\"App Pro\""));
    let renamed = location(&ask(&a, APP, &[]).await);
    assert!(query_opt(&renamed, "code").is_some(), "a new name only warns");
    assert!(live_record(&a, client).await);
    expire().await;
    docs.serve(APP, 200, None, &doc(r#","scope":"openid email""#));
    let moved = location(&ask(&a, APP, &[]).await);
    assert_eq!(query(&moved, "reason"), "approve");
    assert!(!live_record(&a, client).await, "the record ends");
    assert!(
        a.c.oauth.env().plane.revoked.lock().unwrap().is_empty(),
        "no Grant is revoked"
    );
}

/// Makes the client's snapshot stale now.
async fn sqlx_expire(tx: &mut TenantTx, client: [u8; 16]) {
    let row = tx.cimd_client(APP).await.unwrap().unwrap();
    assert_eq!(row.client_uuid, client);
    let snap = access_store::clients::CimdSnapshot {
        document: &row.document,
        document_hash: row.document_hash,
        authority_hash: row.authority_hash,
        visual_hash: row.visual_hash,
        logo: None,
        fetched_ms: u64::try_from(row.first_seen_ms).unwrap(),
        fresh_until_ms: u64::try_from(row.first_seen_ms).unwrap() + 1,
    };
    assert!(tx.refresh_cimd_client(client, &snap, false).await.unwrap());
}

// AG-5, §11.3.6 §8.3, HL-36, Ek B 4176
#[tokio::test]
async fn a_domain_the_policy_drops_retires_its_clients() {
    let c = mcp_realm("cimd-retire").await;
    let a = c.at(0);
    c.oauth.env().documents.serve(APP, 200, None, &doc(""));
    ask(&a, APP, &[]).await;
    let client = consent(&a, &["openid"]).await;
    let ok = location(&ask(&a, APP, &[]).await);
    let code = query(&ok, "code");
    let t = body(
        &a.token(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", APP),
                ("code", &code),
                ("redirect_uri", CB),
                ("code_verifier", VERIFIER),
            ],
            None,
        )
        .await,
        200,
    );
    a.cimd_policy(true, &["other.example"]).await;
    assert_eq!(problem(&ask(&a, APP, &[]).await), "invalid-client");
    assert!(cimd_uuid(&a, APP).await.is_none(), "retired");
    assert!(!live_record(&a, client).await);
    let refreshed = a
        .token(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", APP),
                ("refresh_token", t["refresh_token"].as_str().unwrap()),
            ],
            None,
        )
        .await;
    assert_eq!(body(&refreshed, 401)["error"], "invalid_client");
    a.cimd_policy(true, &["app.example"]).await;
    ask(&a, APP, &[]).await;
    let again = cimd_uuid(&a, APP).await.unwrap();
    assert_ne!(again, client, "the same URL is a new client");
}

// §11.8.3, AG-6, AG-18, Ek B 4488, 4248
#[tokio::test]
async fn claude_codes_published_document_signs_in_on_any_loopback_port() {
    let c = Cluster::new(&["cimd-claude"]).await;
    let a = c.at(0);
    a.cimd_policy(true, &["claude.ai"]).await;
    a.register_resource(MCP).await;
    let url = "https://claude.ai/oauth/claude-code-client-metadata";
    let published = include_str!("fixtures/cimd/claude-code.json");
    c.oauth.env().documents.serve(url, 200, None, published);
    let r = a
        .authorize(
            &[
                ("client_id", url),
                ("redirect_uri", "http://127.0.0.1:53682/callback"),
                ("resource", MCP),
            ],
            Some(&a.f.cookie),
        )
        .await;
    assert_eq!(query(&location(&r), "reason"), "approve");
    let wrong = a
        .authorize(
            &[
                ("client_id", url),
                ("redirect_uri", "http://127.0.0.1:53682/other"),
                ("resource", MCP),
            ],
            Some(&a.f.cookie),
        )
        .await;
    assert_eq!(problem(&wrong), "invalid-redirect-uri");
}

const PARTY: [u8; 16] = [0x50; 16];

async fn bind_party(a: &At<'_>) {
    let mut tx = TenantTx::begin(&a.c.db.app, a.f.realm.tenant, a.f.realm.realm)
        .await
        .unwrap();
    access_store::idp::bind_subject_party(&mut tx, &a.f.subject, &PARTY)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn return_to_of(asked: &str) -> String {
    query(asked, "return_to")
}

// EI-18, §11.6, P58, Ek B 4246, 4251, 4541, 4542
#[tokio::test]
async fn only_the_persons_own_allowed_grant_issue_records_a_consent() {
    let c = mcp_realm("cimd-approve").await;
    let a = c.at(0);
    bind_party(&a).await;
    c.oauth.env().documents.serve(APP, 200, None, &doc(""));
    let asked = location(&ask(&a, APP, &[]).await);
    let back = return_to_of(&asked);
    let realm = a.realm();
    let exercise = [0x33; 32];
    // EI-18
    let none = c
        .oauth
        .approve(realm, Some(&a.f.cookie), &back, a.f.domain, exercise)
        .await
        .unwrap();
    assert_eq!(none, Err(NotApproved::NoGrant), "consent without an AAS Grant");
    let standing = &c.oauth.env().standing;
    standing.live.lock().unwrap().push((a.f.domain, GRANT));
    standing.issued.lock().unwrap().push((
        a.f.domain,
        exercise,
        IssuedGrant {
            grant: GRANT,
            holder: [0x51; 16],
            signer: PARTY,
        },
    ));
    let other = c
        .oauth
        .approve(realm, Some(&a.f.cookie), &back, a.f.domain, exercise)
        .await
        .unwrap();
    assert_eq!(other, Err(NotApproved::NoGrant), "held by someone else");
    // §11.6 rule 5
    let anonymous = c
        .oauth
        .approve(realm, None, &back, a.f.domain, exercise)
        .await
        .unwrap();
    assert_eq!(anonymous, Err(NotApproved::SignIn));
    standing.issued.lock().unwrap()[0].2.holder = PARTY;
    let client = cimd_uuid(&a, APP).await.unwrap();
    assert!(!live_record(&a, client).await);
    let ok = c
        .oauth
        .approve(realm, Some(&a.f.cookie), &back, a.f.domain, exercise)
        .await
        .unwrap();
    assert_eq!(ok.as_deref(), Ok(back.as_str()));
    assert!(live_record(&a, client).await);
    let p = access_identity_oauth::domain::request::Params::parse(back.split_once('?').unwrap().1)
        .unwrap();
    let pairs: Vec<(&str, &str)> = [("client_id", APP), ("request_uri", p.get("request_uri").unwrap())]
        .into_iter()
        .collect();
    let code = a.authorize(&pairs, Some(&a.f.cookie)).await;
    let to = location(&code);
    assert!(to.starts_with(CB) && query_opt(&to, "code").is_some(), "{to}");
}

// AS-M14, AG-6, §11.3, OP-154 m.3 (i), Ek B 4247, 4248, 4249, 4250
#[tokio::test]
async fn the_consent_screen_shows_hostnames_and_the_clients_claims_as_claims() {
    let c = mcp_realm("cimd-view").await;
    let a = c.at(0);
    a.cimd_policy(true, &["app.example", "claude.ai"]).await;
    let url = "https://claude.ai/oauth/claude-code-client-metadata";
    c.oauth.env().documents.serve(
        url,
        200,
        None,
        include_str!("fixtures/cimd/claude-code.json"),
    );
    let asked = location(
        &a.authorize(
            &[
                ("client_id", url),
                ("redirect_uri", "http://localhost:4242/callback"),
                ("resource", MCP),
            ],
            Some(&a.f.cookie),
        )
        .await,
    );
    let v = c
        .oauth
        .approval_view(a.realm(), Some(&a.f.cookie), &return_to_of(&asked))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v.client_host, "claude.ai");
    assert_eq!(v.client_says, "Claude Code");
    assert_eq!(v.redirect_hosts, vec!["127.0.0.1", "localhost"]);
    assert!(v.loopback_only, "AG-6: the extra warning");
    assert!(v.new_app);
    assert!(!v.visual_changed);
    assert_eq!(v.resource, MCP);
    let signed_out = c
        .oauth
        .approval_view(a.realm(), None, &return_to_of(&asked))
        .await
        .unwrap();
    assert_eq!(signed_out, Err(NotApproved::SignIn));
    let elsewhere = c
        .oauth
        .approval_view(a.realm(), Some(&a.f.cookie), "/authorize?client_id=x")
        .await
        .unwrap();
    assert_eq!(elsewhere, Err(NotApproved::NoRequest));
}
