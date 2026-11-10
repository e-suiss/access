//! OpenID Federation clients on the real authorization server (OP-155 m.3 (j), IDP-1, IDP-19,
//! IDP-20, OP-153 m.3 (gg)): real PostgreSQL, a real identity signer, federation documents served
//! in process behind the guarded outbound rules, statements signed at test time.

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

use access_identity_oauth::app::oauth::Reply;
use access_identity_oidf::testing::Entity;
use access_kernel::json::{self, Json};
use access_store::identity::TenantTx;
use access_store::oidf::FederationSettingsRow;
use support::{At, Cluster, location, now, query};

const TA: &str = "https://ta.example";
const RP: &str = "https://rp.example";
const CONFLICTED: &str = "https://rp2.example";
const CB: &str = "https://rp.example/cb";
const MCP: &str = "https://mcp.example/mcp";
const WELL_KNOWN: &str = "/.well-known/openid-federation";

fn j(s: &str) -> Json {
    json::parse(s.as_bytes(), 1 << 16).unwrap()
}

fn rp_metadata(id: &str) -> Json {
    j(&format!(
        r#"{{"openid_relying_party":{{"client_name":"Federated","redirect_uris":["{}/cb"]}}}}"#,
        id
    ))
}

async fn federate(a: &At<'_>, ta: &Entity) {
    let mut tx = TenantTx::begin(&a.c.db.app, a.f.realm.tenant, a.f.realm.realm)
        .await
        .unwrap();
    let b = a.bound(&mut tx, "idp.federation.enable").await;
    tx.put_federation_settings(
        &b,
        &FederationSettingsRow {
            enabled: true,
            ..FederationSettingsRow::default()
        },
    )
    .await
    .unwrap();
    let b = a.bound(&mut tx, "idp.federation.trust_anchor_add").await;
    let jwks = access_crypto::jose::output::to_string(&ta.key.jwks());
    tx.put_trust_anchor(&b, &ta.id, jwks.as_bytes(), true)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn ask(a: &At<'_>, client_id: &str, extra: &[(&str, &str)]) -> Reply {
    let cb = format!("{client_id}/cb");
    let mut p = vec![
        ("client_id", client_id),
        ("redirect_uri", cb.as_str()),
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

async fn rows(a: &At<'_>, id: &str) -> (bool, bool) {
    let mut tx = TenantTx::begin(&a.c.db.app, a.f.realm.tenant, a.f.realm.realm)
        .await
        .unwrap();
    let oidf = tx.oidf_client(id).await.unwrap().is_some();
    let cimd = tx.cimd_client(id).await.unwrap().is_some();
    tx.commit().await.unwrap();
    (oidf, cimd)
}

fn fetch_url(ta: &Entity, sub: &str) -> String {
    format!(
        "{}?sub={}",
        ta.fetch_endpoint(),
        sub.replace(':', "%3A").replace('/', "%2F")
    )
}

// IDP-1, IDI-10, IDP-19, IDP-20, OP-155 m.3 (j), OP-154 m.8 (a), Ek B 4745, 4746, 4747, 4750
#[tokio::test]
async fn a_url_client_id_with_a_chain_resolves_through_federation_only() {
    let c = Cluster::new(&["oidf-rp"]).await;
    let a = c.at(0);
    a.register_resource(MCP).await;
    let docs = &c.oauth.env().documents;
    let t = now();
    let (iat, exp) = (t - 1_000, t + 3_600_000);
    let ta = Entity::new(TA).unwrap();
    let rp = Entity::new(RP).unwrap();
    let bad = Entity::new(CONFLICTED).unwrap();
    let ta_meta = j(&format!(
        r#"{{"federation_entity":{{"federation_fetch_endpoint":"{}"}}}}"#,
        ta.fetch_endpoint()
    ));
    docs.serve(
        &format!("{TA}{WELL_KNOWN}"),
        200,
        None,
        &ta.config(&[], &ta_meta, iat, exp),
    );
    docs.serve(
        &format!("{RP}{WELL_KNOWN}"),
        200,
        None,
        &rp.config(&[TA], &rp_metadata(RP), iat, exp),
    );
    docs.serve(
        &fetch_url(&ta, RP),
        200,
        None,
        &ta.about(&rp, None, iat, exp),
    );
    // IDI-10
    let off = ask(&a, RP, &[]).await;
    assert_eq!(problem(&off), "invalid-client", "no federation, no CIMD");
    assert_eq!(docs.fetched(&format!("{RP}{WELL_KNOWN}")), 0);
    let chained = ask(&a, RP, &[("trust_chain", "[]")]).await;
    assert_eq!(
        problem(&chained),
        "invalid-client",
        "a trust_chain in a realm that is no leaf"
    );
    federate(&a, &ta).await;
    let asked = location(&ask(&a, RP, &[]).await);
    assert!(asked.contains("/login?"), "{asked}");
    // IDP-20
    assert_eq!(
        query(&asked, "reason"),
        "approve",
        "a federated client still asks the person: the chain is not an Acceptance"
    );
    assert_eq!(
        rows(&a, RP).await,
        (true, false),
        "resolved by OIDF, never by CIMD"
    );
    assert_eq!(docs.fetched(&format!("{RP}{WELL_KNOWN}")), 1);
    let again = location(&ask(&a, RP, &[]).await);
    assert_eq!(query(&again, "reason"), "approve");
    assert_eq!(
        docs.fetched(&format!("{RP}{WELL_KNOWN}")),
        1,
        "a fresh chain is kept within one hour and its exp"
    );
    // IDP-19
    let conflict =
        j(r#"{"openid_relying_party":{"client_name":{"value":"A","one_of":["B","C"]}}}"#);
    docs.serve(
        &format!("{CONFLICTED}{WELL_KNOWN}"),
        200,
        None,
        &bad.config(&[TA], &rp_metadata(CONFLICTED), iat, exp),
    );
    docs.serve(
        &fetch_url(&ta, CONFLICTED),
        200,
        None,
        &ta.about(&bad, Some(&conflict), iat, exp),
    );
    let refused = ask(&a, CONFLICTED, &[]).await;
    assert_eq!(
        problem(&refused),
        "invalid-client",
        "a policy conflict refuses the chain"
    );
    assert_eq!(rows(&a, CONFLICTED).await, (false, false));
    let offline = format!(
        r#"["{}","{}","{}"]"#,
        bad.config(&[TA], &rp_metadata(CONFLICTED), iat, exp),
        ta.about(&bad, Some(&conflict), iat, exp),
        ta.config(&[], &ta_meta, iat, exp)
    );
    let refused = ask(&a, CONFLICTED, &[("trust_chain", &offline)]).await;
    assert_eq!(problem(&refused), "invalid-client");
    let _ = CB;
}
