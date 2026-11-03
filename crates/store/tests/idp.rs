//! MD-14, EI-25, TN-110, OP-146 I10: identity plane configuration is written only against a
//! committed ALLOW of an `idp.*` action in the realm's governing domain.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::fmt::Write as _;
use std::time::Duration;

use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{
    ClientRow, Decision, SettingsRow, bind, client, create_settings, governance, insert_client,
    mappers, retire_client, set_mapper, settings, update_client, update_settings,
};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

const TTL: Duration = Duration::from_secs(10);
const ALLOW_NONCE: [u8; 16] = [1; 16];
const INTENT: [u8; 32] = [9; 32];

/// A domain whose log holds ALLOW decisions at positions 1..=allows and one DENY after them.
async fn domain(db: &TestDb, t: TenantId, seed: u8, allows: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let (lease, mut head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    for i in 1..=allows + 1 {
        let pos = head.pos + 1;
        let leaf = [seed.wrapping_add(i); 32];
        let outcome = if i <= allows { "allow" } else { "deny" };
        let next = HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        };
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: leaf,
                envelope: vec![0xa1, i],
            }],
            head: next.clone(),
            nonces: vec![NonceRow {
                nonce: vec![i; 16],
                actor: vec![1],
                intent_digest: INTENT,
                decision_pos: pos,
                outcome: String::from(outcome),
            }],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

async fn realm(db: &TestDb, t: TenantId, d: &DomainId, slug: &str) -> RealmId {
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, d, slug, "pool-default")
        .await
        .unwrap();
    tx.enter_realm(r).await.unwrap();
    create_settings(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    r
}

fn decision<'a>(d: &'a DomainId, position: u64, nonce: &'a [u8], action: &'a str) -> Decision<'a> {
    Decision {
        domain: d,
        position,
        nonce,
        intent: INTENT,
        change: [5; 32],
        action,
    }
}

fn client_row(seed: u8) -> ClientRow {
    ClientRow {
        client_uuid: [seed; 16],
        client_id: format!(
            "cli_{}",
            "a".repeat(25) + &char::from(b'a' + seed % 20).to_string()
        ),
        display_name: String::from("Shop"),
        auth_method: String::from("none"),
        jwks_uri: None,
        redirect_uris: vec![String::from("https://shop.example/cb")],
        active: true,
    }
}

// EI-25, MD-14, TN-15: a client is written only with an ALLOW bound in its transaction; the
// same decision binds once, and a retry finds it already bound
#[tokio::test]
async fn a_client_is_written_against_its_committed_allow() {
    // TN-110, IDP-7, OP-73
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 10, 3).await;
    let r = realm(&db, t, &d, "acme").await;

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let gov = governance(&mut tx).await.unwrap().unwrap();
    assert!(gov.domain == d && gov.slug == "acme" && gov.issuer.is_none());
    let b = bind(
        &mut tx,
        &decision(&d, 1, &ALLOW_NONCE, "idp.client.register"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(b.position(), 1);
    let c = client_row(1);
    insert_client(&mut tx, &b, &c).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        bind(
            &mut tx,
            &decision(&d, 1, &ALLOW_NONCE, "idp.client.register")
        )
        .await
        .unwrap()
        .is_none()
    );
    let mut changed = c.clone();
    changed.redirect_uris = vec![String::from("http://127.0.0.1/cb")];
    let b = bind(&mut tx, &decision(&d, 2, &[2; 16], "idp.client.update"))
        .await
        .unwrap()
        .unwrap();
    assert!(update_client(&mut tx, &b, &changed).await.unwrap());
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(client(&mut tx, &c.client_id).await.unwrap(), Some(changed));
    let b = bind(&mut tx, &decision(&d, 3, &[3; 16], "idp.client.retire"))
        .await
        .unwrap()
        .unwrap();
    assert!(retire_client(&mut tx, &b, &c.client_id).await.unwrap());
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(!client(&mut tx, &c.client_id).await.unwrap().unwrap().active);
}

async fn refused(db: &TestDb, t: TenantId, r: RealmId, d: &Decision<'_>) {
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(bind(&mut tx, d).await.is_err());
}

// EI-25: a DENY, an unknown position, another intent, or a decision of a domain that only
// consumes the realm does not bind (§12.1.1 2a: its idp.* commit has no authority here)
#[tokio::test]
async fn only_an_allow_of_the_governing_domain_binds() {
    // MD-5a, TN-1, INV-37, MD-14
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 20, 1).await;
    let other = domain(&db, t, 40, 1).await;
    let r = realm(&db, t, &d, "acme-b").await;
    let deny = decision(&d, 2, &[2; 16], "idp.client.register");
    refused(&db, t, r, &deny).await;
    refused(&db, t, r, &decision(&d, 9, &[9; 16], "idp.client.register")).await;
    let mut wrong = decision(&d, 1, &ALLOW_NONCE, "idp.client.register");
    wrong.intent = [8; 32];
    refused(&db, t, r, &wrong).await;
    refused(
        &db,
        t,
        r,
        &decision(&other, 1, &ALLOW_NONCE, "idp.client.register"),
    )
    .await;
}

// EI-25, TN-110: no write path around the binding: a direct insert, an ALLOW bound in an
// earlier transaction, or an ALLOW of another action is refused by the database
#[tokio::test]
async fn the_database_refuses_unbound_configuration() {
    // MD-14, INV-2
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 50, 2).await;
    let r = realm(&db, t, &d, "acme-c").await;
    let hex: String = d.as_bytes().iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    });
    let insert = |pos: u64, uuid: &str| {
        format!(
            "INSERT INTO access.idp_clients (tenant_id, realm_id, client_uuid, client_id, display_name,
               auth_method, redirect_uris, domain_id, decision_pos)
             SELECT tenant_id, realm_id, '{uuid}', 'cli_bbbbbbbbbbbbbbbbbbbbbbbbbb', 'x', 'none', '{{}}',
               '\\x{hex}', {pos} FROM access.realms"
        )
    };
    let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        tx.raw_rows(&insert(1, "019a0000-0000-7000-8000-000000000001"))
            .await
            .is_err()
    );

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    bind(
        &mut tx,
        &decision(&d, 1, &ALLOW_NONCE, "idp.client.register"),
    )
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        tx.raw_rows(&insert(1, "019a0000-0000-7000-8000-000000000002"))
            .await
            .is_err()
    );

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 2, &[2; 16], "idp.client.register"))
        .await
        .unwrap()
        .unwrap();
    let mut s = settings(&mut tx).await.unwrap().unwrap();
    s.jose_alg = String::from("Ed25519");
    assert!(update_settings(&mut tx, &b, &s).await.is_err());

    let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        tx.raw_rows("UPDATE access.idp_realm_settings SET jose_alg = 'Ed25519'")
            .await
            .is_err()
    );
    let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        tx.raw_rows("UPDATE access.idp_config_log SET action = 'idp.realm.rp_id'")
            .await
            .is_err()
    );
}

fn defaults() -> SettingsRow {
    SettingsRow {
        jose_alg: String::from("ES256"),
        argon2_m_kib: 7 * 1024,
        argon2_t: 5,
        argon2_p: 1,
        rp_id: None,
        cimd_enabled: false,
        cimd_domains: Vec::new(),
    }
}

// OP-146 m.4 (f), OP-33, m.8 (e), IDP-5: a realm starts on the Genesis defaults; its settings
// change only under a decision, and Argon2 parameters only rise
#[tokio::test]
async fn realm_settings_start_on_defaults_and_argon2_only_rises() {
    // TN-111, IDP-5, IDI-4, CR-36
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 60, 2).await;
    let r = realm(&db, t, &d, "acme-d").await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(settings(&mut tx).await.unwrap(), Some(defaults()));
    let b = bind(&mut tx, &decision(&d, 1, &ALLOW_NONCE, "idp.realm.argon2"))
        .await
        .unwrap()
        .unwrap();
    let mut raised = defaults();
    raised.argon2_m_kib = 19 * 1024;
    assert!(update_settings(&mut tx, &b, &raised).await.unwrap());
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 2, &[2; 16], "idp.realm.argon2"))
        .await
        .unwrap()
        .unwrap();
    assert!(update_settings(&mut tx, &b, &defaults()).await.is_err());

    let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        tx.raw_rows(
            "INSERT INTO access.idp_realm_settings (tenant_id, realm_id, jose_alg)
             SELECT tenant_id, realm_id, 'Ed25519' FROM access.realms"
        )
        .await
        .is_err()
    );
}

// must-never #18, §9.9.4 k.1, TN-117: a tenant cannot define a reserved protocol claim
#[tokio::test]
async fn reserved_claims_cannot_be_mapped() {
    // P55, E39, F23, PI-8
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 70, 2).await;
    let r = realm(&db, t, &d, "acme-e").await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 1, &ALLOW_NONCE, "idp.mapper.set"))
        .await
        .unwrap()
        .unwrap();
    set_mapper(&mut tx, &b, "department", Some("department"))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(
        mappers(&mut tx).await.unwrap(),
        [(String::from("department"), String::from("department"))]
    );
    let b = bind(&mut tx, &decision(&d, 2, &[2; 16], "idp.mapper.set"))
        .await
        .unwrap()
        .unwrap();
    assert!(set_mapper(&mut tx, &b, "sub", Some("email")).await.is_err());
}

// TN-20, OP-137: a client_id is global and never reused, also across tenants
#[tokio::test]
async fn a_client_id_is_global() {
    // TN-15, INV-32
    let db = fresh().await.unwrap();
    let a = create_tenant(&db.app, "pool-default").await.unwrap();
    let b = create_tenant(&db.app, "pool-default").await.unwrap();
    let da = domain(&db, a, 80, 1).await;
    let db_ = domain(&db, b, 90, 1).await;
    let ra = realm(&db, a, &da, "acme-f").await;
    let rb = realm(&db, b, &db_, "acme-g").await;
    for (t, r, d, seed) in [(a, ra, da, 1), (b, rb, db_, 2)] {
        let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
        let bound = bind(
            &mut tx,
            &decision(&d, 1, &ALLOW_NONCE, "idp.client.register"),
        )
        .await
        .unwrap()
        .unwrap();
        let mut c = client_row(1);
        c.client_uuid = [seed; 16];
        let done = insert_client(&mut tx, &bound, &c).await;
        assert_eq!(done.is_ok(), seed == 1);
        if done.is_ok() {
            tx.commit().await.unwrap();
        }
    }
}
