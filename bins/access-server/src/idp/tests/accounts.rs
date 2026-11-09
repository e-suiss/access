//! The account actions of catalog 3 against the real plane (OP-153 m.25 (b), (i)): a migration
//! export sealed to the receiving deployment's key and imported there from the opened bundle,
//! and an administrator's binding across two realms of one tenant.

use access_identity_admin::domain::Change;
use access_identity_admin::domain::accounts::{AccountBind, AccountImport, MigrationExport};

use super::*;

/// Prepares `p`, has the actor `seed` sign it and returns the AIS.
async fn signed(w: &World, p: &Proposal, seed: u8) -> Vec<u8> {
    let prepared = w.admin().prepare(p).await.unwrap();
    sign(
        &statement(prepared.domain, &p.nonce, prepared.digest, p.basis),
        seed,
    )
}

/// Imports `content` into the realm `at` under `idp.account.import`.
async fn import(
    w: &World,
    at: (TenantId, RealmId),
    d: Digest,
    content: &str,
    nonce: u8,
) -> access_identity_account::app::import::Report {
    let (file, accounts) = access_identity_account::app::import::file_of(content);
    let p = proposal(
        at,
        Change::AccountImport(AccountImport {
            file,
            accounts: u32::try_from(accounts).unwrap(),
        }),
        nonce,
        idp_anchor(d),
        1,
    );
    let ais = signed(w, &p, ROOT_KEY).await;
    let (applied, report) = Box::pin(w.admin().import_accounts(&p, ais, content))
        .await
        .unwrap();
    written(&applied);
    report.unwrap()
}

// TN-85, TN-86, OP-153 m.19 (d), m.25 (i), (gg), Ek B 3571
#[tokio::test]
async fn a_migration_export_opens_only_for_its_recipient_and_imports_there() {
    let w = World::new().await;
    let (ta, ra, da) = w.realm_with("export-from", Some(0)).await;
    onboard(&w.plane, da, ROOT, ROOT_KEY).await;
    let content = [
        r#"{"email":"exp.one@example.com","password_hash":"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"}"#,
        r#"{"email":"exp.two@example.com","username":"exp_two","legacy_idp_reference":"ref-2"}"#,
    ]
    .join("\n");
    let report = import(&w, (ta, ra), da, &content, 0xe0).await;
    assert_eq!(report.created, 2, "{report:?}");

    let recipient = access_crypto::migration_bundle::RecipientKey::generate().unwrap();
    let p = proposal(
        (ta, ra),
        Change::MigrationExport(MigrationExport {
            recipient: recipient.public().unwrap(),
        }),
        0xe1,
        idp_anchor(da),
        1,
    );
    // TN-86
    assert!(p.change.action().reserved());
    let ais = signed(&w, &p, ROOT_KEY).await;
    let (applied, bundle) = Box::pin(w.admin().export_accounts(&p, ais.clone()))
        .await
        .unwrap();
    written(&applied);
    let bundle = bundle.unwrap();
    let again = Box::pin(w.admin().export_accounts(&p, ais)).await.unwrap();
    assert!(again.1.is_none(), "a retry seals nothing");
    let other = access_crypto::migration_bundle::RecipientKey::generate().unwrap();
    assert!(access_identity_admin::app::accounts::open_bundle(&bundle, &other).is_err());
    let mut tampered = bundle.clone();
    if let Some(b) = tampered.last_mut() {
        *b ^= 1;
    }
    assert!(access_identity_admin::app::accounts::open_bundle(&tampered, &recipient).is_err());
    let lines = access_identity_admin::app::accounts::open_bundle(&bundle, &recipient).unwrap();
    assert_eq!(lines.lines().count(), 2);
    assert!(lines.contains("exp.one@example.com") && lines.contains("ref-2"));
    assert!(lines.contains("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"));

    let (tb, rb, db) = w.realm_with("export-to", Some(0)).await;
    onboard(&w.plane, db, ROOT, ROOT_KEY).await;
    let landed = import(&w, (tb, rb), db, &lines, 0xe2).await;
    assert_eq!(landed.created, 2, "{landed:?}");
    assert_eq!(landed.legacy, 2);
    assert_eq!(landed.skipped, Vec::new());
}

/// A subject of the realm `at`.
async fn subject_in(w: &World, (tenant, realm): (TenantId, RealmId)) -> [u8; 16] {
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let s = t
        .insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap();
    t.commit().await.unwrap();
    s
}

// OP-153 m.18 (e), m.25 (b), §12.1.1, TN-2, TN-65, C7, MD-5, (gg), Ek B 3459
#[tokio::test]
async fn an_administrator_binds_two_realms_of_one_tenant_with_a_realm_signed_offer() {
    use access_identity_account::domain::binding_offer::pair_digest;
    use access_identity_admin::app::accounts::BINDING_OFFER_REFUSED;
    let w = World::new().await;
    let (tenant, ra, da) = w.realm_with("bind-a", Some(0)).await;
    onboard(&w.plane, da, ROOT, ROOT_KEY).await;
    let rb = w
        .admin()
        .create_realm(&NewRealm {
            tenant,
            slug: "bind-b",
            style: IssuerStyle::Subdomain,
            placement: "pool-default",
            root: Root::Sole(ROOT),
            ct3_delay_s: Some(0),
            causal_binding: false,
            schemas: Vec::new(),
            acceptances: Vec::new(),
            issuer_predicate_input: Vec::new(),
            provisioned_by: None,
        })
        .await
        .unwrap();
    let db = rb.domain;
    let rb = rb.realm;
    onboard(&w.plane, db, ROOT, ROOT_KEY).await;
    let alice = subject_in(&w, (tenant, ra)).await;
    let bob = subject_in(&w, (tenant, rb)).await;
    let bind = |at, d, b: AccountBind, nonce| {
        proposal(at, Change::AccountBind(b), nonce, idp_anchor(d), 1)
    };
    let a_half = bind(
        (tenant, ra),
        da,
        AccountBind {
            subject: alice,
            peer_realm: *rb.as_bytes(),
            peer_subject: bob,
            offer: None,
        },
        0xf0,
    );
    let ais = signed(&w, &a_half, ROOT_KEY).await;
    let offer = match Box::pin(w.admin().bind_account(&a_half, ais, None))
        .await
        .unwrap()
    {
        Applied::Written {
            secret: Some(s), ..
        } => s.expose().to_owned(),
        other => panic!("{other:?}"),
    };
    assert!(
        !offer.contains(&access_kernel::json::b64url_encode(&alice))
            && !offer.contains(&access_kernel::json::b64url_encode(&bob))
    );
    let accept = |peer_subject, token: &str, nonce| {
        bind(
            (tenant, rb),
            db,
            AccountBind {
                subject: bob,
                peer_realm: *ra.as_bytes(),
                peer_subject,
                offer: Some(suiss_crypto::digest::sha256(token.as_bytes())),
            },
            nonce,
        )
    };
    // OP-153 m.18 (e)
    let other = subject_in(&w, (tenant, ra)).await;
    let wrong = accept(other, &offer, 0xf1);
    let ais = signed(&w, &wrong, ROOT_KEY).await;
    assert!(matches!(
        Box::pin(w.admin().bind_account(&wrong, ais, Some(&offer))).await,
        Err(AdminError::Refused(c)) if c == BINDING_OFFER_REFUSED
    ));
    let mut forged = offer.clone();
    forged.push('A');
    let tampered = accept(alice, &forged, 0xf2);
    let ais = signed(&w, &tampered, ROOT_KEY).await;
    assert!(matches!(
        Box::pin(w.admin().bind_account(&tampered, ais, Some(&forged))).await,
        Err(AdminError::Refused(c)) if c == BINDING_OFFER_REFUSED
    ));
    let b_half = accept(alice, &offer, 0xf3);
    let ais = signed(&w, &b_half, ROOT_KEY).await;
    let done = Box::pin(w.admin().bind_account(&b_half, ais, Some(&offer)))
        .await
        .unwrap();
    assert!(
        matches!(done, Applied::Written { secret: None, .. }),
        "{done:?}"
    );

    let pair = pair_digest((*ra.as_bytes(), alice), (*rb.as_bytes(), bob));
    for (realm, subject, role) in [(ra, alice, "offer"), (rb, bob, "accept")] {
        let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
        let halves = t.binding_halves_of(subject).await.unwrap();
        t.commit().await.unwrap();
        assert_eq!(halves.len(), 1, "{halves:?}");
        let h = &halves[0];
        assert_eq!(
            (h.role.as_str(), h.proof.as_str(), h.state.as_str()),
            (role, "admin_exercise", "committed")
        );
        assert_eq!(h.binding.as_slice(), &pair[..16]);
    }
    let claims = identity_events(&w.db, "claim.identity_binding_person", 2).await;
    assert!(claims.len() >= 2);
}
