//! The account actions of catalog 3 against the real plane (OP-153 m.25 (b), (i)): a migration
//! export sealed to the receiving deployment's key and imported there from the opened bundle.

use access_identity_admin::domain::Change;
use access_identity_admin::domain::accounts::{AccountImport, MigrationExport};

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
