//! The S7 organization reads through the console's BFF against the real admin surface (§8.5 S7,
//! OP-153 m.10 (c), m.3 (gg), Ek B 3735, 3808).

use access_kernel::json::b64url_encode;
use access_store::orgs::Source;

use super::*;

// §8.5 S7, §8.17.7.6, TN-91, OP-153 m.10 (c), (gg), Ek B 3735, 3808, 3819
#[tokio::test]
async fn s7_reads_an_organizations_roots_members_and_membership_sources() {
    let c = console("mgmt-orgs", false).await;
    let party = [0x0a; 16];
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    let org = t.insert_org(party, "Acme", &[7; 32]).await.unwrap();
    t.insert_membership(org, c.subject, Source::Founder, true, None)
        .await
        .unwrap();
    let joiner = t
        .insert_subject("active", "realm-kek:1", &[8; 40])
        .await
        .unwrap();
    t.open_member(
        (org, joiner),
        Source::DomainAutojoin,
        Some(("member", 2)),
        None,
        Some(86_400),
    )
    .await
    .unwrap();
    t.commit().await.unwrap();

    let list = c.admin_get("/admin/v1/realms/acme/organizations").await;
    assert_eq!(list.status, StatusCode::OK, "{}", list.body);
    assert_eq!(list.body["items"][0]["organization"], b64url_encode(&party));
    assert_eq!(list.body["items"][0]["display_name"], "Acme");

    let one = c
        .admin_get(&format!(
            "/admin/v1/realms/acme/organizations/{}",
            b64url_encode(&party)
        ))
        .await;
    assert_eq!(one.status, StatusCode::OK, "{}", one.body);
    assert_eq!(one.body["roots"], 1);
    let members = one.body["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    let founder = members.iter().find(|m| m["owner"] == true).unwrap();
    assert_eq!(founder["membership_source"], "founder");
    // TN-109, §8.17.9.3: how a member joined is its membership source, never a sign-in source
    let autojoined = members.iter().find(|m| m["owner"] == false).unwrap();
    assert_eq!(autojoined["membership_source"], "domain_autojoin");
    assert_eq!(autojoined["role"]["version"], 2);
    assert_eq!(autojoined["role_grant"], "pending");
    assert!(autojoined["cooling_until"].is_string());
    assert!(one.body.get("billing").is_none());

    let none = c
        .admin_get(&format!(
            "/admin/v1/realms/acme/organizations/{}",
            b64url_encode(&[0x0b; 16])
        ))
        .await;
    assert_eq!(none.status, StatusCode::NOT_FOUND, "{}", none.body);
}
