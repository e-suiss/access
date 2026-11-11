//! The async DR profile and promote on the real server path (OP-29, HL-31, §16.7.1, §17.4.8,
//! FA-13, OP-158 m.3 (r)): `putDrProfile` commits `idp.realm.dr_profile`; `dr-promote` refuses a
//! cell with a realm that declared none, and otherwise ends every session and refresh family,
//! keeps the server closed until the re-shred, and leaves every authority domain unled until it
//! continues under a fence proof.

use access_authority_sequencer::cell::{self, Fence, MoveError, Point};

use super::*;

// OP-29, HL-31, FA-13, Ek B 5702, 6016, 6091
#[tokio::test]
async fn hl_31_an_async_dr_promote_signs_everyone_out_and_declares_its_rpo() {
    let c = console("dr-promote", false).await;
    let routes = access_store::tenancy::routes(&c.w.db.router).await.unwrap();
    assert_eq!(
        routes.iter().map(|r| r.slug.as_str()).collect::<Vec<_>>(),
        ["acme", "platform"]
    );
    let refused = crate::dr::promote(&c.w.db.app, &c.w.db.router).await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|e| e.contains("realm acme declares no async DR profile")),
        "{refused:?}"
    );
    assert_eq!(
        access_store::restore::pending_reshred(&c.w.db.app)
            .await
            .unwrap(),
        None,
        "a refused promote records nothing"
    );
    let set = c
        .put_setting(
            "dr-profile",
            "putDrProfile",
            serde_json::json!({ "rpo_s": 300 }),
        )
        .await;
    assert_eq!(set.status, StatusCode::OK, "{}", set.body);
    let mut t = TenantTx::begin(&c.w.db.app, c.route.tenant, c.route.realm)
        .await
        .unwrap();
    assert_eq!(
        access_store::cells::dr_profile(&mut t).await.unwrap(),
        Some(300)
    );
    t.commit().await.unwrap();

    let still = crate::dr::promote(&c.w.db.app, &c.w.db.router).await;
    assert!(
        still
            .as_ref()
            .is_err_and(|e| e.contains("realm platform declares no async DR profile")),
        "{still:?}"
    );
    // the platform realm declares through its own idp.* Exercise, signed by its root
    let platform = routes.iter().find(|r| r.slug == "platform").unwrap();
    let mut t = TenantTx::begin(&c.w.db.app, platform.tenant, platform.realm)
        .await
        .unwrap();
    let governing = access_store::idp::governance(&mut t)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    let ids = crate::bootstrap::cell_ids(&c.w.db.app, &c.w.keys)
        .await
        .unwrap();
    let declared = DeclaredTargets::default();
    let b = Bootstrap {
        app: &c.w.db.app,
        router: &c.w.db.router,
        plane: &c.w.plane,
        realm_keys: &c.w.keyring,
        hsm: &c.w.keys,
        base: &c.w.base,
        declared: &declared,
        console: None,
    };
    let admin = b.admin(&ids, None);
    b.change(
        &admin,
        (platform.tenant, platform.realm),
        Digest(*governing.domain.as_bytes()),
        &crate::bootstrap::root_key(&c.w.keys).unwrap(),
        access_identity_admin::domain::Change::DrProfile(Some(
            access_identity_admin::domain::resilience::DrProfile { rpo_s: 600 },
        )),
    )
    .await
    .unwrap();
    c.w.domains.release().await;

    let promoted = crate::dr::promote(&c.w.db.app, &c.w.db.router)
        .await
        .unwrap();
    assert_eq!(promoted.realms.len(), 2);
    assert_eq!(promoted.realms[1].rpo_s, 600);
    let acme = &promoted.realms[0];
    // HL-31: the declared RPO is above zero and everyone signs in again
    assert_eq!((acme.slug.as_str(), acme.rpo_s), ("acme", 300));
    assert!(acme.signed_out >= 1, "{promoted:?}");
    // OP-42: closed until the shred journal is applied again
    assert_eq!(
        access_store::restore::pending_reshred(&c.w.db.app)
            .await
            .unwrap(),
        Some(promoted.restore)
    );
    assert!(crate::reshred::gate(&c.w.db.app, None).await.is_err());

    // FA-13: the async copy does not continue a domain's lineage by itself
    let domain = c.domain;
    let unled = c.w.domains.take_over(domain).await;
    assert!(
        matches!(
            unled,
            Err(access_authority_core::CoreError::Unavailable(
                "promoted-copy"
            ))
        ),
        "{unled:?}"
    );
    assert!(matches!(
        cell::continue_promoted(&c.w.db.sequencer, &c.w.db.app, domain, None, None).await,
        Err(MoveError::Unfenced)
    ));
    let id = access_store::scope::DomainId::from_bytes(domain.0);
    let head = access_store::authority::read_head(&c.w.db.sequencer, &id)
        .await
        .unwrap();
    let fence = Fence {
        evidence: String::from("stonith: the lost region's primary was fenced by its storage API"),
        last: Point {
            pos: head.pos,
            leaf: head.leaf_hash,
        },
    };
    let epoch = cell::continue_promoted(&c.w.db.sequencer, &c.w.db.app, domain, Some(&fence), None)
        .await
        .unwrap();
    assert!(epoch > head.epoch);
    c.w.domains.take_over(domain).await.unwrap();
    // HL-31: the console's own session was issued before the promote and has ended
    let after = c
        .put_setting("dr-profile", "putDrProfile", serde_json::json!({}))
        .await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED, "{}", after.body);
    assert_eq!(after.body["reason"], "ended");
}
