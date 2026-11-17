//! The local platform administrator on the real path (OP-159 m.41 (a), m.47 (d), (i), INV-29): the
//! bootstrap makes the account in the platform environment with its password and authenticator
//! app and adds it to the platform tenant's administrators; once its `tenant_administration` Claim
//! is stated, the platform environment's administrator rule selects its Party, which then
//! provisions on that holding and on nothing else; a second run changes nothing.

use access_identity_admin::app::provision::{Created, Order, Platform, Provisioned};
use access_identity_admin::domain::provision::{FounderCommitment, PlatformChange, TenantOrder};

use super::*;

use crate::bootstrap::platform_admin::{DEVICE_LABEL, PlatformAdminPlan};

const IDENTIFIER: &str = "admin@platform.local";

fn admin_plan(totp: &Path) -> Plan {
    Plan {
        platform_admin: Some(PlatformAdminPlan {
            identifier: String::from(IDENTIFIER),
            password: Secret::new(String::from("platform horse battery staple")),
            totp: Some(TotpSeedFile::open(totp).unwrap()),
        }),
        ..plan()
    }
}

/// A tenant creation in the platform environment signed by the administrator's device key on `basis`.
async fn create_tenant_as_admin(
    w: &World,
    basis: ExerciseBasis,
    nonce: [u8; 16],
) -> (TenantId, Provisioned) {
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let declared = DeclaredTargets::default();
    let bootstrap = Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        environment_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &declared,
        console: None,
    };
    let admin = bootstrap.admin(&ids, None);
    let route = route_by_slug(&w.db.router, "platform")
        .await
        .unwrap()
        .unwrap();
    let platform = Platform {
        tenant: route.tenant,
        environment: route.environment,
        router: &w.db.router,
    };
    let tenant = TenantId::from_bytes(idp::new_uuid(&w.db.app).await.unwrap());
    let change = PlatformChange::Tenant(TenantOrder {
        tenant: *tenant.as_bytes(),
        display_name: String::from("Globex"),
        primary_slug: format!("globex-{}", nonce[0]),
        placement: String::from(PLACEMENT),
        founder: FounderCommitment {
            index: [1; 32],
            token: [2; 32],
            code: [3; 32],
        },
    });
    let device = token_key(&w.keys, DEVICE_LABEL).unwrap();
    let m = Moment::at(server_time(&w.db.app).await.unwrap());
    let prepared = admin
        .prepare_provision(&platform, &change, m.validity)
        .await
        .unwrap();
    MetaExercises::lead(&w.plane, prepared.domain)
        .await
        .unwrap();
    let ais = sign(
        &device,
        &m.statement(prepared.domain, &nonce, prepared.digest, basis),
    )
    .unwrap();
    let order = Order {
        change: &change,
        nonce: nonce.to_vec(),
        validity: m.validity,
        basis,
        capacity: Capacity::Own,
        mail: None,
    };
    let done = Box::pin(admin.provision(&platform, order, ais))
        .await
        .unwrap();
    w.domains.release().await;
    (tenant, done)
}

// OP-159 m.41 (a), m.47 (d), (f), (i), INV-29, TN-110, OP-151 m.2 M2, §10.2.2
#[tokio::test]
async fn the_platform_admin_is_made_once_and_provisions_only_on_the_admin_rule() {
    use std::os::unix::fs::PermissionsExt as _;

    let w = World::new("bootstrap-platform-admin").await;
    let dir = std::env::temp_dir().join(format!("abs-platform-admin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("platform-admin-totp");
    let plan = admin_plan(&path);

    let first = w.run(&plan).await;
    let out = first.platform_admin.clone().unwrap();
    assert!(out.created);
    assert_eq!(out.environment, "platform");
    assert_eq!(out.identifier, IDENTIFIER);
    assert!(out.issuer.ends_with("/env/platform"), "{}", out.issuer);
    assert!(out.subject.starts_with("usr_"), "{}", out.subject);
    assert_eq!(
        out.actions,
        [
            "idp.platform.tenant_create",
            "idp.platform.tenant_suspend",
            "idp.platform.tenant_reactivate",
            "idp.platform.tenant_placement"
        ]
    );
    let device = token_key(&w.keys, DEVICE_LABEL).unwrap();
    assert_eq!(
        out.party,
        b64url_encode(&root_party(&device.public_key()).0)
    );
    let totp = out.totp.clone().unwrap();
    assert!(totp.created);
    assert_eq!(totp.seed_file, path.display().to_string());
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let text = std::fs::read_to_string(&path).unwrap();
    let seed = text.strip_suffix('\n').unwrap().to_owned();
    assert!(is_seed(&seed), "{text:?}");
    let summary = serde_json::to_string(&first).unwrap();
    assert!(!summary.contains(&seed));
    assert!(!summary.contains("platform horse battery staple"));
    assert!(!format!("{plan:?}").contains("platform horse battery staple"));
    assert_eq!(
        totp_seeds_in(&w, "platform", IDENTIFIER).await,
        vec![seed.clone()]
    );
    let json = serde_json::to_value(&first).unwrap();
    assert_eq!(json["platform_admin"]["environment"], "platform");

    let second = w.run(&admin_plan(&path)).await;
    let again = second.platform_admin.unwrap();
    assert!(!again.created);
    assert!(!again.totp.unwrap().created);
    assert_eq!(again.instance, out.instance);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    assert_eq!(totp_seeds_in(&w, "platform", IDENTIFIER).await, vec![seed]);

    // INV-29
    let route = route_by_slug(&w.db.router, "platform")
        .await
        .unwrap()
        .unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.environment)
        .await
        .unwrap();
    let domain = Digest(
        *idp::governance(&mut t)
            .await
            .unwrap()
            .unwrap()
            .domain
            .as_bytes(),
    );
    t.commit().await.unwrap();
    let idp_anchor = ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR));
    let (_, refused) = create_tenant_as_admin(&w, idp_anchor, [1; 16]).await;
    assert!(matches!(refused, Provisioned::NotAllowed { .. }));
    // OP-159 m.47 (f)
    let restated = administer(&w).await;
    assert_eq!(restated.renewed, 1, "{restated:?}");
    let party = Id(<[u8; 16]>::try_from(
        access_kernel::json::b64url_decode(&out.party)
            .unwrap()
            .as_slice(),
    )
    .unwrap());
    let basis = rule_basis(&w, "platform", party, ("idp.platform", "tenant_create")).await;
    let holding = holding_of(&basis);
    let (tenant, done) = create_tenant_as_admin(&w, ExerciseBasis::Holding(holding), [2; 16]).await;
    let Provisioned::Done { created, .. } = done else {
        panic!("tenant creation on the administrator rule not allowed");
    };
    assert!(created == Created::Tenant(tenant));
    assert!(
        access_store::tenancy::tenant(&w.db.router, tenant)
            .await
            .unwrap()
            .is_some()
    );

    std::fs::remove_dir_all(&dir).unwrap();
}
