//! The local platform administrator on the real path (OP-159 m.41 (a), INV-29): the bootstrap
//! makes the account in the platform environment with its password and authenticator app, and the
//! platform environment's root grants its Party the `idp.platform.*` actions; the Party then provisions
//! on that holding and on nothing else; a second run changes nothing.

use access_identity_admin::app::provision::{Created, Order, Platform, Provisioned};
use access_identity_admin::domain::provision::PlatformChange;

use super::*;
use access_internal_api::idp::IdpAction;

use crate::bootstrap::platform_admin::{
    DEVICE_LABEL, EnvironmentAdminOut, META_GRANTS, PlatformAdminPlan, environment_device_label,
};

const IDENTIFIER: &str = "admin@platform.local";

fn admin_plan(totp: &Path) -> Plan {
    Plan {
        platform_admin: Some(PlatformAdminPlan {
            identifier: String::from(IDENTIFIER),
            password: Secret::new(String::from("platform horse battery staple")),
            totp: Some(TotpSeedFile::open(totp).unwrap()),
            environments: Vec::new(),
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
    let change = PlatformChange::Tenant {
        tenant: *tenant.as_bytes(),
        placement: String::from(PLACEMENT),
    };
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
    };
    let done = Box::pin(admin.provision(&platform, order, ais))
        .await
        .unwrap();
    w.domains.release().await;
    (tenant, done)
}

// OP-159 m.41 (a), INV-29, TN-110, OP-151 m.2 M2, §10.2.2
#[tokio::test]
async fn the_platform_admin_is_made_once_and_provisions_only_on_its_grant() {
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
            "idp.platform.environment_create",
            "idp.platform.sandbox_create"
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
    assert!(json["platform_admin"]["basis"]["holding"]["grant"].is_string());

    let second = w.run(&admin_plan(&path)).await;
    let again = second.platform_admin.unwrap();
    assert!(!again.created);
    assert!(!again.totp.unwrap().created);
    assert_eq!(again.basis, out.basis);
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
    let holding = holding_of(&out.basis);
    let (tenant, done) = create_tenant_as_admin(&w, ExerciseBasis::Holding(holding), [2; 16]).await;
    let Provisioned::Done { created, .. } = done else {
        panic!("tenant creation on the platform Grant not allowed");
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

// OP-159 m.43 (c), TN-119, INV-29, TN-114, §10.2.2
#[tokio::test]
async fn the_platform_admin_has_the_same_account_in_acme_and_acmes_root_grants_it_once() {
    let w = World::new("boot-environment-admin").await;
    let dir = std::env::temp_dir().join(format!("abs-environment-admin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("platform-admin-totp");
    let with_acme = || {
        let mut plan = admin_plan(&path);
        plan.tenants = vec![String::from("acme"), String::from("globex")];
        if let Some(p) = plan.platform_admin.as_mut() {
            p.environments = vec![String::from("acme")];
        }
        plan
    };

    let first = w.run(&with_acme()).await;
    let out = first.platform_admin.clone().unwrap();
    let [acme] = out.environments.as_slice() else {
        panic!("{:?}", out.environments);
    };
    assert!(acme.created);
    assert!(acme.delegated_admin_opened);
    assert_eq!(acme.environment, "acme");
    assert!(acme.issuer.ends_with("/env/acme"), "{}", acme.issuer);
    let device = token_key(&w.keys, &environment_device_label("acme")).unwrap();
    assert_eq!(
        acme.party,
        b64url_encode(&root_party(&device.public_key()).0)
    );
    let resources: Vec<&str> = acme.grants.iter().map(|g| g.resource.as_str()).collect();
    assert_eq!(resources.first(), Some(&"idp"));
    for (namespace, _) in META_GRANTS {
        assert!(resources.contains(&namespace), "{namespace}");
    }
    let idp_actions = &acme.grants[0].actions;
    assert_eq!(idp_actions.len(), IdpAction::ALL.len());
    assert!(
        idp_actions
            .iter()
            .all(|a| a.starts_with("idp.") && !a.starts_with("idp.platform."))
    );
    // §10.2.2
    let seed = std::fs::read_to_string(&path)
        .unwrap()
        .trim_end()
        .to_owned();
    assert!(acme.totp.as_ref().unwrap().created);
    assert_eq!(
        totp_seeds_in(&w, "platform", IDENTIFIER).await,
        vec![seed.clone()]
    );
    assert_eq!(
        totp_seeds_in(&w, "acme", IDENTIFIER).await,
        vec![seed.clone()]
    );
    let summary = serde_json::to_string(&first).unwrap();
    assert!(!summary.contains(&seed));
    assert!(!summary.contains("platform horse battery staple"));

    let second = w.run(&with_acme()).await;
    let again = second.platform_admin.unwrap();
    let [acme_again] = again.environments.as_slice() else {
        panic!("{:?}", again.environments);
    };
    assert!(!acme_again.created);
    assert!(!acme_again.delegated_admin_opened);
    assert!(!acme_again.totp.as_ref().unwrap().created);
    assert_eq!(acme_again.instance, acme.instance);
    let bases =
        |a: &EnvironmentAdminOut| a.grants.iter().map(|g| g.basis.clone()).collect::<Vec<_>>();
    assert_eq!(bases(acme_again), bases(acme));
    assert_eq!(totp_seeds_in(&w, "acme", IDENTIFIER).await, vec![seed]);

    // TN-119, INV-29
    assert_eq!(again.basis, out.basis);
    let globex = route_by_slug(&w.db.router, "globex")
        .await
        .unwrap()
        .unwrap();
    let keks = crate::login::EnvironmentKeks::new(w.keys.clone());
    let accounts = access_identity_account::adapters::pg::PgAccounts::sealed(
        w.db.app.clone(),
        keks.vault(globex.environment).unwrap(),
    );
    {
        use access_identity_account::ports::{AccountDb as _, AccountTx as _};
        let mut tx = accounts
            .begin(globex.tenant, globex.environment)
            .await
            .unwrap();
        assert!(
            tx.subject_by_identifier(IDENTIFIER)
                .await
                .unwrap()
                .is_none()
        );
        tx.commit().await.unwrap();
    }

    std::fs::remove_dir_all(&dir).unwrap();
}

// OP-159 m.43 (c)
#[test]
fn a_platform_admin_environment_is_a_tenant_of_the_plan_named_once() {
    let dir =
        std::env::temp_dir().join(format!("abs-environment-admin-plan-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let head = "platform = \"platform\"\ntenants = [\"acme\"]\n[platform_admin]\nidentifier = \"admin@platform.local\"\npassword = \"x\"\n";
    let ok = dir.join("ok.toml");
    std::fs::write(&ok, format!("{head}environments = [\"acme\"]\n")).unwrap();
    assert_eq!(
        Plan::load(&ok)
            .unwrap()
            .platform_admin
            .unwrap()
            .environments,
        ["acme"]
    );
    let none = dir.join("none.toml");
    std::fs::write(&none, head).unwrap();
    assert_eq!(
        Plan::load(&none)
            .unwrap()
            .platform_admin
            .unwrap()
            .environments,
        Vec::<String>::new()
    );
    for (name, environments, want) in [
        ("elsewhere", "[\"globex\"]", "platform_admin"),
        ("platform", "[\"platform\"]", "platform_admin"),
        ("twice", "[\"acme\", \"acme\"]", "named twice"),
    ] {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(&path, format!("{head}environments = {environments}\n")).unwrap();
        let err = Plan::load(&path).unwrap_err().to_string();
        assert!(err.contains(want), "{name}: {err}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
