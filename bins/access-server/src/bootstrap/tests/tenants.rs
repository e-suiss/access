//! A tenant's founding and administration end to end (OP-159 m.47, TN-138 … TN-141): the platform
//! root creates a tenant with a founder commitment; the founder proves the address, opens the
//! management environment rooted in its device Party and closes the founding; the founder's key
//! opens environments whose Genesis carries the administrator rule over the management issuer and
//! which are bound as consuming its Claims; a non-owner administrator holds the rule while its
//! `tenant_administration` line is live and stands nowhere once it is removed.

use access_identity_admin::app::founding::FoundingError;
use access_identity_admin::app::provision::{Order, Platform, Provisioned};
use access_identity_admin::app::tenant::{TenantError, TenantOrder as TenantWrite};
use access_identity_admin::domain::provision::{PlatformChange, ProvisionInvalid, TenantOrder};
use access_identity_admin::domain::tenant::{
    NewTenantEnvironment, TenantChange, TenantInvalid, catalog as tenant_catalog,
};
use access_store::tenant_admin as tenants;

use super::*;

const SLUG: &str = "acme-admin";
const FOUNDER: &str = "admin@acme.example";

struct Scene<'a> {
    w: &'a World,
    bootstrap: Bootstrap<'a, TestPlane, EnvironmentKeyring>,
}

impl Scene<'_> {
    fn admin<'b>(&'b self, ids: &'b IdKey) -> Admin<'b, TestPlane, TestPlane, EnvironmentKeyring> {
        self.bootstrap.admin(ids, None)
    }

    async fn platform(&self) -> Platform<'_> {
        let route = route_by_slug(&self.w.db.router, "platform")
            .await
            .unwrap()
            .unwrap();
        Platform {
            tenant: route.tenant,
            environment: route.environment,
            router: &self.w.db.router,
        }
    }
}

fn domain_of(rows: &[access_store::authority::StateRow]) -> Vec<suiss_crypto::dcbor::Value> {
    rows.iter()
        .filter_map(|r| r.value.as_deref())
        .filter_map(|v| suiss_crypto::dcbor::decode(v, suiss_crypto::dcbor::Limits::CEILING).ok())
        .collect()
}

async fn state(w: &World, domain: Digest) -> Vec<suiss_crypto::dcbor::Value> {
    domain_of(
        &access_store::authority::state(&w.db.sequencer, &DomainId::from_bytes(domain.0))
            .await
            .unwrap(),
    )
}

fn gates(values: &[suiss_crypto::dcbor::Value]) -> Vec<access_kernel::claim::Gate> {
    values
        .iter()
        .filter_map(|v| meta::ContentState::from_value(v).ok())
        .filter_map(|c| access_kernel::claim::Gate::of(&c.content).ok())
        .collect()
}

fn meta_root(values: &[suiss_crypto::dcbor::Value], domain: &Digest) -> meta::Root {
    let _ = domain;
    values
        .iter()
        .filter_map(|v| meta::AnchorState::from_value(v).ok())
        .find(|a| a.scope == meta::AnchorScope::Domain)
        .map(|a| a.root)
        .unwrap()
}

/// Signs `change` as the platform root and has the platform environment's domain commit it.
async fn provision(
    s: &Scene<'_>,
    admin: &Admin<'_, TestPlane, TestPlane, EnvironmentKeyring>,
    change: &PlatformChange,
    nonce: [u8; 16],
) -> Provisioned {
    let platform = s.platform().await;
    let root = root_key(&s.w.keys).unwrap();
    let m = Moment::at(server_time(&s.w.db.app).await.unwrap());
    let prepared = admin
        .prepare_provision(&platform, change, m.validity)
        .await
        .unwrap();
    MetaExercises::lead(&s.w.plane, prepared.domain)
        .await
        .unwrap();
    let basis = ExerciseBasis::Anchor(meta::object_id(&prepared.domain, kind::ANCHOR, IDP_ANCHOR));
    let ais = sign(
        &root,
        &m.statement(prepared.domain, &nonce, prepared.digest, basis),
    )
    .unwrap();
    let done = Box::pin(admin.provision(
        &platform,
        Order {
            change,
            nonce: nonce.to_vec(),
            validity: m.validity,
            basis,
            capacity: Capacity::Own,
            mail: None,
        },
        ais,
    ))
    .await
    .unwrap();
    s.w.domains.release().await;
    done
}

/// Signs `change` with `key` on the management domain's `idp` Anchor and has it applied.
async fn tenant_write(
    s: &Scene<'_>,
    admin: &Admin<'_, TestPlane, TestPlane, EnvironmentKeyring>,
    (tenant, management, domain): (TenantId, EnvironmentId, Digest),
    (key, subject): (&HsmSigner, [u8; 16]),
    change: &TenantChange,
) -> Result<
    (
        Applied,
        Option<access_identity_admin::app::tenant::OpenedEnvironment>,
    ),
    TenantError,
> {
    let m = Moment::at(server_time(&s.w.db.app).await.unwrap());
    let prepared = admin
        .prepare_tenant((tenant, management), change, m.validity)
        .await?;
    MetaExercises::lead(&s.w.plane, prepared.domain)
        .await
        .unwrap();
    let basis = ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR));
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let ais = sign(
        key,
        &m.statement(prepared.domain, &nonce, prepared.digest, basis),
    )
    .unwrap();
    let done = Box::pin(admin.apply_tenant(
        TenantWrite {
            tenant,
            environment: management,
            change,
            subject: Some(subject),
            nonce: nonce.to_vec(),
            validity: m.validity,
            basis,
            capacity: Capacity::Own,
            console: None,
        },
        ais,
    ))
    .await;
    s.w.domains.release().await;
    done
}

fn environment(slug: &str, sandbox: bool) -> TenantChange {
    TenantChange::EnvironmentCreate(NewTenantEnvironment {
        slug: String::from(slug),
        style: IssuerStyle::Path,
        sandbox,
        schemas: Vec::new(),
        acceptances: Vec::new(),
        issuer_predicate_input: Vec::new(),
    })
}

// OP-159 m.47 (a), (b), (c), (d), (e), (h), TN-138, TN-139, TN-140, TN-141, TN-4, INV-29, TNI-15
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one tenant from its creation through its first environments"
)]
async fn a_tenant_is_founded_by_its_invited_founder_and_opens_its_environments() {
    let w = World::new("tenant-founding").await;
    w.run(&plan()).await;
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let declared = DeclaredTargets::default();
    let s = Scene {
        w: &w,
        bootstrap: Bootstrap {
            app: &w.db.app,
            router: &w.db.router,
            plane: &w.plane,
            environment_keys: &w.keyring,
            hsm: &w.keys,
            base: &w.base,
            declared: &declared,
            console: None,
        },
    };
    let admin = s.admin(&ids);

    // TN-141
    let tenant = TenantId::from_bytes(idp::new_uuid(&w.db.app).await.unwrap());
    let (commitment, secrets) = admin
        .founder_commitment(*tenant.as_bytes(), FOUNDER, 0)
        .unwrap();
    let change = PlatformChange::Tenant(TenantOrder {
        tenant: *tenant.as_bytes(),
        display_name: String::from("Acme"),
        management_slug: String::from(SLUG),
        placement: String::from(PLACEMENT),
        founder: commitment,
    });
    assert!(matches!(
        provision(&s, &admin, &change, [1; 16]).await,
        Provisioned::Done { .. }
    ));
    let row = access_store::tenancy::tenant(&w.db.router, tenant)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "provisioning");
    assert!(!tenants::slug_free(&w.db.router, SLUG).await.unwrap());
    // TN-16
    let mut again = change.clone();
    if let PlatformChange::Tenant(t) = &mut again {
        t.tenant = *TenantId::from_bytes(idp::new_uuid(&w.db.app).await.unwrap()).as_bytes();
    }
    let platform = s.platform().await;
    assert!(matches!(
        admin
            .prepare_provision(&platform, &again, Moment::at(1).validity)
            .await,
        Err(
            access_identity_admin::app::provision::ProvisionError::Invalid(
                ProvisionInvalid::SlugTaken
            )
        )
    ));

    // TN-89 (5), (7)
    let token = secrets.token.expose().clone();
    let view = admin.founding(SLUG, &token).await.unwrap();
    assert_eq!(view.display_name, "Acme");
    assert!(view.route.tenant == tenant);
    assert!(matches!(
        admin.founding("acme", &token).await,
        Err(FoundingError::NotFound)
    ));
    let founder_key = token_key(&w.keys, &crate::bootstrap::tenants::founder_label(SLUG)).unwrap();
    let founder = root_party(&founder_key.public_key());
    assert!(matches!(
        admin.open_management(SLUG, &token, founder).await,
        Err(FoundingError::State)
    ));
    assert!(matches!(
        admin
            .verify_founding(SLUG, &token, (FOUNDER, "AAAAAAAA"))
            .await,
        Err(FoundingError::Code)
    ));
    assert!(matches!(
        admin
            .verify_founding(SLUG, &token, ("other@acme.example", secrets.code.expose()))
            .await,
        Err(FoundingError::Code)
    ));
    admin
        .verify_founding(SLUG, &token, (FOUNDER, secrets.code.expose()))
        .await
        .unwrap();

    // TN-138, TN-111, TNI-15
    let opened = admin.open_management(SLUG, &token, founder).await.unwrap();
    w.domains.release().await;
    assert!(opened.environment == EnvironmentId::from_bytes(*tenant.as_bytes()));
    let mut t = TenantTx::begin(&w.db.app, tenant, opened.environment)
        .await
        .unwrap();
    assert_eq!(
        tenants::environment_kind(&mut t).await.unwrap().as_deref(),
        Some("management")
    );
    let m_issuer = Id(access_store::issuer::environment_issuer(&mut t)
        .await
        .unwrap()
        .unwrap());
    t.commit().await.unwrap();
    let m_state = state(&w, opened.domain).await;
    assert_eq!(
        meta_root(&m_state, &opened.domain),
        meta::Root::Sole(founder)
    );
    let operator = root_party(&root_key(&w.keys).unwrap().public_key());
    assert!(gates(&m_state).iter().all(|g| g.issuer != Some(operator)));
    assert!(gates(&m_state).iter().any(|g| g.issuer == Some(m_issuer)
        && g.use_ == access_kernel::claim::SUBJECT_SELECTION
        && g.classes == [String::from("tenant_administration")]));
    assert!(m_state.iter().any(|v| {
        meta::ContentState::from_value(v).is_ok_and(|c| {
            c.content.get("spp").is_some_and(|spp| {
                access_kernel::schema::Spp::from_value(spp)
                    .is_ok_and(|p| p.namespace == tenant_catalog(founder).namespace)
            })
        })
    }));

    // TN-141, OP-159 m.47 (e)
    s.bootstrap
        .onboard(
            tenant,
            opened.environment,
            opened.domain,
            &founder_key,
            founder,
        )
        .await
        .unwrap();
    let password = Secret::new(String::from("founder horse battery staple"));
    let (subject, _, _) = s
        .bootstrap
        .account(&ids, (tenant, opened.environment), FOUNDER, Some(&password))
        .await
        .unwrap();
    admin
        .finish_founding(SLUG, &token, (subject, founder))
        .await
        .unwrap();
    assert_eq!(
        access_store::tenancy::tenant(&w.db.router, tenant)
            .await
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    assert!(admin.founding(SLUG, &token).await.unwrap().route.completed);
    assert!(matches!(
        admin
            .verify_founding(SLUG, &token, (FOUNDER, secrets.code.expose()))
            .await,
        Err(FoundingError::State)
    ));
    let m = (tenant, opened.environment, opened.domain);

    // OP-159 m.47 (d), (h), TN-4, TN-139
    let (applied, shop) = tenant_write(
        &s,
        &admin,
        m,
        (&founder_key, subject),
        &environment("shop", false),
    )
    .await
    .unwrap();
    assert!(matches!(applied, Applied::Written { .. }));
    let shop = shop.unwrap();
    let shop_state = state(&w, shop.domain).await;
    assert_eq!(
        meta_root(&shop_state, &shop.domain),
        meta::Root::Sole(founder)
    );
    let shop_gates = gates(&shop_state);
    for (use_, class) in [
        (
            access_kernel::claim::SUBJECT_SELECTION,
            "tenant_administration",
        ),
        (access_kernel::claim::PREDICATE_INPUT, "authentication"),
        (
            access_kernel::claim::ACTOR_BINDING,
            "identity_binding_person",
        ),
    ] {
        assert!(
            shop_gates.iter().any(|g| g.issuer == Some(m_issuer)
                && g.use_ == use_
                && g.classes.iter().any(|c| c == class)),
            "{use_} {class}"
        );
    }
    let rule: Vec<meta::GrantState> = shop_state
        .iter()
        .filter_map(|v| meta::GrantState::from_value(v).ok())
        .filter(|g| g.content.holder == access_authority_core::genesis::admin_holder())
        .collect();
    assert_eq!(
        rule.len(),
        access_authority_core::genesis::ADMIN_RULE_META.len() + 1
    );
    assert!(rule.iter().all(|g| {
        !g.content
            .authority
            .authority
            .actions
            .exact
            .iter()
            .any(|a| a.namespace == "idp.platform" || a.namespace == "idp.tenant")
    }));
    let mut t = TenantTx::begin_tenant(&w.db.app, tenant).await.unwrap();
    let consumers = access_store::environment_binding::consumed_by(
        &mut t,
        &DomainId::from_bytes(shop.domain.0),
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    assert!(consumers == [opened.environment]);
    let mut t = TenantTx::begin(&w.db.app, tenant, opened.environment)
        .await
        .unwrap();
    assert!(
        access_store::issuer::has_issuer_instance(&mut t, &DomainId::from_bytes(shop.domain.0))
            .await
            .unwrap()
    );
    t.commit().await.unwrap();

    // TN-16, OP-151 m.3 (m)
    assert!(matches!(
        tenant_write(
            &s,
            &admin,
            m,
            (&founder_key, subject),
            &environment("shop", false)
        )
        .await,
        Err(TenantError::Invalid(TenantInvalid::Provision(
            ProvisionInvalid::SlugTaken
        )))
    ));
    let (_, play) = tenant_write(
        &s,
        &admin,
        m,
        (&founder_key, subject),
        &environment("shop-play", true),
    )
    .await
    .unwrap();
    let play = play.unwrap();
    assert!(
        access_store::sandbox::budget(&w.db.router, &play.domain.0)
            .await
            .unwrap()
            .is_some()
    );
    // TN-138
    let shop_route = route_by_slug(&w.db.router, "shop").await.unwrap().unwrap();
    assert!(matches!(
        admin
            .prepare_tenant(
                (tenant, shop_route.environment),
                &environment("other", false),
                Moment::at(1).validity
            )
            .await,
        Err(TenantError::Invalid(TenantInvalid::NotManagement))
    ));
}

// OP-159 m.47 (d), (e), (f), (k), TN-109, TNI-14
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one administrator from its first episode through its removal"
)]
async fn a_tenant_administrator_holds_the_rule_while_its_line_lives() {
    let w = World::new("tenant-admin-rule").await;
    w.run(&plan()).await;
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let declared = DeclaredTargets::default();
    let s = Scene {
        w: &w,
        bootstrap: Bootstrap {
            app: &w.db.app,
            router: &w.db.router,
            plane: &w.plane,
            environment_keys: &w.keyring,
            hsm: &w.keys,
            base: &w.base,
            declared: &declared,
            console: None,
        },
    };
    let admin = s.admin(&ids);
    let tenant = TenantId::from_bytes(idp::new_uuid(&w.db.app).await.unwrap());
    let (commitment, secrets) = admin
        .founder_commitment(*tenant.as_bytes(), FOUNDER, 0)
        .unwrap();
    let change = PlatformChange::Tenant(TenantOrder {
        tenant: *tenant.as_bytes(),
        display_name: String::from("Acme"),
        management_slug: String::from(SLUG),
        placement: String::from(PLACEMENT),
        founder: commitment,
    });
    provision(&s, &admin, &change, [1; 16]).await;
    let token = secrets.token.expose().clone();
    admin
        .verify_founding(SLUG, &token, (FOUNDER, secrets.code.expose()))
        .await
        .unwrap();
    let founder_key = token_key(&w.keys, &crate::bootstrap::tenants::founder_label(SLUG)).unwrap();
    let founder = root_party(&founder_key.public_key());
    let opened = admin.open_management(SLUG, &token, founder).await.unwrap();
    w.domains.release().await;
    s.bootstrap
        .onboard(
            tenant,
            opened.environment,
            opened.domain,
            &founder_key,
            founder,
        )
        .await
        .unwrap();
    let password = Secret::new(String::from("founder horse battery staple"));
    let (subject, _, _) = s
        .bootstrap
        .account(&ids, (tenant, opened.environment), FOUNDER, Some(&password))
        .await
        .unwrap();
    admin
        .finish_founding(SLUG, &token, (subject, founder))
        .await
        .unwrap();
    let m = (tenant, opened.environment, opened.domain);
    let (_, shop) = tenant_write(
        &s,
        &admin,
        m,
        (&founder_key, subject),
        &environment("shop", false),
    )
    .await
    .unwrap();
    let shop = shop.unwrap();
    let shop_route = route_by_slug(&w.db.router, "shop").await.unwrap().unwrap();

    // TNI-14
    let (helper, _, _) = s
        .bootstrap
        .account(
            &ids,
            (tenant, opened.environment),
            "helper@acme.example",
            Some(&password),
        )
        .await
        .unwrap();
    let helper_key = token_key(&w.keys, "access/test/tenant-helper").unwrap();
    let helper_party = root_party(&helper_key.public_key());
    s.bootstrap
        .onboard(
            tenant,
            shop_route.environment,
            shop.domain,
            &helper_key,
            helper_party,
        )
        .await
        .unwrap();
    let mut t = TenantTx::begin(&w.db.app, tenant, opened.environment)
        .await
        .unwrap();
    tenants::add_admin(
        &mut t,
        &helper,
        &tenants::NewAdmin {
            party: Some(&helper_party.0),
            owner: false,
            exercise: None,
            cooling_s: None,
        },
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let courier = administration(&w);
    open_ingest_day(&w).await;
    assert!(
        courier
            .admit(
                (tenant, opened.environment),
                &helper,
                (&DomainId::from_bytes(shop.domain.0), &helper_party.0),
            )
            .await
            .unwrap()
            .is_some()
    );
    w.domains.release().await;

    // OP-159 m.47 (d)
    let basis = rule_basis(
        &w,
        "shop",
        helper_party,
        ("idp.environment", "security_notices"),
    )
    .await;
    let holding = ExerciseBasis::Holding(holding_of(&basis));
    let written = s
        .bootstrap
        .change_as(
            &admin,
            (tenant, shop_route.environment),
            (&helper_key, holding),
            (
                access_identity_admin::domain::Change::SecurityNotices(true),
                None,
            ),
        )
        .await
        .unwrap();
    assert!(matches!(written, Applied::Written { .. }), "{written:?}");
    w.domains.release().await;

    // OP-159 m.47 (f)
    let shop_d = DomainId::from_bytes(shop.domain.0);
    let line = |world: &World| {
        let app = world.db.app.clone();
        async move {
            let mut t = TenantTx::begin(&app, tenant, opened.environment)
                .await
                .unwrap();
            let found = tenants::lines(&mut t, Some(&helper))
                .await
                .unwrap()
                .into_iter()
                .find(|l| l.domain == shop_d)
                .unwrap();
            t.commit().await.unwrap();
            found
        }
    };
    let stated = line(&w).await;
    let now = server_time(&w.db.app).await.unwrap();
    let mut t = TenantTx::begin(&w.db.app, tenant, opened.environment)
        .await
        .unwrap();
    tenants::stated(
        &mut t,
        (&helper, &shop_d, stated.episode),
        &stated.claim.unwrap(),
        (now - 7_200_000, now - 1),
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    assert!(matches!(
        admin
            .standing(
                (tenant, shop_route.environment),
                shop.domain,
                &[],
                Some(helper_party),
            )
            .await,
        Err(access_identity_admin::AdminError::Refused(code)) if code == "actor-binding"
    ));
    assert!(
        courier
            .admit(
                (tenant, opened.environment),
                &helper,
                (&shop_d, &helper_party.0),
            )
            .await
            .unwrap()
            .is_some()
    );
    w.domains.release().await;
    admin
        .standing(
            (tenant, shop_route.environment),
            shop.domain,
            &[],
            Some(helper_party),
        )
        .await
        .unwrap();

    // OP-159 m.47 (f)
    let (removed, _) = tenant_write(
        &s,
        &admin,
        m,
        (&founder_key, subject),
        &TenantChange::AdminRemove { subject: helper },
    )
    .await
    .unwrap();
    assert!(matches!(removed, Applied::Written { .. }), "{removed:?}");
    assert!(matches!(
        tenant_write(
            &s,
            &admin,
            m,
            (&founder_key, subject),
            &TenantChange::AdminRemove { subject },
        )
        .await,
        Err(TenantError::Invalid(TenantInvalid::LastOwner))
    ));
    assert_eq!(
        courier
            .end((tenant, opened.environment), &helper)
            .await
            .unwrap(),
        1
    );
    w.domains.release().await;
    assert!(matches!(
        admin
            .standing(
                (tenant, shop_route.environment),
                shop.domain,
                &[],
                Some(helper_party),
            )
            .await,
        Err(access_identity_admin::AdminError::Refused(code)) if code == "actor-binding"
    ));
    let refused = s
        .bootstrap
        .change_as(
            &admin,
            (tenant, shop_route.environment),
            (&helper_key, holding),
            (
                access_identity_admin::domain::Change::SecurityNotices(false),
                None,
            ),
        )
        .await;
    assert!(refused.is_err(), "{refused:?}");
    admin
        .standing(
            (tenant, shop_route.environment),
            shop.domain,
            &[],
            Some(founder),
        )
        .await
        .unwrap();

    // TN-109
    let (cool, _, _) = s
        .bootstrap
        .account(
            &ids,
            (tenant, opened.environment),
            "cool@globex.example",
            Some(&password),
        )
        .await
        .unwrap();
    let cool_key = token_key(&w.keys, "access/test/tenant-cool").unwrap();
    let cool_party = root_party(&cool_key.public_key());
    s.bootstrap
        .onboard(
            tenant,
            shop_route.environment,
            shop.domain,
            &cool_key,
            cool_party,
        )
        .await
        .unwrap();
    let mut t = TenantTx::begin(&w.db.app, tenant, opened.environment)
        .await
        .unwrap();
    tenants::add_admin(
        &mut t,
        &cool,
        &tenants::NewAdmin {
            party: Some(&cool_party.0),
            owner: false,
            exercise: None,
            cooling_s: Some(access_identity_admin::domain::tenant::ADMIN_COOLING_S),
        },
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    courier
        .admit(
            (tenant, opened.environment),
            &cool,
            (&shop_d, &cool_party.0),
        )
        .await
        .unwrap();
    w.domains.release().await;
    assert!(matches!(
        admin
            .standing(
                (tenant, shop_route.environment),
                shop.domain,
                &[],
                Some(cool_party),
            )
            .await,
        Err(access_identity_admin::AdminError::Refused(code)) if code == "actor-binding"
    ));

    // OP-159 m.48 (d)
    assert_eq!(
        courier
            .end((tenant, opened.environment), &cool)
            .await
            .unwrap(),
        1
    );
    w.domains.release().await;
    assert_eq!(
        courier
            .revive((tenant, opened.environment), &helper)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        courier
            .revive((tenant, opened.environment), &cool)
            .await
            .unwrap(),
        1
    );
    w.domains.release().await;
    let mut t = TenantTx::begin(&w.db.app, tenant, opened.environment)
        .await
        .unwrap();
    let episodes: Vec<_> = tenants::lines(&mut t, Some(&cool))
        .await
        .unwrap()
        .into_iter()
        .map(|l| (l.episode, l.ended_ms.is_some(), l.claim.is_some()))
        .collect();
    let helper_lines = tenants::lines(&mut t, Some(&helper)).await.unwrap().len();
    t.commit().await.unwrap();
    assert_eq!(episodes, [(1, true, true), (2, false, true)]);
    assert_eq!(helper_lines, 1);
}

// OP-159 m.47 (b), (c), TN-141, TN-89 (5), (8)
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one founding from its link through its completion over HTTP"
)]
async fn the_founding_routes_take_a_founder_from_the_link_to_an_active_tenant() {
    use tower::ServiceExt as _;
    let w = World::new("tenant-founding-http").await;
    w.run(&plan()).await;
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let declared = DeclaredTargets::default();
    let s = Scene {
        w: &w,
        bootstrap: Bootstrap {
            app: &w.db.app,
            router: &w.db.router,
            plane: &w.plane,
            environment_keys: &w.keyring,
            hsm: &w.keys,
            base: &w.base,
            declared: &declared,
            console: None,
        },
    };
    let admin = s.admin(&ids);
    let tenant = TenantId::from_bytes(idp::new_uuid(&w.db.app).await.unwrap());
    let (commitment, secrets) = admin
        .founder_commitment(*tenant.as_bytes(), FOUNDER, 0)
        .unwrap();
    provision(
        &s,
        &admin,
        &PlatformChange::Tenant(TenantOrder {
            tenant: *tenant.as_bytes(),
            display_name: String::from("Acme"),
            management_slug: String::from(SLUG),
            placement: String::from(PLACEMENT),
            founder: commitment,
        }),
        [1; 16],
    )
    .await;
    let routes = crate::founding::router(crate::founding::Founding {
        app: w.db.app.clone(),
        router: w.db.router.clone(),
        ids: Arc::new(crate::ids::CellIds::new(w.keys.clone())),
        plane: w.plane.clone(),
        base: w.base.clone(),
        keys: Arc::new(EnvironmentKeyring::new(
            SignerKeys::new(w.identity_signer.clone()),
            w.keys.clone(),
        )),
        keks: crate::login::EnvironmentKeks::new(w.keys.clone()),
    });
    let token = secrets.token.expose().clone();
    let call = |method: &'static str, path: String, body: serde_json::Value| {
        let routes = routes.clone();
        async move {
            let r = routes
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(if body.is_null() {
                            String::new()
                        } else {
                            body.to_string()
                        }))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = r.status();
            let referrer = r.headers().get("referrer-policy").cloned();
            let bytes = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
            (status, referrer, bytes)
        }
    };
    let base = format!("/env/{SLUG}/v1/foundings/{token}");
    let (status, referrer, body) = call("GET", base.clone(), serde_json::Value::Null).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(referrer.unwrap(), "no-referrer");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["display_name"], "Acme");
    assert_eq!(v["environment"]["kind"], "management");
    assert!(!body.windows(FOUNDER.len()).any(|x| x == FOUNDER.as_bytes()));
    let (status, _, _) = call(
        "GET",
        format!("/env/acme/v1/foundings/{token}"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, 404);
    let (status, _, body) = call(
        "POST",
        format!("{base}/verify"),
        serde_json::json!({ "email": FOUNDER, "code": "AAAAAAAA" }),
    )
    .await;
    assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
    let device = suiss_crypto::signer::SoftSigner::generate_p256().unwrap().0;
    let (status, _, body) = call(
        "POST",
        format!("{base}/complete"),
        serde_json::json!({
            "email": FOUNDER,
            "code": secrets.code.expose(),
            "password": "founder horse battery staple",
            "device_key": b64url_encode(&access_internal_api::instances::cose_key(&device.public_key())),
        }),
    )
    .await;
    w.domains.release().await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let done: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        done["party"],
        b64url_encode(&crate::bootstrap::root_party(&device.public_key()).0)
    );
    assert_eq!(
        access_store::tenancy::tenant(&w.db.router, tenant)
            .await
            .unwrap()
            .unwrap()
            .status,
        "active"
    );
    let (status, _, _) = call(
        "POST",
        format!("{base}/complete"),
        serde_json::json!({
            "email": FOUNDER,
            "code": secrets.code.expose(),
            "password": "founder horse battery staple",
            "device_key": b64url_encode(&access_internal_api::instances::cose_key(&device.public_key())),
        }),
    )
    .await;
    assert_eq!(status, 409);
}
