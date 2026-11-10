//! The catalog upgrade on a domain opened with an older `idp.*` catalog (OP-151 m.18 (g)).

use access_internal_api::idp::Submission;
use access_internal_api::idp::{
    GenesisOpened, GenesisOrder, IdpAction, NAMESPACES, catalog_upgrade_required, spp_at,
};
use access_internal_api::instances::{Registration, RegistrationVerdict};
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use suiss_crypto::dcbor::Value;

use super::*;

/// Opens Genesis as the catalog stood before `idp.hook` and `idp.webhook` existed, with the
/// CT3 time-lock `delay_s`.
struct OldCatalog<'a> {
    plane: &'a TestPlane,
    domains: &'a TestDomains,
    delay_s: Option<u64>,
}

impl Governance for OldCatalog<'_> {
    async fn open(&self, mut order: GenesisOrder) -> Result<GenesisOpened, Unavailable> {
        order.ct3_delay_s = self.delay_s;
        let mut fields = access_authority_core::genesis::realm(&order, &mut OsSalts)
            .map_err(|e| Unavailable(e.to_string()))?;
        let acceptances = fields.get_mut("acceptances").unwrap();
        let Value::Array(items) = &mut acceptances.value else {
            panic!("acceptances");
        };
        items.retain(|a| {
            let ns = a
                .get("spp")
                .and_then(|s| s.get("namespace"))
                .and_then(|n| match n {
                    Value::Text(t) => Some(t.clone()),
                    _ => None,
                });
            !matches!(ns.as_deref(), Some("idp.hook" | "idp.webhook"))
        });
        let now = Instances::now(self.plane).await?;
        let domain = self
            .domains
            .create(order.tenant, fields, now)
            .await
            .unwrap();
        Ok(GenesisOpened { domain })
    }
}

impl Instances for OldCatalog<'_> {
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, Unavailable> {
        Instances::register(self.plane, r).await
    }

    async fn now(&self) -> Result<u64, Unavailable> {
        Instances::now(self.plane).await
    }
}

/// The realm `slug` in a new tenant, its domain opened with the old catalog.
async fn old_realm(w: &World, slug: &str, delay_s: Option<u64>) -> Digest {
    let governance = OldCatalog {
        plane: &w.plane,
        domains: &w.domains,
        delay_s,
    };
    realm_with(w, &governance, slug).await.1.domain
}

/// The realm `slug` in a new tenant, its domain opened by `governance`.
async fn realm_with<G: Governance + access_identity_admin::ports::Instances>(
    w: &World,
    governance: &G,
    slug: &str,
) -> (TenantId, access_identity_admin::app::CreatedRealm) {
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let admin = Admin {
        app: &w.db.app,
        ids: &ids,
        decider: &w.plane,
        governance,
        pep: IDENTITY_PEP,
        base: &w.base,
        keys: &w.keyring,
        platform_tenant: None,
        declared: DeclaredTargets::default(),
        vault: None,
    };
    let tenant = create_tenant(&w.db.app, PLACEMENT).await.unwrap();
    let root = root_party(&root_key(&w.keys).unwrap().public_key());
    let created = admin
        .create_realm(&NewRealm {
            tenant,
            slug,
            style: IssuerStyle::Path,
            placement: PLACEMENT,
            root: Root::Sole(root),
            ct3_delay_s: None,
            causal_binding: false,
            schemas: Vec::new(),
            acceptances: Vec::new(),
            issuer_predicate_input: Vec::new(),
            provisioned_by: None,
        })
        .await
        .unwrap();
    (tenant, created)
}

fn old_plan(slug: &str) -> Plan {
    Plan {
        tenants: vec![String::from(slug)],
        products: Vec::new(),
        ..plan()
    }
}

async fn accepts(w: &World, domain: Digest, action: IdpAction) -> bool {
    let r = MetaExercises::accepts(&w.plane, domain, action.action_ref())
        .await
        .unwrap();
    w.domains.release().await;
    r
}

fn upgraded<'s>(summary: &'s Summary, slug: &str) -> &'s [crate::bootstrap::catalog::CatalogOut] {
    &summary
        .realms
        .iter()
        .find(|r| r.slug == slug)
        .unwrap()
        .catalog
}

#[tokio::test]
async fn an_old_domain_accepts_the_current_catalog_once_its_root_signs_it() {
    // OP-151 m.18 (g)
    let w = World::new("catalog-upgrade").await;
    let domain = old_realm(&w, "elder", Some(0)).await;
    assert!(!accepts(&w, domain, IdpAction::HookRegister).await);
    assert!(!accepts(&w, domain, IdpAction::WebhookRegister).await);
    assert!(accepts(&w, domain, IdpAction::ClientRegister).await);

    let summary = w.run(&old_plan("elder")).await;
    let mut namespaces: Vec<_> = upgraded(&summary, "elder")
        .iter()
        .map(|c| (c.namespace.as_str(), c.state))
        .collect();
    namespaces.sort_unstable();
    assert_eq!(
        namespaces,
        vec![("idp.hook", "accepted"), ("idp.webhook", "accepted")]
    );
    assert_eq!(upgraded(&summary, "platform"), []);
    assert!(accepts(&w, domain, IdpAction::HookRegister).await);
    assert!(accepts(&w, domain, IdpAction::WebhookRetire).await);

    let again = w.run(&old_plan("elder")).await;
    assert_eq!(upgraded(&again, "elder"), []);
}

#[tokio::test]
async fn the_upgrade_waits_out_the_time_lock_and_reuses_its_open_attempt() {
    // §13.7.3, SEC26
    let w = World::new("catalog-locked").await;
    let domain = old_realm(&w, "locked", None).await;
    let first = w.run(&old_plan("locked")).await;
    let pending = upgraded(&first, "locked");
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().all(|c| c.state == "pending"));
    let after: Vec<_> = pending.iter().map(|c| c.after.unwrap()).collect();
    let now = server_time(&w.db.app).await.unwrap();
    assert!(
        after
            .iter()
            .all(|a| *a > now + 86_000_000 && *a <= now + 86_400_000)
    );

    let second = w.run(&old_plan("locked")).await;
    let again: Vec<_> = upgraded(&second, "locked")
        .iter()
        .map(|c| c.after.unwrap())
        .collect();
    assert_eq!(again, after);
    assert!(!accepts(&w, domain, IdpAction::HookRegister).await);
}

/// Opens Genesis as `idp.*` catalog `version` declared it: catalog 1 has no `idp.org` and no
/// `idp.social`, catalog 3 no `idp.agent` and no `idp.vault`, catalog 4 none of `idp.saml`,
/// `idp.scim`, `idp.gateway`, `idp.federation` and `idp.vc`, catalog 5 none of `idp.domain`,
/// `idp.proxy`, `idp.ssh`, `idp.linux`, `idp.hr`, `idp.export`, `idp.signal` and `idp.relay`, and none a later
/// action in the other namespaces; the CT3 time-lock is zero.
struct FirstCatalog<'a> {
    plane: &'a TestPlane,
    domains: &'a TestDomains,
    version: u64,
}

fn spp_namespace(acceptance: &Value) -> Option<String> {
    match acceptance.get("spp")?.get("namespace")? {
        Value::Text(t) => Some(t.clone()),
        _ => None,
    }
}

impl Governance for FirstCatalog<'_> {
    async fn open(&self, mut order: GenesisOrder) -> Result<GenesisOpened, Unavailable> {
        order.ct3_delay_s = Some(0);
        let Root::Sole(founder) = order.root else {
            panic!("root");
        };
        let mut fields = access_authority_core::genesis::realm(&order, &mut OsSalts)
            .map_err(|e| Unavailable(e.to_string()))?;
        let acceptances = fields.get_mut("acceptances").unwrap();
        let Value::Array(items) = &mut acceptances.value else {
            panic!("acceptances");
        };
        items.retain(|a| spp_namespace(a).is_none_or(|ns| !NAMESPACES.contains(&ns.as_str())));
        items.extend(
            NAMESPACES
                .iter()
                .filter(|ns| !spp_at(ns, founder, self.version).actions.is_empty())
                .map(|ns| access_authority_core::genesis::schemas_at(ns, founder, self.version)),
        );
        items.sort_by_key(|v| {
            suiss_crypto::dcbor::encode(v, suiss_crypto::dcbor::Limits::CEILING).unwrap()
        });
        let now = Instances::now(self.plane).await?;
        let domain = self
            .domains
            .create(order.tenant, fields, now)
            .await
            .unwrap();
        Ok(GenesisOpened { domain })
    }
}

impl Instances for FirstCatalog<'_> {
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, Unavailable> {
        Instances::register(self.plane, r).await
    }

    async fn now(&self) -> Result<u64, Unavailable> {
        Instances::now(self.plane).await
    }
}

fn bootstrap<'a>(
    w: &'a World,
    declared: &'a DeclaredTargets,
) -> Bootstrap<'a, TestPlane, RealmKeyring> {
    Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared,
        console: None,
    }
}

/// The root's Exercise of `action` on `[slug, kind]` in `domain`, decided on the sequencer.
async fn exercise(w: &World, domain: Digest, slug: &str, action: IdpAction, kind: &str) -> Verdict {
    let root = root_key(&w.keys).unwrap();
    let at = Moment::at(server_time(&w.db.app).await.unwrap());
    let intent = IntentEnvelope {
        provenance: std::collections::BTreeMap::new(),
        action: action.action_ref(),
        resources: vec![ResourceRef {
            namespace: String::from(access_internal_api::idp::RESOURCE_NAMESPACE),
            path: vec![String::from(slug), String::from(kind)],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: at.validity,
    };
    let digest = intent_digest(&intent).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let basis = ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR));
    let ais = sign(&root, &at.statement(domain, &nonce, digest, basis)).unwrap();
    let verdict = Decider::decide(
        &w.plane,
        Submission {
            actor: None,
            domain,
            nonce,
            intent,
            payload: None,
            basis,
            capacity: Capacity::Own,
            ais,
            contributions: Vec::new(),
            pep: String::from(IDENTITY_PEP),
        },
    )
    .await
    .unwrap();
    w.domains.release().await;
    verdict
}

#[tokio::test]
async fn a_catalog_1_realm_refuses_the_version_2_actions_until_its_upgrade_commits() {
    // OP-153 m.3 (a)
    let w = World::new("catalog-v2").await;
    let governance = FirstCatalog {
        plane: &w.plane,
        domains: &w.domains,
        version: 1,
    };
    let (tenant, created) = realm_with(&w, &governance, "first").await;
    let domain = created.domain;
    assert!(accepts(&w, domain, IdpAction::ClientRegister).await);
    assert!(accepts(&w, domain, IdpAction::AccountDelete).await);
    assert!(!accepts(&w, domain, IdpAction::AccountExport).await);
    assert!(!accepts(&w, domain, IdpAction::OrgCreate).await);
    assert!(!accepts(&w, domain, IdpAction::SocialEnable).await);
    assert!(!accepts(&w, domain, IdpAction::RealmLocaleOverrides).await);

    let declared = DeclaredTargets::default();
    let b = bootstrap(&w, &declared);
    let root = root_key(&w.keys).unwrap();
    let party = root_party(&root.public_key());
    b.onboard(tenant, created.realm, domain, &root, party)
        .await
        .unwrap();
    w.domains.release().await;
    for (action, kind) in [
        (IdpAction::RealmLocaleOverrides, "realm"),
        (IdpAction::OrgCreate, "org"),
    ] {
        let Verdict::NotAllowed { decision, .. } =
            exercise(&w, domain, "first", action, kind).await
        else {
            panic!("{action:?} before the upgrade");
        };
        assert!(catalog_upgrade_required(&decision), "{action:?}");
    }

    let summary = w.run(&old_plan("first")).await;
    let mut namespaces: Vec<_> = upgraded(&summary, "first")
        .iter()
        .map(|c| (c.namespace.as_str(), c.state))
        .collect();
    namespaces.sort_unstable();
    assert_eq!(
        namespaces,
        vec![
            ("idp.account", "accepted"),
            ("idp.agent", "accepted"),
            ("idp.client", "accepted"),
            ("idp.domain", "accepted"),
            ("idp.export", "accepted"),
            ("idp.federation", "accepted"),
            ("idp.gateway", "accepted"),
            ("idp.hr", "accepted"),
            ("idp.linux", "accepted"),
            ("idp.org", "accepted"),
            ("idp.proxy", "accepted"),
            ("idp.realm", "accepted"),
            ("idp.relay", "accepted"),
            ("idp.saml", "accepted"),
            ("idp.scim", "accepted"),
            ("idp.signal", "accepted"),
            ("idp.social", "accepted"),
            ("idp.ssh", "accepted"),
            ("idp.upstream", "accepted"),
            ("idp.vault", "accepted"),
            ("idp.vc", "accepted"),
        ]
    );
    for action in IdpAction::ALL {
        assert!(accepts(&w, domain, action).await, "{action:?}");
    }
    assert!(matches!(
        exercise(
            &w,
            domain,
            "first",
            IdpAction::RealmLocaleOverrides,
            "realm"
        )
        .await,
        Verdict::Committed(_)
    ));
    assert!(matches!(
        exercise(&w, domain, "first", IdpAction::OrgCreate, "org").await,
        Verdict::Committed(_)
    ));
}

#[tokio::test]
async fn a_catalog_3_realm_refuses_the_version_4_actions_until_its_upgrade_commits() {
    // OP-154 m.3 (a), OP-153 m.3 (a)
    let w = World::new("catalog-v4").await;
    let governance = FirstCatalog {
        plane: &w.plane,
        domains: &w.domains,
        version: 3,
    };
    let (tenant, created) = realm_with(&w, &governance, "third").await;
    let domain = created.domain;
    assert!(accepts(&w, domain, IdpAction::AccountBind).await);
    assert!(accepts(&w, domain, IdpAction::RealmCspModeLoosen).await);
    for action in IdpAction::ALL.into_iter().filter(|a| a.since() == 4) {
        assert!(!accepts(&w, domain, action).await, "{action:?}");
    }

    let declared = DeclaredTargets::default();
    let b = bootstrap(&w, &declared);
    let root = root_key(&w.keys).unwrap();
    let party = root_party(&root.public_key());
    b.onboard(tenant, created.realm, domain, &root, party)
        .await
        .unwrap();
    w.domains.release().await;
    for (action, kind) in [
        (IdpAction::AgentRegister, "agent"),
        (IdpAction::RealmDeviceCode, "realm"),
        (IdpAction::ClientDcrPolicy, "client"),
    ] {
        let Verdict::NotAllowed { decision, .. } =
            exercise(&w, domain, "third", action, kind).await
        else {
            panic!("{action:?} before the upgrade");
        };
        assert!(catalog_upgrade_required(&decision), "{action:?}");
    }

    let summary = w.run(&old_plan("third")).await;
    let mut namespaces: Vec<_> = upgraded(&summary, "third")
        .iter()
        .map(|c| (c.namespace.as_str(), c.state))
        .collect();
    namespaces.sort_unstable();
    assert_eq!(
        namespaces,
        vec![
            ("idp.agent", "accepted"),
            ("idp.client", "accepted"),
            ("idp.domain", "accepted"),
            ("idp.export", "accepted"),
            ("idp.federation", "accepted"),
            ("idp.gateway", "accepted"),
            ("idp.hr", "accepted"),
            ("idp.linux", "accepted"),
            ("idp.org", "accepted"),
            ("idp.proxy", "accepted"),
            ("idp.realm", "accepted"),
            ("idp.relay", "accepted"),
            ("idp.saml", "accepted"),
            ("idp.scim", "accepted"),
            ("idp.signal", "accepted"),
            ("idp.ssh", "accepted"),
            ("idp.upstream", "accepted"),
            ("idp.vault", "accepted"),
            ("idp.vc", "accepted"),
        ]
    );
    for action in IdpAction::ALL {
        assert!(accepts(&w, domain, action).await, "{action:?}");
    }
    for (action, kind) in [
        (IdpAction::AgentRegister, "agent"),
        (IdpAction::RealmDeviceCode, "realm"),
    ] {
        assert!(
            matches!(
                exercise(&w, domain, "third", action, kind).await,
                Verdict::Committed(_)
            ),
            "{action:?}"
        );
    }
}

#[tokio::test]
async fn a_catalog_4_realm_refuses_the_version_5_actions_until_its_upgrade_commits() {
    // OP-155 m.3 (a), m.1 (a), OP-153 m.3 (a)
    let w = World::new("catalog-v5").await;
    let governance = FirstCatalog {
        plane: &w.plane,
        domains: &w.domains,
        version: 4,
    };
    let (tenant, created) = realm_with(&w, &governance, "fourth").await;
    let domain = created.domain;
    assert!(accepts(&w, domain, IdpAction::AgentRegister).await);
    assert!(accepts(&w, domain, IdpAction::RealmDeviceCodeClose).await);
    for action in IdpAction::ALL.into_iter().filter(|a| a.since() == 5) {
        assert!(!accepts(&w, domain, action).await, "{action:?}");
    }

    let declared = DeclaredTargets::default();
    let b = bootstrap(&w, &declared);
    let root = root_key(&w.keys).unwrap();
    let party = root_party(&root.public_key());
    b.onboard(tenant, created.realm, domain, &root, party)
        .await
        .unwrap();
    w.domains.release().await;
    for (action, kind) in [
        (IdpAction::RealmCiba, "realm"),
        (IdpAction::ScimClientRegister, "scim"),
        (IdpAction::OrgSsoEnforce, "org"),
        (IdpAction::ClientProfile, "client"),
    ] {
        let Verdict::NotAllowed { decision, .. } =
            exercise(&w, domain, "fourth", action, kind).await
        else {
            panic!("{action:?} before the upgrade");
        };
        assert!(catalog_upgrade_required(&decision), "{action:?}");
    }

    let summary = w.run(&old_plan("fourth")).await;
    let mut namespaces: Vec<_> = upgraded(&summary, "fourth")
        .iter()
        .map(|c| (c.namespace.as_str(), c.state))
        .collect();
    namespaces.sort_unstable();
    assert_eq!(
        namespaces,
        vec![
            ("idp.client", "accepted"),
            ("idp.domain", "accepted"),
            ("idp.export", "accepted"),
            ("idp.federation", "accepted"),
            ("idp.gateway", "accepted"),
            ("idp.hr", "accepted"),
            ("idp.linux", "accepted"),
            ("idp.org", "accepted"),
            ("idp.proxy", "accepted"),
            ("idp.realm", "accepted"),
            ("idp.relay", "accepted"),
            ("idp.saml", "accepted"),
            ("idp.scim", "accepted"),
            ("idp.signal", "accepted"),
            ("idp.ssh", "accepted"),
            ("idp.upstream", "accepted"),
            ("idp.vc", "accepted"),
        ]
    );
    for action in IdpAction::ALL {
        assert!(accepts(&w, domain, action).await, "{action:?}");
    }
    for (action, kind) in [
        (IdpAction::RealmCiba, "realm"),
        (IdpAction::ScimClientRegister, "scim"),
        (IdpAction::GatewayRegister, "gateway"),
    ] {
        assert!(
            matches!(
                exercise(&w, domain, "fourth", action, kind).await,
                Verdict::Committed(_)
            ),
            "{action:?}"
        );
    }
}

#[tokio::test]
async fn a_catalog_5_realm_refuses_the_version_6_actions_until_its_upgrade_commits() {
    // OP-156 m.3 (a), m.1 (a), OP-153 m.3 (a)
    let w = World::new("catalog-v6").await;
    let governance = FirstCatalog {
        plane: &w.plane,
        domains: &w.domains,
        version: 5,
    };
    let (tenant, created) = realm_with(&w, &governance, "fifth").await;
    let domain = created.domain;
    assert!(accepts(&w, domain, IdpAction::RealmCiba).await);
    assert!(accepts(&w, domain, IdpAction::GatewayRegister).await);
    for action in IdpAction::ALL.into_iter().filter(|a| a.since() == 6) {
        assert!(!accepts(&w, domain, action).await, "{action:?}");
    }

    let declared = DeclaredTargets::default();
    let b = bootstrap(&w, &declared);
    let root = root_key(&w.keys).unwrap();
    let party = root_party(&root.public_key());
    b.onboard(tenant, created.realm, domain, &root, party)
        .await
        .unwrap();
    w.domains.release().await;
    for (action, kind) in [
        (IdpAction::RealmPush, "realm"),
        (IdpAction::ProxyRegister, "proxy"),
        (IdpAction::SshCaEnable, "ssh"),
        (IdpAction::ExportSinkRegister, "export"),
    ] {
        let Verdict::NotAllowed { decision, .. } =
            exercise(&w, domain, "fifth", action, kind).await
        else {
            panic!("{action:?} before the upgrade");
        };
        assert!(catalog_upgrade_required(&decision), "{action:?}");
    }

    let summary = w.run(&old_plan("fifth")).await;
    let mut namespaces: Vec<_> = upgraded(&summary, "fifth")
        .iter()
        .map(|c| (c.namespace.as_str(), c.state))
        .collect();
    namespaces.sort_unstable();
    assert_eq!(
        namespaces,
        vec![
            ("idp.domain", "accepted"),
            ("idp.export", "accepted"),
            ("idp.hr", "accepted"),
            ("idp.linux", "accepted"),
            ("idp.proxy", "accepted"),
            ("idp.realm", "accepted"),
            ("idp.relay", "accepted"),
            ("idp.signal", "accepted"),
            ("idp.ssh", "accepted"),
        ]
    );
    for action in IdpAction::ALL {
        assert!(accepts(&w, domain, action).await, "{action:?}");
    }
    for (action, kind) in [
        (IdpAction::RealmPush, "realm"),
        (IdpAction::ProxyRegister, "proxy"),
        (IdpAction::HrSourceRegister, "hr"),
    ] {
        assert!(
            matches!(
                exercise(&w, domain, "fifth", action, kind).await,
                Verdict::Committed(_)
            ),
            "{action:?}"
        );
    }
}

#[tokio::test]
async fn an_idp_write_before_the_upgrade_answers_catalog_upgrade_required() {
    // OP-153 m.3 (a), TN-110
    let w = World::new("catalog-required").await;
    let governance = OldCatalog {
        plane: &w.plane,
        domains: &w.domains,
        delay_s: None,
    };
    let (tenant, created) = realm_with(&w, &governance, "behind").await;
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let declared = DeclaredTargets::default();
    let b = bootstrap(&w, &declared);
    let root = root_key(&w.keys).unwrap();
    let party = root_party(&root.public_key());
    b.onboard(tenant, created.realm, created.domain, &root, party)
        .await
        .unwrap();
    let id = ids
        .encode(access_identity_admin::domain::WEBHOOK_PREFIX, [0x52; 16])
        .unwrap();
    let change = access_identity_admin::app::rest::compile(
        access_identity_admin::app::rest::Op::RegisterWebhook,
        None,
        &serde_json::json!({"webhook_id": id, "url": "https://sync.shop.example/events",
                "events": ["account.created"]}),
        &ids,
    )
    .unwrap();
    let admin = b.admin(&ids, None);
    let refused = b
        .change(
            &admin,
            (tenant, created.realm),
            created.domain,
            &root,
            change,
        )
        .await;
    w.domains.release().await;
    assert!(
        matches!(
            refused,
            Err(BootstrapError::Admin(AdminError::Invalid(
                access_identity_admin::domain::Invalid::CatalogUpgradeRequired
            )))
        ),
        "{refused:?}"
    );
}

/// Opens Genesis as it stood before recovery joined it: the bootstrap Grant without
/// `instance_recover` and the realm issuer's Acceptance without `recovery_result`; the CT3
/// time-lock is zero.
struct PreRecovery<'a> {
    plane: &'a TestPlane,
    domains: &'a TestDomains,
}

fn without_recovery(v: &mut Value) {
    let Value::Map(entries) = v else {
        return;
    };
    for (k, val) in entries.iter_mut() {
        match (k, val) {
            (Value::Text(t), val @ Value::Map(_)) if t == "authority" => {
                let mut a = access_authority_core::genesis::bootstrap_authority();
                a.authority
                    .actions
                    .exact
                    .remove(&access_kernel::meta::core_action("instance_recover"));
                *val = access_kernel::codec::Canonical::to_value(&a);
            }
            (Value::Text(t), Value::Array(classes)) if t == "classes" => {
                classes.retain(|c| *c != Value::text("recovery_result"));
            }
            _ => {}
        }
    }
}

impl Governance for PreRecovery<'_> {
    async fn open(&self, mut order: GenesisOrder) -> Result<GenesisOpened, Unavailable> {
        order.ct3_delay_s = Some(0);
        let mut fields = access_authority_core::genesis::realm(&order, &mut OsSalts)
            .map_err(|e| Unavailable(e.to_string()))?;
        for name in ["grants", "acceptances"] {
            let Value::Array(items) = &mut fields.get_mut(name).unwrap().value else {
                panic!("{name}");
            };
            items.iter_mut().for_each(without_recovery);
            items.sort_by_key(|v| {
                suiss_crypto::dcbor::encode(v, suiss_crypto::dcbor::Limits::CEILING).unwrap()
            });
        }
        let now = Instances::now(self.plane).await?;
        let domain = self
            .domains
            .create(order.tenant, fields, now)
            .await
            .unwrap();
        Ok(GenesisOpened { domain })
    }
}

impl Instances for PreRecovery<'_> {
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, Unavailable> {
        Instances::register(self.plane, r).await
    }

    async fn now(&self) -> Result<u64, Unavailable> {
        Instances::now(self.plane).await
    }
}

// OP-153 m.3 (c), m.13 (e), OP-152 m.8 (a)
#[tokio::test]
async fn a_domain_opened_before_recovery_takes_it_once_its_root_signs_it() {
    let w = World::new("recovery-upgrade").await;
    let governance = PreRecovery {
        plane: &w.plane,
        domains: &w.domains,
    };
    let domain = realm_with(&w, &governance, "elder").await.1.domain;
    let summary = w.run(&old_plan("elder")).await;
    let mut steps: Vec<_> = upgraded(&summary, "elder")
        .iter()
        .map(|c| (c.namespace.as_str(), c.state))
        .collect();
    steps.sort_unstable();
    assert_eq!(
        steps,
        vec![
            ("access.bootstrap", "accepted"),
            ("access.recovery_result", "accepted")
        ]
    );
    let grant = access_kernel::meta::object_id(
        &domain,
        access_kernel::meta::kind::GRANT,
        access_authority_core::genesis::BOOTSTRAP_GRANT,
    );
    let rows = access_store::authority::state_of(
        &w.db.app,
        &DomainId::from_bytes(domain.0),
        &[access_kernel::meta::key(
            access_kernel::meta::kind::GRANT,
            &grant,
        )],
    )
    .await
    .unwrap();
    let state = <access_kernel::meta::GrantState as access_kernel::codec::Canonical>::from_value(
        &suiss_crypto::dcbor::decode(
            rows[0].value.as_deref().unwrap(),
            suiss_crypto::dcbor::Limits::CEILING,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        state
            .content
            .authority
            .authority
            .actions
            .exact
            .contains(&access_kernel::meta::core_action("instance_recover"))
    );
    let again = w.run(&old_plan("elder")).await;
    assert_eq!(upgraded(&again, "elder"), []);
}

/// Opens Genesis as a realm was opened before the realm issuer's `org_member` subject
/// selection (OP-153 m.25 (i) (3)).
struct PreOrgMember<'a> {
    plane: &'a TestPlane,
    domains: &'a TestDomains,
}

impl Governance for PreOrgMember<'_> {
    async fn open(&self, mut order: GenesisOrder) -> Result<GenesisOpened, Unavailable> {
        order.ct3_delay_s = Some(0);
        order.acceptances.retain(|a| {
            access_kernel::claim::Gate::of(a).is_ok_and(|g| {
                g.use_ != "subject-selection" || !g.classes.iter().any(|c| c == "org_member")
            })
        });
        let fields = access_authority_core::genesis::realm(&order, &mut OsSalts)
            .map_err(|e| Unavailable(e.to_string()))?;
        let now = Instances::now(self.plane).await?;
        let domain = self
            .domains
            .create(order.tenant, fields, now)
            .await
            .unwrap();
        Ok(GenesisOpened { domain })
    }
}

impl Instances for PreOrgMember<'_> {
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, Unavailable> {
        Instances::register(self.plane, r).await
    }

    async fn now(&self) -> Result<u64, Unavailable> {
        Instances::now(self.plane).await
    }
}

// E18, OP-153 m.17 (c), m.25 (i) (3), OP-152 m.8 (a)
#[tokio::test]
async fn a_domain_opened_before_org_member_selection_takes_it_once_its_root_signs_it() {
    let w = World::new("org-member-upgrade").await;
    let governance = PreOrgMember {
        plane: &w.plane,
        domains: &w.domains,
    };
    realm_with(&w, &governance, "older").await;
    let summary = w.run(&old_plan("older")).await;
    let steps: Vec<_> = upgraded(&summary, "older")
        .iter()
        .map(|c| (c.namespace.as_str(), c.state))
        .collect();
    assert_eq!(steps, vec![("access.org_member", "accepted")]);
    let again = w.run(&old_plan("older")).await;
    assert_eq!(upgraded(&again, "older"), []);
}

/// Opens Genesis as a realm was opened before the agent and workload Acceptances (OP-154 m.9
/// (f), m.11 (d)).
struct PreAgents<'a> {
    plane: &'a TestPlane,
    domains: &'a TestDomains,
}

impl Governance for PreAgents<'_> {
    async fn open(&self, mut order: GenesisOrder) -> Result<GenesisOpened, Unavailable> {
        order.ct3_delay_s = Some(0);
        let agents = [
            "operated_by",
            "sponsored_by",
            "agent_kind",
            "identity_binding_workload",
            "attestation_runtime",
        ];
        order.acceptances.retain(|a| {
            access_kernel::claim::Gate::of(a)
                .is_ok_and(|g| !g.classes.iter().any(|c| agents.contains(&c.as_str())))
        });
        let fields = access_authority_core::genesis::realm(&order, &mut OsSalts)
            .map_err(|e| Unavailable(e.to_string()))?;
        let now = Instances::now(self.plane).await?;
        let domain = self
            .domains
            .create(order.tenant, fields, now)
            .await
            .unwrap();
        Ok(GenesisOpened { domain })
    }
}

impl Instances for PreAgents<'_> {
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, Unavailable> {
        Instances::register(self.plane, r).await
    }

    async fn now(&self) -> Result<u64, Unavailable> {
        Instances::now(self.plane).await
    }
}

// OP-154 m.3 (c), (d), (s), m.9 (f), m.11 (d), OP-152 m.8 (a)
#[tokio::test]
async fn a_domain_opened_before_agents_takes_their_acceptances_once_its_root_signs_them() {
    let w = World::new("agents-upgrade").await;
    let governance = PreAgents {
        plane: &w.plane,
        domains: &w.domains,
    };
    realm_with(&w, &governance, "agentless").await;
    let summary = w.run(&old_plan("agentless")).await;
    let mut steps: Vec<_> = upgraded(&summary, "agentless")
        .iter()
        .map(|c| (c.namespace.as_str(), c.state))
        .collect();
    steps.sort_unstable();
    assert_eq!(
        steps,
        vec![
            ("access.agent_claims", "accepted"),
            ("access.agent_selection", "accepted"),
            ("access.attestation_runtime", "accepted"),
            ("access.workload_binding", "accepted"),
        ]
    );
    let again = w.run(&old_plan("agentless")).await;
    assert_eq!(upgraded(&again, "agentless"), []);
}

/// Opens Genesis as one before the agent Acceptances, with the CT3 time-lock of a real realm.
struct PreAgentsLocked<'a> {
    plane: &'a TestPlane,
    domains: &'a TestDomains,
}

impl Governance for PreAgentsLocked<'_> {
    async fn open(&self, mut order: GenesisOrder) -> Result<GenesisOpened, Unavailable> {
        order.ct3_delay_s = Some(3600);
        order.acceptances.retain(|a| {
            access_kernel::claim::Gate::of(a)
                .is_ok_and(|g| !g.classes.iter().any(|c| c == "attestation_runtime"))
        });
        let fields = access_authority_core::genesis::realm(&order, &mut OsSalts)
            .map_err(|e| Unavailable(e.to_string()))?;
        let now = Instances::now(self.plane).await?;
        let domain = self
            .domains
            .create(order.tenant, fields, now)
            .await
            .unwrap();
        Ok(GenesisOpened { domain })
    }
}

impl Instances for PreAgentsLocked<'_> {
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, Unavailable> {
        Instances::register(self.plane, r).await
    }

    async fn now(&self) -> Result<u64, Unavailable> {
        Instances::now(self.plane).await
    }
}

// §13.7.3, OP-154 m.11 (d), OP-152 m.8 (a)
#[tokio::test]
async fn an_agent_acceptance_upgrade_waits_out_the_time_lock_on_the_same_exercise() {
    let w = World::new("agents-upgrade-lock").await;
    let governance = PreAgentsLocked {
        plane: &w.plane,
        domains: &w.domains,
    };
    realm_with(&w, &governance, "locked").await;
    let first = w.run(&old_plan("locked")).await;
    let pending: Vec<_> = upgraded(&first, "locked")
        .iter()
        .map(|c| (c.namespace.clone(), c.state, c.after.is_some()))
        .collect();
    assert_eq!(
        pending,
        vec![(String::from("access.attestation_runtime"), "pending", true)]
    );
    let second = w.run(&old_plan("locked")).await;
    assert_eq!(upgraded(&second, "locked"), upgraded(&first, "locked"));
}
