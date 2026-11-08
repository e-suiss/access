//! The catalog upgrade on a domain opened with an older `idp.*` catalog (OP-151 m.18 (g)).

use access_internal_api::idp::{GenesisOpened, GenesisOrder, IdpAction};
use access_internal_api::instances::{Registration, RegistrationVerdict};
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
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let governance = OldCatalog {
        plane: &w.plane,
        domains: &w.domains,
        delay_s,
    };
    let admin = Admin {
        app: &w.db.app,
        ids: &ids,
        decider: &w.plane,
        governance: &governance,
        pep: IDENTITY_PEP,
        base: &w.base,
        keys: &w.keyring,
        platform_tenant: None,
        declared: DeclaredTargets::default(),
        vault: None,
    };
    let tenant = create_tenant(&w.db.app, PLACEMENT).await.unwrap();
    let root = root_party(&root_key(&w.keys).unwrap().public_key());
    admin
        .create_realm(&NewRealm {
            tenant,
            slug,
            style: IssuerStyle::Path,
            placement: PLACEMENT,
            root: Root::Sole(root),
            ct3_delay_s: None,
            schemas: Vec::new(),
            acceptances: Vec::new(),
            issuer_predicate_input: Vec::new(),
            provisioned_by: None,
        })
        .await
        .unwrap()
        .domain
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
