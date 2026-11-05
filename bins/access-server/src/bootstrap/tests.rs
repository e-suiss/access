#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use access_authority_core::adapters::{Domains, OsSalts, Setup};
use access_authority_sequencer::LEASE_TTL;
use access_authority_sequencer::adapters::SourcesClock;
use access_identity_oauth::adapters::SignerKeys;
use access_identity_oauth::adapters::outbound::DeclaredTargets;
use access_identity_signer::adapters::{DirVault, SealedFactory, now_ms, serve};
use access_identity_signer::service::Service;
use access_store::tenancy::tenants_after;
use access_store::testing::{TestDb, fresh};
use suiss_crypto::envelope::SoftKek;
use suiss_crypto::rotation::Policy;
use tokio::net::UnixListener;

use super::*;
use crate::idp::{ActorBindings, Plane, RealmKeyring};
use crate::login::kek_label;
use crate::testing::hsm;

const PIN: &str = "1234-test-only";

type TestPlane = Plane<KeyStore, ActorBindings, OsSalts, SourcesClock>;

/// A real identity signer on a Unix socket in a fresh directory.
fn identity_signer(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("abs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let service = Service::start(
        SealedFactory::new(SoftKek::new("realm-kek", [7; 32])),
        DirVault::new(&dir),
        Policy::REALM,
    )
    .unwrap();
    let path = dir.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        listener,
        Arc::new(Mutex::new(service)),
        vec![uid],
        now_ms,
    ));
    path
}

/// The bootstrap's world. Its token handles are never dropped: unloading `SoftHSM` after it
/// used OpenSSL leaves OpenSSL's exit handler behind in some hosts' loaders, and the test
/// process then crashes at exit.
struct World {
    db: TestDb,
    plane: TestPlane,
    domains: Arc<Domains<KeyStore, ActorBindings, OsSalts, SourcesClock>>,
    keys: Arc<KeyStore>,
    keyring: RealmKeyring,
    base: RealmBase,
}

impl World {
    async fn new(name: &str) -> Self {
        let db = fresh().await.unwrap();
        let (module, label) = hsm(name);
        let pin = Secret::new(String::from(PIN));
        let open = || KeyStore::open(&module, &label, &pin).unwrap();
        let actors = ActorBindings::default();
        let domains = Arc::new(Domains::new(Setup {
            sequencer: db.sequencer.clone(),
            app: db.app.clone(),
            keys: open(),
            holder: String::from("bootstrap-test"),
            ttl: LEASE_TTL,
            binding: actors.clone(),
            salts: OsSalts,
            clock: SourcesClock::new(db.sequencer.clone()),
            deriver: db.deriver.clone(),
            signer: None,
        }));
        let plane = Plane::new(
            domains.clone(),
            db.sequencer.clone(),
            db.app.clone(),
            SourcesClock::new(db.sequencer.clone()),
            actors,
        );
        Box::leak(Box::new(domains.clone()));
        let keys = Arc::new(open());
        Box::leak(Box::new(keys.clone()));
        let keyring = RealmKeyring::new(SignerKeys::new(identity_signer(name)), keys.clone());
        Self {
            db,
            plane,
            domains,
            keys,
            keyring,
            base: RealmBase::parse("https://access.test").unwrap(),
        }
    }

    async fn run(&self, plan: &Plan) -> Summary {
        let summary = Bootstrap {
            app: &self.db.app,
            router: &self.db.router,
            plane: &self.plane,
            realm_keys: &self.keyring,
            hsm: &self.keys,
            base: &self.base,
            declared: &DeclaredTargets::default(),
        }
        .run(plan)
        .await
        .unwrap();
        self.domains.release().await;
        summary
    }
}

fn client_key() -> PublicKey {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    PublicKey::P256(key.public_key().as_ref().to_vec())
}

fn plan() -> Plan {
    Plan {
        platform: String::from("platform"),
        tenants: vec![String::from("acme")],
        style: Style::Path,
        products: vec![ProductPlan {
            product: PlatformProduct::Work,
            display_name: String::from("Suiss Work"),
            client_key: client_key(),
            service_key: PublicKey::Ed25519(
                ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            event_receiver: Some(String::from("https://work.test/ssf")),
            redirect_uri: RedirectUri::parse("https://work.test/cb").unwrap(),
        }],
    }
}

// OP-69, OP-149 m.21, TN-111, L0-META-7, OP-149 m.4, MD-14, EI-25, OP-137: the bootstrap creates
// the platform tenant, a sample tenant and the Work client through the identity plane's paths,
// and a second run finds all of it and creates nothing
#[tokio::test]
async fn the_bootstrap_is_idempotent() {
    let w = World::new("bootstrap").await;
    let plan = plan();
    let first = w.run(&plan).await;
    assert_eq!(first.realms.len(), 2);
    let json = serde_json::to_value(&first).unwrap();
    assert_eq!(json["v"], 1);
    for key in [
        "tenant",
        "realm",
        "slug",
        "issuer",
        "discovery",
        "domain",
        "platform",
        "created",
    ] {
        assert!(json["realms"][0].get(key).is_some(), "{key}");
    }
    assert!(first.realms.iter().all(|r| r.created));
    let platform = &first.realms[0];
    assert!(platform.platform && !first.realms[1].platform);
    assert_eq!(platform.issuer, "https://access.test/realms/platform");
    assert_eq!(
        platform.discovery,
        "https://access.test/realms/platform/.well-known/suiss-configuration"
    );
    assert!(platform.tenant.starts_with("tnt_"));
    assert_eq!(platform.realm.len(), 36);
    assert_eq!(first.clients.len(), 1);
    assert!(first.clients[0].created);
    assert_eq!(first.clients[0].audience, platform.issuer);

    let second = w.run(&plan).await;
    assert!(second.realms.iter().all(|r| !r.created));
    assert!(second.clients.iter().all(|c| !c.created));
    assert_eq!(second.root.party, first.root.party);
    assert_eq!(second.clients[0].client_id, first.clients[0].client_id);
    for (a, b) in first.realms.iter().zip(&second.realms) {
        assert_eq!(
            (&a.tenant, &a.realm, &a.domain, &a.issuer),
            (&b.tenant, &b.realm, &b.domain, &b.issuer)
        );
    }
    assert_eq!(
        tenants_after(&w.db.router, None, 100).await.unwrap().len(),
        2
    );

    for r in &second.realms {
        let route = route_by_slug(&w.db.router, &r.slug).await.unwrap().unwrap();
        let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let g = idp::governance(&mut t).await.unwrap().unwrap();
        t.commit().await.unwrap();
        // L0-META-7: the root's Instance is registered once in each governing domain
        let challenge =
            root_challenge(&root_key(&w.keys).unwrap(), Digest(*g.domain.as_bytes())).unwrap();
        for nonce in [challenge.clone(), register_nonce(&challenge)] {
            let row = find_nonce(&w.db.app, &g.domain, &nonce)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.outcome, "allow");
        }
        // OP-146 m.16 (m)
        assert!(w.keys.kek(&kek_label(route.realm.as_bytes())).is_ok());
    }

    let route = route_by_slug(&w.db.router, "platform")
        .await
        .unwrap()
        .unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let row = idp::client(&mut t, &second.clients[0].client_id)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    assert!(row.active);
    assert_eq!(row.auth_method, "private_key_jwt");
    assert_eq!(row.platform_product.as_deref(), Some("work"));
    assert_eq!(row.event_receiver.as_deref(), Some("https://work.test/ssf"));
}

// OP-149 m.4: a product client is registered only in the platform tenant's realm, never in a
// sample tenant's
#[tokio::test]
async fn product_clients_live_in_the_platform_realm() {
    let w = World::new("bootstrap-platform").await;
    let summary = w.run(&plan()).await;
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let there = idp::client(&mut t, &summary.clients[0].client_id)
        .await
        .unwrap();
    t.commit().await.unwrap();
    assert!(there.is_none());
}

// OP-149 m.20: a plan names one public key per file, as a JWK or a one-key JWKS
#[test]
fn plan_keys_are_one_public_jwk() {
    let dir = std::env::temp_dir().join(format!("abs-jwk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let okp = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    let one = dir.join("one.jwk");
    std::fs::write(&one, okp).unwrap();
    assert!(matches!(jwk(&one), Ok(PublicKey::Ed25519(_))));
    let set = dir.join("set.jwks");
    std::fs::write(&set, format!(r#"{{"keys":[{okp}]}}"#)).unwrap();
    assert!(matches!(jwk(&set), Ok(PublicKey::Ed25519(_))));
    let two = dir.join("two.jwks");
    std::fs::write(&two, format!(r#"{{"keys":[{okp},{okp}]}}"#)).unwrap();
    assert!(jwk(&two).is_err());
    let private = dir.join("private.jwk");
    std::fs::write(
        &private,
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#,
    )
    .unwrap();
    assert!(jwk(&private).is_err());
}

// OP-69, TI-9: a plan is checked whole; an unknown key is refused
#[test]
fn plans_refuse_unknown_settings() {
    let dir = std::env::temp_dir().join(format!("abs-plan-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ok = dir.join("ok.toml");
    std::fs::write(
        &ok,
        "platform = \"platform\"\ntenants = [\"acme\"]\nissuer_style = \"path\"\n",
    )
    .unwrap();
    let plan = Plan::load(&ok).unwrap();
    assert_eq!(plan.style, Style::Path);
    assert_eq!(plan.tenants, vec![String::from("acme")]);
    let bad = dir.join("bad.toml");
    std::fs::write(&bad, "platform = \"platform\"\nskip_signatures = true\n").unwrap();
    assert!(Plan::load(&bad).is_err());
    assert!(Plan::load(&dir.join("missing.toml")).is_err());
}

// OP-69, OP-149 m.21: the local deployment's plan is valid
#[test]
fn the_local_deployment_plan_is_valid() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/compose/access/bootstrap.toml"
    );
    let plan = Plan::load(Path::new(path)).unwrap();
    assert_eq!(plan.platform, "platform");
    assert_eq!(plan.style, Style::Path);
}
