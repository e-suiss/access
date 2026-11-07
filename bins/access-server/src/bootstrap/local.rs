//! What a product's end-to-end tests need from a local deployment besides the realms and
//! clients (OP-149 m.26 (b), (c), (e), m.28 (b)): a test user with a password and a software
//! passkey, a public client to sign in with and a device Instance that binds the user to a
//! Party, in a sample realm; the
//! Acceptance under which a local declarant Party's unsigned `party_compromise` Claims are
//! admitted there, so a product's PEP can produce `party.compromised` at Claim Ingest; and the
//! `idp.client.update` and `idp.client.retire` changes of a platform client, which produce
//! `api_client.updated` and `api_client.disabled`. Each goes through the paths production uses,
//! and every step looks for its result first.

use std::path::PathBuf;
use std::sync::Arc;

use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::hibp::MirrorRanges;
use access_identity_account::adapters::pg::{PgAccounts, PgTx};
use access_identity_account::adapters::system::{
    SystemClock, SystemEntropy, cgroup_memory_budget, cores,
};
use access_identity_account::app::accounts::{
    PasswordServices, change_status, create, set_password,
};
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::local::LocalLimiter;
use access_identity_account::app::login::LoginGate;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::domain::throttle::ThrottlePolicy;
use access_identity_account::ports::{AccountDb, AccountTx, BreachRanges, RangeUnavailable};
use access_identity_admin::AdminError;
use access_identity_admin::app::{Admin, Applied};
use access_identity_admin::domain::{AuthMethod, Change, Client, ClientId};
use access_identity_admin::ports::{Decider, Governance, Instances, RealmKeys};
use access_identity_events::adapters::RealmKek as _;
use access_identity_events::domain::catalog::IdentityKind;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::ports::RealmEntry;
use access_identity_session::adapters::OsRandom;
use access_identity_session::adapters::passkeys::PgPasskeys;
use access_identity_session::app::{Auth, Passkeys};
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::adapters::{LogSignals, Outbox};
use access_identity_ui::app::devices::{self, DeviceKey};
use access_identity_ui::ports::{Kits as _, Messages as _, RealmKit};
use access_identity_webauthn::app::RegistrationOutcome;
use access_identity_webauthn::domain::ceremony::{ClientExtensionResults, RegistrationResponse};
use access_identity_webauthn::domain::ids::UserHandle;
use access_identity_webauthn::domain::software::SoftwareAuthenticator;
use access_identity_webauthn::ports::CredentialRegistry as _;
use access_kernel::claim::{PARTY_COMPROMISE, PREDICATE_INPUT};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::model::{Id, SubjectSelector};
use access_kernel::verify::cose::PublicKey;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp;
use access_store::issuer::subject_instance;
use access_store::tenancy::route_by_slug;
use serde::Serialize;
use suiss_crypto::dcbor::Value;
use suiss_crypto::pkcs11::HsmSigner;
use suiss_crypto::signer::Signer as _;

use super::{
    Bootstrap, BootstrapError, CompromiseOut, CompromisePlan, MetaExercises, Plan, TestUserOut,
    TestUserPlan, cell_ids, root_key, root_party, token_key,
};
use crate::login::{HsmKits, RealmKeks};

/// The token label of the local compromise declarant's key (OP-149 m.26 (c)).
pub(crate) const DECLARANT_LABEL: &str = "access/bootstrap/compromise-declarant";

/// The token label of the test user's device key (OP-149 m.28 (b)).
pub(crate) const TEST_DEVICE_LABEL: &str = "access/bootstrap/test-user-device";

/// The token label of the test user's software passkey (OP-149 m.26 (e)).
pub(crate) const TEST_PASSKEY_LABEL: &str = "access/bootstrap/test-user-passkey";

/// Who the bootstrap is in the account audit log (OP-10).
const BOOTSTRAP: Actor<'static> = Actor {
    actor: "access-bootstrap",
    correlation: "bootstrap",
};

/// The breach corpus the test user's password is checked against (IDP-3): the deployment's
/// local mirror when the plan names one; without one there is nothing to check against, and
/// the bootstrap says so.
enum Corpus {
    Mirror(MirrorRanges),
    Absent,
}

impl Corpus {
    fn of(dir: Option<PathBuf>) -> Self {
        if let Some(d) = dir {
            return Self::Mirror(MirrorRanges::new(d));
        }
        tracing::warn!(
            "test_user: no breach_ranges_dir in the plan; the test password is not checked \
             against a breach corpus"
        );
        Self::Absent
    }
}

impl BreachRanges for Corpus {
    async fn range(&self, prefix: &str) -> Result<String, RangeUnavailable> {
        match self {
            Self::Mirror(m) => m.range(prefix).await,
            Self::Absent => Ok(String::new()),
        }
    }
}

/// The change a one-shot command makes to a platform client (OP-149 m.26 (c)).
#[derive(Clone, Debug)]
pub(crate) enum ProductChange {
    /// `idp.client.update` with a new display name.
    Update {
        /// The new display name.
        display_name: String,
    },
    /// `idp.client.retire`.
    Retire,
}

/// What a platform client change committed.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ChangeOut {
    pub(crate) product: String,
    pub(crate) client_id: String,
    /// The `idp.*` action committed.
    pub(crate) action: String,
    /// The event the change queued for the platform client's streams.
    pub(crate) event: &'static str,
    /// The `ExerciseID`, base64url.
    pub(crate) exercise: String,
    /// Position of the decision record.
    pub(crate) position: u64,
}

/// A `staged` account with `identifier`, the plan's password as its credential (§10.2.1), moved
/// to `active` along TN-49.
async fn create_account(
    accounts: &PgAccounts,
    scope: &Realm<'_>,
    identifier: &Identifier,
    u: &TestUserPlan,
) -> Result<[u8; 16], BootstrapError> {
    let subject = create(
        accounts,
        scope,
        std::slice::from_ref(identifier),
        &BOOTSTRAP,
    )
    .await?;
    let hasher = Hasher::new(HasherConfig::sized(
        Argon2Params::CANONICAL,
        cores(),
        cgroup_memory_budget(),
    ));
    let corpus = Corpus::of(u.breach_ranges_dir.clone());
    let services = PasswordServices {
        hasher: &hasher,
        ranges: &corpus,
        entropy: &SystemEntropy,
    };
    set_password(
        accounts,
        scope,
        &services,
        subject,
        u.password.expose(),
        &BOOTSTRAP,
    )
    .await?;
    for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
        change_status(accounts, scope, subject, to, &BOOTSTRAP).await?;
    }
    Ok(subject)
}

/// The `acceptance-content` under which `issuer`'s `party_compromise` Claims are predicate
/// input about any subject, for good (L2-CLM-3); a sample realm's Genesis establishes it.
pub(super) fn acceptance(issuer: Id) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (Value::text("use"), Value::text(PREDICATE_INPUT)),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text(PARTY_COMPROMISE)]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

impl<P, K> Bootstrap<'_, P, K>
where
    P: Decider + Governance + Instances + MetaExercises,
    K: RealmKeys,
{
    /// The test user of `u` in the realm, active with a password credential (AAL1) and a
    /// software passkey (AAL2), the public client a headless login signs in with (OP-149 m.26
    /// (b), (e)), and its Party. An account holding the identifier is found, not made again.
    pub(super) async fn test_user(
        &self,
        admin: &Admin<'_, P, P, K>,
        ids: &IdKey,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        root: &HsmSigner,
        u: &TestUserPlan,
    ) -> Result<(TestUserOut, Id), BootstrapError> {
        let kind = if u.identifier.contains('@') {
            IdentifierKind::Email
        } else {
            IdentifierKind::Username
        };
        let identifier = Identifier::new(kind, &u.identifier)
            .map_err(|e| BootstrapError::Plan(format!("test_user identifier: {e}")))?;
        let keks = RealmKeks::new(Arc::clone(self.hsm));
        let kek = keks
            .kek(tenant, realm)
            .ok_or_else(|| BootstrapError::Unavailable(String::from("realm KEK")))?;
        let scope = Realm {
            tenant,
            realm,
            kek: &*kek,
            ids,
        };
        let accounts = PgAccounts(self.app.clone());
        let mut tx = accounts.begin(tenant, realm).await?;
        let existing = tx.subject_by_identifier(identifier.value()).await?;
        tx.commit().await?;
        let (subject, created) = if let Some(s) = existing {
            (s, false)
        } else {
            (
                create_account(&accounts, &scope, &identifier, u).await?,
                true,
            )
        };
        let client_id = self
            .public_client(admin, (tenant, realm), domain, root, u)
            .await?;
        let (party, instance) = self.device_party((tenant, realm), domain, subject).await?;
        let passkey = self.passkey(&u.realm, subject, identifier.value()).await?;
        Ok((
            TestUserOut {
                realm: u.realm.clone(),
                issuer: String::new(),
                identifier: String::from(identifier.value()),
                subject: scope.external(subject)?,
                client_id,
                redirect_uri: String::from(u.redirect_uri.as_str()),
                party: b64url_encode(&party.0),
                instance: b64url_encode(&instance.0),
                passkey: b64url_encode(&passkey),
                allowed: None,
                created,
            },
            party,
        ))
    }

    /// Whether `subject` holds the live passkey `credential_id` in the realm.
    async fn has_passkey(
        &self,
        kit: &RealmKit,
        registry: &PgPasskeys<'_>,
        subject: [u8; 16],
        credential_id: &[u8],
    ) -> Result<bool, BootstrapError> {
        let mut t = TenantTx::begin(self.app, kit.tenant, kit.realm).await?;
        let handle = t.user_handle(subject).await?;
        t.commit().await?;
        let Some(h) = handle else {
            return Ok(false);
        };
        Ok(registry
            .list(kit.rp.realm, &UserHandle::from_bytes(h))
            .await
            .map_err(|e| BootstrapError::Unavailable(e.to_string()))?
            .iter()
            .any(|r| r.id.as_bytes() == credential_id))
    }

    /// The test user's software passkey (OP-149 m.26 (e)): an Ed25519 key kept in the token
    /// answers the realm's own registration ceremony, through the step the hosted
    /// `POST /v1/account/passkeys/{registration}` finishes with (§10.2.4, OP-150 L2), so the
    /// passkey is a device-bound, user-verified credential of the account like any other. A
    /// registered passkey of that key is found, not made again. Returns the credential id.
    async fn passkey(
        &self,
        slug: &str,
        subject: [u8; 16],
        identifier: &str,
    ) -> Result<[u8; 32], BootstrapError> {
        let key = token_key(self.hsm, TEST_PASSKEY_LABEL)?;
        let PublicKey::Ed25519(public) = key.public_key() else {
            return Err(BootstrapError::Encode);
        };
        let authenticator = SoftwareAuthenticator::ed25519(public);
        let route = route_by_slug(self.router, slug)
            .await?
            .ok_or(AdminError::NoRealm)?;
        let issuer = Issuer::parse(&route.issuer)
            .map_err(|e| BootstrapError::Plan(format!("test_user: realm issuer: {e}")))?;
        let entry = RealmEntry {
            tenant: route.tenant,
            realm: route.realm,
            slug: route.slug.clone(),
            issuer,
        };
        let kits = HsmKits::new(
            RealmKeks::new(Arc::clone(self.hsm)),
            self.router.clone(),
            SessionPolicy::DEFAULT,
        );
        let kit = kits
            .kit(&entry)
            .await
            .map_err(|_| BootstrapError::Unavailable(String::from("realm keys")))?;
        let registry = PgPasskeys {
            pool: self.app,
            tenant: kit.tenant,
            kek: &*kit.kek,
            ids: &kit.ids,
        };
        if self
            .has_passkey(&kit, &registry, subject, &authenticator.credential_id)
            .await?
        {
            return Ok(authenticator.credential_id);
        }
        let db = PgAccounts(self.app.clone());
        let realm = kit.realm();
        let notifier = Outbox.notifier(&realm);
        let link_base = format!("{}/login/link#", kit.issuer);
        let gate = LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0);
        let hasher = Hasher::new(HasherConfig::sized(
            Argon2Params::CANONICAL,
            cores(),
            cgroup_memory_budget(),
        ));
        let auth = Auth {
            db: &db,
            realm: kit.realm(),
            policy: kit.auth,
            lifetimes: kit.lifetimes,
            clock: &SystemClock,
            random: &OsRandom,
            notifier: &notifier,
            link_base: &link_base,
            gate: &gate,
            hasher: &hasher,
            hooks: &access_identity_hooks::ports::NoHooks,
            passkeys: Passkeys {
                registry: &registry,
                signals: &LogSignals,
                decoys: &kit.decoys,
                rp: &kit.rp,
                policy: &kit.webauthn,
            },
        };
        let start = auth
            .start_passkey(subject, identifier, identifier)
            .await
            .map_err(|e| BootstrapError::Unavailable(e.to_string()))?;
        let origin = format!("https://{}", entry.issuer.authority());
        let reg =
            authenticator.registration(kit.rp.rp_id.as_str(), &origin, &start.state.challenge);
        let outcome = auth
            .register_passkey(
                subject,
                &start.state,
                &RegistrationResponse {
                    raw_id: &reg.id,
                    client_data_json: &reg.client_data_json,
                    attestation_object: &reg.attestation_object,
                    transports: &[String::from("internal")],
                    extensions: ClientExtensionResults::default(),
                },
                BOOTSTRAP.correlation,
            )
            .await
            .map_err(|e| BootstrapError::Unavailable(e.to_string()))?;
        match outcome {
            RegistrationOutcome::Registered(_) => Ok(authenticator.credential_id),
            RegistrationOutcome::Rejected(r) => {
                Err(BootstrapError::Refused(format!("test_user passkey: {r}")))
            }
        }
    }

    /// The test user's Party and device Instance in the realm's governing domain (OP-149 m.28
    /// (b), m.16 (a), L0-META-7): a device key kept in the token signs its own `party_register`
    /// and `instance_create`, and the identity plane binds the subject to that Party, queues the
    /// `identity_binding_person` Claim and records the device key, as `POST /v1/me/instances`
    /// does (OP-150 m.12 (d)). A subject with a Party and a device keeps them.
    async fn device_party(
        &self,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        subject: [u8; 16],
    ) -> Result<(Id, Id), BootstrapError> {
        let key = token_key(self.hsm, TEST_DEVICE_LABEL)?;
        let party = root_party(&key.public_key());
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let bound = idp::subject_party(&mut t, &subject).await?;
        let instance = subject_instance(&mut t, &subject).await?;
        t.commit().await?;
        if let (Some(p), Some(i)) = (bound, instance) {
            return Ok((Id(p), Id(i)));
        }
        if bound.is_some_and(|p| p != party.0) {
            return Err(BootstrapError::Plan(String::from(
                "test_user: the account is bound to a Party that is not the plan's device key's",
            )));
        }
        let onboarded = self
            .register(tenant, realm, domain, &key, party, subject)
            .await?;
        let mut tx = PgTx(TenantTx::begin(self.app, tenant, realm).await?);
        devices::bind_party(&mut tx, &subject, &party.0, &onboarded.register_ais).await?;
        let device = DeviceKey {
            subject,
            key: key.public_key(),
            instance: onboarded.instance.0,
            session: None,
        };
        devices::record_device_key(&mut tx, &device).await?;
        tx.0.commit().await?;
        Ok((party, onboarded.instance))
    }

    /// The active public client of the realm with the test user's redirect URI, registered by
    /// an `idp.client.register` Exercise the root signs when there is none.
    async fn public_client(
        &self,
        admin: &Admin<'_, P, P, K>,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        root: &HsmSigner,
        u: &TestUserPlan,
    ) -> Result<String, BootstrapError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let mut found = None;
        for id in idp::clients_with_redirect(&mut t, u.redirect_uri.as_str()).await? {
            if let Some(row) = idp::client(&mut t, &id).await?
                && row.active
                && row.auth_method == AuthMethod::None.name()
                && row.platform_product.is_none()
            {
                found = Some(row.client_id);
                break;
            }
        }
        t.commit().await?;
        if let Some(id) = found {
            return Ok(id);
        }
        let client = Client {
            id: admin.new_client_id().await?,
            display_name: u.client_display_name.clone(),
            auth: AuthMethod::None,
            redirect_uris: vec![u.redirect_uri.clone()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            platform: None,
        };
        let id = String::from(client.id.as_str());
        self.change(
            admin,
            (tenant, realm),
            domain,
            root,
            Change::ClientRegister(client),
        )
        .await?;
        Ok(id)
    }

    /// The local declarant's key, made in the token once, and its Party (OP-149 m.26 (c)).
    pub(super) fn declarant(&self) -> Result<(HsmSigner, Id), BootstrapError> {
        let key = token_key(self.hsm, DECLARANT_LABEL)?;
        let issuer = root_party(&key.public_key());
        Ok((key, issuer))
    }

    /// The local declarant's Instance in the realm's domain, whose Genesis accepted its
    /// `party_compromise` Claims as predicate input (OP-149 m.26 (c), L2-CLM-3, L2-CLM-5).
    /// An Acceptance is a Genesis fact: a realm created without one keeps none, so the summary
    /// says whether this run created the realm.
    pub(super) async fn compromise(
        &self,
        c: &CompromisePlan,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        key: &HsmSigner,
        issuer: Id,
        created: bool,
    ) -> Result<CompromiseOut, BootstrapError> {
        self.onboard(tenant, realm, domain, key, issuer).await?;
        Ok(CompromiseOut {
            realm: c.realm.clone(),
            domain: b64url_encode(&domain.0),
            issuer: b64url_encode(&issuer.0),
            class: PARTY_COMPROMISE,
            created,
        })
    }

    /// Commits `change` to the platform client of `product` in the platform realm as an
    /// `idp.client.update` or `idp.client.retire` Exercise the root signs (OP-149 m.26 (c),
    /// MD-14, EI-25); its event is queued with the write.
    ///
    /// # Errors
    /// [`BootstrapError`]; a product the plan does not name, or one without an active client,
    /// is a plan error.
    pub(crate) async fn change_product_client(
        &self,
        plan: &Plan,
        product: &str,
        change: ProductChange,
    ) -> Result<ChangeOut, BootstrapError> {
        let p = plan
            .products
            .iter()
            .find(|p| p.product.name() == product)
            .ok_or_else(|| BootstrapError::Plan(format!("the plan names no product {product}")))?;
        let route = route_by_slug(self.router, &plan.platform)
            .await?
            .ok_or(AdminError::NoRealm)?;
        let mut t = TenantTx::begin(self.app, route.tenant, route.realm).await?;
        let g = idp::governance(&mut t).await?.ok_or(AdminError::NoRealm)?;
        t.commit().await?;
        let domain = Digest(*g.domain.as_bytes());
        let ids = cell_ids(self.app, self.hsm).await?;
        let admin = self.admin(&ids, Some(route.tenant));
        let root = root_key(self.hsm)?;
        let client_id = self
            .find_product_client((route.tenant, route.realm), p)
            .await?
            .ok_or_else(|| {
                BootstrapError::Plan(format!("{product} has no active platform client"))
            })?;
        let id = ClientId::parse(&client_id).map_err(AdminError::from)?;
        let (change, event) = match change {
            ProductChange::Update { display_name } => (
                Change::ClientUpdate(Client {
                    display_name,
                    ..p.client(id)
                }),
                IdentityKind::ApiClientUpdated,
            ),
            ProductChange::Retire => (Change::ClientRetire(id), IdentityKind::ApiClientDisabled),
        };
        let action = change.action().label();
        let applied = self
            .change(&admin, (route.tenant, route.realm), domain, &root, change)
            .await?;
        let (exercise, position) = match applied {
            Applied::Written {
                exercise, position, ..
            }
            | Applied::AlreadyWritten { exercise, position } => (exercise, position),
            Applied::NotAllowed { decision, .. } => {
                return Err(BootstrapError::Refused(format!("{:?}", decision.outcome)));
            }
        };
        Ok(ChangeOut {
            product: p.product.name().to_owned(),
            client_id,
            action,
            event: event.name(),
            exercise: b64url_encode(&exercise.0),
            position,
        })
    }
}
