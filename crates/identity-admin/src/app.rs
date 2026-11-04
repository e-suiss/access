//! Use cases over the domain and its ports (OP-63): realm creation (TN-111) and the `idp.*`
//! write path (MD-14, EI-25).

use access_crypto::opaque_id::IdKey;
use access_identity_account::domain::password::Argon2Params;
use access_identity_oauth::domain::issuer::{Issuer, IssuerStyle, RealmBase};
use access_internal_api::idp::{GenesisOrder, Submission, Verdict};
use access_internal_api::instances::{
    PlatformProduct, Registrant, Registration, RegistrationVerdict, SelfSigned,
};
use access_kernel::combinator::{Capacity, Decision};
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::meta::{ExerciseBasis, Root};
use access_kernel::model::{Id, Window};
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{self, ClientRow, Decision as Bind, Governing, SettingsRow};
use access_store::scope::DomainId;
use access_store::tenancy::{self, HostKind};

use access_identity_events::app::emit;
use access_identity_events::domain::catalog::{
    ClientChange, IdentityEvent, IdentityKind, TENANT_PREFIX,
};

use crate::AdminError;
use crate::domain::{
    Attribute, AuthMethod, CLIENT_PREFIX, Change, Client, ClientId, Invalid, JoseAlg, cose_key,
    from_cose_key, raises,
};
use crate::ports::{Decider, Governance, Instances, RealmKeys};

/// A realm to create (TN-111, TN-16, TN-10).
pub struct NewRealm<'a> {
    /// The tenant.
    pub tenant: TenantId,
    /// The immutable slug.
    pub slug: &'a str,
    /// How its issuer is formed.
    pub style: IssuerStyle,
    /// Its placement (OP-40).
    pub placement: &'a str,
    /// The founding root of its governing domain (§12.5.1).
    pub root: Root,
    /// The CT3 time-lock; `None` keeps the default.
    pub ct3_delay_s: Option<u64>,
}

/// A created realm.
pub struct CreatedRealm {
    /// The realm.
    pub realm: RealmId,
    /// Its governing domain.
    pub domain: Digest,
    /// Its fixed issuer.
    pub issuer: Issuer,
}

/// An `idp.*` change as an actor proposes it: what the intent is built from (EI-25).
pub struct Proposal {
    /// The tenant.
    pub tenant: TenantId,
    /// The realm.
    pub realm: RealmId,
    /// The change.
    pub change: Change,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The intent's validity.
    pub validity: Window,
    /// The actor's declared basis.
    pub basis: ExerciseBasis,
    /// The actor's declared capacity.
    pub capacity: Capacity,
}

/// What the actor signs: the realm's governing domain and the intent of the change.
pub struct Prepared {
    /// The domain the AIS names.
    pub domain: Digest,
    /// The intent.
    pub intent: IntentEnvelope,
    /// Its digest.
    pub digest: Digest,
}

/// The result of an `idp.*` Exercise; a refusal is a decision, not an error.
#[derive(Debug, PartialEq, Eq)]
pub enum Applied {
    /// Committed and written (TN-110: the Exercise reference goes back to the caller).
    Written {
        /// The `ExerciseID`.
        exercise: Digest,
        /// Position of the decision record.
        position: u64,
        /// A `client_secret_basic` client's new secret, shown once and never stored
        /// (CR-38).
        secret: Option<ClientSecret>,
    },
    /// A retry of a decision already written; nothing changed.
    AlreadyWritten {
        /// The `ExerciseID`.
        exercise: Digest,
        /// Position of the decision record.
        position: u64,
    },
    /// Denied or waiting on an action; nothing was written.
    NotAllowed {
        /// The decision.
        decision: Decision,
        /// Position of its record, when recorded.
        position: Option<u64>,
    },
}

/// A server-generated client secret: 256 random bits as base64url (CR-38). Shown to the
/// caller once; only its digest is stored. It never appears in `Debug`.
#[derive(PartialEq, Eq)]
pub struct ClientSecret(String);

impl ClientSecret {
    /// The secret's text, to hand to the client's operator once.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for ClientSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ClientSecret(<redacted>)")
    }
}

/// The identity plane's configuration service.
pub struct Admin<'a, D, G, K> {
    /// The `access_app` pool.
    pub app: &'a Pool,
    /// The cell's opaque id key (OP-137).
    pub ids: &'a IdKey,
    /// The authority plane's decisions.
    pub decider: &'a D,
    /// The authority plane's Genesis.
    pub governance: &'a G,
    /// The identity plane's PEP name.
    pub pep: &'a str,
    /// Where realm issuers are formed.
    pub base: &'a RealmBase,
    /// The realms' keys outside the database.
    pub keys: &'a K,
    /// The platform tenant: only its administrators register platform product clients
    /// (OP-149 m.4). `None` allows none.
    pub platform_tenant: Option<TenantId>,
}

/// What the product signed for one realm it pairs with (OP-149 m.4, m.16 (a)): its system
/// Party there and the Exercises its service key signed itself.
#[derive(Clone, PartialEq, Eq)]
pub struct PairTarget {
    /// The tenant.
    pub tenant: TenantId,
    /// The realm whose governing domain gets the service Instance.
    pub realm: RealmId,
    /// The product's system Party in that domain.
    pub party: Id,
    /// `party_register`, when the Party is new there.
    pub register: Option<SelfSigned>,
    /// `instance_create`.
    pub create: SelfSigned,
}

/// The pairing of a platform client in one realm's governing domain (OP-149 m.4).
#[derive(Clone, PartialEq, Eq)]
pub struct Paired {
    /// The tenant.
    pub tenant: TenantId,
    /// The realm whose governing domain holds the service Instance.
    pub realm: RealmId,
    /// The authority plane's answer.
    pub verdict: RegistrationVerdict,
}

fn host_of(authority: &str) -> &str {
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

impl<D: Decider, G: Governance, K: RealmKeys> Admin<'_, D, G, K> {
    /// Creates a realm: opens its governing domain with a Genesis, then writes the realm with
    /// its fixed issuer and the Genesis default settings (TN-111, TN-16, OP-146 m.8 (c)). There
    /// is no master realm; every realm is created this way. A tenant's first realm also queues
    /// `tenant.created` (OP-149 m.4): from then on the tenant can be paired with.
    ///
    /// # Errors
    /// [`AdminError`]; a slug taken by another realm leaves the new domain without a realm.
    pub async fn create_realm(&self, r: &NewRealm<'_>) -> Result<CreatedRealm, AdminError> {
        let issuer = self.base.issuer(r.slug, r.style)?;
        let opened = self
            .governance
            .open(GenesisOrder {
                tenant: *r.tenant.as_bytes(),
                root: r.root.clone(),
                ct3_delay_s: r.ct3_delay_s,
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let domain = DomainId::from_bytes(opened.domain.0);
        let mut t = TenantTx::begin_tenant(self.app, r.tenant).await?;
        let realm = tenancy::create_realm(&mut t, &domain, r.slug, r.placement).await?;
        t.enter_realm(realm).await?;
        if r.style == IssuerStyle::Subdomain {
            tenancy::add_hostname(&mut t, host_of(issuer.authority()), HostKind::Subdomain).await?;
        }
        if !tenancy::set_issuer(&mut t, issuer.as_str()).await? {
            return Err(AdminError::Conflict);
        }
        idp::create_settings(&mut t).await?;
        // OP-149 m.4, m.17 (e)
        if tenancy::realm_count(&mut t).await? == 1 {
            let at = access_store::authority::server_time(self.app).await?;
            let id = access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?;
            let tenant = self.ids.encode(TENANT_PREFIX, *r.tenant.as_bytes())?;
            let event = IdentityEvent::tenant_created(id, &tenant, r.placement, at);
            emit(&mut t, &event).await?;
        }
        t.commit().await?;
        // OP-146 m.16 (m)
        self.open_keys(r.tenant, realm).await?;
        Ok(CreatedRealm {
            realm,
            domain: opened.domain,
            issuer,
        })
    }

    /// Opens the realm's keys outside the database with its JOSE algorithm (OP-146 m.16 (m),
    /// m.15 (e), m.7 (b)): realm creation does it, and this repeats it when that step failed
    /// after the realm was written. The realm's tokens are signed once its first key is past
    /// its publish lead (SAI-46).
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn open_keys(&self, tenant: TenantId, realm: RealmId) -> Result<(), AdminError> {
        let alg = jose_alg(self.app, tenant, realm).await?;
        self.keys
            .open(realm, alg)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))
    }

    /// A fresh `client_id` (OP-137, TN-15): the permuted `UUIDv7` of the new client.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn new_client_id(&self) -> Result<ClientId, AdminError> {
        let uuid = idp::new_uuid(self.app).await?;
        Ok(ClientId::parse(&self.ids.encode(CLIENT_PREFIX, uuid)?)?)
    }

    async fn governing(&self, p: &Proposal, state: bool) -> Result<Governing, AdminError> {
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let g = idp::governance(&mut t).await?.ok_or(AdminError::NoRealm)?;
        let current = Self::current(&mut t, &p.change, &g, state).await;
        t.commit().await?;
        current?;
        Ok(g)
    }

    /// Checks the change against the realm; with `state`, also against its current
    /// configuration, which a retry of an applied change no longer matches.
    async fn current(
        t: &mut TenantTx,
        change: &Change,
        g: &Governing,
        state: bool,
    ) -> Result<(), AdminError> {
        change.check()?;
        match change {
            Change::RpId(rp) => {
                let issuer = g
                    .issuer
                    .as_deref()
                    .and_then(|i| Issuer::parse(i).ok())
                    .ok_or(AdminError::NoRealm)?;
                if !rp.covers(host_of(issuer.authority())) {
                    return Err(Invalid::RpId.into());
                }
            }
            _ if !state => {}
            Change::ClientRegister(c) => {
                if idp::client(t, c.id.as_str()).await?.is_some() {
                    return Err(Invalid::ClientExists.into());
                }
            }
            Change::ClientUpdate(Client { id, .. }) | Change::ClientRetire(id) => {
                if !idp::client(t, id.as_str()).await?.is_some_and(|c| c.active) {
                    return Err(Invalid::NoClient.into());
                }
            }
            Change::Argon2(new) => {
                let s = idp::settings(t).await?.ok_or(AdminError::NoRealm)?;
                let current = Argon2Params {
                    m_kib: s.argon2_m_kib,
                    t: s.argon2_t,
                    p: s.argon2_p,
                };
                if !raises(new, &current) {
                    return Err(Invalid::Argon2.into());
                }
            }
            Change::CimdPolicy(_) | Change::MapperSet { .. } | Change::JoseAlg(_) => {}
        }
        Ok(())
    }

    /// The intent the actor signs for `p` (EI-25), once the change fits the realm's current
    /// configuration.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn prepare(&self, p: &Proposal) -> Result<Prepared, AdminError> {
        self.prepared(p, true).await
    }

    async fn prepared(&self, p: &Proposal, state: bool) -> Result<Prepared, AdminError> {
        // OP-149 m.4
        if let Change::ClientRegister(c) | Change::ClientUpdate(c) = &p.change
            && c.platform.is_some()
            && self.platform_tenant != Some(p.tenant)
        {
            return Err(Invalid::PlatformTenant.into());
        }
        let g = self.governing(p, state).await?;
        let intent = p
            .change
            .intent(&g.slug, p.validity)
            .map_err(|_| AdminError::Encode)?;
        let digest = intent_digest(&intent).map_err(|_| AdminError::Encode)?;
        Ok(Prepared {
            domain: Digest(*g.domain.as_bytes()),
            intent,
            digest,
        })
    }

    /// Has the realm's governing domain commit `p` with the actor's `ais`, then writes the
    /// change against the committed ALLOW in one transaction (MD-14, EI-25, TN-110).
    ///
    /// # Errors
    /// [`AdminError`]; a DENY or a pending decision is [`Applied::NotAllowed`].
    pub async fn apply(&self, p: &Proposal, ais: Vec<u8>) -> Result<Applied, AdminError> {
        let prepared = self.prepared(p, false).await?;
        let verdict = self
            .decider
            .decide(Submission {
                domain: prepared.domain,
                nonce: p.nonce.clone(),
                intent: prepared.intent,
                basis: p.basis,
                capacity: p.capacity,
                ais,
                pep: String::from(self.pep),
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let committed = match verdict {
            Verdict::Committed(c) => c,
            Verdict::NotAllowed { decision, position } => {
                return Ok(Applied::NotAllowed { decision, position });
            }
            Verdict::Refused { code } if code == "unavailable" => {
                return Err(AdminError::Unavailable(code));
            }
            Verdict::Refused { code } => return Err(AdminError::Refused(code)),
        };
        // EI-25: the decision is about this very intent, nonce and domain
        if committed.intent != prepared.digest
            || committed.domain != prepared.domain
            || committed.nonce != p.nonce
        {
            return Err(AdminError::Unbound);
        }
        let change = p.change.digest().map_err(|_| AdminError::Encode)?;
        let domain = DomainId::from_bytes(committed.domain.0);
        let label = p.change.action().label();
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let bound = idp::bind(
            &mut t,
            &Bind {
                domain: &domain,
                position: committed.position,
                nonce: &committed.nonce,
                intent: committed.intent.0,
                change: change.0,
                action: &label,
            },
        )
        .await?;
        let Some(bound) = bound else {
            t.rollback().await?;
            self.after(p).await?;
            return Ok(Applied::AlreadyWritten {
                exercise: committed.exercise,
                position: committed.position,
            });
        };
        let secret = self.write(&mut t, &bound, &p.change).await?;
        self.announce(&mut t, p, &committed.exercise).await?;
        t.commit().await?;
        self.after(p).await?;
        Ok(Applied::Written {
            exercise: committed.exercise,
            position: committed.position,
            secret,
        })
    }

    /// What follows a written change outside the database: a new JOSE algorithm reaches the
    /// identity signer for the realm's next keys (OP-146 m.8 (e), m.16 (m)). A retry of the
    /// change repeats it.
    async fn after(&self, p: &Proposal) -> Result<(), AdminError> {
        if let Change::JoseAlg(alg) = &p.change {
            self.keys
                .open(p.realm, *alg)
                .await
                .map_err(|e| AdminError::Unavailable(e.0))?;
        }
        Ok(())
    }

    /// OP-149 m.4: an API client change queues its event in the write's transaction, so it
    /// is delivered exactly when the change is written.
    async fn announce(
        &self,
        t: &mut TenantTx,
        p: &Proposal,
        exercise: &Digest,
    ) -> Result<(), AdminError> {
        let product = |c: &Client| c.platform.as_ref().map(|p| p.product);
        let (kind, client_id, platform_product) = match &p.change {
            Change::ClientRegister(c) => {
                (IdentityKind::ApiClientCreated, c.id.as_str(), product(c))
            }
            Change::ClientUpdate(c) => (IdentityKind::ApiClientUpdated, c.id.as_str(), product(c)),
            Change::ClientRetire(id) => (
                IdentityKind::ApiClientDisabled,
                id.as_str(),
                idp::client(t, id.as_str())
                    .await?
                    .and_then(|r| r.platform_product)
                    .as_deref()
                    .and_then(PlatformProduct::parse),
            ),
            _ => return Ok(()),
        };
        let at = access_store::authority::server_time(self.app).await?;
        let id = access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?;
        let tenant = self.ids.encode(TENANT_PREFIX, *p.tenant.as_bytes())?;
        let event = IdentityEvent::api_client(
            kind,
            id,
            &ClientChange {
                tenant: &tenant,
                realm: p.realm.as_bytes(),
                client_id,
                exercise: &exercise.0,
                platform_product,
                at,
            },
        );
        emit(t, &event).await?;
        Ok(())
    }

    /// CR-38: a `client_secret_basic` client gets a fresh server-generated secret when it is
    /// registered or switched to the method; an update that keeps the method keeps the secret.
    async fn client_row(
        &self,
        t: &mut TenantTx,
        c: &Client,
    ) -> Result<(ClientRow, Option<ClientSecret>), AdminError> {
        let (secret_hash, secret) = if c.auth == AuthMethod::ClientSecretBasic {
            let kept = idp::client(t, c.id.as_str())
                .await?
                .filter(|r| r.active)
                .and_then(|r| r.secret_hash);
            if let Some(h) = kept {
                (Some(h), None)
            } else {
                let raw = access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?;
                let text = access_kernel::json::b64url_encode(&raw);
                (
                    Some(access_crypto::oauth::secret_digest(text.as_bytes())),
                    Some(ClientSecret(text)),
                )
            }
        } else {
            (None, None)
        };
        let uris = |list: &[crate::domain::RedirectUri]| -> Vec<String> {
            list.iter().map(|u| String::from(u.as_str())).collect()
        };
        Ok((
            ClientRow {
                client_uuid: self.ids.decode(CLIENT_PREFIX, c.id.as_str())?,
                client_id: String::from(c.id.as_str()),
                display_name: c.display_name.clone(),
                auth_method: String::from(c.auth.name()),
                jwks_uri: c.auth.jwks_uri().map(String::from),
                redirect_uris: uris(&c.redirect_uris),
                active: true,
                secret_hash,
                post_logout_redirect_uris: uris(&c.post_logout_redirect_uris),
                backchannel_logout_uri: c.backchannel_logout_uri.clone(),
                jwks: c.auth.jwks(),
                platform_product: c.platform.as_ref().map(|p| String::from(p.product.name())),
                service_key: c.platform.as_ref().map(|p| cose_key(&p.service_key)),
            },
            secret,
        ))
    }

    async fn write(
        &self,
        t: &mut TenantTx,
        bound: &idp::Bound,
        change: &Change,
    ) -> Result<Option<ClientSecret>, AdminError> {
        let mut secret = None;
        let done = match change {
            Change::ClientRegister(c) => {
                let (row, s) = self.client_row(t, c).await?;
                idp::insert_client(t, bound, &row).await?;
                secret = s;
                true
            }
            Change::ClientUpdate(c) => {
                let (row, s) = self.client_row(t, c).await?;
                secret = s;
                idp::update_client(t, bound, &row).await?
            }
            Change::ClientRetire(id) => idp::retire_client(t, bound, id.as_str()).await?,
            Change::MapperSet { claim, source } => {
                idp::set_mapper(
                    t,
                    bound,
                    claim.as_str(),
                    source.as_ref().map(Attribute::as_str),
                )
                .await?;
                true
            }
            Change::CimdPolicy(_) | Change::JoseAlg(_) | Change::Argon2(_) | Change::RpId(_) => {
                let s = idp::settings(t).await?.ok_or(AdminError::NoRealm)?;
                idp::update_settings(t, bound, &settings_with(s, change)).await?
            }
        };
        if done {
            Ok(secret)
        } else {
            Err(AdminError::Conflict)
        }
    }
}

fn settings_with(mut s: SettingsRow, change: &Change) -> SettingsRow {
    match change {
        Change::CimdPolicy(p) => {
            s.cimd_enabled = p.enabled;
            s.cimd_domains = p.domains.iter().cloned().collect();
        }
        Change::JoseAlg(a) => s.jose_alg = String::from(a.name()),
        Change::Argon2(p) => {
            s.argon2_m_kib = p.m_kib;
            s.argon2_t = p.t;
            s.argon2_p = p.p;
        }
        Change::RpId(r) => s.rp_id = Some(String::from(r.as_str())),
        Change::ClientRegister(_)
        | Change::ClientUpdate(_)
        | Change::ClientRetire(_)
        | Change::MapperSet { .. } => {}
    }
    s
}

impl<D: Decider, G: Governance, K: RealmKeys> Admin<'_, D, G, K> {
    /// Pairs the platform client `client` of the platform tenant's realm `home` with every realm
    /// in `targets` (OP-149 m.4, m.16 (a)): in each realm's governing domain the product's
    /// system Party and its service Instance are registered by Exercises the product signed with
    /// the service key the client registered; the identity plane binds that key to the
    /// product's Party and forwards them. A repeat opens nothing new (the nonces replay); a
    /// realm the authority plane refuses is reported, not retried.
    ///
    /// # Errors
    /// [`AdminError`]: no such active platform client, storage, or the authority plane
    /// unreachable.
    pub async fn pair<I: Instances>(
        &self,
        instances: &I,
        home: RealmId,
        client: &ClientId,
        targets: &[PairTarget],
    ) -> Result<Vec<Paired>, AdminError> {
        let platform = self.platform_tenant.ok_or(Invalid::PlatformTenant)?;
        let mut t = TenantTx::begin(self.app, platform, home).await?;
        let row = idp::client(&mut t, client.as_str())
            .await?
            .filter(|r| r.active)
            .ok_or(Invalid::NoClient)?;
        t.commit().await?;
        let product = row
            .platform_product
            .as_deref()
            .and_then(PlatformProduct::parse)
            .ok_or(Invalid::NoClient)?;
        let key = row
            .service_key
            .as_deref()
            .and_then(from_cose_key)
            .ok_or(Invalid::PublicKey)?;
        let mut out = Vec::new();
        for target in targets {
            let mut t = TenantTx::begin(self.app, target.tenant, target.realm).await?;
            let g = idp::governance(&mut t).await?;
            t.commit().await?;
            let Some(g) = g else { continue };
            let verdict = instances
                .register(Registration {
                    tenant: *target.tenant.as_bytes(),
                    domain: Digest(*g.domain.as_bytes()),
                    registrant: Registrant::Service {
                        product,
                        client: String::from(client.as_str()),
                    },
                    party: target.party,
                    key: key.clone(),
                    register: target.register.clone(),
                    create: target.create.clone(),
                    pep: String::from(self.pep),
                })
                .await
                .map_err(|e| AdminError::Unavailable(e.0))?;
            out.push(Paired {
                tenant: target.tenant,
                realm: target.realm,
                verdict,
            });
        }
        Ok(out)
    }
}

/// The realm's JOSE algorithm, ES256 until a decision changes it (OP-146 m.8 (e)).
///
/// # Errors
/// [`AdminError`].
pub async fn jose_alg(app: &Pool, tenant: TenantId, realm: RealmId) -> Result<JoseAlg, AdminError> {
    let mut t = TenantTx::begin(app, tenant, realm).await?;
    let s = idp::settings(&mut t).await?.ok_or(AdminError::NoRealm)?;
    t.commit().await?;
    JoseAlg::from_name(&s.jose_alg).ok_or(AdminError::Store(access_store::StoreError::Corrupt))
}
