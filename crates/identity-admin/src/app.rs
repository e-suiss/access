//! Use cases over the domain and its ports (OP-63): realm creation (TN-111) and the `idp.*`
//! write path (MD-14, EI-25), and the platform product API (OP-149 m.4).

pub mod accounts;
pub mod agents;
pub mod domains;
pub mod household;
pub mod issuer;
pub mod org_flows;
pub mod orgs;
pub mod platform;
pub mod provision;
pub mod rest;
mod signals;
pub mod transfers;
pub mod vault;
pub mod workloads;

use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::pg::PgTx;
use access_identity_account::app::accounts::status_moved;
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::recovery_policy::{self, RecoveryPolicy};
use access_identity_account::domain::status::AccountStatus;
use access_identity_oauth::adapters::outbound::DeclaredTargets;
use access_identity_oauth::domain::issuer::{Issuer, IssuerStyle, RealmBase};
use access_internal_api::idp::{ACTOR_BINDING, GenesisOrder, Submission, Verdict};
use access_internal_api::instances::PlatformProduct;
use access_kernel::claim::body::Class;
use access_kernel::combinator::{Capacity, Decision};
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::json::{Json, b64url_decode};
use access_kernel::meta::{ExerciseBasis, Root};
use access_kernel::model::Id;
use access_kernel::model::Window;
use access_kernel::schema::Spp;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::realm::{self as resources, GroupRow, UpstreamRow};
use access_store::idp::{self, ClientRow, Decision as Bind, Governing, KeyChange, SettingsRow};
use access_store::scope::DomainId;
use access_store::tenancy::{self, HostKind};
use suiss_crypto::dcbor::{self, Limits};

use access_identity_events::app::emit;
use access_identity_events::domain::catalog::{
    ClientChange, IdentityEvent, IdentityKind, TENANT_PREFIX,
};

use crate::AdminError;
use crate::domain::{
    Attribute, AuthMethod, CLIENT_PREFIX, Change, Client, ClientId, ExtensionPolicy, Group,
    HookChange, Invalid, JoseAlg, MembershipIssuer, Upstream, WebhookChange, cose_key,
    extension_invalid, issuer_cutoff, policy_value, raises,
};

/// Clients that opted in to their realm's public `sub` (MD-10, OP-151 m.9 (h)); no realm label
/// (OP-47).
pub static PUBLIC_SUB_OPT_IN: access_telemetry::metrics::Counter<0> =
    access_telemetry::metrics::Counter::new(
        "access_public_sub_opt_in_total",
        "Clients that opted in to their realm's public sub (MD-10)",
        [],
    );

/// Organizations one founder may create a day (OP-153 m.3 (o): five tenants a day per
/// platform account, PD).
pub const ORGS_PER_FOUNDER_PER_DAY: i64 = 5;

/// One day in seconds.
const DAY_S: i64 = 86_400;

/// How long a rotated client secret stays valid next to its successor (CR-38, PD).
pub const SECRET_OVERLAP_MS: u64 = 24 * 3_600_000;
use crate::ports::{Decider, Governance, Instances, RealmKeys};
use access_identity_hooks::ports::KeyVault;
use access_store::idp::realm::PolicyKind;

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
    /// Whether its governing domain declares causal-bound allowances (OP-152 m.7 (d) E11).
    pub causal_binding: bool,
    /// Further catalogs its Genesis publishes, by the founding root (OP-141 m.35 (c)).
    pub schemas: Vec<Spp>,
    /// Further Acceptances its Genesis establishes, each an `acceptance-content` (L0-META-5,
    /// OP-149 m.26 (c)).
    pub acceptances: Vec<suiss_crypto::dcbor::Value>,
    /// Classes of the realm issuer's Claims its Genesis accepts as predicate input besides
    /// `authentication`, which every realm accepts (SI-5, OP-149 m.29 (b), OP-152 m.5 (i)).
    pub issuer_predicate_input: Vec<String>,
    /// The `idp.platform.*` Exercise that opens it, recorded with it (TN-110, EI-25); `None`
    /// for a realm the local plan opens.
    pub provisioned_by: Option<Digest>,
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
    /// The realm subject whose authenticated session asks for the change: the AIS must be
    /// signed by a live Instance of the Party that subject is bound to (§13.4 G54, OP-149
    /// m.16 (a)). `None` only for the operator's own root key, which has no session.
    pub subject: Option<[u8; 16]>,
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

/// Stable code of a change the catalog declares whose identity-plane write is not served yet
/// (OP-153 m.25 (b)).
pub const NOT_YET_SERVED: &str = "not-yet-served";

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
    /// The operator's declared delivery targets: a `suiss_event_receiver` on a private
    /// address or another port than 443 must be one (OP-149 m.23).
    pub declared: DeclaredTargets,
    /// Seals hook and webhook signing keys under the realm KEK (OP-42, OP-135); without it no
    /// hook or webhook is registered and no webhook key rotates (MD-8).
    pub vault: Option<&'a dyn KeyVault>,
}

/// `classes` with `authentication` first and no repeats (OP-152 m.5 (i), OP-149 m.29 (b)).
fn predicate_input(classes: &[String]) -> Vec<String> {
    let mut out = vec![Class::Authentication.name()];
    for c in classes {
        if !out.contains(c) {
            out.push(c.clone());
        }
    }
    out
}

fn host_of(authority: &str) -> &str {
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// Creates a realm: opens its governing domain with a Genesis, then writes the realm with
    /// its fixed issuer and the Genesis default settings (TN-111, TN-16, OP-146 m.8 (c)). There
    /// is no master realm; every realm is created this way. A tenant's first realm also queues
    /// `tenant.created` (OP-149 m.4): from then on the tenant can be paired with.
    ///
    /// # Errors
    /// [`AdminError`]; a slug taken by another realm leaves the new domain without a realm.
    pub async fn create_realm(&self, r: &NewRealm<'_>) -> Result<CreatedRealm, AdminError> {
        let issuer = self.base.issuer(r.slug, r.style)?;
        // §10.1.4 rule 3, OP-150 L2
        let claim_issuer = issuer::new_party()?;
        let opened = self
            .governance
            .open(GenesisOrder {
                tenant: *r.tenant.as_bytes(),
                slug: String::from(r.slug),
                root: r.root.clone(),
                ct3_delay_s: r.ct3_delay_s,
                causal_binding: r.causal_binding,
                schemas: r.schemas.clone(),
                issuer: Some(access_kernel::model::Id(claim_issuer)),
                // E18, OP-153 m.25 (i) (3)
                acceptances: r
                    .acceptances
                    .iter()
                    .cloned()
                    .chain([access_internal_api::idp::org_member_selection(
                        access_kernel::model::Id(claim_issuer),
                    )])
                    // OP-154 m.3 (c), (e), (g)
                    .chain([
                        agents::agent_claims(access_kernel::model::Id(claim_issuer)),
                        agents::agent_selection(access_kernel::model::Id(claim_issuer)),
                    ])
                    // OP-154 m.3 (d), (s)
                    .chain([
                        workloads::workload_binding(access_kernel::model::Id(claim_issuer)),
                        workloads::runtime_attestation(access_kernel::model::Id(claim_issuer)),
                    ])
                    .collect(),
                issuer_predicate_input: predicate_input(&r.issuer_predicate_input),
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let domain = DomainId::from_bytes(opened.domain.0);
        let mut t = TenantTx::begin_tenant(self.app, r.tenant).await?;
        let realm = tenancy::create_realm(&mut t, &domain, r.slug, r.placement).await?;
        t.enter_realm(realm).await?;
        if let Some(exercise) = &r.provisioned_by {
            tenancy::record_provision(&mut t, &exercise.0).await?;
        }
        access_store::issuer::set_realm_issuer(&mut t, &claim_issuer).await?;
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
            .map_err(|e| AdminError::Unavailable(e.0))?;
        // OP-150 L2
        Box::pin(self.register_issuer(tenant, realm))
            .await
            .map(drop)
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
        let current = Self::current(&mut t, &p.change, &g, state, &self.declared).await;
        t.commit().await?;
        current?;
        Ok(g)
    }

    /// Checks the change against the realm; with `state`, also against its current
    /// configuration, which a retry of an applied change no longer matches.
    #[expect(
        clippy::too_many_lines,
        reason = "one match over the changes, each arm the state it must find"
    )]
    async fn current(
        t: &mut TenantTx,
        change: &Change,
        g: &Governing,
        state: bool,
        declared: &DeclaredTargets,
    ) -> Result<(), AdminError> {
        change.check(declared)?;
        match change {
            // OP-153 m.22 (g), m.25 (b)
            Change::CspMode { mode, loosens } => {
                let stored = idp::branding(t)
                    .await?
                    .and_then(|b| dcbor::decode(&b, Limits::CEILING).ok());
                let current = crate::domain::accounts::CspMode::of(stored.as_ref());
                if mode.loosens(current) != *loosens {
                    return Err(AdminError::Conflict);
                }
            }
            // OP-153 m.18 (e), m.25 (b)
            Change::AccountBind(b) => {
                if t.realm().is_some_and(|r| *r.as_bytes() == b.peer_realm)
                    || resources::account(t, b.subject).await?.is_none()
                {
                    return Err(Invalid::NoAccount.into());
                }
            }

            // TN-18, OP-153 m.3 (u)
            Change::RelatedOrigins(r) => {
                let s = idp::settings(t).await?.ok_or(AdminError::NoRealm)?;
                let issuer_host = g
                    .issuer
                    .as_deref()
                    .and_then(|i| Issuer::parse(i).ok())
                    .map(|i| String::from(host_of(i.authority())));
                let rp = s.rp_id.or(issuer_host);
                if r.labels(rp.as_deref()).len() > crate::domain::MAX_RELATED_LABELS {
                    return Err(Invalid::RelatedOrigins.into());
                }
                let verified = idp::verified_domains(t).await?;
                let under = |h: &str| {
                    verified.iter().any(|d| {
                        h == d || h.strip_suffix(d.as_str()).is_some_and(|p| p.ends_with('.'))
                    })
                };
                if !r.hosts().into_iter().all(under) {
                    return Err(Invalid::RelatedOrigins.into());
                }
            }
            // TN-85, OP-153 m.19 (d), m.25 (b)
            Change::LocaleOverrides(_)
            | Change::AccountImport(_)
            | Change::MigrationExport(_)
            | Change::GuardianshipRecord(_) => {}
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
            Change::Hook(_) | Change::Webhook(_) => {
                extension_current(t, change, declared, state).await?;
            }
            _ if !state => {}
            Change::OrgCreate(o) => {
                if t.org_by_party(o.party).await?.is_some() {
                    return Err(Invalid::OrgExists.into());
                }
            }
            Change::OrgMemberRemove(m) => org_member_current(t, *m).await?,
            // OP-154 m.3 (c), (e)
            Change::Agent(a) => agents::current(t, a).await?,
            // OP-154 m.3 (t)
            Change::Vault(v) => vault::current(t, v).await?,
            // OP-154 m.3 (j)
            Change::DcrPolicy { policy, loosens } => {
                let current =
                    access_identity_oauth::app::oauth::dcr::policy_of(&t.dcr_policy().await?);
                if policy.narrows(&current) == *loosens {
                    return Err(AdminError::Conflict);
                }
            }
            // AG-8
            Change::ResourceRegister(r) => {
                if t.protected_resource(&r.resource).await?.is_some() {
                    return Err(Invalid::ResourceExists.into());
                }
            }
            Change::OrgInvite(i) => orgs::invite_current(t, i).await?,
            Change::OrgUpdate(u) => orgs::update_current(t, u).await?,
            Change::OrgInviteRevoke { org, invitation } => {
                let org = orgs::live_org(t, *org).await?;
                if t.invitation_org(*invitation).await? != Some((org.id, true)) {
                    return Err(Invalid::NoInvitation.into());
                }
            }
            // TN-90
            Change::OrgDomainClaim(d) => {
                let org = orgs::live_org(t, d.org).await?;
                if t.open_domain_claims(Some(org.id))
                    .await?
                    .iter()
                    .any(|c| c.domain == d.domain)
                {
                    return Err(Invalid::NoDomain.into());
                }
            }
            Change::OrgDomainRelease { org, claim } => {
                let org = orgs::live_org(t, *org).await?;
                if !t
                    .open_domain_claims(Some(org.id))
                    .await?
                    .iter()
                    .any(|c| c.id == *claim)
                {
                    return Err(Invalid::NoDomain.into());
                }
            }
            // TN-120
            Change::OrgSsoDraft(d) => {
                orgs::live_org(t, d.org).await?;
            }
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
            Change::ClientSecretRotate(id) => {
                let c = idp::client(t, id.as_str()).await?.filter(|c| c.active);
                match c {
                    None => return Err(Invalid::NoClient.into()),
                    Some(c) if c.auth_method != AuthMethod::ClientSecretBasic.name() => {
                        return Err(Invalid::NoSecret.into());
                    }
                    Some(_) => {}
                }
            }
            Change::GroupCreate(g) => {
                if resources::group(t, g.name.as_str()).await?.is_some() {
                    return Err(Invalid::GroupExists.into());
                }
                if let MembershipIssuer::Upstream(u) = &g.issuer
                    && !resources::upstream(t, u.as_str())
                        .await?
                        .is_some_and(|u| u.active)
                {
                    return Err(Invalid::NoUpstream.into());
                }
            }
            Change::GroupUpdate(g) => {
                let current = resources::group(t, g.name.as_str())
                    .await?
                    .filter(|g| g.active);
                let current = current.ok_or(Invalid::NoGroup)?;
                // TN-117
                if current.membership_issuer != g.issuer.text() {
                    return Err(Invalid::MembershipIssuer.into());
                }
            }
            Change::GroupRetire(name) => {
                if !resources::group(t, name.as_str())
                    .await?
                    .is_some_and(|g| g.active)
                {
                    return Err(Invalid::NoGroup.into());
                }
            }
            Change::GroupMembersAdd(m) | Change::GroupMembersRemove(m) => {
                let g = resources::group(t, m.group.as_str())
                    .await?
                    .filter(|g| g.active);
                let g = g.ok_or(Invalid::NoGroup)?;
                // TN-117
                if g.membership_issuer != MembershipIssuer::Admin.text() {
                    return Err(Invalid::UpstreamMembership.into());
                }
                for s in &m.subjects {
                    if resources::account(t, *s).await?.is_none() {
                        return Err(Invalid::NoAccount.into());
                    }
                }
            }
            Change::AccountSuspend(s) | Change::AccountReactivate(s) => {
                let a = resources::account(t, *s).await?.ok_or(Invalid::NoAccount)?;
                let leaves = if matches!(change, Change::AccountSuspend(_)) {
                    matches!(a.status.as_str(), "active" | "locked")
                } else {
                    a.status == "suspended"
                };
                if !leaves {
                    return Err(Invalid::AccountState.into());
                }
            }
            Change::UpstreamRegister(u) => {
                if resources::upstream(t, u.name.as_str()).await?.is_some() {
                    return Err(Invalid::UpstreamExists.into());
                }
            }
            Change::UpstreamUpdate(Upstream { name, .. }) | Change::UpstreamRetire(name) => {
                if !resources::upstream(t, name.as_str())
                    .await?
                    .is_some_and(|u| u.active)
                {
                    return Err(Invalid::NoUpstream.into());
                }
            }
            Change::AccountCanary(s) | Change::AccountDelete(s) => {
                if resources::account(t, *s).await?.is_none() {
                    return Err(Invalid::NoAccount.into());
                }
            }
            Change::UpstreamLink(l) => {
                let u = resources::upstream(t, l.upstream.as_str())
                    .await?
                    .filter(|u| u.active)
                    .ok_or(Invalid::NoUpstream)?;
                if resources::account(t, l.account).await?.is_none() {
                    return Err(Invalid::NoAccount.into());
                }
                let held = t.upstream_subject(&link_digest(&u, &l.sub)).await?;
                if held.is_some_and(|s| s != l.account) {
                    return Err(Invalid::UpstreamSubjectLinked.into());
                }
            }
            Change::AccountResetIntent { subject, .. }
            | Change::AccountTapIssue(crate::domain::TapIssue { subject, .. }) => {
                if resources::account(t, *subject).await?.is_none() {
                    return Err(Invalid::NoAccount.into());
                }
                // TN-60
                if t.account_recovery_policy(*subject)
                    .await?
                    .is_some_and(|p| !p.assisted_recovery)
                {
                    return Err(Invalid::RecoveryOption.into());
                }
                // TN-62
                if matches!(change, Change::AccountTapIssue(_)) && !recovery_policy(t).await?.tap {
                    return Err(Invalid::RecoveryOption.into());
                }
            }
            Change::RecoveryPolicy { policy, loosens } => {
                // TN-55, OP-153 m.3 (e)
                let current = recovery_policy(t).await?;
                match policy.change(&current) {
                    Ok(l) if l == *loosens => {}
                    Ok(_) => return Err(AdminError::Conflict),
                    Err(_) => return Err(Invalid::RecoveryPolicy.into()),
                }
            }
            Change::ProtectionMode { mode, loosens } => {
                // OP-151 m.14 (f)
                let tier = access_identity_risk::app::settings::change_tier(t, mode)
                    .await
                    .map_err(risk)?;
                if *loosens != (tier == access_identity_risk::domain::mode::Tier::Ct2) {
                    return Err(AdminError::Conflict);
                }
            }
            Change::SocialEnable(s) | Change::SocialUpdate(s) => {
                let row = t.social_provider(s.preset.as_str()).await?;
                let active = row.is_some_and(|r| r.active);
                match change {
                    Change::SocialEnable(_) if active => return Err(Invalid::SocialExists.into()),
                    Change::SocialUpdate(_) if !active => return Err(Invalid::NoSocial.into()),
                    _ => {}
                }
                // IDP-31 (4), OP-153 m.3 (l)
                if s.client.is_none() && !t.realm_is_sandbox().await? {
                    return Err(Invalid::SharedSocialKey.into());
                }
            }
            Change::SocialDisable(preset) => {
                if !t
                    .social_provider(preset.as_str())
                    .await?
                    .is_some_and(|r| r.active)
                {
                    return Err(Invalid::NoSocial.into());
                }
            }
            Change::CimdPolicy(_)
            | Change::DeviceCode(_)
            | Change::MapperSet { .. }
            | Change::JoseAlg(_)
            | Change::Branding(_)
            | Change::KeyPolicy(_)
            | Change::KeyRotate { .. }
            | Change::KeyDrop { .. }
            | Change::SigninPolicy(_)
            | Change::SessionPolicy(_)
            | Change::ExtensionPolicy(_) => {}
        }
        Ok(())
    }

    /// How many passkeys the realm's accounts hold: an RP ID change makes every one of them
    /// unusable (IDI-4).
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn passkey_count(&self, tenant: TenantId, realm: RealmId) -> Result<u64, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let n = resources::passkey_count(&mut t).await?;
        t.commit().await?;
        Ok(n)
    }

    /// A rotation or drop names a key the realm publishes now; a retry of an applied one no
    /// longer has to (TN-118, §13.2).
    async fn published(&self, p: &Proposal) -> Result<(), AdminError> {
        let (Change::KeyRotate { retire: kid } | Change::KeyDrop { kid, .. }) = &p.change else {
            return Ok(());
        };
        let doc = self
            .keys
            .jwks(p.realm)
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        if jwks_kids(&doc).contains(kid) {
            Ok(())
        } else {
            Err(Invalid::NoKey.into())
        }
    }

    /// The intent the actor signs for `p` (EI-25), once the change fits the realm's current
    /// configuration.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn prepare(&self, p: &Proposal) -> Result<Prepared, AdminError> {
        let prepared = self.prepared(p, true).await?;
        self.published(p).await?;
        Ok(prepared)
    }

    async fn prepared(&self, p: &Proposal, state: bool) -> Result<Prepared, AdminError> {
        // TN-62, TN-61
        if let (
            Some(me),
            Change::AccountResetIntent { subject, .. }
            | Change::AccountTapIssue(crate::domain::TapIssue { subject, .. }),
        ) = (&p.subject, &p.change)
            && me == subject
        {
            return Err(Invalid::SelfIssue.into());
        }
        // OP-149 m.4
        if let Change::ClientRegister(c) | Change::ClientUpdate(c) = &p.change
            && c.platform.is_some()
            && self.platform_tenant != Some(p.tenant)
        {
            return Err(Invalid::PlatformTenant.into());
        }
        let g = self.governing(p, state).await?;
        if let Change::OrgCreate(o) = &p.change {
            self.org_creatable(p, Digest(*g.domain.as_bytes()), o.party)
                .await?;
        }
        // OP-154 m.3 (c)
        if let Change::Agent(crate::domain::agent::AgentChange::Register(r)) = &p.change {
            self.agent_registrable(Digest(*g.domain.as_bytes()), r)
                .await?;
        }
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

    /// An organization is created only for a live organization Party of the realm's domain
    /// (OP-153 m.3 (b), m.10 (e)), by a founder with a session, at most
    /// [`ORGS_PER_FOUNDER_PER_DAY`] a day (OP-153 m.3 (o), HL-41).
    async fn org_creatable(
        &self,
        p: &Proposal,
        domain: Digest,
        party: [u8; 16],
    ) -> Result<(), AdminError> {
        let founder = p
            .subject
            .ok_or_else(|| AdminError::Refused(String::from(ACTOR_BINDING)))?;
        let kind = self
            .governance
            .party(domain, Id(party))
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        if !kind.is_some_and(|k| {
            k.actor_kind == access_kernel::meta::ActorKind::Organization && !k.ended
        }) {
            return Err(Invalid::NotOrganization.into());
        }
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let today = t.orgs_founded_since(founder, DAY_S).await?;
        t.commit().await?;
        if today >= ORGS_PER_FOUNDER_PER_DAY {
            return Err(Invalid::OrgLimit.into());
        }
        Ok(())
    }

    /// Records an organization's Party from the `party_register` its founder's client signed
    /// with a one-time key (OP-153 m.3 (b), L0-META-7): the Party is an organization rooted
    /// solely in the founder's Party, so it never has an Instance (C6). The founder's session
    /// subject must be bound to a Party of the realm.
    ///
    /// # Errors
    /// [`AdminError`]; a refusal by the domain is [`AdminError::Refused`].
    pub async fn register_organization(
        &self,
        (tenant, realm): (TenantId, RealmId),
        founder: [u8; 16],
        party: Id,
        key: access_kernel::verify::cose::PublicKey,
        register: access_internal_api::instances::SelfSigned,
    ) -> Result<bool, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let g = idp::governance(&mut t).await?.ok_or(AdminError::NoRealm)?;
        let root = idp::subject_party(&mut t, &founder).await?;
        let today = t.orgs_founded_since(founder, DAY_S).await?;
        t.commit().await?;
        let root = root.ok_or_else(|| AdminError::Refused(String::from(ACTOR_BINDING)))?;
        // OP-153 m.3 (o), HL-41
        if today >= ORGS_PER_FOUNDER_PER_DAY {
            return Err(Invalid::OrgLimit.into());
        }
        let register_nonce = register.nonce.clone();
        let verdict = self
            .governance
            .register_organization(crate::ports::OrgRegistration {
                tenant: *tenant.as_bytes(),
                domain: Digest(*g.domain.as_bytes()),
                party,
                founder: Id(root),
                key,
                register,
                pep: String::from(self.pep),
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        if matches!(verdict, crate::ports::OrgRegistered::Registered { .. }) {
            // TN-91, OP-153 m.3 (b), (p)
            let exercise =
                access_kernel::meta::exercise_id(&Digest(*g.domain.as_bytes()), &register_nonce)
                    .map_err(|_| AdminError::Encode)?;
            let anchor =
                access_kernel::meta::object_id(&exercise, access_kernel::meta::kind::ANCHOR, 0);
            let mut t = TenantTx::begin(self.app, tenant, realm).await?;
            t.record_party_anchor(party.0, anchor.0).await?;
            t.commit().await?;
        }
        match verdict {
            crate::ports::OrgRegistered::Registered { replayed } => Ok(replayed),
            crate::ports::OrgRegistered::Refused { code } => Err(AdminError::Refused(code)),
        }
    }

    /// Has the realm's governing domain commit one core meta-action write `w`, such as a Grant
    /// revoke or amend of a bulk job (E17, TN-125): the signer's account must still be able to
    /// act in the realm (§13.4 G54), and the plane decides it like any other Exercise. Nothing
    /// is written on the identity side.
    ///
    /// # Errors
    /// [`AdminError`]; a DENY or a pending decision is [`Applied::NotAllowed`].
    pub async fn meta(
        &self,
        (tenant, realm): (TenantId, RealmId),
        w: Submission,
    ) -> Result<Applied, AdminError> {
        if w.payload.is_none() {
            return Err(AdminError::Encode);
        }
        self.standing((tenant, realm), w.domain, &w.ais, None)
            .await?;
        let nonce = w.nonce.clone();
        let verdict = self
            .decider
            .decide(Submission {
                actor: None,
                pep: String::from(self.pep),
                ..w
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        match verdict {
            Verdict::Committed(c) if c.nonce == nonce => Ok(if c.replayed {
                Applied::AlreadyWritten {
                    exercise: c.exercise,
                    position: c.position,
                }
            } else {
                Applied::Written {
                    exercise: c.exercise,
                    position: c.position,
                    secret: None,
                }
            }),
            Verdict::Committed(_) => Err(AdminError::Unbound),
            Verdict::NotAllowed { decision, position } => {
                Ok(Applied::NotAllowed { decision, position })
            }
            Verdict::Refused { code, .. } if code == "unavailable" => {
                Err(AdminError::Unavailable(code))
            }
            Verdict::Refused { code, .. } => Err(AdminError::Refused(code)),
        }
    }

    /// Has the realm's governing domain commit `p` with the actor's `ais`, then writes the
    /// change against the committed ALLOW in one transaction (MD-14, EI-25, TN-110).
    ///
    /// # Errors
    /// [`AdminError`]; a DENY or a pending decision is [`Applied::NotAllowed`].
    pub async fn apply(&self, p: &Proposal, ais: Vec<u8>) -> Result<Applied, AdminError> {
        let prepared = self.prepared(p, false).await?;
        let actor = self.actor(p).await?;
        self.standing((p.tenant, p.realm), prepared.domain, &ais, actor)
            .await?;
        self.recovery_grace(p, prepared.domain, &ais, actor).await?;
        let issuer = self
            .recovery_issuer(p, prepared.domain, &ais, actor)
            .await?;
        let verdict = self
            .decider
            .decide(Submission {
                actor,
                domain: prepared.domain,
                nonce: p.nonce.clone(),
                intent: prepared.intent,
                payload: None,
                basis: p.basis,
                capacity: p.capacity,
                ais,
                contributions: Vec::new(),
                pep: String::from(self.pep),
            })
            .await
            .map_err(|e| AdminError::Unavailable(e.0))?;
        let committed = match verdict {
            Verdict::Committed(c) => c,
            // OP-153 m.3 (a)
            Verdict::NotAllowed { decision, .. }
                if access_internal_api::idp::catalog_upgrade_required(&decision) =>
            {
                return Err(Invalid::CatalogUpgradeRequired.into());
            }
            Verdict::NotAllowed { decision, position } => {
                return Ok(Applied::NotAllowed { decision, position });
            }
            Verdict::Refused { code, .. } if code == "unavailable" => {
                return Err(AdminError::Unavailable(code));
            }
            Verdict::Refused { code, .. } => return Err(AdminError::Refused(code)),
        };
        // EI-25
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
        let secret = self
            .first_application(t, p, &bound, &committed.exercise, issuer)
            .await?;
        self.after(p).await?;
        Ok(Applied::Written {
            exercise: committed.exercise,
            position: committed.position,
            secret,
        })
    }

    /// The first application of a bound decision, in the transaction that bound it: the change
    /// must fit the realm's current configuration, which only a retry no longer matches (TN-110,
    /// EI-25); then the write, its effects and its events, committed together.
    #[expect(
        clippy::too_many_lines,
        reason = "the write and each change's effects in the one transaction that binds them"
    )]
    async fn first_application(
        &self,
        t: TenantTx,
        p: &Proposal,
        bound: &idp::Bound,
        exercise: &Digest,
        issuer: Option<[u8; 16]>,
    ) -> Result<Option<ClientSecret>, AdminError> {
        let mut t = PgTx::new(t);
        let g = idp::governance(&mut t.0)
            .await?
            .ok_or(AdminError::NoRealm)?;
        Self::current(&mut t.0, &p.change, &g, true, &self.declared).await?;
        self.published(p).await?;
        let moved = account_move(&mut t.0, &p.change).await?;
        let secret = self.write(&mut t.0, bound, &p.change).await?;
        if let Some((subject, from, to)) = moved {
            // TN-49, TN-41, OP-150 L2
            let correlation = access_kernel::json::b64url_encode(&exercise.0);
            let who = access_identity_account::app::Actor {
                actor: DECIDED_BY,
                correlation: &correlation,
            };
            let named = access_identity_account::app::Named {
                realm: p.realm,
                ids: self.ids,
            };
            status_moved(&mut t, &named, subject, (from, to), &who)
                .await
                .map_err(account)?;
            // OP-148, §7.9.8, E42, TN-49
            self.status_notice(&mut t, p, subject, to).await?;
        }
        if let Change::AccountDelete(subject) = &p.change {
            // OP-153 m.3 (bb), TN-78
            let correlation = access_kernel::json::b64url_encode(&exercise.0);
            let who = access_identity_account::app::Actor {
                actor: DECIDED_BY,
                correlation: &correlation,
            };
            let named = access_identity_account::app::Named {
                realm: p.realm,
                ids: self.ids,
            };
            access_identity_account::app::privacy::request_deletion(
                &mut t,
                &named,
                *subject,
                access_identity_account::app::privacy::DeletionSource::Admin,
                Some(&exercise.0),
                access_kernel::meta::CT3_DELAY_DEFAULT_S,
                &who,
            )
            .await
            .map_err(account)?;
        }
        if let Change::OrgCreate(o) = &p.change {
            // TN-5, OP-153 m.3 (b)
            let founder = p
                .subject
                .ok_or_else(|| AdminError::Refused(String::from(ACTOR_BINDING)))?;
            let org =
                t.0.insert_org(o.party, &o.display_name, &exercise.0)
                    .await?;
            t.0.insert_membership(
                org,
                founder,
                access_store::orgs::Source::Founder,
                true,
                None,
            )
            .await?;
            // OP-149 m.4, OP-153 m.4
            let at = access_store::authority::server_time(self.app).await?;
            orgs::organization_event(
                &mut t.0,
                self.ids,
                IdentityKind::OrganizationCreated,
                org,
                at,
            )
            .await?;
            orgs::membership_event(
                &mut t.0,
                self.ids,
                IdentityKind::MembershipAdded,
                (founder, org),
                at,
            )
            .await?;
        }
        // OP-154 m.3 (c), (e), (g)
        if let Change::Agent(a) = &p.change {
            let at = access_store::authority::server_time(self.app).await?;
            agents::committed(&mut t, p.realm, a, exercise, at).await?;
        }
        // OP-154 m.3 (e), AG-41, X13
        if let Change::AccountSuspend(s) | Change::AccountDelete(s) = &p.change {
            let at = access_store::authority::server_time(self.app).await?;
            agents::sponsor_left(&mut t, p.realm, *s, at).await?;
        }
        let mut secret = secret;
        if let Change::AccountResetIntent { .. } | Change::AccountTapIssue(_) = &p.change {
            secret = self
                .recovery_token(&mut t, p, &g, exercise, issuer)
                .await?
                .or(secret);
        }
        if let Change::OrgInvite(i) = &p.change {
            // TN-89, OP-153 m.3 (o)
            self.invite(&mut t.0, p, &g, i, exercise).await?;
        }
        if let Change::AccountBind(b) = &p.change {
            // OP-153 m.18 (e), m.25 (b)
            secret = self
                .bind_half(&mut t, p, &g, *b, exercise)
                .await?
                .or(secret);
        }
        // TN-90, TN-120, OP-153 m.3 (o), (p)
        secret = org_flows::committed(&mut t.0, &p.change, p.subject, &exercise.0)
            .await?
            .or(secret);
        declare_transmitter(&mut t.0, bound, &p.change, exercise).await?;
        self.announce(&mut t.0, p, exercise).await?;
        let at = access_store::authority::server_time(self.app).await?;
        signals::queue_for(&mut t.0, &p.change, at).await?;
        t.0.commit().await?;
        Ok(secret)
    }

    /// Writes a committed invitation and queues its mail (TN-89, OP-153 m.3 (o)): the inviter
    /// is the session's subject and its Party, and the realm's vault keys must be at hand.
    async fn invite(
        &self,
        t: &mut TenantTx,
        p: &Proposal,
        g: &Governing,
        i: &crate::domain::OrgInvite,
        exercise: &Digest,
    ) -> Result<(), AdminError> {
        let inviter = p
            .subject
            .ok_or_else(|| AdminError::Refused(String::from(ACTOR_BINDING)))?;
        let party = idp::subject_party(t, &inviter)
            .await?
            .ok_or_else(|| AdminError::Refused(String::from(ACTOR_BINDING)))?;
        let vault = self
            .keys
            .vault(p.realm)
            .ok_or_else(|| AdminError::Unavailable(String::from("vault")))?;
        let issuer = g.issuer.as_deref().ok_or(AdminError::NoRealm)?;
        let at = access_store::authority::server_time(self.app).await?;
        orgs::invite(
            t,
            &orgs::Invite {
                vault: &vault,
                ids: self.ids,
                inviter: (inviter, party),
                issuer,
                exercise: &exercise.0,
                at,
            },
            i,
        )
        .await
        .map(drop)
    }

    /// TN-56, OP-153 m.3 (e): while the actor's own account is in the grace period after a
    /// recovery, deleting it, a new API key (a client or a client secret) and linking it to an
    /// identity provider are refused before anything is decided.
    async fn recovery_grace(
        &self,
        p: &Proposal,
        domain: Digest,
        ais: &[u8],
        actor: Option<Id>,
    ) -> Result<(), AdminError> {
        if !matches!(
            &p.change,
            Change::AccountDelete(_)
                | Change::ClientRegister(_)
                | Change::ClientSecretRotate(_)
                | Change::UpstreamLink(_)
        ) {
            return Ok(());
        }
        let party = match actor {
            Some(party) => Some(party),
            None => self
                .decider
                .signer(domain, ais)
                .await
                .map_err(|e| AdminError::Unavailable(e.0))?,
        };
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let subject = match (p.subject, party) {
            (Some(s), _) => Some(s),
            (None, Some(party)) => idp::party_subject(&mut t, &party.0).await?,
            (None, None) => None,
        };
        let restricted = subject.filter(|subject| match &p.change {
            Change::AccountDelete(s) => s == subject,
            Change::UpstreamLink(l) => l.account == *subject,
            _ => true,
        });
        let Some(subject) = restricted else {
            t.commit().await?;
            return Ok(());
        };
        let now = access_store::authority::server_time(self.app).await?;
        let now = i64::try_from(now).map_err(|_| AdminError::Encode)?;
        let until = t.recovery_grace_until(subject, now).await?;
        t.commit().await?;
        if until.is_some() {
            return Err(Invalid::RecoveryGrace.into());
        }
        Ok(())
    }

    /// The Party the session subject of `p` is bound to (§13.4 G54, OP-149 m.16 (a)); a subject
    /// without one cannot change the realm.
    async fn actor(&self, p: &Proposal) -> Result<Option<Id>, AdminError> {
        let Some(subject) = &p.subject else {
            return Ok(None);
        };
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let party = idp::subject_party(&mut t, subject).await?;
        t.commit().await?;
        party
            .map(|p| Some(Id(p)))
            .ok_or_else(|| AdminError::Refused(String::from(ACTOR_BINDING)))
    }

    /// The Party that signs a change in `(tenant, realm)` stands only while its account there
    /// can act (§13.4 G54, §12.3.1, TN-49): a Party bound to a suspended, locked or deleted
    /// account changes nothing, whether a session or an Instance key alone asks. A Party bound
    /// to no account of the realm, such as the operator's root, is not narrowed here (OP-150
    /// m.11 (f)); a key no live Instance holds is the authority plane's to refuse.
    ///
    /// # Errors
    /// [`AdminError::Refused`] with `actor-binding`; [`AdminError`].
    pub async fn standing(
        &self,
        (tenant, realm): (TenantId, RealmId),
        domain: Digest,
        ais: &[u8],
        actor: Option<Id>,
    ) -> Result<(), AdminError> {
        let party = match actor {
            Some(party) => Some(party),
            None => self
                .decider
                .signer(domain, ais)
                .await
                .map_err(|e| AdminError::Unavailable(e.0))?,
        };
        let Some(party) = party else {
            return Ok(());
        };
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let status = match idp::party_subject(&mut t, &party.0).await? {
            Some(subject) => Some(resources::account(&mut t, subject).await?.map(|a| a.status)),
            None => None,
        };
        t.commit().await?;
        match status {
            None => Ok(()),
            Some(Some(s))
                if AccountStatus::parse(&s).is_some_and(AccountStatus::can_authenticate) =>
            {
                Ok(())
            }
            Some(_) => Err(AdminError::Refused(String::from(ACTOR_BINDING))),
        }
    }

    /// What follows a written change outside the database: a new JOSE algorithm reaches the
    /// identity signer for the realm's next keys (OP-146 m.8 (e), m.16 (m)), and a decided key
    /// policy, rotation or drop reaches the realm's key set (TN-118, §13.2). A retry of the
    /// change repeats it; each of them is idempotent.
    async fn after(&self, p: &Proposal) -> Result<(), AdminError> {
        let done = match &p.change {
            Change::JoseAlg(alg) => self.keys.open(p.realm, *alg).await,
            // TN-118, §13.2
            Change::KeyPolicy(policy) => self.keys.set_policy(p.realm, *policy).await,
            Change::KeyRotate { retire } => self.keys.rotate(p.realm, *retire).await,
            Change::KeyDrop { kid, .. } => self.keys.drop_key(p.realm, *kid).await,
            _ => Ok(()),
        };
        done.map_err(|e| AdminError::Unavailable(e.0))
    }

    /// OP-149 m.4: an API client change queues its event in the write's transaction, so it
    /// is delivered exactly when the change is written.
    async fn announce(
        &self,
        t: &mut TenantTx,
        p: &Proposal,
        exercise: &Digest,
    ) -> Result<(), AdminError> {
        let product = |c: &Client| c.platform.as_ref().map(|p| p.product.clone());
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
                platform_product: platform_product.as_ref(),
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
                let (hash, secret) = new_secret()?;
                (Some(hash), Some(secret))
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
                event_receiver: c.platform.as_ref().and_then(|p| p.event_receiver.clone()),
                require_par: c.require_par,
                public_sub: c.subject.public,
                sector_identifier_uri: c.subject.sector_identifier_uri.clone(),
                third_party: c.third_party,
            },
            secret,
        ))
    }

    /// Registers or updates `c`; counts a new public `sub` opt-in (MD-10), never labelled by
    /// realm (OP-47).
    async fn write_client(
        &self,
        t: &mut TenantTx,
        bound: &idp::Bound,
        c: &Client,
        register: bool,
    ) -> Result<(bool, Option<ClientSecret>), AdminError> {
        let was_public = !register
            && idp::client(t, c.id.as_str())
                .await?
                .is_some_and(|r| r.public_sub);
        let (row, secret) = self.client_row(t, c).await?;
        let done = if register {
            idp::insert_client(t, bound, &row).await?;
            true
        } else {
            idp::update_client(t, bound, &row).await?
        };
        // OP-154 m.3 (r), (d)
        if let (true, crate::domain::AuthMethod::Spiffe(w)) = (done, &c.auth) {
            Box::pin(workloads::register(t, bound, row.client_uuid, w)).await?;
        }
        if done && c.subject.public && !was_public {
            PUBLIC_SUB_OPT_IN.incr([]);
        }
        Ok((done, secret))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one match over the changes, each arm its write"
    )]
    async fn write(
        &self,
        t: &mut TenantTx,
        bound: &idp::Bound,
        change: &Change,
    ) -> Result<Option<ClientSecret>, AdminError> {
        let mut secret = None;
        let done = match change {
            Change::ClientRegister(c) | Change::ClientUpdate(c) => {
                let (done, s) = self
                    .write_client(t, bound, c, matches!(change, Change::ClientRegister(_)))
                    .await?;
                secret = s;
                done
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
                // RR-45, TN-17
                if let Change::RpId(r) = change
                    && s.rp_id.as_deref() != Some(r.as_str())
                {
                    t.insert_rp_id_change(s.rp_id.as_deref(), r.as_str())
                        .await?;
                }
                let done = idp::update_settings(t, bound, &settings_with(s, change)).await?;
                if let Change::CimdPolicy(p) = change {
                    retire_cimd_outside(t, p).await?;
                }
                done
            }
            Change::Branding(b) => {
                // OP-153 m.22 (g)
                let stored = idp::branding(t)
                    .await?
                    .and_then(|b| dcbor::decode(&b, Limits::CEILING).ok());
                let mode = crate::domain::accounts::CspMode::of(stored.as_ref());
                let bytes = dcbor::encode(&mode.applied_to(b.to_value()), Limits::CEILING)
                    .map_err(|_| AdminError::Encode)?;
                idp::set_branding(t, bound, &bytes).await?;
                true
            }
            Change::CspMode { mode, .. } => {
                // OP-153 m.22 (g), m.25 (b)
                let stored = idp::branding(t)
                    .await?
                    .and_then(|b| dcbor::decode(&b, Limits::CEILING).ok())
                    .unwrap_or_else(|| crate::domain::Branding::default().to_value());
                let bytes = dcbor::encode(&mode.applied_to(stored), Limits::CEILING)
                    .map_err(|_| AdminError::Encode)?;
                idp::set_branding(t, bound, &bytes).await?;
                true
            }
            Change::RelatedOrigins(r) => {
                let origins: Vec<String> = r.origins.iter().cloned().collect();
                idp::set_related_origins(t, bound, &origins).await?;
                true
            }
            Change::LocaleOverrides(o) => {
                let bytes = dcbor::encode(&o.to_value(), Limits::CEILING)
                    .map_err(|_| AdminError::Encode)?;
                idp::set_locale_overrides(t, bound, &bytes).await?;
                true
            }
            Change::KeyPolicy(_) | Change::KeyRotate { .. } | Change::KeyDrop { .. } => {
                let declared_at = access_store::authority::server_time(self.app).await?;
                idp::record_key_change(t, bound, &key_change(change, declared_at)?).await?;
                true
            }
            Change::ClientSecretRotate(id) => {
                let (hash, s) = new_secret()?;
                secret = Some(s);
                resources::rotate_secret(t, bound, id.as_str(), &hash, SECRET_OVERLAP_MS).await?
            }
            Change::GroupCreate(g) => {
                resources::insert_group(t, bound, &group_row(g)).await?;
                true
            }
            Change::GroupUpdate(g) => {
                resources::rename_group(t, bound, g.name.as_str(), &g.display_name).await?
            }
            Change::GroupRetire(name) => resources::retire_group(t, bound, name.as_str()).await?,
            Change::GroupMembersAdd(m) => {
                let ids: Vec<[u8; 16]> = m.subjects.iter().copied().collect();
                resources::add_members(t, bound, m.group.as_str(), &ids).await?;
                true
            }
            Change::GroupMembersRemove(m) => {
                let ids: Vec<[u8; 16]> = m.subjects.iter().copied().collect();
                resources::remove_members(t, bound, m.group.as_str(), &ids).await?;
                true
            }
            Change::AccountSuspend(s) => resources::set_account_state(t, bound, *s, true).await?,
            Change::AccountReactivate(s) => {
                resources::set_account_state(t, bound, *s, false).await?
            }
            Change::UpstreamRegister(u) => {
                resources::put_upstream(t, bound, &upstream_row(u), true).await?
            }
            Change::UpstreamUpdate(u) => {
                resources::put_upstream(t, bound, &upstream_row(u), false).await?
            }
            Change::UpstreamRetire(name) => {
                resources::retire_upstream(t, bound, name.as_str()).await?
            }
            Change::SigninPolicy(p) => {
                set_policy(t, bound, PolicyKind::Signin, &p.to_value()).await?
            }
            Change::SessionPolicy(p) => {
                set_policy(t, bound, PolicyKind::Session, &p.to_value()).await?
            }
            Change::ExtensionPolicy(p) => {
                set_policy(t, bound, PolicyKind::Extension, &p.to_value()).await?
            }
            Change::Hook(_) | Change::Webhook(_) => {
                secret = self.write_extension(t, bound, change).await?;
                true
            }
            Change::ProtectionMode { mode, .. } => {
                access_identity_risk::app::settings::apply_mode(t, bound, mode)
                    .await
                    .map_err(risk)?;
                true
            }
            Change::AccountCanary(s) => {
                access_identity_risk::app::settings::mark_canary(t, bound, *s)
                    .await
                    .map_err(risk)?
            }
            Change::UpstreamLink(l) => {
                let u = resources::upstream(t, l.upstream.as_str())
                    .await?
                    .filter(|u| u.active)
                    .ok_or(Invalid::NoUpstream)?;
                t.link_upstream_subject_decided(bound, &link_digest(&u, &l.sub), l.account)
                    .await?
                    .ok_or(Invalid::UpstreamSubjectLinked)?
            }
            Change::AccountDelete(_)
            | Change::AccountImport(_)
            | Change::MigrationExport(_)
            | Change::AccountBind(_)
            | Change::GuardianshipRecord(_)
            | Change::OrgCreate(_)
            | Change::OrgInvite(_)
            | Change::OrgDomainClaim(_)
            | Change::OrgSsoDraft(_)
            | Change::AccountResetIntent { .. }
            | Change::Agent(_)
            | Change::AccountTapIssue(_) => true,
            // OP-154 m.3 (t)
            Change::Vault(v) => vault::write(t, bound, v).await?,
            Change::DeviceCode(on) => {
                t.put_device_code(bound, *on).await?;
                true
            }
            Change::DcrPolicy { policy, .. } => {
                t.put_dcr_policy(
                    bound,
                    &access_store::dcr::DcrPolicyRow {
                        enabled: policy.enabled,
                        domains: policy.domains.iter().cloned().collect(),
                        tokens: policy.tokens.iter().copied().collect(),
                    },
                )
                .await?;
                // §11.4.5
                let now = t.db_now_ms().await?;
                for c in t.dcr_clients().await? {
                    let hosts = access_identity_oauth::app::oauth::dcr::of_dcr(&c)
                        .map(|cl| {
                            access_identity_oauth::domain::cimd::redirect_hosts(&cl.redirect_uris)
                        })
                        .unwrap_or_default();
                    if !policy.admits(&c.token, &hosts) {
                        t.retire_dcr_client(c.client_uuid, "policy", now).await?;
                    }
                }
                true
            }
            Change::ResourceRegister(r) => {
                access_store::clients::insert_protected_resource(
                    t,
                    bound,
                    &r.resource,
                    &r.display_name,
                )
                .await?;
                true
            }
            Change::OrgInviteRevoke { invitation, .. } => t.revoke_invitation(*invitation).await?,
            Change::OrgDomainRelease { org, claim } => {
                org_flows::release_domain(t, *org, *claim).await?
            }
            Change::OrgUpdate(u) => orgs::update(t, self.ids, u, self.app).await?,
            Change::SocialEnable(s) | Change::SocialUpdate(s) => {
                write_social(t, bound, s).await?;
                true
            }
            Change::SocialDisable(preset) => {
                let mut row = t
                    .social_provider(preset.as_str())
                    .await?
                    .filter(|r| r.active)
                    .ok_or(Invalid::NoSocial)?;
                row.active = false;
                t.put_social_provider(bound, &row).await?;
                true
            }
            Change::OrgMemberRemove(m) => {
                let org = t
                    .org_by_party(m.org)
                    .await?
                    .filter(|o| !o.ended)
                    .ok_or(Invalid::NoOrg)?;
                // TN-91
                let ended = t
                    .end_membership(org.id, m.subject, "remove")
                    .await
                    .map_err(|e| {
                        if access_store::orgs::last_owner(&e) {
                            AdminError::Invalid(Invalid::LastOwner)
                        } else {
                            e.into()
                        }
                    })?;
                if ended {
                    // OP-153 m.4
                    let at = access_store::authority::server_time(self.app).await?;
                    orgs::membership_event(
                        t,
                        self.ids,
                        IdentityKind::MembershipRemoved,
                        (m.subject, org.id),
                        at,
                    )
                    .await?;
                }
                ended
            }
            Change::RecoveryPolicy { policy, .. } => {
                let bytes = policy.to_bytes().map_err(|_| AdminError::Encode)?;
                t.insert_recovery_realm_policy(&bytes, bound).await?;
                true
            }
        };
        if done {
            Ok(secret)
        } else {
            Err(AdminError::Conflict)
        }
    }
}

/// IDP-31, TN-87: writes the preset's new client; a changed client id keeps the one before and
/// when it changed, which the provider's view turns into its warnings.
async fn write_social(
    t: &mut TenantTx,
    bound: &idp::Bound,
    s: &crate::domain::Social,
) -> Result<(), AdminError> {
    let now = t.server_time().await?;
    let before = t.social_provider(s.preset.as_str()).await?;
    let new_id = s.client.as_ref().map(|c| c.client_id.clone());
    let (previous, changed) = match &before {
        Some(b) if b.client_id.is_some() && b.client_id != new_id => {
            (b.client_id.clone(), Some(now))
        }
        Some(b) => (b.previous_client_id.clone(), b.client_changed_ms),
        None => (None, None),
    };
    let row = access_store::federation::SocialRow {
        preset: String::from(s.preset.as_str()),
        client_id: new_id,
        client_secret_ref: s.client.as_ref().map(|c| c.secret_ref.clone()),
        active: true,
        previous_client_id: previous,
        client_changed_ms: changed,
        position: 0,
    };
    t.put_social_provider(bound, &row).await?;
    Ok(())
}

/// TN-91, OP-153 m.3 (p): the member exists, and removing it leaves an active owner.
async fn org_member_current(
    t: &mut TenantTx,
    m: crate::domain::OrgMember,
) -> Result<(), AdminError> {
    let org = t
        .org_by_party(m.org)
        .await?
        .filter(|o| !o.ended)
        .ok_or(Invalid::NoOrg)?;
    let members = t.memberships(org.id).await?;
    let member = members
        .iter()
        .find(|x| x.subject == m.subject)
        .ok_or(Invalid::NoMember)?;
    if member.owner && members.iter().filter(|x| x.owner).count() == 1 {
        return Err(Invalid::LastOwner.into());
    }
    Ok(())
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// The account that issues a reset intent or a pass: the subject of the Party whose
    /// Instance signed the write. Nobody issues one for their own account (TN-62); `None` for
    /// every other change, or a signer without an account.
    async fn recovery_issuer(
        &self,
        p: &Proposal,
        domain: Digest,
        ais: &[u8],
        actor: Option<Id>,
    ) -> Result<Option<[u8; 16]>, AdminError> {
        let target = match &p.change {
            Change::AccountResetIntent { subject, .. }
            | Change::AccountTapIssue(crate::domain::TapIssue { subject, .. }) => *subject,
            _ => return Ok(None),
        };
        let party = match actor {
            Some(a) => Some(a),
            None => self
                .decider
                .signer(domain, ais)
                .await
                .map_err(|e| AdminError::Unavailable(e.0))?,
        };
        let Some(party) = party else {
            return Ok(p.subject);
        };
        let mut t = TenantTx::begin(self.app, p.tenant, p.realm).await?;
        let subject = idp::party_subject(&mut t, &party.0).await?;
        t.commit().await?;
        // TN-62
        if subject == Some(target) || p.subject == Some(target) {
            return Err(Invalid::SelfIssue.into());
        }
        Ok(subject.or(p.subject))
    }
}

/// The RFC 7293 time of a message to the account's own address: e-mail only (OP-153 m.3 (i)).
pub(crate) async fn mailbox_since(
    t: &mut TenantTx,
    subject: [u8; 16],
    to: &access_identity_account::notify::message::Address,
) -> Result<Option<u64>, AdminError> {
    if !matches!(
        to,
        access_identity_account::notify::message::Address::Email(_)
    ) {
        return Ok(None);
    }
    let since = t.mailbox_since(subject).await?;
    Ok(Some(
        since
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(1)
            .max(1),
    ))
}

/// The realm's recovery policy, or the default one (OP-153 m.3 (e)).
async fn recovery_policy(t: &mut TenantTx) -> Result<RecoveryPolicy, AdminError> {
    match t.recovery_realm_policy().await? {
        Some(b) => RecoveryPolicy::from_bytes(&b).map_err(|_| AdminError::Encode),
        None => Ok(RecoveryPolicy::DEFAULT),
    }
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// Tells the account's own address that its status changed (`relay.message.account_status.v1`).
    async fn status_notice(
        &self,
        t: &mut PgTx,
        p: &Proposal,
        subject: [u8; 16],
        status: AccountStatus,
    ) -> Result<(), AdminError> {
        use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
        use access_identity_account::notify::message::{Address, Body, Message};
        use access_identity_account::notify::notifier::OutboxNotifier;
        use access_identity_account::notify::ports::Notifier as _;
        let kek = self
            .vault
            .and_then(|v| v.realm_kek(p.tenant, p.realm))
            .ok_or_else(|| AdminError::Unavailable(String::from("kek")))?;
        let realm = access_identity_account::app::Realm {
            tenant: p.tenant,
            realm: p.realm,
            kek: &*kek,
            ids: self.ids,
        };
        let Some((kind, stored)) = t.0.contact(subject).await? else {
            return Ok(());
        };
        let Some(value) =
            access_identity_account::app::vault::reveal_with_kek(&mut t.0, &*kek, subject, &stored)
                .await
                .map_err(account)?
        else {
            return Ok(());
        };
        let to = if kind == "phone" {
            Address::Phone(value)
        } else {
            Address::Email(value)
        };
        let valid_since_ms = mailbox_since(&mut t.0, subject, &to).await?;
        let now = access_store::authority::server_time(self.app).await?;
        OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock)
            .notify(
                &mut t.0,
                &Message {
                    subject,
                    to,
                    locale: None,
                    valid_since_ms,
                    body: Body::AccountStatus { status, at_ms: now },
                },
            )
            .await
            .map_err(|_| AdminError::Unavailable(String::from("relay")))?;
        Ok(())
    }

    /// The token a committed `idp.account.reset_intent` or `idp.account.tap_issue` issues, in
    /// the transaction that applies it (TN-61, TN-62): stored by digest only and bound to its
    /// Exercise. A reset intent goes to the account's own registered address, never to a
    /// recovery channel, and opens a credential-only window; a pass is handed to the issuer
    /// once, to read out. Issue and use are separate audit events, the issue naming the issuer.
    #[expect(
        clippy::too_many_lines,
        reason = "one token, its delivery and its audit row"
    )]
    async fn recovery_token(
        &self,
        t: &mut PgTx,
        p: &Proposal,
        g: &Governing,
        exercise: &Digest,
        issuer: Option<[u8; 16]>,
    ) -> Result<Option<ClientSecret>, AdminError> {
        use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
        use access_identity_account::domain::recovery_token as tokens;
        use access_identity_account::notify::message::{
            Address, Body, LinkPurpose, Message, Notice,
        };
        use access_identity_account::notify::notifier::OutboxNotifier;
        use access_identity_account::notify::ports::Notifier as _;
        use access_store::recovery::NewToken;
        let kek = self
            .vault
            .and_then(|v| v.realm_kek(p.tenant, p.realm))
            .ok_or_else(|| AdminError::Unavailable(String::from("kek")))?;
        let realm = access_identity_account::app::Realm {
            tenant: p.tenant,
            realm: p.realm,
            kek: &*kek,
            ids: self.ids,
        };
        let notifier = OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock);
        let now = access_store::authority::server_time(self.app).await?;
        let correlation = access_kernel::json::b64url_encode(&exercise.0);
        let issuer = match issuer.or(p.subject) {
            Some(s) => realm.external(s).map_err(account)?,
            None => String::from(DECIDED_BY),
        };
        let (subject, out) = match &p.change {
            Change::AccountResetIntent { subject, ttl_ms } => {
                let (kind, stored) =
                    t.0.contact(*subject)
                        .await?
                        .ok_or(Invalid::RecoveryOption)?;
                let value = access_identity_account::app::vault::reveal_with_kek(
                    &mut t.0, &*kek, *subject, &stored,
                )
                .await
                .map_err(account)?
                .ok_or(Invalid::RecoveryOption)?;
                let to = if kind == "phone" {
                    Address::Phone(value)
                } else {
                    Address::Email(value)
                };
                let valid_since_ms = mailbox_since(&mut t.0, *subject, &to).await?;
                let token = access_kernel::json::b64url_encode(
                    &access_crypto::random::bytes::<32>()
                        .map_err(|_| AdminError::Unavailable(String::from("random")))?,
                );
                let expires = now.saturating_add(*ttl_ms);
                t.0.insert_recovery_token(&NewToken {
                    subject: *subject,
                    kind: tokens::RESET_INTENT,
                    token_hash: &tokens::digest(&token),
                    attempt: None,
                    exercise: Some(&exercise.0),
                    address: None,
                    entropy_bits: 256,
                    one_time: true,
                    at_ms: i64::try_from(now).map_err(|_| AdminError::Encode)?,
                    expires_ms: i64::try_from(expires).map_err(|_| AdminError::Encode)?,
                })
                .await
                .map_err(|_| AdminError::Conflict)?;
                let base = g.issuer.as_deref().ok_or(AdminError::NoRealm)?;
                let link = format!(
                    "{}/login/recovery#intent={token}",
                    base.trim_end_matches('/')
                );
                notifier
                    .notify(
                        &mut t.0,
                        &Message {
                            subject: *subject,
                            to,
                            locale: None,
                            valid_since_ms,
                            body: Body::Link {
                                purpose: LinkPurpose::ResetIntent,
                                link: access_crypto::Secret::new(link),
                                expires_at_ms: expires,
                            },
                        },
                    )
                    .await
                    .map_err(|_| AdminError::Unavailable(String::from("relay")))?;
                let target = realm.external(*subject).map_err(account)?;
                t.0.audit(&access_store::audit::AuditEvent {
                    event_type: "recovery.reset_intent.issued",
                    actor: &issuer,
                    target: &target,
                    correlation: &correlation,
                })
                .await?;
                (*subject, None)
            }
            Change::AccountTapIssue(tap) => {
                let raw = access_crypto::random::bytes::<{ recovery_policy::TAP_LENGTH_MAX }>()
                    .map_err(|_| AdminError::Unavailable(String::from("random")))?;
                let code = recovery_policy::tap_code(&raw, usize::from(tap.length));
                let expires = now.saturating_add(tap.ttl_ms);
                t.0.insert_recovery_token(&NewToken {
                    subject: tap.subject,
                    kind: tokens::TEMPORARY_ACCESS_PASS,
                    token_hash: &tokens::typed_digest(&code),
                    attempt: None,
                    exercise: Some(&exercise.0),
                    address: None,
                    entropy_bits: i16::from(tap.length).saturating_mul(5),
                    one_time: tap.one_time,
                    at_ms: i64::try_from(now).map_err(|_| AdminError::Encode)?,
                    expires_ms: i64::try_from(expires).map_err(|_| AdminError::Encode)?,
                })
                .await
                .map_err(|_| AdminError::Conflict)?;
                let target = realm.external(tap.subject).map_err(account)?;
                t.0.audit(&access_store::audit::AuditEvent {
                    event_type: "recovery.tap.issued",
                    actor: &issuer,
                    target: &target,
                    correlation: &correlation,
                })
                .await?;
                (tap.subject, Some(ClientSecret(code)))
            }
            _ => return Ok(None),
        };
        // TN-61 rule 2
        if let Some((kind, stored)) = t.0.contact(subject).await?
            && let Some(value) = access_identity_account::app::vault::reveal_with_kek(
                &mut t.0, &*kek, subject, &stored,
            )
            .await
            .map_err(account)?
        {
            let to = if kind == "phone" {
                Address::Phone(value)
            } else {
                Address::Email(value)
            };
            let valid_since_ms = mailbox_since(&mut t.0, subject, &to).await?;
            notifier
                .notify(
                    &mut t.0,
                    &Message {
                        subject,
                        to,
                        locale: None,
                        valid_since_ms,
                        body: Body::Notice {
                            notice: Notice::RecoveryRequested,
                            at_ms: now,
                            until_ms: None,
                        },
                    },
                )
                .await
                .map_err(|_| AdminError::Unavailable(String::from("relay")))?;
        }
        Ok(out)
    }
}

/// Who a decided account status move is in the account audit log (OP-10); the correlation is
/// the `ExerciseID`.
const DECIDED_BY: &str = "idp-decision";

/// The status move an `idp.account.*` change makes: the subject, the status it leaves and the
/// one it enters, read before the move is written.
async fn account_move(
    t: &mut TenantTx,
    change: &Change,
) -> Result<Option<([u8; 16], AccountStatus, AccountStatus)>, AdminError> {
    let (subject, to) = match change {
        Change::AccountSuspend(s) => (*s, AccountStatus::Suspended),
        Change::AccountReactivate(s) => (*s, AccountStatus::Active),
        _ => return Ok(None),
    };
    let a = resources::account(t, subject)
        .await?
        .ok_or(Invalid::NoAccount)?;
    let from = AccountStatus::parse(&a.status)
        .ok_or(AdminError::Store(access_store::StoreError::Corrupt))?;
    Ok(Some((subject, from, to)))
}

/// An account use case failure as the write path reports it.
fn account(e: access_identity_account::AccountError) -> AdminError {
    match e {
        access_identity_account::AccountError::Store(s) => s.into(),
        _ => AdminError::Unavailable(String::from("account")),
    }
}

/// A risk store failure as the write path reports it.
fn risk(e: access_identity_risk::RiskError) -> AdminError {
    match e {
        access_identity_risk::RiskError::Store(s) => s.into(),
        access_identity_risk::RiskError::Mode(_) => Invalid::ProtectionMode.into(),
        access_identity_risk::RiskError::Account(_) | access_identity_risk::RiskError::Corrupt => {
            AdminError::Unavailable(String::from("risk"))
        }
    }
}

impl<D: Decider, G: Governance + Instances, K: RealmKeys> Admin<'_, D, G, K> {
    /// A new hook or webhook id: a fresh UUID as an opaque external id under `prefix`
    /// (OP-65, OP-137).
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn new_extension_id(&self, prefix: &str) -> Result<String, AdminError> {
        let uuid = idp::new_uuid(self.app).await?;
        Ok(self.ids.encode(prefix, uuid)?)
    }

    /// TN-135, TN-136, OP-151 m.10 (e): writes a hook or webhook change with M6's use cases, the
    /// realm's extension policy read in the same transaction; a registration's or rotation's key
    /// is shown once.
    async fn write_extension(
        &self,
        t: &mut TenantTx,
        bound: &idp::Bound,
        change: &Change,
    ) -> Result<Option<ClientSecret>, AdminError> {
        let vault = self
            .vault
            .ok_or_else(|| AdminError::Unavailable(String::from("key-vault")))?;
        let policy = extension_policy(t).await?;
        let shown = match change {
            Change::Hook(h) => {
                if let HookChange::Register { spec, .. } = h
                    && !policy.permits(&spec.disclose)
                {
                    return Err(Invalid::Disclosure.into());
                }
                let allow = allow_private(&policy, &self.declared, h);
                match access_identity_hooks::app::write(t, bound, h, vault, allow).await {
                    Ok(access_identity_hooks::app::Written::Registered(k)) => Some(k),
                    Ok(access_identity_hooks::app::Written::Retired) => None,
                    Err(e) => return Err(extension_error(&e)),
                }
            }
            Change::Webhook(w) => {
                let allow = webhook_allow_private(&policy, &self.declared, w);
                let now = access_store::authority::server_time(self.app).await?;
                let written =
                    access_identity_events::app::webhooks::write(t, bound, w, vault, now, allow)
                        .await;
                match written {
                    Ok(access_identity_events::app::webhooks::Written::Key(k)) => Some(k),
                    Ok(access_identity_events::app::webhooks::Written::Done) => None,
                    Err(e) => return Err(extension_error(&e)),
                }
            }
            _ => return Err(AdminError::Encode),
        };
        Ok(shown.map(|k| ClientSecret(String::from(k.expose()))))
    }
}

/// Stores one of the realm's policies under `bound`.
async fn set_policy(
    t: &mut TenantTx,
    bound: &idp::Bound,
    kind: PolicyKind,
    value: &dcbor::Value,
) -> Result<bool, AdminError> {
    let bytes = dcbor::encode(value, Limits::CEILING).map_err(|_| AdminError::Encode)?;
    resources::set_policy(t, bound, kind, &bytes).await?;
    Ok(true)
}

fn extension_error(e: &access_identity_hooks::app::WriteError) -> AdminError {
    use access_identity_hooks::app::WriteError;
    match e {
        WriteError::Invalid(i) => extension_invalid(*i).into(),
        WriteError::Conflict => AdminError::Conflict,
        WriteError::Unavailable => AdminError::Unavailable(String::from("extension-write")),
    }
}

/// The realm's extension policy; nothing stored is the default (OP-151 m.10 (e)).
async fn extension_policy(t: &mut TenantTx) -> Result<ExtensionPolicy, AdminError> {
    let stored = resources::policies(t).await?;
    ExtensionPolicy::from_stored(stored.extension.as_deref())
        .map_err(|_| AdminError::Store(access_store::StoreError::Corrupt))
}

/// OP-151 m.10 (e), OP-149 m.23: a private target needs the realm's permission and the
/// operator's declaration of that very URL.
fn allow_private(policy: &ExtensionPolicy, declared: &DeclaredTargets, h: &HookChange) -> bool {
    match h {
        HookChange::Register { spec, .. } => policy.private_allowed(declared.declares(&spec.url)),
        HookChange::Retire { .. } => false,
    }
}

fn webhook_allow_private(
    policy: &ExtensionPolicy,
    declared: &DeclaredTargets,
    w: &WebhookChange,
) -> bool {
    let url = match w {
        WebhookChange::Register { spec, .. } => &spec.url,
        WebhookChange::Update { url, .. } => url,
        WebhookChange::Retire { .. } => return false,
    };
    policy.private_allowed(declared.declares(url))
}

/// The hook or webhook change against the realm: its target and disclosures under the realm's
/// extension policy; with `state`, also the hook or webhook it names (OP-151 m.10 (d)).
async fn extension_current(
    t: &mut TenantTx,
    change: &Change,
    declared: &DeclaredTargets,
    state: bool,
) -> Result<(), AdminError> {
    let policy = extension_policy(t).await?;
    match change {
        Change::Hook(h) => {
            if let HookChange::Register { spec, .. } = h {
                spec.check(allow_private(&policy, declared, h))
                    .map_err(extension_invalid)?;
                if !policy.permits(&spec.disclose) {
                    return Err(Invalid::Disclosure.into());
                }
            }
            if !state {
                return Ok(());
            }
            match h {
                HookChange::Register { spec, .. } => {
                    if access_store::extensions::live_hook(t, spec.point.name())
                        .await?
                        .is_some()
                    {
                        return Err(Invalid::HookPointTaken.into());
                    }
                }
                HookChange::Retire { id } => {
                    let live = access_store::extensions::hooks(t, Some(id), &[0; 16], 1)
                        .await?
                        .into_iter()
                        .any(|h| h.active);
                    if !live {
                        return Err(Invalid::NoHook.into());
                    }
                }
            }
        }
        Change::Webhook(w) => {
            w.check(webhook_allow_private(&policy, declared, w))
                .map_err(|e| extension_invalid(access_identity_hooks::domain::Invalid(e.0)))?;
            if !state {
                return Ok(());
            }
            let found = access_store::extensions::webhook(t, w.id()).await?;
            match w {
                WebhookChange::Register { .. } if found.is_some() => {
                    return Err(AdminError::Conflict);
                }
                WebhookChange::Update { .. } | WebhookChange::Retire { .. }
                    if !found.as_ref().is_some_and(|f| f.active) =>
                {
                    return Err(Invalid::NoWebhook.into());
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(())
}

/// Context of an upstream provider's transmitter id.
pub const TRANSMITTER_CONTEXT: &str = "access/upstream-transmitter/v1";

/// The inbound transmitter id of the realm's upstream provider `name`: the same for every
/// declaration of it.
#[must_use]
pub fn transmitter_id(name: &str) -> [u8; 16] {
    let d = suiss_crypto::digest::context_digest(TRANSMITTER_CONTEXT, name.as_bytes()).0;
    let mut id = [0; 16];
    id.copy_from_slice(d.get(..16).unwrap_or(&[0; 16]));
    id
}

/// A push transmitter has no credential to seal; anything asked to seal is refused.
struct NoCredential;

impl access_identity_events::ports::Sealer for NoCredential {
    fn seal(
        &self,
        _: TenantId,
        _: RealmId,
        _: &[u8; 16],
        _: &[u8],
    ) -> Result<access_store::events::SealedKey, access_identity_events::ports::Unavailable> {
        Err(access_identity_events::ports::Unavailable)
    }

    fn open(
        &self,
        _: TenantId,
        _: RealmId,
        _: &[u8; 16],
        _: &access_store::events::SealedKey,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, access_identity_events::ports::Unavailable> {
        Err(access_identity_events::ports::Unavailable)
    }
}

/// OP-151 m.7 (g): an `idp.upstream.register` with SSF fields declares the provider as an
/// inbound transmitter in the write's transaction, bound to the decision (EI-25); an
/// `idp.upstream.retire` ends it under its own decision.
async fn declare_transmitter(
    t: &mut TenantTx,
    bound: &idp::Bound,
    change: &Change,
    exercise: &Digest,
) -> Result<(), AdminError> {
    if let Change::UpstreamRetire(name) = change {
        t.disable_transmitter(bound, transmitter_id(name.as_str()))
            .await?;
        return Ok(());
    }
    let Change::UpstreamRegister(Upstream {
        name,
        ssf: Some(cfg),
        ..
    }) = change
    else {
        return Ok(());
    };
    access_identity_events::app::receiver::declare(
        t,
        bound,
        &NoCredential,
        transmitter_id(name.as_str()),
        cfg,
        None,
        Some(exercise.0),
    )
    .await
    .map_err(|_| AdminError::Unavailable(String::from("ssf-receiver")))
}

/// A fresh server-generated client secret and its stored digest (CR-38).
fn new_secret() -> Result<([u8; 32], ClientSecret), AdminError> {
    let raw = access_crypto::random::bytes::<32>().map_err(|_| AdminError::Encode)?;
    let text = access_kernel::json::b64url_encode(&raw);
    Ok((
        access_crypto::oauth::secret_digest(text.as_bytes()),
        ClientSecret(text),
    ))
}

fn group_row(g: &Group) -> GroupRow {
    GroupRow {
        name: String::from(g.name.as_str()),
        display_name: g.display_name.clone(),
        membership_issuer: g.issuer.text(),
        active: true,
        position: 0,
    }
}

/// H(iss, sub) of an upstream subject (OP-152 m.7 (d) E6): `iss` is the issuer the provider's
/// signals name their subjects under, its SSF transmitter's when it has one, else its own.
fn link_digest(u: &UpstreamRow, sub: &str) -> [u8; 32] {
    let issuer = u
        .ssf
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("issuer").and_then(|i| i.as_str()).map(String::from))
        .unwrap_or_else(|| u.issuer.clone());
    access_identity_events::domain::inbound::subject_digest(&issuer, sub)
}

fn upstream_row(u: &Upstream) -> UpstreamRow {
    UpstreamRow {
        name: String::from(u.name.as_str()),
        issuer: u.issuer.clone(),
        client_id: u.client_id.clone(),
        client_secret_ref: u.client_secret_ref.clone(),
        jwks_uri: u.jwks_uri.clone(),
        ssf: u
            .ssf
            .as_ref()
            .map(|s| crate::domain::realm::ssf_json(s).to_string()),
        active: true,
        position: 0,
    }
}

/// AG-5, §11.3.6: a CIMD client the realm's new policy no longer admits retires now: its
/// consent records end and its identity grants are revoked, so introspection answers inactive.
async fn retire_cimd_outside(
    t: &mut TenantTx,
    p: &crate::domain::CimdPolicy,
) -> Result<(), AdminError> {
    use access_identity_oauth::domain::cimd::{domain_admitted, host};
    let domains: Vec<String> = p.domains.iter().cloned().collect();
    let live = t.cimd_clients().await?;
    if live.is_empty() {
        return Ok(());
    }
    let now = t.db_now_ms().await?;
    for (uuid, url) in live {
        let admitted = host(&url).is_some_and(|h| domain_admitted(&domains, &h));
        if !p.enabled || !admitted {
            let reason = if p.enabled {
                "domain_policy"
            } else {
                "disabled"
            };
            t.retire_cimd_client(uuid, reason, now).await?;
        }
    }
    Ok(())
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
        _ => {}
    }
    s
}

/// The record of a decided key change written at `declared_at`; a drop declares its issuer
/// cutoff (§13.7.7, SEC9).
fn key_change(change: &Change, declared_at: u64) -> Result<KeyChange, AdminError> {
    let mut c = KeyChange {
        action: change.action().label(),
        kid: None,
        policy: None,
        compromised_at: None,
        declared_at,
        cutoff_at: None,
    };
    match change {
        Change::KeyPolicy(p) => {
            c.policy = Some(
                dcbor::encode(&policy_value(p), Limits::CEILING).map_err(|_| AdminError::Encode)?,
            );
        }
        Change::KeyRotate { retire } => c.kid = Some(*retire),
        Change::KeyDrop {
            kid,
            compromised_at,
        } => {
            c.kid = Some(*kid);
            c.compromised_at = *compromised_at;
            c.cutoff_at = Some(issuer_cutoff(*compromised_at, declared_at));
        }
        _ => return Err(AdminError::Encode),
    }
    Ok(c)
}

/// The `kid`s of a JWKS document (RFC 7517, CR-24); a malformed one has none.
#[must_use]
pub fn jwks_kids(doc: &str) -> Vec<[u8; 32]> {
    let Ok(Json::Object(top)) = access_kernel::json::parse(doc.as_bytes(), 64 * 1024) else {
        return Vec::new();
    };
    let Some((_, Json::Array(keys))) = top.iter().find(|(k, _)| k == "keys") else {
        return Vec::new();
    };
    keys.iter()
        .filter_map(|k| match k {
            Json::Object(m) => m
                .iter()
                .find(|(n, _)| n == "kid")
                .and_then(|(_, v)| v.as_str()),
            _ => None,
        })
        .filter_map(|kid| b64url_decode(kid).ok())
        .filter_map(|b| b.try_into().ok())
        .collect()
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
