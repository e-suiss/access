//! What the platform-admin surface provisions (OP-151 m.2 M2, OP-159 m.47 (c), (h)): tenants with an
//! invited founder, their suspension and placement. Each is an `idp.platform.*` Exercise in the
//! platform environment's governing domain, so the platform surface has no write path of its own
//! (TN-110, PI-4, INV-2). The platform opens no environment: a tenant's founder opens its
//! primary environment and its administrators the rest (TN-141, TN-140); the operator holds
//! nothing in them (INV-29, TNI-15).

use std::collections::{BTreeMap, BTreeSet};

use access_identity_oauth::domain::issuer::{IssuerStyle, check_slug};
use access_internal_api::idp::RESOURCE_NAMESPACE;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::Root;
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::schema::{ActionSchema, EffectClass, Spp, action_digest};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use super::{CHANGE_CONTEXT, CHANGE_PARAM};

/// The namespace of the platform actions; only the platform environment's Genesis publishes it.
pub const NAMESPACE: &str = "idp.platform";

/// Version of the platform catalog; the `idp.*` catalogs are versioned apart (OP-153 m.3 (a)).
/// Version 2 retires `environment_create` and `sandbox_create` (OP-159 m.47 (h)).
pub const CATALOG_VERSION: u64 = 2;

/// How long a founder invitation holds (TN-89, TN-141, PD): seven days; at most thirty.
pub const FOUNDING_TTL_S: i64 = 7 * 86_400;

/// Slugs no environment can take: the console's own paths under `/console/` (OP-159 m.42 (e)).
pub const RESERVED_SLUGS: [&str; 2] = ["api", "assets"];

/// Checks the slug of an environment being created: an environment slug (TN-16) that is not reserved
/// (OP-159 m.42 (e)).
///
/// # Errors
/// [`ProvisionInvalid::Slug`].
pub fn check_new_slug(slug: &str) -> Result<(), ProvisionInvalid> {
    check_slug(slug).map_err(|_| ProvisionInvalid::Slug)?;
    if RESERVED_SLUGS.contains(&slug) {
        return Err(ProvisionInvalid::Slug);
    }
    Ok(())
}

/// The placement new tenants and environments take unless the caller names one (OP-40).
pub const DEFAULT_PLACEMENT: &str = "pool-default";

/// One `idp.platform.*` action (OP-159 m.47 (h)).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlatformAction {
    /// Creates a tenant with an invited founder (TN-1, TN-141); never removed (OP-73): CT2.
    TenantCreate,
    /// Suspends a tenant: its environments stop serving (CT2).
    TenantSuspend,
    /// Lifts a tenant's suspension (CT1).
    TenantReactivate,
    /// Moves where a tenant's new environments are placed (OP-40, CT2).
    TenantPlacement,
}

/// The actions catalog version 1 published and version 2 retires (OP-159 m.47 (h)).
pub const RETIRED: [&str; 2] = ["environment_create", "sandbox_create"];

impl PlatformAction {
    /// Every action, in catalog order.
    pub const ALL: [Self; 4] = [
        Self::TenantCreate,
        Self::TenantSuspend,
        Self::TenantReactivate,
        Self::TenantPlacement,
    ];

    /// Its name within the namespace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TenantCreate => "tenant_create",
            Self::TenantSuspend => "tenant_suspend",
            Self::TenantReactivate => "tenant_reactivate",
            Self::TenantPlacement => "tenant_placement",
        }
    }

    /// `idp.platform.<name>`.
    #[must_use]
    pub fn label(self) -> String {
        format!("{NAMESPACE}.{}", self.name())
    }

    /// Its Action Schema: not reserved; a reactivation is reversible, the rest are not.
    #[must_use]
    pub fn schema(self) -> ActionSchema {
        schema_named(
            self.name(),
            if self == Self::TenantReactivate {
                EffectClass::Reversible
            } else {
                EffectClass::Irreversible
            },
        )
    }

    /// The reference an intent names it by.
    #[must_use]
    pub fn action_ref(self) -> ActionRef {
        ActionRef {
            namespace: String::from(NAMESPACE),
            name: String::from(self.name()),
            major: 1,
            schema: action_digest(&self.schema()),
        }
    }
}

fn schema_named(name: &str, effect: EffectClass) -> ActionSchema {
    ActionSchema {
        reversibility: None,
        name: String::from(name),
        major: 1,
        effect,
        reserved: false,
        consumption_bearing: false,
        params: BTreeMap::new(),
        resource_types: BTreeSet::new(),
        render: None,
    }
}

/// The references of the retired version 1 actions.
#[must_use]
pub fn retired() -> BTreeSet<ActionRef> {
    RETIRED
        .iter()
        .map(|n| ActionRef {
            namespace: String::from(NAMESPACE),
            name: String::from(*n),
            major: 1,
            schema: action_digest(&schema_named(n, EffectClass::Irreversible)),
        })
        .collect()
}

/// The catalog of the platform actions, published by the platform environment's founder in its Genesis
/// (OP-141 m.35 (c)); no other environment's domain accepts it.
#[must_use]
pub fn catalog(publisher: Id) -> Spp {
    Spp {
        publisher,
        namespace: String::from(NAMESPACE),
        catalog_version: CATALOG_VERSION,
        actions: PlatformAction::ALL
            .into_iter()
            .map(PlatformAction::schema)
            .collect(),
        retirements: retired(),
        core_spec_min: None,
    }
}

/// Why a provisioning request is refused before any decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProvisionInvalid {
    /// A slug outside `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$` (TN-16), or a reserved one
    /// (OP-159 m.42 (e)).
    #[error("invalid slug")]
    Slug,
    /// A placement outside `^[a-z0-9][a-z0-9-]{0,62}$` (OP-40).
    #[error("invalid placement")]
    Placement,
    /// A root that names no Party, a joint root with `k < 2` or `k > n`, or one Party twice
    /// (§13.7.7: `Joint(k >= 2)`).
    #[error("invalid root")]
    Root,
    /// A sole root without `acknowledge_no_recovery: true` (TN-111, TN-60, §13.7.7).
    #[error("recovery not acknowledged")]
    RecoveryNotAcknowledged,
    /// A CT3 time-lock outside one hour to thirty days.
    #[error("invalid time-lock")]
    TimeLock,
    /// No such tenant, or one that is not active.
    #[error("no such tenant")]
    NoTenant,
    /// The slug is taken, now or by a deleted environment (TN-16, INV-32).
    #[error("slug taken")]
    SlugTaken,
    /// A display name that is empty or longer than 120 characters (TN-131).
    #[error("invalid name")]
    Name,
    /// A founder address that is not one (TN-89 (4)).
    #[error("invalid email")]
    Email,
    /// The tenant is not in the state the change needs.
    #[error("tenant state")]
    TenantState,
}

impl ProvisionInvalid {
    /// The stable problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Slug => "invalid-slug",
            Self::Placement => "invalid-placement",
            Self::Root => "invalid-root",
            Self::RecoveryNotAcknowledged => "recovery-not-acknowledged",
            Self::TimeLock => "invalid-time-lock",
            Self::NoTenant => "not-found",
            Self::SlugTaken => "slug-taken",
            Self::Name => "invalid-tenant-name",
            Self::Email => "invalid-email",
            Self::TenantState => "tenant-state",
        }
    }
}

/// Shortest CT3 time-lock a Genesis may set, seconds.
pub const MIN_CT3_DELAY_S: u64 = 3_600;

/// Longest CT3 time-lock a Genesis may set, seconds.
pub const MAX_CT3_DELAY_S: u64 = 30 * 86_400;

/// Why the Suiss-hosted template cannot build the rootTerms `domain.recover` entry (§13.6,
/// §13.7.7, N-14): S7 then says "Recovery not available".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotAvailable {
    /// No recovery keys were named.
    NoKeys,
    /// Fewer than three keys.
    TooFewKeys,
    /// A key is held by a Party outside the founding root (SEC20).
    HolderNotRoot,
    /// A key is named twice.
    DuplicateKey,
}

impl NotAvailable {
    /// The stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NoKeys => "no-recovery-keys",
            Self::TooFewKeys => "too-few-recovery-keys",
            Self::HolderNotRoot => "recovery-holder-not-root",
            Self::DuplicateKey => "duplicate-recovery-key",
        }
    }
}

/// Whether recovery can be declared for the new domain (§13.6, §13.7.7, N-14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// The Genesis carries a `threshold`-of-`keys` recovery entry.
    Available {
        /// Contributions a recovery needs.
        threshold: u64,
        /// Keys in the entry.
        keys: u64,
    },
    /// The rootTerms `domain.recover` entry cannot be built: "Recovery not available" (NG).
    NotAvailable(NotAvailable),
}

impl Recovery {
    /// Its name in the contract.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Available { .. } => "available",
            Self::NotAvailable(_) => "not_available",
        }
    }

    /// The stable reason a recovery is not available.
    #[must_use]
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Available { .. } => None,
            Self::NotAvailable(r) => Some(r.code()),
        }
    }
}

/// One recovery key a founder names: the root Party that holds it and its RFC 7638 thumbprint.
/// The key itself stays on the holder's device or offline; Access only ever sees the
/// thumbprint (SEC20, U16).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecoveryKey {
    /// The holder.
    pub party: Id,
    /// The key's thumbprint.
    pub kid: [u8; 32],
}

/// The recovery keys of a new domain and how they are held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryKeys {
    /// Device keys (passkey or security key) or offline ceremony keys.
    pub held_on: access_kernel::recovery::KeyHolding,
    /// The keys.
    pub keys: Vec<RecoveryKey>,
}

/// Keys from which the template builds the organization entry, 3-of-5 (§13.6 POLICY DEFAULT).
pub const ORGANIZATION_KEYS: usize = 5;

/// Keys from which the template builds the small-domain entry, 2-of-3 (§13.6 POLICY DEFAULT).
pub const SMALL_KEYS: usize = 3;

/// The recovery a Genesis with `root` and the founders' `keys` declares, and the entry it
/// carries (§13.6, SEC20, OP-158 m.3 (m), m.19 (c)): five or more keys build 3-of-n, three or
/// four build 2-of-n; at least two are hardware-bound and every holder is a root Party. A sole
/// root's own keys count: a recovery's independence is the keys' custody (L0-EVAL-26a).
#[must_use]
pub fn recovery(
    root: &Root,
    keys: Option<&RecoveryKeys>,
) -> (Recovery, Option<access_kernel::recovery::RecoveryEntry>) {
    let not = |r| (Recovery::NotAvailable(r), None);
    let Some(keys) = keys.filter(|k| !k.keys.is_empty()) else {
        return not(NotAvailable::NoKeys);
    };
    let parties: BTreeSet<Id> = match root {
        Root::Sole(p) => BTreeSet::from([*p]),
        Root::Joint { parties, .. } => parties.clone(),
    };
    let kids: std::collections::BTreeSet<[u8; 32]> = keys.keys.iter().map(|k| k.kid).collect();
    if kids.len() != keys.keys.len() {
        return not(NotAvailable::DuplicateKey);
    }
    let holders: std::collections::BTreeSet<Id> = keys.keys.iter().map(|k| k.party).collect();
    if !holders.is_subset(&parties) {
        return not(NotAvailable::HolderNotRoot);
    }
    let threshold: u64 = match kids.len() {
        n if n >= ORGANIZATION_KEYS => 3,
        n if n >= SMALL_KEYS => 2,
        _ => return not(NotAvailable::TooFewKeys),
    };
    let n = u64::try_from(kids.len()).unwrap_or(u64::MAX);
    let entry = access_kernel::recovery::RecoveryEntry::new(
        threshold,
        kids,
        access_kernel::recovery::HARDWARE_BOUND_MIN,
        keys.held_on,
        holders,
    );
    (Recovery::Available { threshold, keys: n }, Some(entry))
}

/// Checks a founding root (TN-111, §13.7.7): `Joint(k >= 2)` is the recommendation; a sole root
/// is accepted only when the caller acknowledges that it cannot be recovered.
///
/// # Errors
/// [`ProvisionInvalid::Root`] or [`ProvisionInvalid::RecoveryNotAcknowledged`].
pub fn check_root(root: &Root, acknowledge_no_recovery: bool) -> Result<(), ProvisionInvalid> {
    match root {
        Root::Sole(_) if !acknowledge_no_recovery => Err(ProvisionInvalid::RecoveryNotAcknowledged),
        Root::Sole(_) => Ok(()),
        Root::Joint { parties, k } => {
            let n = u64::try_from(parties.len()).map_err(|_| ProvisionInvalid::Root)?;
            if *k < 2 || *k > n {
                return Err(ProvisionInvalid::Root);
            }
            Ok(())
        }
    }
}

/// Checks a placement name (OP-40).
///
/// # Errors
/// [`ProvisionInvalid::Placement`].
pub fn check_placement(p: &str) -> Result<(), ProvisionInvalid> {
    let b = p.as_bytes();
    let ok = (1..=63).contains(&b.len())
        && b.first()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
    if ok {
        Ok(())
    } else {
        Err(ProvisionInvalid::Placement)
    }
}

/// The fixed budget of the sandbox template (OP-151 m.3 (c), (m); H8, D7): structural fair use,
/// not a plan. PD values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxBudget {
    /// Exercises the domain may commit per UTC day.
    pub exercises_per_day: u64,
    /// Projections the domain may issue per UTC day.
    pub projections_per_day: u64,
}

/// OP-151 m.3 (m): the sandbox template's `BudgetTerms` (PD).
pub const SANDBOX_BUDGET: SandboxBudget = SandboxBudget {
    exercises_per_day: 10_000,
    projections_per_day: 50_000,
};

/// Which side of the sandbox line a domain is on (OP-151 m.3 (m), X21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regime {
    /// A production domain.
    Production,
    /// A sandbox domain.
    Sandbox,
}

/// Whether authority may flow between a domain of `home` and one of `other` (OP-151 m.3 (m)):
/// never across the sandbox line, either way.
#[must_use]
pub fn flows(home: Regime, other: Regime) -> bool {
    home == other
}

/// An environment to open: its tenant, slug, issuer form, placement and founding root (TN-111).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentOrder {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The immutable slug.
    pub slug: String,
    /// How its issuer is formed.
    pub style: IssuerStyle,
    /// Its placement.
    pub placement: String,
    /// The founding root of its governing domain.
    pub root: Root,
    /// The CT3 time-lock in seconds; `None` keeps the default.
    pub ct3_delay_s: Option<u64>,
    /// Whether its governing domain declares causal-bound allowances (OP-152 m.7 (d) E11).
    pub causal_binding: bool,
    /// Whether the caller acknowledged that the domain cannot be recovered.
    pub acknowledge_no_recovery: bool,
    /// The founders' recovery keys, from which the Suiss-hosted template builds the rootTerms
    /// recovery entry (§13.6, OP-158 m.3 (m)).
    pub recovery: Option<RecoveryKeys>,
}

impl EnvironmentOrder {
    /// Checks the order's own fields.
    ///
    /// # Errors
    /// [`ProvisionInvalid`].
    pub fn check(&self) -> Result<(), ProvisionInvalid> {
        check_new_slug(&self.slug)?;
        check_placement(&self.placement)?;
        check_root(&self.root, self.acknowledge_no_recovery)?;
        if let Some(d) = self.ct3_delay_s
            && !(MIN_CT3_DELAY_S..=MAX_CT3_DELAY_S).contains(&d)
        {
            return Err(ProvisionInvalid::TimeLock);
        }
        Ok(())
    }
}

/// What a tenant's founding commits to (TN-89 (1), (8), TN-141): the primary environment's
/// blind index of the founder's identifier and the SHA-256 of the link token and of the magic
/// code. The secrets themselves exist only in the mail.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FounderCommitment {
    /// The blind index of the founder's folded identifier.
    pub index: [u8; 32],
    /// SHA-256 of the link token.
    pub token: [u8; 32],
    /// SHA-256 of the magic code.
    pub code: [u8; 32],
}

impl core::fmt::Debug for FounderCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FounderCommitment").finish_non_exhaustive()
    }
}

impl FounderCommitment {
    fn value(&self) -> Value {
        Value::Map(vec![
            (Value::text("index"), Value::Bytes(self.index.to_vec())),
            (Value::text("token"), Value::Bytes(self.token.to_vec())),
            (Value::text("code"), Value::Bytes(self.code.to_vec())),
        ])
    }
}

/// A tenant to create (OP-159 m.47 (c)): a server-assigned id, its display name, the slug its
/// primary environment will take, its placement and the founder commitment. The management
/// environment's id is the tenant's own (TN-141): the founder's blind index is that
/// environment's before it exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantOrder {
    /// The new tenant's id.
    pub tenant: [u8; 16],
    /// Its display name: its own text, never authority (TN-1, TN-131).
    pub display_name: String,
    /// The primary environment's slug (TN-138).
    pub primary_slug: String,
    /// Its placement.
    pub placement: String,
    /// What its founding commits to.
    pub founder: FounderCommitment,
}

/// Checks a tenant's display name (TN-131): 1 to 120 characters, no control characters.
///
/// # Errors
/// [`ProvisionInvalid::Name`].
pub fn check_name(name: &str) -> Result<(), ProvisionInvalid> {
    let n = name.chars().count();
    if (1..=120).contains(&n) && !name.chars().any(char::is_control) && name.trim() == name {
        Ok(())
    } else {
        Err(ProvisionInvalid::Name)
    }
}

/// One provisioning change: what an `idp.platform.*` intent binds (EI-25).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformChange {
    /// A tenant with an invited founder (TN-141).
    Tenant(TenantOrder),
    /// New secrets for the founder of a tenant whose founding did not complete (TN-141): the
    /// tenant creation's action over the same tenant.
    Reinvite {
        /// The tenant.
        tenant: [u8; 16],
        /// The new commitment; the identifier index stays the founding's.
        founder: FounderCommitment,
    },
    /// Suspends a tenant.
    Suspend {
        /// The tenant.
        tenant: [u8; 16],
    },
    /// Lifts a tenant's suspension.
    Reactivate {
        /// The tenant.
        tenant: [u8; 16],
    },
    /// Moves a tenant's placement for its new environments (OP-40).
    Placement {
        /// The tenant.
        tenant: [u8; 16],
        /// The placement.
        placement: String,
    },
}

impl PlatformChange {
    /// Its action.
    #[must_use]
    pub const fn action(&self) -> PlatformAction {
        match self {
            Self::Tenant(_) | Self::Reinvite { .. } => PlatformAction::TenantCreate,
            Self::Suspend { .. } => PlatformAction::TenantSuspend,
            Self::Reactivate { .. } => PlatformAction::TenantReactivate,
            Self::Placement { .. } => PlatformAction::TenantPlacement,
        }
    }

    /// The tenant it is about.
    #[must_use]
    pub const fn tenant(&self) -> [u8; 16] {
        match self {
            Self::Tenant(t) => t.tenant,
            Self::Reinvite { tenant, .. }
            | Self::Suspend { tenant }
            | Self::Reactivate { tenant }
            | Self::Placement { tenant, .. } => *tenant,
        }
    }

    /// Checks the change's own fields.
    ///
    /// # Errors
    /// [`ProvisionInvalid`].
    pub fn check(&self) -> Result<(), ProvisionInvalid> {
        match self {
            Self::Tenant(t) => {
                check_name(&t.display_name)?;
                check_new_slug(&t.primary_slug)?;
                check_placement(&t.placement)
            }
            Self::Placement { placement, .. } => check_placement(placement),
            Self::Reinvite { .. } | Self::Suspend { .. } | Self::Reactivate { .. } => Ok(()),
        }
    }

    fn body(&self) -> Value {
        match self {
            Self::Tenant(t) => Value::Map(vec![
                (Value::text("tenant"), Value::Bytes(t.tenant.to_vec())),
                (Value::text("display_name"), Value::text(&t.display_name)),
                (Value::text("primary_slug"), Value::text(&t.primary_slug)),
                (Value::text("placement"), Value::text(&t.placement)),
                (Value::text("founder"), t.founder.value()),
            ]),
            Self::Reinvite { tenant, founder } => Value::Map(vec![
                (Value::text("tenant"), Value::Bytes(tenant.to_vec())),
                (Value::text("reinvite"), founder.value()),
            ]),
            Self::Suspend { tenant } | Self::Reactivate { tenant } => {
                Value::Map(vec![(Value::text("tenant"), Value::Bytes(tenant.to_vec()))])
            }
            Self::Placement { tenant, placement } => Value::Map(vec![
                (Value::text("tenant"), Value::Bytes(tenant.to_vec())),
                (Value::text("placement"), Value::text(placement)),
            ]),
        }
    }

    /// The digest the intent carries as its `change` (EI-25).
    ///
    /// # Errors
    /// [`dcbor::EncodeError`].
    pub fn digest(&self) -> Result<Digest, dcbor::EncodeError> {
        let v = Value::Map(vec![
            (Value::text("action"), Value::text(&self.action().label())),
            (Value::text("body"), self.body()),
        ]);
        let bytes = dcbor::encode(&v, Limits::CEILING)?;
        Ok(Digest(context_digest(CHANGE_CONTEXT, &bytes).0))
    }

    /// The resource it acts on, under the platform environment `platform`'s `idp` Anchor:
    /// `idp:[platform, "platform", "tenant", key]`.
    #[must_use]
    pub fn resource(&self, platform: &str) -> ResourceRef {
        ResourceRef {
            namespace: String::from(RESOURCE_NAMESPACE),
            path: vec![
                String::from(platform),
                String::from("platform"),
                String::from("tenant"),
                hex(&self.tenant()),
            ],
            incarnation: 0,
        }
    }

    /// The intent that authorizes it in the platform environment `platform`, valid over `validity`.
    ///
    /// # Errors
    /// [`dcbor::EncodeError`].
    pub fn intent(
        &self,
        platform: &str,
        validity: Window,
    ) -> Result<IntentEnvelope, dcbor::EncodeError> {
        Ok(IntentEnvelope {
            provenance: BTreeMap::new(),
            action: self.action().action_ref(),
            resources: vec![self.resource(platform)],
            params: BTreeMap::new(),
            opaque: BTreeMap::from([(String::from(CHANGE_PARAM), self.digest()?)]),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity,
        })
    }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    b.iter().fold(
        String::with_capacity(b.len().saturating_mul(2)),
        |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        },
    )
}

#[cfg(test)]
mod tests;
