//! What the platform-admin surface provisions (OP-151 m.2 M2): tenants, realms whose governing
//! domain a Genesis opens (TN-111, §12.5.1) and sandbox domains (OP-151 m.3 (m), X21). Each is
//! an `idp.platform.*` Exercise in the platform realm's governing domain, so the platform surface
//! has no write path of its own (TN-110, PI-4, INV-2). The operator holds nothing in the domains
//! it opens (INV-29): the founding root is the caller's.

use std::collections::{BTreeMap, BTreeSet};

use access_identity_oauth::domain::issuer::{IssuerStyle, check_slug};
use access_internal_api::idp::RESOURCE_NAMESPACE;
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::Root;
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::schema::{ActionSchema, EffectClass, Spp, action_digest};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use super::{CHANGE_CONTEXT, CHANGE_PARAM};

/// The namespace of the platform actions; only the platform realm's Genesis publishes it.
pub const NAMESPACE: &str = "idp.platform";

/// Version of the platform catalog; the `idp.*` catalogs are versioned apart (OP-153 m.3 (a)).
pub const CATALOG_VERSION: u64 = 1;

/// The placement new tenants and realms take unless the caller names one (OP-40).
pub const DEFAULT_PLACEMENT: &str = "pool-default";

/// One `idp.platform.*` action. Each opens something that is never removed (OP-73): CT2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlatformAction {
    /// Creates a tenant (TN-1).
    TenantCreate,
    /// Creates a realm by opening its governing domain with a Genesis (TN-111, §5.16).
    RealmCreate,
    /// Creates a sandbox domain from the sandbox template (OP-151 m.3 (m), X21).
    SandboxCreate,
}

impl PlatformAction {
    /// Every action, in catalog order.
    pub const ALL: [Self; 3] = [Self::TenantCreate, Self::RealmCreate, Self::SandboxCreate];

    /// Its name within the namespace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TenantCreate => "tenant_create",
            Self::RealmCreate => "realm_create",
            Self::SandboxCreate => "sandbox_create",
        }
    }

    /// `idp.platform.<name>`.
    #[must_use]
    pub fn label(self) -> String {
        format!("{NAMESPACE}.{}", self.name())
    }

    /// Its Action Schema: irreversible, not reserved.
    #[must_use]
    pub fn schema(self) -> ActionSchema {
        ActionSchema {
            reversibility: None,
            name: String::from(self.name()),
            major: 1,
            effect: EffectClass::Irreversible,
            reserved: false,
            consumption_bearing: false,
            params: BTreeMap::new(),
            resource_types: BTreeSet::new(),
            render: None,
        }
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

/// The catalog of the platform actions, published by the platform realm's founder in its Genesis
/// (OP-141 m.35 (c)); no other realm's domain accepts it.
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
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

/// Why a provisioning request is refused before any decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProvisionInvalid {
    /// A slug outside `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$` (TN-16).
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
    /// The slug is taken, now or by a deleted realm (TN-16, INV-32).
    #[error("slug taken")]
    SlugTaken,
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

/// A realm to open: its tenant, slug, issuer form, placement and founding root (TN-111).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmOrder {
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

impl RealmOrder {
    /// Checks the order's own fields.
    ///
    /// # Errors
    /// [`ProvisionInvalid`].
    pub fn check(&self) -> Result<(), ProvisionInvalid> {
        check_slug(&self.slug).map_err(|_| ProvisionInvalid::Slug)?;
        check_placement(&self.placement)?;
        check_root(&self.root, self.acknowledge_no_recovery)?;
        if let Some(d) = self.ct3_delay_s
            && !(MIN_CT3_DELAY_S..=MAX_CT3_DELAY_S).contains(&d)
        {
            return Err(ProvisionInvalid::TimeLock);
        }
        Ok(())
    }

    fn value(&self) -> Value {
        let mut fields = vec![
            (Value::text("tenant"), Value::Bytes(self.tenant.to_vec())),
            (Value::text("slug"), Value::text(&self.slug)),
            (
                Value::text("style"),
                Value::text(match self.style {
                    IssuerStyle::Subdomain => "subdomain",
                    IssuerStyle::Path => "path",
                }),
            ),
            (Value::text("placement"), Value::text(&self.placement)),
            (Value::text("root"), root_value(&self.root)),
            (
                Value::text("acknowledge_no_recovery"),
                Value::Bool(self.acknowledge_no_recovery),
            ),
        ];
        if let Some(d) = self.ct3_delay_s {
            fields.push((Value::text("ct3_delay_s"), Value::Unsigned(d)));
        }
        if self.causal_binding {
            fields.push((Value::text("causal_binding"), Value::Bool(true)));
        }
        // §13.6, OP-158 m.3 (m)
        if let (_, Some(entry)) = recovery(&self.root, self.recovery.as_ref()) {
            fields.push((Value::text("recovery"), entry.to_value()));
        }
        Value::Map(fields)
    }
}

fn root_value(r: &Root) -> Value {
    match r {
        Root::Sole(p) => Value::Map(vec![(Value::text("sole"), p.to_value())]),
        Root::Joint { parties, k } => Value::Map(vec![(
            Value::text("joint"),
            Value::Map(vec![
                (Value::text("k"), Value::Unsigned(*k)),
                (
                    Value::text("parties"),
                    Value::Array(parties.iter().map(Canonical::to_value).collect()),
                ),
            ]),
        )]),
    }
}

/// One provisioning change: what an `idp.platform.*` intent binds (EI-25).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlatformChange {
    /// A tenant with a server-assigned id.
    Tenant {
        /// The new tenant's id.
        tenant: [u8; 16],
        /// Its placement.
        placement: String,
    },
    /// A production realm.
    Realm(RealmOrder),
    /// A sandbox realm and its domain, from the sandbox template.
    Sandbox(RealmOrder),
}

impl PlatformChange {
    /// Its action.
    #[must_use]
    pub const fn action(&self) -> PlatformAction {
        match self {
            Self::Tenant { .. } => PlatformAction::TenantCreate,
            Self::Realm(_) => PlatformAction::RealmCreate,
            Self::Sandbox(_) => PlatformAction::SandboxCreate,
        }
    }

    /// Checks the change's own fields.
    ///
    /// # Errors
    /// [`ProvisionInvalid`].
    pub fn check(&self) -> Result<(), ProvisionInvalid> {
        match self {
            Self::Tenant { placement, .. } => check_placement(placement),
            Self::Realm(r) | Self::Sandbox(r) => r.check(),
        }
    }

    fn body(&self) -> Value {
        match self {
            Self::Tenant { tenant, placement } => Value::Map(vec![
                (Value::text("tenant"), Value::Bytes(tenant.to_vec())),
                (Value::text("placement"), Value::text(placement)),
            ]),
            Self::Realm(r) => r.value(),
            Self::Sandbox(r) => {
                let budget = Value::Map(vec![
                    (
                        Value::text("exercises_per_day"),
                        Value::Unsigned(SANDBOX_BUDGET.exercises_per_day),
                    ),
                    (
                        Value::text("projections_per_day"),
                        Value::Unsigned(SANDBOX_BUDGET.projections_per_day),
                    ),
                ]);
                Value::Map(vec![
                    (Value::text("realm"), r.value()),
                    (Value::text("budget"), budget),
                ])
            }
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

    /// The resource it creates, under the platform realm `platform`'s `idp` Anchor:
    /// `idp:[platform, "platform", kind, key]`.
    #[must_use]
    pub fn resource(&self, platform: &str) -> ResourceRef {
        let (kind, key) = match self {
            Self::Tenant { tenant, .. } => ("tenant", hex(tenant)),
            Self::Realm(r) => ("realm", r.slug.clone()),
            Self::Sandbox(r) => ("sandbox", r.slug.clone()),
        };
        ResourceRef {
            namespace: String::from(RESOURCE_NAMESPACE),
            path: vec![
                String::from(platform),
                String::from("platform"),
                String::from(kind),
                key,
            ],
            incarnation: 0,
        }
    }

    /// The intent that authorizes it in the platform realm `platform`, valid over `validity`.
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
