//! What a tenant's administrators change from its management environment (OP-159 m.47, TN-138 …
//! TN-141): the `idp.tenant.*` actions, published only in a management environment's Genesis.
//! An environment opens in the tenant whose management environment's governing domain records the
//! order (PI-7), with the tenant's placement; administrators are invited, removed and made owners.

use std::collections::{BTreeMap, BTreeSet};

use access_identity_oauth::domain::issuer::IssuerStyle;
use access_internal_api::idp::RESOURCE_NAMESPACE;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::schema::{ActionSchema, EffectClass, Spp, action_digest};
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

use super::provision::{ProvisionInvalid, check_new_slug};
use super::{CHANGE_CONTEXT, CHANGE_PARAM};

/// The namespace of the tenant actions (TN-140).
pub const NAMESPACE: &str = "idp.tenant";

/// Version of the tenant catalog.
pub const CATALOG_VERSION: u64 = 1;

/// The environment kind a management environment is (TN-138).
pub const MANAGEMENT: &str = "management";

/// The environment kind every other environment is.
pub const STANDARD: &str = "standard";

/// How long a tenant administrator invitation holds when the request names no lifetime (TN-89):
/// seven days.
pub const INVITE_DAYS: u32 = 7;

/// How long a cross-domain first acceptance of a tenant administrator invitation waits before the
/// administrator holds anything (TN-109, OP-159 m.47 (f)): 24 hours.
pub const ADMIN_COOLING_S: i64 = 24 * 3_600;

/// One `idp.tenant.*` action (TN-140).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TenantAction {
    /// Opens an environment of the tenant with the administrator rule in its Genesis (CT2).
    EnvironmentCreate,
    /// Invites a tenant administrator (CT2).
    AdminInvite,
    /// Removes a tenant administrator (CT1).
    AdminRemove,
    /// Makes an administrator an owner, a root of every environment (CT3).
    OwnerAdd,
}

impl TenantAction {
    /// Every action, in catalog order.
    pub const ALL: [Self; 4] = [
        Self::EnvironmentCreate,
        Self::AdminInvite,
        Self::AdminRemove,
        Self::OwnerAdd,
    ];

    /// The actions the administrator rule of the management environment covers: every one but
    /// `owner_add`, which is the owners' own (OP-159 m.47 (e)).
    pub const ADMINISTERED: [Self; 3] = [
        Self::EnvironmentCreate,
        Self::AdminInvite,
        Self::AdminRemove,
    ];

    /// Its name within the namespace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EnvironmentCreate => "environment_create",
            Self::AdminInvite => "admin_invite",
            Self::AdminRemove => "admin_remove",
            Self::OwnerAdd => "owner_add",
        }
    }

    /// `idp.tenant.<name>`.
    #[must_use]
    pub fn label(self) -> String {
        format!("{NAMESPACE}.{}", self.name())
    }

    /// Its Action Schema: an environment and an invitation are never taken back (CT2), a removal
    /// is reversible (CT1), an owner is reserved (CT3).
    #[must_use]
    pub fn schema(self) -> ActionSchema {
        let (effect, reserved) = match self {
            Self::EnvironmentCreate | Self::AdminInvite => (EffectClass::Irreversible, false),
            Self::AdminRemove => (EffectClass::Reversible, false),
            Self::OwnerAdd => (EffectClass::Irreversible, true),
        };
        ActionSchema {
            reversibility: None,
            name: String::from(self.name()),
            major: 1,
            effect,
            reserved,
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

/// The tenant catalog, published by a management environment's founder in its Genesis (TN-140);
/// no other environment's domain accepts it.
#[must_use]
pub fn catalog(publisher: Id) -> Spp {
    Spp {
        publisher,
        namespace: String::from(NAMESPACE),
        catalog_version: CATALOG_VERSION,
        actions: TenantAction::ALL
            .into_iter()
            .map(TenantAction::schema)
            .collect(),
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

/// Why a tenant change is refused before any decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TenantInvalid {
    /// The environment's own fields.
    #[error(transparent)]
    Provision(#[from] ProvisionInvalid),
    /// The change was sent to an environment that is not the tenant's management environment
    /// (TN-138).
    #[error("not the management environment")]
    NotManagement,
    /// The address is not one.
    #[error("invalid email")]
    Email,
    /// An invitation outside one to thirty days (TN-89).
    #[error("invalid lifetime")]
    Lifetime,
    /// No such administrator, or one already removed or already an owner.
    #[error("no such administrator")]
    NoAdmin,
    /// The last owner cannot be removed (m.47 (e)).
    #[error("last owner")]
    LastOwner,
    /// The management environment sent as many invitations this hour or day as it may, or too
    /// few of its recent ones were accepted (TN-89 (11), TN-95).
    #[error("invitation limit")]
    InviteLimit,
}

impl TenantInvalid {
    /// The stable problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Provision(p) => p.code(),
            Self::NotManagement => "management-environment",
            Self::Email => "invalid-email",
            Self::Lifetime => "invalid-lifetime",
            Self::NoAdmin => "not-found",
            Self::LastOwner => "last-tenant-owner",
            Self::InviteLimit => "rate-limited",
        }
    }
}

/// An environment the tenant opens (TN-140): its slug, issuer form, whether it is a sandbox, and
/// the further catalogs and Acceptances its founding root publishes in its Genesis (OP-141 m.35
/// (c), L0-META-5), each bound by the change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTenantEnvironment {
    /// The immutable slug.
    pub slug: String,
    /// How its issuer is formed.
    pub style: IssuerStyle,
    /// A sandbox environment from the sandbox template (OP-151 m.3 (m)).
    pub sandbox: bool,
    /// Further catalogs its Genesis publishes.
    pub schemas: Vec<Spp>,
    /// Further Acceptances its Genesis establishes, each an `acceptance-content`.
    pub acceptances: Vec<Value>,
    /// Classes of the environment issuer's Claims its Genesis accepts as predicate input besides
    /// `authentication`.
    pub issuer_predicate_input: Vec<String>,
}

/// A tenant administrator invitation (TN-89 (1)–(9), (11), OP-159 m.47 (f)).
#[derive(Clone, PartialEq, Eq)]
pub struct AdminInvite {
    /// The invitee's address, NFKC-folded and in lower case (TN-89 (4)).
    pub email: String,
    /// Days the link holds, 1 to 30.
    pub days: u32,
    /// The inviter's name in the mail: attacker input (TN-89 (11)).
    pub inviter_name: Option<String>,
}

impl core::fmt::Debug for AdminInvite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AdminInvite")
            .field("email", &"[redacted]")
            .field("days", &self.days)
            .finish_non_exhaustive()
    }
}

/// One `idp.tenant.*` change: what its intent binds (EI-25).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantChange {
    /// `idp.tenant.environment_create`.
    EnvironmentCreate(NewTenantEnvironment),
    /// `idp.tenant.admin_invite`.
    AdminInvite(AdminInvite),
    /// `idp.tenant.admin_remove` of the administrator `subject`.
    AdminRemove {
        /// The administrator's subject in the management environment.
        subject: [u8; 16],
    },
    /// `idp.tenant.owner_add` of the administrator `subject`.
    OwnerAdd {
        /// The administrator's subject in the management environment.
        subject: [u8; 16],
    },
}

/// Folds an address the way an invitation matches it (TN-89 (4)): trimmed, NFKC, lower case.
#[must_use]
pub fn folded_email(raw: &str) -> Option<String> {
    let e = access_identity_account::app::vault::folded(raw);
    let (local, domain) = e.split_once('@')?;
    let ok = !local.is_empty()
        && local.len() <= 64
        && domain.len() <= 253
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !e.chars().any(char::is_whitespace);
    ok.then_some(e)
}

/// The address's domain.
#[must_use]
pub fn email_domain(email: &str) -> &str {
    email.rsplit_once('@').map_or("", |(_, d)| d)
}

impl TenantChange {
    /// Its action.
    #[must_use]
    pub const fn action(&self) -> TenantAction {
        match self {
            Self::EnvironmentCreate(_) => TenantAction::EnvironmentCreate,
            Self::AdminInvite(_) => TenantAction::AdminInvite,
            Self::AdminRemove { .. } => TenantAction::AdminRemove,
            Self::OwnerAdd { .. } => TenantAction::OwnerAdd,
        }
    }

    /// Checks the change's own fields.
    ///
    /// # Errors
    /// [`TenantInvalid`].
    pub fn check(&self) -> Result<(), TenantInvalid> {
        match self {
            Self::EnvironmentCreate(e) => check_new_slug(&e.slug).map_err(Into::into),
            Self::AdminInvite(i) => {
                if folded_email(&i.email).as_deref() != Some(i.email.as_str()) {
                    return Err(TenantInvalid::Email);
                }
                if !(1..=30).contains(&i.days) {
                    return Err(TenantInvalid::Lifetime);
                }
                Ok(())
            }
            Self::AdminRemove { .. } | Self::OwnerAdd { .. } => Ok(()),
        }
    }

    fn body(&self) -> Value {
        match self {
            Self::EnvironmentCreate(e) => Value::Map(vec![
                (Value::text("slug"), Value::text(&e.slug)),
                (
                    Value::text("style"),
                    Value::text(match e.style {
                        IssuerStyle::Subdomain => "subdomain",
                        IssuerStyle::Path => "path",
                    }),
                ),
                (Value::text("sandbox"), Value::Bool(e.sandbox)),
                (
                    Value::text("schemas"),
                    Value::Array(
                        e.schemas
                            .iter()
                            .map(access_kernel::codec::Canonical::to_value)
                            .collect(),
                    ),
                ),
                (
                    Value::text("acceptances"),
                    Value::Array(e.acceptances.clone()),
                ),
                (
                    Value::text("issuer_predicate_input"),
                    Value::Array(
                        e.issuer_predicate_input
                            .iter()
                            .map(|c| Value::text(c))
                            .collect(),
                    ),
                ),
            ]),
            Self::AdminInvite(i) => Value::Map(vec![
                (Value::text("email"), Value::text(&i.email)),
                (Value::text("days"), Value::Unsigned(u64::from(i.days))),
            ]),
            Self::AdminRemove { subject } | Self::OwnerAdd { subject } => Value::Map(vec![(
                Value::text("subject"),
                Value::Bytes(subject.to_vec()),
            )]),
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

    /// The resource it acts on under the management environment `management`'s `idp` Anchor:
    /// `idp:[management, "tenant", kind, key]`.
    #[must_use]
    pub fn resource(&self, management: &str) -> ResourceRef {
        let (kind, key) = match self {
            Self::EnvironmentCreate(e) => ("environment", e.slug.clone()),
            Self::AdminInvite(i) => ("admin", i.email.clone()),
            Self::AdminRemove { subject } | Self::OwnerAdd { subject } => ("admin", hex(subject)),
        };
        ResourceRef {
            namespace: String::from(RESOURCE_NAMESPACE),
            path: vec![
                String::from(management),
                String::from("tenant"),
                String::from(kind),
                key,
            ],
            incarnation: 0,
        }
    }

    /// The intent that authorizes it in the management environment `management`, valid over
    /// `validity`.
    ///
    /// # Errors
    /// [`dcbor::EncodeError`].
    pub fn intent(
        &self,
        management: &str,
        validity: Window,
    ) -> Result<IntentEnvelope, dcbor::EncodeError> {
        Ok(IntentEnvelope {
            provenance: BTreeMap::new(),
            action: self.action().action_ref(),
            resources: vec![self.resource(management)],
            params: BTreeMap::new(),
            opaque: BTreeMap::from([(String::from(CHANGE_PARAM), self.digest()?)]),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity,
        })
    }
}

/// The root of a new environment of the tenant (OP-159 m.47 (e)): its owners' Parties, one alone
/// or any one of several; `None` without an owner.
#[must_use]
pub fn owners_root(owners: &BTreeSet<Id>) -> Option<access_kernel::meta::Root> {
    match owners.len() {
        0 => None,
        1 => owners.first().map(|p| access_kernel::meta::Root::Sole(*p)),
        _ => Some(access_kernel::meta::Root::Joint {
            parties: owners.clone(),
            k: 1,
        }),
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
