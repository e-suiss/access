//! The event catalog (OP-149 m.4, m.7, §9.16): every type's name and URN, the identity plane's
//! own events as they sit in the outbox, and the JSON payload of each event as the schemas in
//! `sdks/openapi/events` define it.

use core::fmt::Write as _;

use access_identity_account::domain::events::{AccountEvent, EventOrder};
use access_internal_api::events::{Detail, Event, Kind, Source, Subject};
use access_kernel::json::b64url_encode;
use serde_json::{Map, Value, json};

use crate::domain::Invalid;

/// Prefix of every event type URN.
pub const URN_PREFIX: &str = "urn:suiss:access:event:";

pub use access_identity_oauth::ports::oauth::TENANT_PREFIX;

/// Prefix of the identity outbox kinds this crate reads.
pub const OUTBOX_PREFIX: &str = "event.";

/// Every event name, authority events first; the identity events of OP-151 m.3 (i) last.
pub const NAMES: [&str; 29] = [
    "authority-revoked",
    "authority-narrowed",
    "authority-expired",
    "mandate-ended",
    "instance-terminated",
    "revalidation-required",
    "projection-invalidated",
    "acceptance-changed",
    "party.disabled",
    "party.compromised",
    "tenant.created",
    "organization.created",
    "organization.updated",
    "api_client.created",
    "api_client.updated",
    "api_client.disabled",
    "account.created",
    "account.updated",
    "account.suspended",
    "account.reactivated",
    "account.deleted",
    "membership.added",
    "membership.removed",
    "session.revoked",
    "credential.changed",
    "preference.changed",
    "document.accepted",
    "agent.suspended",
    "login.failed_surge",
];

/// The type URN of `name`.
#[must_use]
pub fn urn(name: &str) -> String {
    format!("{URN_PREFIX}{name}")
}

/// Catalog events nothing produces yet: organizations and their memberships arrive with the
/// organization model, preferences, documents and agent suspension with their own domains. A
/// subscription cannot name them until a producer exists (TN-136, §12.4.2).
pub const UNPRODUCED: [&str; 5] = [
    "membership.added",
    "membership.removed",
    "preference.changed",
    "document.accepted",
    "agent.suspended",
];

/// Whether a webhook or stream may subscribe to `name`: a catalog event with a producer.
#[must_use]
pub fn subscribable(name: &str) -> bool {
    NAMES.contains(&name) && !UNPRODUCED.contains(&name)
}

/// The event names a webhook or stream may subscribe to.
pub fn subscribable_names() -> impl Iterator<Item = &'static str> {
    NAMES.into_iter().filter(|n| subscribable(n))
}

/// The event name of a type URN in the catalog.
#[must_use]
pub fn name_of(urn: &str) -> Option<&'static str> {
    let name = urn.strip_prefix(URN_PREFIX)?;
    NAMES.into_iter().find(|n| *n == name)
}

/// An identity plane event (OP-149 m.4, m.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityKind {
    /// `tenant.created`.
    TenantCreated,
    /// `organization.created`.
    OrganizationCreated,
    /// `organization.updated`.
    OrganizationUpdated,
    /// `api_client.created`: `idp.client.register`.
    ApiClientCreated,
    /// `api_client.updated`: `idp.client.update`.
    ApiClientUpdated,
    /// `api_client.disabled`: `idp.client.retire`.
    ApiClientDisabled,
    /// `party.disabled` from a suspension.
    PartyDisabled,
    /// `projection-invalidated`: the realm's authorization server ended a refresh family of
    /// authority tokens on reuse (§9.9.3 rule 6).
    ProjectionInvalidated,
    /// An account, session or credential event of the account use cases (OP-151 m.3 (i)).
    Account(AccountEvent),
    /// `membership.added`; its producer arrives with organization membership.
    MembershipAdded,
    /// `membership.removed`; its producer arrives with organization membership.
    MembershipRemoved,
    /// `preference.changed` (IDP-37); its producer arrives with the preference center.
    PreferenceChanged,
    /// `document.accepted`; its producer arrives with document acceptance.
    DocumentAccepted,
    /// `agent.suspended`; its producer arrives with agent connections.
    AgentSuspended,
    /// `login.failed_surge`; its producer arrives with the risk signals.
    LoginFailedSurge,
}

impl IdentityKind {
    const ALL: [Self; 14] = [
        Self::TenantCreated,
        Self::OrganizationCreated,
        Self::OrganizationUpdated,
        Self::ApiClientCreated,
        Self::ApiClientUpdated,
        Self::ApiClientDisabled,
        Self::PartyDisabled,
        Self::ProjectionInvalidated,
        Self::MembershipAdded,
        Self::MembershipRemoved,
        Self::PreferenceChanged,
        Self::DocumentAccepted,
        Self::AgentSuspended,
        Self::LoginFailedSurge,
    ];

    /// The event name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TenantCreated => "tenant.created",
            Self::OrganizationCreated => "organization.created",
            Self::OrganizationUpdated => "organization.updated",
            Self::ApiClientCreated => "api_client.created",
            Self::ApiClientUpdated => "api_client.updated",
            Self::ApiClientDisabled => "api_client.disabled",
            Self::PartyDisabled => "party.disabled",
            Self::ProjectionInvalidated => "projection-invalidated",
            Self::Account(a) => a.name(),
            Self::MembershipAdded => "membership.added",
            Self::MembershipRemoved => "membership.removed",
            Self::PreferenceChanged => "preference.changed",
            Self::DocumentAccepted => "document.accepted",
            Self::AgentSuspended => "agent.suspended",
            Self::LoginFailedSurge => "login.failed_surge",
        }
    }

    /// The identity outbox kind.
    #[must_use]
    pub const fn outbox_kind(self) -> &'static str {
        match self {
            Self::TenantCreated => "event.tenant.created",
            Self::OrganizationCreated => "event.organization.created",
            Self::OrganizationUpdated => "event.organization.updated",
            Self::ApiClientCreated => "event.api_client.created",
            Self::ApiClientUpdated => "event.api_client.updated",
            Self::ApiClientDisabled => "event.api_client.disabled",
            Self::PartyDisabled => "event.party.disabled",
            Self::ProjectionInvalidated => "event.projection_invalidated",
            Self::Account(a) => a.outbox_kind(),
            Self::MembershipAdded => "event.membership.added",
            Self::MembershipRemoved => "event.membership.removed",
            Self::PreferenceChanged => "event.preference.changed",
            Self::DocumentAccepted => "event.document.accepted",
            Self::AgentSuspended => "event.agent.suspended",
            Self::LoginFailedSurge => "event.login.failed_surge",
        }
    }

    /// The kind of an identity outbox kind.
    #[must_use]
    pub fn from_outbox(kind: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.outbox_kind() == kind)
            .or_else(|| AccountEvent::from_outbox(kind).map(Self::Account))
    }

    /// Whether the identity plane itself produces it, so a webhook may ask for it (OP-151
    /// m.3 (i)); authority events reach tenants through streams (OP-149 m.7).
    #[must_use]
    pub fn of_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .chain(AccountEvent::ALL.into_iter().map(Self::Account))
            .find(|k| k.name() == name)
    }
}

/// An identity event as it sits in the outbox: its id, time and payload. The payload holds ids
/// only, no personal data (OP-73).
#[derive(Clone, Debug, PartialEq)]
pub struct IdentityEvent {
    /// What happened.
    pub kind: IdentityKind,
    /// 32 random bytes, the dedup key.
    pub id: [u8; 32],
    /// The payload, as its schema defines it.
    pub payload: Value,
}

/// A UUID in its text form.
#[must_use]
pub fn uuid(b: &[u8; 16]) -> String {
    let mut out = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub use access_internal_api::instances::PlatformProduct;

/// An API client change as `idp.client.*` committed it.
#[derive(Clone, Copy, Debug)]
pub struct ClientChange<'a> {
    /// Tenant, its external `tnt_` id.
    pub tenant: &'a str,
    /// Realm.
    pub realm: &'a [u8; 16],
    /// The `client_id`.
    pub client_id: &'a str,
    /// The `ExerciseID` that allowed it.
    pub exercise: &'a [u8; 32],
    /// The matched product, when the client is a platform client.
    pub platform_product: Option<&'a PlatformProduct>,
    /// When, Unix ms.
    pub at: u64,
}

impl IdentityEvent {
    /// `api_client.created`, `api_client.updated` or `api_client.disabled`.
    #[must_use]
    pub fn api_client(kind: IdentityKind, id: [u8; 32], c: &ClientChange<'_>) -> Self {
        let mut p = json!({
            "tenant": c.tenant,
            "realm": uuid(c.realm),
            "client_id": c.client_id,
            "exercise": b64url_encode(c.exercise),
            "at": c.at,
        });
        if let (Some(product), Some(m)) = (c.platform_product, p.as_object_mut()) {
            m.insert("platform_product".into(), product.name().into());
        }
        Self {
            kind,
            id,
            payload: p,
        }
    }

    /// `tenant.created`; `tenant` is the external `tnt_` id.
    #[must_use]
    pub fn tenant_created(id: [u8; 32], tenant: &str, placement: &str, at: u64) -> Self {
        Self {
            kind: IdentityKind::TenantCreated,
            id,
            payload: json!({"tenant": tenant, "placement": placement, "at": at}),
        }
    }

    /// `organization.created` or `organization.updated`; `tenant` is the external `tnt_` id.
    #[must_use]
    pub fn organization(
        kind: IdentityKind,
        id: [u8; 32],
        tenant: &str,
        organization: &[u8; 16],
        at: u64,
    ) -> Self {
        Self {
            kind,
            id,
            payload: json!({
                "tenant": tenant,
                "organization": uuid(organization),
                "at": at,
            }),
        }
    }

    /// An account, session or credential event as the account use cases queued it.
    #[must_use]
    pub fn account(order: &EventOrder) -> Self {
        Self {
            kind: IdentityKind::Account(order.kind),
            id: order.id,
            payload: order.payload.clone(),
        }
    }

    /// `membership.added` or `membership.removed` of `account` (its `usr_` id) in
    /// `organization`.
    #[must_use]
    pub fn membership(
        kind: IdentityKind,
        id: [u8; 32],
        realm: &[u8; 16],
        account: &str,
        organization: &[u8; 16],
        at: u64,
    ) -> Self {
        Self {
            kind,
            id,
            payload: json!({
                "realm": uuid(realm),
                "account": account,
                "organization": uuid(organization),
                "at": at,
            }),
        }
    }

    /// `preference.changed` of `account`: which preference topics changed, never their values
    /// (IDP-37).
    #[must_use]
    pub fn preference_changed(
        id: [u8; 32],
        realm: &[u8; 16],
        account: &str,
        topics: &[&str],
        at: u64,
    ) -> Self {
        Self {
            kind: IdentityKind::PreferenceChanged,
            id,
            payload: json!({"realm": uuid(realm), "account": account, "topics": topics, "at": at}),
        }
    }

    /// `document.accepted`: `account` accepted `document` at `version`.
    #[must_use]
    pub fn document_accepted(
        id: [u8; 32],
        realm: &[u8; 16],
        account: &str,
        document: &str,
        version: &str,
        at: u64,
    ) -> Self {
        Self {
            kind: IdentityKind::DocumentAccepted,
            id,
            payload: json!({
                "realm": uuid(realm),
                "account": account,
                "document": document,
                "version": version,
                "at": at,
            }),
        }
    }

    /// `agent.suspended`: the agent Party `agent` was suspended.
    #[must_use]
    pub fn agent_suspended(id: [u8; 32], realm: &[u8; 16], agent: &[u8; 16], at: u64) -> Self {
        Self {
            kind: IdentityKind::AgentSuspended,
            id,
            payload: json!({"realm": uuid(realm), "agent": b64url_encode(agent), "at": at}),
        }
    }

    /// `login.failed_surge`: `failures` failed sign-ins in the realm within `window_ms`.
    #[must_use]
    pub fn login_failed_surge(
        id: [u8; 32],
        realm: &[u8; 16],
        failures: u32,
        window_ms: u64,
        at: u64,
    ) -> Self {
        Self {
            kind: IdentityKind::LoginFailedSurge,
            id,
            payload: json!({
                "realm": uuid(realm),
                "failures": failures,
                "window_ms": window_ms,
                "at": at,
            }),
        }
    }

    /// `party.disabled` from a suspension (OP-149 m.7).
    #[must_use]
    pub fn party_suspended(id: [u8; 32], party: &[u8; 16], at: u64) -> Self {
        Self {
            kind: IdentityKind::PartyDisabled,
            id,
            payload: json!({
                "party": b64url_encode(party),
                "at": at,
                "reason_class": "suspended",
            }),
        }
    }

    /// `projection-invalidated` of the refresh family `family` of `domain`, whose first token
    /// came from `exercise` (§9.9.3 rule 6, P50).
    #[must_use]
    pub fn projection_invalidated(
        id: [u8; 32],
        domain: &[u8; 32],
        exercise: &[u8; 32],
        family: &[u8; 16],
        at: u64,
    ) -> Self {
        Self {
            kind: IdentityKind::ProjectionInvalidated,
            id,
            payload: json!({
                "domain": b64url_encode(domain),
                "source": { "exercise": b64url_encode(exercise) },
                "subject": { "kind": "projection", "id": b64url_encode(family) },
                "at": at,
            }),
        }
    }

    /// When it happened, Unix ms.
    #[must_use]
    pub fn at(&self) -> u64 {
        self.payload.get("at").and_then(Value::as_u64).unwrap_or(0)
    }

    /// The outbox bytes: `{"id", "payload"}` as JSON.
    ///
    /// # Errors
    /// [`Invalid`] when encoding fails.
    pub fn to_outbox(&self) -> Result<Vec<u8>, Invalid> {
        serde_json::to_vec(&json!({"id": b64url_encode(&self.id), "payload": self.payload}))
            .map_err(|_| Invalid("encoding"))
    }

    /// Reads an outbox row of `kind`.
    ///
    /// # Errors
    /// [`Invalid`].
    pub fn from_outbox(kind: &str, bytes: &[u8]) -> Result<Self, Invalid> {
        let kind = IdentityKind::from_outbox(kind).ok_or(Invalid("kind"))?;
        let v: Value = serde_json::from_slice(bytes).map_err(|_| Invalid("json"))?;
        let id = v
            .get("id")
            .and_then(Value::as_str)
            .and_then(|s| access_kernel::json::b64url_decode(s).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or(Invalid("id"))?;
        let payload = v.get("payload").filter(|p| p.is_object()).cloned();
        Ok(Self {
            kind,
            id,
            payload: payload.ok_or(Invalid("payload"))?,
        })
    }

    /// The event ready to queue.
    #[must_use]
    pub fn ready(&self) -> Ready {
        Ready {
            id: b64url_encode(&self.id),
            name: self.kind.name(),
            at: self.at(),
            sub_id: subject_id(&self.payload),
            payload: self.payload.clone(),
        }
    }
}

/// An event in the form the fan-out queues: its id, name, time, subject and payload.
#[derive(Clone, Debug, PartialEq)]
pub struct Ready {
    /// The dedup key, base64url.
    pub id: String,
    /// The catalog name.
    pub name: &'static str,
    /// When it happened, Unix ms.
    pub at: u64,
    /// The SET `sub_id` opaque value.
    pub sub_id: String,
    /// The payload.
    pub payload: Value,
}

fn subject_id(p: &Value) -> String {
    [
        "account",
        "agent",
        "party",
        "client_id",
        "organization",
        "tenant",
        "realm",
    ]
    .into_iter()
    .find_map(|k| p.get(k).and_then(Value::as_str))
    .or_else(|| p.pointer("/subject/id").and_then(Value::as_str))
    .map(String::from)
    .unwrap_or_default()
}

fn source_json(s: Source) -> Value {
    match s {
        Source::Exercise(d) => json!({"exercise": b64url_encode(&d.0)}),
        Source::Claim(i) => json!({"claim": b64url_encode(&i.0)}),
    }
}

/// The JSON payload of an authority event, keyed by its event id (`event_id` of the
/// authority outbox, the domain's keyed HMAC, TI-RT10).
#[must_use]
pub fn authority_ready(e: &Event, event_id: &[u8; 32]) -> Ready {
    let mut m = Map::new();
    m.insert("domain".into(), b64url_encode(&e.domain.0).into());
    m.insert("source".into(), source_json(e.source));
    let party = |p: &[u8; 16]| Value::from(b64url_encode(p));
    match (&e.kind, &e.subject, &e.detail) {
        (Kind::PartyDisabled, Subject::Party(p), Detail::Disabled { reason }) => {
            m.insert("party".into(), party(&p.0));
            m.insert("at".into(), e.at.into());
            m.insert("reason_class".into(), reason.name().into());
        }
        (
            Kind::PartyCompromised,
            Subject::Party(p),
            Detail::Compromised {
                keys,
                occurred_at,
                window_from,
                declared_at,
                evidence,
            },
        ) => {
            m.insert("party".into(), party(&p.0));
            m.insert(
                "instances".into(),
                keys.iter().map(|(i, _)| party(&i.0)).collect(),
            );
            m.insert(
                "kids".into(),
                keys.iter()
                    .map(|(_, k)| Value::from(b64url_encode(k)))
                    .collect(),
            );
            if let Some(t) = occurred_at {
                m.insert("occurred_at".into(), (*t).into());
            }
            m.insert("window_from".into(), (*window_from).into());
            m.insert("declared_at".into(), (*declared_at).into());
            m.insert("evidence_digest".into(), b64url_encode(&evidence.0).into());
        }
        _ => {
            m.insert(
                "subject".into(),
                json!({"kind": e.subject.kind(), "id": b64url_encode(e.subject.bytes())}),
            );
            m.insert("at".into(), e.at.into());
            if let Detail::Instance { party: p } = &e.detail {
                m.insert("party".into(), party(&p.0));
            }
        }
    }
    let payload = Value::Object(m);
    Ready {
        id: b64url_encode(event_id),
        name: e.kind.name(),
        at: e.at,
        sub_id: subject_id(&payload),
        payload,
    }
}
