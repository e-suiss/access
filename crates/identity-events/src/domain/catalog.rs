//! The event catalog (OP-149 m.4, m.7, §9.16): every type's name and URN, the identity plane's
//! own events as they sit in the outbox, and the JSON payload of each event as the schemas in
//! `sdks/openapi/events` define it.

use core::fmt::Write as _;

use access_internal_api::events::{Detail, Event, Kind, Source, Subject};
use access_kernel::json::b64url_encode;
use serde_json::{Map, Value, json};

use crate::domain::Invalid;

/// Prefix of every event type URN.
pub const URN_PREFIX: &str = "urn:suiss:access:event:";

/// Prefix of the identity outbox kinds this crate reads.
pub const OUTBOX_PREFIX: &str = "event.";

/// Every event name, authority events first.
pub const NAMES: [&str; 15] = [
    "authority-revoked",
    "authority-narrowed",
    "authority-expired",
    "mandate-ended",
    "instance-terminated",
    "revalidation-required",
    "projection-invalidated",
    "party.disabled",
    "party.compromised",
    "tenant.created",
    "organization.created",
    "organization.updated",
    "api_client.created",
    "api_client.updated",
    "api_client.disabled",
];

/// The type URN of `name`.
#[must_use]
pub fn urn(name: &str) -> String {
    format!("{URN_PREFIX}{name}")
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
}

impl IdentityKind {
    const ALL: [Self; 7] = [
        Self::TenantCreated,
        Self::OrganizationCreated,
        Self::OrganizationUpdated,
        Self::ApiClientCreated,
        Self::ApiClientUpdated,
        Self::ApiClientDisabled,
        Self::PartyDisabled,
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
        }
    }

    /// The kind of an identity outbox kind.
    #[must_use]
    pub fn from_outbox(kind: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.outbox_kind() == kind)
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
    /// Tenant.
    pub tenant: &'a [u8; 16],
    /// Realm.
    pub realm: &'a [u8; 16],
    /// The `client_id`.
    pub client_id: &'a str,
    /// The `ExerciseID` that allowed it.
    pub exercise: &'a [u8; 32],
    /// The matched product, when the client is a platform client.
    pub platform_product: Option<PlatformProduct>,
    /// When, Unix ms.
    pub at: u64,
}

impl IdentityEvent {
    /// `api_client.created`, `api_client.updated` or `api_client.disabled`.
    #[must_use]
    pub fn api_client(kind: IdentityKind, id: [u8; 32], c: &ClientChange<'_>) -> Self {
        let mut p = json!({
            "tenant": uuid(c.tenant),
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

    /// `tenant.created`.
    #[must_use]
    pub fn tenant_created(id: [u8; 32], tenant: &[u8; 16], placement: &str, at: u64) -> Self {
        Self {
            kind: IdentityKind::TenantCreated,
            id,
            payload: json!({"tenant": uuid(tenant), "placement": placement, "at": at}),
        }
    }

    /// `organization.created` or `organization.updated`.
    #[must_use]
    pub fn organization(
        kind: IdentityKind,
        id: [u8; 32],
        tenant: &[u8; 16],
        organization: &[u8; 16],
        at: u64,
    ) -> Self {
        Self {
            kind,
            id,
            payload: json!({
                "tenant": uuid(tenant),
                "organization": uuid(organization),
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
    ["party", "client_id", "organization", "tenant"]
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
            m.insert("occurred_at".into(), (*occurred_at).into());
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
