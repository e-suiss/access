//! The Suiss discovery document of a realm (OP-149 m.3): beside the standard OIDC documents
//! (§9.15.1), it tells a Suiss product everything but the issuer it already holds. Only what is
//! served is declared, as for the AS metadata (§10.4.6).

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::domain::issuer::Issuer;

/// Well-known suffix of the document.
pub const SUFFIX: &str = "suiss-configuration";

/// `Cache-Control` of the document (OP-149 m.3, PD).
pub const CACHE_CONTROL: &str = "max-age=300";

/// Version of the document's shape.
pub const VERSION: u64 = 1;

/// An endpoint the `endpoints` map may name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Endpoint {
    /// The ADP discovery document (L1-ADP-11).
    Adp,
    /// `GET /access/v1/keys/{kid}`.
    KeyLookup,
    /// `POST /access/v1/keys:batchGet`.
    KeyBatch,
    /// `POST /access/v1/eligibility:check`.
    Eligibility,
    /// `GET /access/v1/tenants/{tenant}/snapshot`.
    TenantSnapshot,
    /// `POST /v1/me/auth-context` on the realm (OP-149 m.8).
    AuthContext,
    /// `POST /v1/me/instances` on the realm (OP-149 m.6).
    Instances,
    /// `POST /access/v1/tenants/{tenant}/pairing/challenges` (OP-149 m.4, m.16 (a)).
    PairingChallenges,
    /// `POST /access/v1/tenants/{tenant}/pairing` (OP-149 m.4, m.16 (a)).
    Pairing,
    /// `/access/v1/platform/streams`: a platform client's event streams (OP-149 m.17 (g)).
    PlatformStreams,
    /// `POST /access/v1/tenants/{tenant}/subjects:resolve` (OP-149 A11).
    SubjectResolution,
    /// `GET /access/v1/exercises/{exercise}` (OP-149 m.9).
    Exercise,
    /// `GET /access/v1/exercises/{exercise}/agency` (OP-149 m.11).
    ExerciseAgency,
    /// `POST /access/v1/claims:ingest` (CMP-8, OP-150 m.2); not served yet.
    ClaimIngest,
    /// `GET /access/v1/status-lists/{list}` (OP-150 m.3 (a), (s)).
    StatusList,
}

impl Endpoint {
    /// The key in `endpoints`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Adp => "adp",
            Self::KeyLookup => "key_lookup",
            Self::KeyBatch => "key_batch",
            Self::Eligibility => "eligibility",
            Self::TenantSnapshot => "tenant_snapshot",
            Self::AuthContext => "auth_context",
            Self::Instances => "instances",
            Self::PairingChallenges => "pairing_challenges",
            Self::Pairing => "pairing",
            Self::PlatformStreams => "platform_streams",
            Self::SubjectResolution => "subject_resolution",
            Self::Exercise => "exercise",
            Self::ExerciseAgency => "exercise_agency",
            Self::ClaimIngest => "claim_ingest",
            Self::StatusList => "status_list",
        }
    }

    /// The path, under the API base or, for a realm endpoint, under the realm issuer.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Adp => "/.well-known/authzen-configuration",
            Self::KeyLookup => "/access/v1/keys/{kid}",
            Self::KeyBatch => "/access/v1/keys:batchGet",
            Self::Eligibility => "/access/v1/eligibility:check",
            Self::TenantSnapshot => "/access/v1/tenants/{tenant}/snapshot",
            Self::AuthContext => "/v1/me/auth-context",
            Self::Instances => "/v1/me/instances",
            Self::PairingChallenges => "/access/v1/tenants/{tenant}/pairing/challenges",
            Self::Pairing => "/access/v1/tenants/{tenant}/pairing",
            Self::PlatformStreams => "/access/v1/platform/streams",
            Self::SubjectResolution => "/access/v1/tenants/{tenant}/subjects:resolve",
            Self::Exercise => "/access/v1/exercises/{exercise}",
            Self::ExerciseAgency => "/access/v1/exercises/{exercise}/agency",
            Self::ClaimIngest => "/access/v1/claims:ingest",
            Self::StatusList => "/access/v1/status-lists/{list}",
        }
    }

    /// Whether the endpoint is the realm's own (Frontend API), not the deployment's.
    #[must_use]
    pub const fn on_realm(self) -> bool {
        matches!(self, Self::AuthContext | Self::Instances)
    }
}

/// The endpoints in service. A slice that serves another adds it here.
pub const SERVED: &[Endpoint] = &[
    Endpoint::Adp,
    Endpoint::KeyLookup,
    Endpoint::KeyBatch,
    Endpoint::Eligibility,
    Endpoint::TenantSnapshot,
    Endpoint::AuthContext,
    Endpoint::Instances,
    Endpoint::PairingChallenges,
    Endpoint::Pairing,
    Endpoint::PlatformStreams,
    Endpoint::SubjectResolution,
    Endpoint::Exercise,
    Endpoint::ExerciseAgency,
    Endpoint::ClaimIngest,
    Endpoint::StatusList,
];

/// Well-known suffix of the realm's SSF transmitter metadata (SSF 1.0 §7.1).
pub const SSF_SUFFIX: &str = "ssf-configuration";

/// The delivery method of the Suiss webhook profile (OP-149 m.4, m.7): `CloudEvents` 1.0
/// structured JSON signed per Standard Webhooks.
pub const WEBHOOK_PROFILE: &str = "urn:suiss:access:delivery:webhook";

/// `suiss_event_subscriptions` of `issuer` (OP-149 m.3, m.7): the realm's SSF transmitter
/// metadata URL, the well-known path inserted before the issuer's path, and the webhook
/// profile a stream names as its delivery method.
#[must_use]
pub fn event_subscriptions(issuer: &Issuer) -> Value {
    json!({
        "ssf_configuration": format!(
            "https://{}{}",
            issuer.authority(),
            issuer.well_known_inserted(SSF_SUFFIX)
        ),
        "webhooks": WEBHOOK_PROFILE,
    })
}

/// The deployment's part of the document, from configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The deployment's region.
    pub region: String,
    /// Relay's base URL.
    pub relay: String,
    /// The management API's base URL.
    pub management_api: String,
    /// The base URL of the deployment's `/access/v1` and ADP endpoints (the ADP issuer).
    pub api_base: String,
    /// Product name to base URL.
    pub products: BTreeMap<String, String>,
}

/// The `endpoints` map of `issuer` (OP-149 m.3): the same map Domain Metadata `discovery`
/// carries as deterministic CBOR.
#[must_use]
pub fn endpoints(issuer: &Issuer, s: &Settings, served: &[Endpoint]) -> BTreeMap<String, String> {
    served
        .iter()
        .map(|e| {
            let url = if e.on_realm() {
                issuer.endpoint(e.path())
            } else {
                format!("{}{}", s.api_base, e.path())
            };
            (e.name().to_owned(), url)
        })
        .collect()
}

/// The document of the realm `issuer`.
#[must_use]
pub fn document(issuer: &Issuer, s: &Settings, served: &[Endpoint]) -> String {
    let mut m = Map::new();
    m.insert("suiss_configuration_version".into(), VERSION.into());
    m.insert("issuer".into(), issuer.as_str().into());
    m.insert("suiss_region".into(), s.region.as_str().into());
    m.insert("suiss_relay".into(), s.relay.as_str().into());
    m.insert(
        "suiss_management_api".into(),
        s.management_api.as_str().into(),
    );
    m.insert(
        "suiss_event_subscriptions".into(),
        event_subscriptions(issuer),
    );
    m.insert("suiss_products".into(), json!(s.products));
    m.insert("endpoints".into(), json!(endpoints(issuer, s, served)));
    Value::Object(m).to_string()
}

/// The deterministic CBOR of `endpoints` (`conformance/cddl/suiss-discovery.cddl`), the
/// opaque `discovery` of Domain Metadata (CR-58 m.3).
#[must_use]
pub fn discovery_cbor(endpoints: &BTreeMap<String, String>) -> Vec<u8> {
    use suiss_crypto::dcbor::{self, Limits, Value as Cbor};
    let map = Cbor::Map(
        endpoints
            .iter()
            .map(|(k, v)| (Cbor::text(k), Cbor::text(v)))
            .collect(),
    );
    let doc = Cbor::Map(vec![
        (Cbor::text("v"), Cbor::Unsigned(VERSION)),
        (Cbor::text("endpoints"), map),
    ]);
    dcbor::encode(&doc, Limits::CEILING).unwrap_or_default()
}
