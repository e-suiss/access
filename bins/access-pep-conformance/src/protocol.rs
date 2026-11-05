//! The JSON-lines adapter protocol `access-pep-conformance/1`: one JSON object per line,
//! the runner writes to the adapter's stdin and reads its stdout (`conformance/pep/README.md`).

use serde::{Deserialize, Serialize};

use crate::case::Mode;

/// Protocol name and version.
pub const PROTOCOL: &str = "access-pep-conformance/1";

/// Runner to adapter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ToSut {
    /// First line; the adapter answers [`FromSut::Ready`].
    Hello {
        /// [`PROTOCOL`].
        protocol: String,
    },
    /// One case; the adapter answers [`FromSut::Result`].
    Case(Box<CaseMessage>),
    /// Last line; the adapter exits.
    Bye,
}

/// The PEP's configuration for one case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pep {
    /// The PEP's own audience identifier.
    pub audience: String,
    /// The pinned domain ID (hex of its CBOR digest).
    pub domain: String,
    /// The pinned, verified `domain-metadata` (hex of its CBOR).
    pub metadata: String,
    /// The expected token issuer.
    pub issuer: String,
}

/// Where the fake upstreams of one case listen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstreams {
    /// ADP `AuthZEN` evaluation endpoint (POST JSON).
    pub adp: String,
    /// RFC 7662 introspection endpoint (POST form).
    pub introspection: String,
    /// JWKS (GET).
    pub jwks: String,
    /// The protected resource: POST here performs the effect.
    pub effect: String,
}

/// What the PEP is asked to enforce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// What protects the effect.
    pub mode: Mode,
    /// The intent digest (hex of its CBOR) the effect applies.
    pub intent: String,
    /// The `AuthZEN` evaluation body the PEP sends to the ADP in `decision` mode.
    pub evaluation: serde_json::Value,
    /// The access token in `introspection` and `jwt` modes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// One case as the adapter sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseMessage {
    /// Case ID.
    pub case: String,
    /// Trusted time, Unix milliseconds; the adapter uses it instead of its own clock.
    pub now: u64,
    /// Upstream calls of this case must give up after this many milliseconds.
    pub deadline_ms: u64,
    /// PEP configuration.
    pub pep: Pep,
    /// Upstream URLs.
    pub upstream: Upstreams,
    /// The request.
    pub request: Request,
}

/// The adapter's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// The PEP allowed and performed the effect.
    Allow,
    /// The PEP denied.
    Deny,
    /// The PEP could not decide and did not perform the effect.
    Error,
}

/// Adapter to runner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum FromSut {
    /// Answer to [`ToSut::Hello`].
    Ready {
        /// [`PROTOCOL`].
        protocol: String,
        /// The PEP implementation's name.
        name: String,
    },
    /// Answer to [`ToSut::Case`].
    Result(CaseResult),
}

/// The outcome of one case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseResult {
    /// Case ID.
    pub case: String,
    /// What the PEP did.
    pub outcome: Outcome,
    /// Why, for the report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
