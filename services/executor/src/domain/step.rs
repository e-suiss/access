//! A job's steps (E62): what each one calls upstream, its `StepRef`, its idempotency key and
//! whether it stays inside the Exercise's intent envelope.

use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::model::ResourceRef;
use serde::{Deserialize, Serialize};
use suiss_crypto::digest::context_digest;

/// How far an effect can be taken back (E47).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reversibility {
    /// It can be taken back.
    Reversible,
    /// A compensating effect undoes it.
    Compensable,
    /// It cannot be taken back; it waits out the delayed-commit window (E47 (2)).
    Irreversible,
}

/// The upstream call of one step: a driver and its arguments (OP-154 m.3 (u)).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "driver", rename_all = "lowercase")]
pub enum Call {
    /// The generic OAuth HTTP driver: one request to an upstream API with the released token.
    Http {
        /// `GET`, `POST`, `PUT`, `PATCH` or `DELETE`.
        method: String,
        /// An `https` URL.
        url: String,
        /// A JSON body.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<serde_json::Value>,
    },
    /// The MCP client driver: one `tools/call` on an MCP server.
    Mcp {
        /// The server's `https` endpoint.
        server: String,
        /// The tool.
        tool: String,
        /// Its arguments.
        #[serde(default)]
        arguments: serde_json::Value,
    },
}

/// One step of a job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepSpec {
    /// A short name for people, 1 to 64 characters.
    pub name: String,
    /// The action, `namespace/name`; it must be the Exercise's.
    pub action: String,
    /// The resource, `namespace:segment/segment`; it must be one of the Exercise's.
    pub resource: String,
    /// How far the effect can be taken back.
    pub reversibility: Reversibility,
    /// Whether the upstream honours the idempotency key; only then is a request whose answer
    /// was lost in a crash sent again, once, with the same key (TI-6).
    #[serde(default)]
    pub idempotent: bool,
    /// The upstream call.
    pub call: Call,
}

/// Why a step list is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StepError {
    /// No steps, or more than [`crate::domain::MAX_STEPS`].
    #[error("executor-steps")]
    Count,
    /// A name, method or URL out of shape.
    #[error("executor-step")]
    Shape,
}

const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

fn https(url: &str) -> bool {
    url.strip_prefix("https://").is_some_and(|rest| {
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        !host.is_empty() && !host.contains('@') && url.len() <= 2048
    })
}

impl StepSpec {
    /// Checks the step's shape: plain-text name, a known method, `https` only.
    ///
    /// # Errors
    /// [`StepError::Shape`].
    pub fn check(&self) -> Result<(), StepError> {
        let name_ok = (1..=64).contains(&self.name.chars().count())
            && !self.name.chars().any(char::is_control);
        let call_ok = match &self.call {
            Call::Http { method, url, .. } => METHODS.contains(&method.as_str()) && https(url),
            Call::Mcp { server, tool, .. } => https(server) && (1..=128).contains(&tool.len()),
        };
        if name_ok && call_ok && self.action.len() <= 256 && self.resource.len() <= 1024 {
            Ok(())
        } else {
            Err(StepError::Shape)
        }
    }
}

/// Checks a job's step list.
///
/// # Errors
/// [`StepError`].
pub fn check_steps(steps: &[StepSpec]) -> Result<(), StepError> {
    if steps.is_empty() || steps.len() > crate::domain::MAX_STEPS {
        return Err(StepError::Count);
    }
    steps.iter().try_for_each(StepSpec::check)
}

/// The `StepRef` of step `index` of the job running `exercise` (E62 (2)).
#[must_use]
pub fn step_ref(exercise: &Digest, index: u32, spec: &StepSpec) -> Digest {
    let mut bytes = exercise.0.to_vec();
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.extend_from_slice(&serde_json::to_vec(spec).unwrap_or_default());
    Digest(context_digest("access/executor/step/v1", &bytes).0)
}

/// The idempotency key `H(ExerciseID ‖ StepRef)`, forwarded upstream (E62 (2)).
#[must_use]
pub fn idempotency_key(exercise: &Digest, step: &Digest) -> Digest {
    let mut bytes = exercise.0.to_vec();
    bytes.extend_from_slice(&step.0);
    Digest(context_digest("access/executor/idempotency/v1", &bytes).0)
}

/// A resource as a step names it: `namespace:segment/segment`.
#[must_use]
pub fn resource_text(r: &ResourceRef) -> String {
    format!("{}:{}", r.namespace, r.path.join("/"))
}

/// Whether the step stays inside the envelope: the Exercise's action on one of its resources.
/// A step outside it never runs under this Exercise (§7.9.7.2, INV-19).
#[must_use]
pub fn within(spec: &StepSpec, envelope: &IntentEnvelope) -> bool {
    let action = format!("{}/{}", envelope.action.namespace, envelope.action.name);
    spec.action == action
        && envelope
            .resources
            .iter()
            .any(|r| resource_text(r) == spec.resource)
}
