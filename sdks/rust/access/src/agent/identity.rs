//! How an agent names itself to people and to the sites it calls (A-12, XI-17, §11.16.2, EU AI
//! Act art. 50): always as an agent, with its operator and, when it acts for someone, its
//! principal. There is no way to present it as a person.

use alloc::format;
use alloc::string::String;

use access_kernel::combinator::Capacity;
use access_kernel::json::b64url_encode;
use access_kernel::model::Id;

/// The agent's self-identification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disclosure {
    /// The agent Instance.
    pub instance: Id,
    /// The agent Party.
    pub agent: Id,
    /// The operator Party that runs it (`operated_by`).
    pub operator: Id,
    /// The principal, under `FOR(principal)`; `None` under `OWN`.
    pub principal: Option<Id>,
}

impl Disclosure {
    /// The disclosure of an agent acting with `capacity`.
    #[must_use]
    pub const fn new(instance: Id, agent: Id, operator: Id, capacity: Capacity) -> Self {
        let principal = match capacity {
            Capacity::For(p) => Some(p),
            Capacity::Own => None,
        };
        Self {
            instance,
            agent,
            operator,
            principal,
        }
    }

    /// The JSON a user-facing surface shows as the agent badge: `party_kind` is always `agent`.
    #[must_use]
    pub fn json(&self) -> String {
        let principal = self
            .principal
            .map(|p| format!(",\"principal\":\"{}\"", b64url_encode(&p.0)))
            .unwrap_or_default();
        format!(
            "{{\"party_kind\":\"agent\",\"agent\":\"{}\",\"instance\":\"{}\",\"operator\":\"{}\"{principal}}}",
            b64url_encode(&self.agent.0),
            b64url_encode(&self.instance.0),
            b64url_encode(&self.operator.0),
        )
    }
}

/// The `Signature-Agent` header value naming the key directory that signs the agent's requests
/// (Web Bot Auth, RFC 9421, OP-154 m.3 (u)): an `https` URL as a structured-field string. The
/// agent does not hide that it is one.
#[must_use]
pub fn signature_agent(directory: &str) -> Option<String> {
    let rest = directory.strip_prefix("https://")?;
    let clean = !rest.is_empty()
        && directory
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\');
    clean.then(|| format!("\"{directory}\""))
}
