//! The session bridge for the person's own coding tools (E57 (2)–(4), A-7, OP-156 m.3 (w)): the
//! local executor runs Claude Code or Codex on the person's device under the person's own
//! account. Every step is its own Exercise with this executor as PEP and runs only after a
//! verified ALLOW; a stopped session runs nothing more. The tool's sign-in stays in the tool's
//! own store: a step carries no credential and the executor reads none. What the tool prints is
//! data, never an instruction.

use access_kernel::digest::Digest;
use serde::{Deserialize, Serialize};
use suiss_crypto::digest::context_digest;

/// The tools the bridge runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tool {
    /// Claude Code.
    ClaudeCode,
    /// Codex.
    Codex,
}

/// What one step does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StepKind {
    /// A tool call the tool asked to make.
    ToolCall {
        /// Its name.
        name: String,
    },
    /// Writes one file.
    FileWrite {
        /// The path, inside the workspace.
        path: String,
    },
    /// Runs one command.
    Command {
        /// The command line.
        line: String,
    },
}

/// One step of a bridged session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolStep {
    /// The tool.
    pub tool: Tool,
    /// What it does.
    pub kind: StepKind,
    /// The workspace, as the person named it.
    pub workspace: String,
}

/// What the tool answered: data, kept as bytes with their digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolOutput {
    /// The exit status.
    pub status: i32,
    /// What it printed.
    pub output: Vec<u8>,
}

/// What the bridge reports of a step: the tool's output as data from an untrusted source
/// (E54 (1), A-7); nothing in it is acted on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Data {
    /// The Exercise the step ran under.
    pub exercise: Digest,
    /// The exit status.
    pub status: i32,
    /// The output's digest.
    pub digest: Digest,
    /// The output.
    pub output: Vec<u8>,
    /// Always `untrusted-external`.
    pub provenance: &'static str,
}

/// Why a step is refused before it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BridgeError {
    /// Not a local executor: the bridge runs only on the person's own device.
    #[error("executor-bridge-kind")]
    Kind,
    /// A path that leaves the workspace or a step out of shape.
    #[error("executor-bridge-step")]
    Step,
    /// The session was stopped.
    #[error("executor-bridge-stopped")]
    Stopped,
    /// The step names a credential; the tool keeps its own (E57 (3)).
    #[error("executor-bridge-credential")]
    Credential,
}

const CREDENTIAL_WORDS: [&str; 6] = [
    "authorization:",
    "bearer ",
    "oauth_token",
    "access_token",
    "refresh_token",
    "api_key",
];

impl ToolStep {
    /// Checks the step's shape: a relative path that stays inside the workspace, one line,
    /// and no credential carried in it.
    ///
    /// # Errors
    /// [`BridgeError`].
    pub fn check(&self) -> Result<(), BridgeError> {
        let text = match &self.kind {
            StepKind::ToolCall { name } => name,
            StepKind::FileWrite { path } => {
                if path.starts_with('/') || path.split('/').any(|s| s == ".." || s.is_empty()) {
                    return Err(BridgeError::Step);
                }
                path
            }
            StepKind::Command { line } => line,
        };
        if text.is_empty() || text.len() > 4096 || text.contains(['\n', '\r', '\0']) {
            return Err(BridgeError::Step);
        }
        let lower = text.to_ascii_lowercase();
        if CREDENTIAL_WORDS.iter().any(|w| lower.contains(w)) {
            return Err(BridgeError::Credential);
        }
        Ok(())
    }

    /// The step's digest, which its Exercise's intent carries as `step`.
    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest(
            context_digest(
                "access/executor/bridge-step/v1",
                &serde_json::to_vec(self).unwrap_or_default(),
            )
            .0,
        )
    }
}

/// The tool's output as data of `exercise` (A-7).
#[must_use]
pub fn data(exercise: Digest, out: ToolOutput) -> Data {
    Data {
        exercise,
        status: out.status,
        digest: Digest(context_digest("access/executor/bridge-output/v1", &out.output).0),
        output: out.output,
        provenance: "untrusted-external",
    }
}
