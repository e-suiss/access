//! The tool table (§9.3A, §9.4.1, §11.2, AG-2): a tool is an `ActionRef` of the publisher's
//! SPP on one resource, and a call is the intent of that action with the call's arguments as
//! parameters. The table is data; the tool description is authority-opaque (A-7) and is never
//! read by this module. The same mapping runs on the client ([`intent`]), so the statement the
//! agent signs and the intent this server asks about are the same bytes.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::json::Json;
use access_kernel::model::{ActionRef, EqValue, Id, ResourceRef, Window};
use suiss_crypto::digest::context_digest;

use super::json::render;

/// Digest context of an argument that is an object or an array: it enters the intent as an
/// opaque digest of its JSON text.
pub const OPAQUE_ARGUMENT: &str = "access/mcp-argument/v1";

/// One tool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolDef {
    /// The MCP tool name.
    pub name: String,
    /// The action a call exercises.
    pub action: ActionRef,
    /// The resource a call acts on.
    pub resource: ResourceRef,
    /// The scopes a call needs, all named in one challenge.
    pub scopes: Vec<String>,
    /// The Public Grant that makes the tool visible to anyone, when the domain made one; `None`
    /// means visibility is the viewer's.
    pub public: Option<Id>,
    /// Arguments that are secrets: never mirrored in an `Mcp-Param-*` header.
    pub secret: BTreeSet<String>,
    /// The tool's listing object (`name`, `description`, `inputSchema`, ...), as published.
    pub listing: Json,
}

/// The table, in a deterministic order (by name).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tools(Vec<ToolDef>);

/// A table entry is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ToolError {
    /// Two tools of one name.
    #[error("tool-duplicate")]
    Duplicate,
    /// The arguments are not an object.
    #[error("tool-arguments")]
    Arguments,
}

impl Tools {
    /// The table of `tools`.
    ///
    /// # Errors
    /// [`ToolError::Duplicate`].
    pub fn new(mut tools: Vec<ToolDef>) -> Result<Self, ToolError> {
        tools.sort_by(|a, b| a.name.cmp(&b.name));
        if tools
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.name == b.name))
        {
            return Err(ToolError::Duplicate);
        }
        Ok(Self(tools))
    }

    /// The tool `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ToolDef> {
        self.0.iter().find(|t| t.name == name)
    }

    /// Every tool, by name.
    #[must_use]
    pub fn all(&self) -> &[ToolDef] {
        &self.0
    }

    /// Whether `argument` of tool `name` is a secret; an unknown tool's arguments all are.
    #[must_use]
    pub fn secret(&self, name: Option<&str>, argument: &str) -> bool {
        match name.and_then(|n| self.get(n)) {
            Some(t) => t.secret.iter().any(|s| s.eq_ignore_ascii_case(argument)),
            None => true,
        }
    }
}

/// The intent of a call of `tool` with `arguments` over `validity`: a string, integer or
/// boolean argument is an `eq` parameter; an object or array is an opaque digest of its text;
/// `null` is left out.
///
/// # Errors
/// [`ToolError::Arguments`].
pub fn intent(
    tool: &ToolDef,
    arguments: Option<&Json>,
    validity: Window,
) -> Result<IntentEnvelope, ToolError> {
    let mut params = BTreeMap::new();
    let mut opaque = BTreeMap::new();
    match arguments {
        None => {}
        Some(Json::Object(members)) => {
            for (k, v) in members {
                match v {
                    Json::Null => {}
                    Json::Str(s) => {
                        params.insert(k.clone(), ParamValue::Eq(EqValue::Text(s.clone())));
                    }
                    Json::Int(i) => {
                        params.insert(k.clone(), ParamValue::Eq(EqValue::Int(*i)));
                    }
                    Json::Bool(b) => {
                        params.insert(k.clone(), ParamValue::Eq(EqValue::Bool(*b)));
                    }
                    Json::Array(_) | Json::Object(_) => {
                        opaque.insert(
                            k.clone(),
                            context_digest(OPAQUE_ARGUMENT, render(v).as_bytes()),
                        );
                    }
                }
            }
        }
        Some(_) => return Err(ToolError::Arguments),
    }
    Ok(IntentEnvelope {
        action: tool.action.clone(),
        resources: alloc::vec![tool.resource.clone()],
        params,
        opaque,
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity,
    })
}
