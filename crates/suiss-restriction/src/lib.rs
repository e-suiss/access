//! Suiss shared restriction engine (OP-76, E43): the Access Restriction Profile, a forbid-only
//! subset of Cedar behind a mandatory wrapper (MD-4, OP-104). Native and Wasm builds give the
//! same result.

mod cost;
mod lexical;

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Effect, Entities, EntityUid, Policy, PolicyId, PolicySet,
    Request, Schema, ValidationMode, Validator,
};

/// Structural limits (OP-104 m.3). POLICY DEFAULT; final values come from the slowest-device bench.
/// A caller starts from [`Limits::default`] and can only narrow them ([`Limits::narrowed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Policy source size in bytes.
    pub(crate) source: usize,
    /// Lexical nesting of `( [ {`.
    pub(crate) nesting: usize,
    /// Tokens per policy.
    pub(crate) tokens: usize,
    /// Depth of the policy's JSON AST.
    pub(crate) ast_depth: usize,
    /// Entity dereference level for strict validation.
    pub(crate) deref: u32,
    /// Weighted cost per policy.
    pub(crate) policy_cost: u64,
    /// Weighted cost of the whole set.
    pub(crate) set_cost: u64,
    /// Number of policies.
    pub(crate) policies: usize,
    /// Request JSON size in bytes.
    pub(crate) input_bytes: usize,
    /// Elements per input collection.
    pub(crate) input_collection: usize,
    /// Bytes per input string.
    pub(crate) input_string: usize,
    /// Entities per request.
    pub(crate) input_entities: usize,
    /// Nesting of input JSON.
    pub(crate) input_nesting: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            source: 64 * 1024,
            nesting: 32,
            tokens: 256,
            ast_depth: 160,
            deref: 2,
            policy_cost: 4096,
            set_cost: 65_536,
            policies: 256,
            input_bytes: 64 * 1024,
            input_collection: 64,
            input_string: 256,
            input_entities: 64,
            input_nesting: 8,
        }
    }
}

/// One limit to lower (OP-140 m.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Narrow {
    /// Policy source size in bytes.
    Source(usize),
    /// Lexical nesting of `( [ {`.
    Nesting(usize),
    /// Tokens per policy.
    Tokens(usize),
    /// Depth of the policy's JSON AST.
    AstDepth(usize),
    /// Entity dereference level for strict validation.
    Deref(u32),
    /// Weighted cost per policy.
    PolicyCost(u64),
    /// Weighted cost of the whole set.
    SetCost(u64),
    /// Number of policies.
    Policies(usize),
    /// Request JSON size in bytes.
    InputBytes(usize),
    /// Elements per input collection.
    InputCollection(usize),
    /// Bytes per input string.
    InputString(usize),
    /// Entities per request.
    InputEntities(usize),
    /// Nesting of input JSON.
    InputNesting(usize),
}

/// A limit was asked to grow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("limits can only be narrowed")]
pub struct WiderLimit;

fn lower<T: PartialOrd>(slot: &mut T, value: T) -> Result<(), WiderLimit> {
    if value > *slot {
        return Err(WiderLimit);
    }
    *slot = value;
    Ok(())
}

impl Limits {
    /// These limits with one of them lowered.
    ///
    /// # Errors
    /// [`WiderLimit`] when the new value is above the current one.
    pub fn narrowed(mut self, change: Narrow) -> Result<Self, WiderLimit> {
        match change {
            Narrow::Source(v) => lower(&mut self.source, v)?,
            Narrow::Nesting(v) => lower(&mut self.nesting, v)?,
            Narrow::Tokens(v) => lower(&mut self.tokens, v)?,
            Narrow::AstDepth(v) => lower(&mut self.ast_depth, v)?,
            Narrow::Deref(v) => lower(&mut self.deref, v)?,
            Narrow::PolicyCost(v) => lower(&mut self.policy_cost, v)?,
            Narrow::SetCost(v) => lower(&mut self.set_cost, v)?,
            Narrow::Policies(v) => lower(&mut self.policies, v)?,
            Narrow::InputBytes(v) => lower(&mut self.input_bytes, v)?,
            Narrow::InputCollection(v) => lower(&mut self.input_collection, v)?,
            Narrow::InputString(v) => lower(&mut self.input_string, v)?,
            Narrow::InputEntities(v) => lower(&mut self.input_entities, v)?,
            Narrow::InputNesting(v) => lower(&mut self.input_nesting, v)?,
        }
        Ok(self)
    }
}

/// Why a policy set is not accepted.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CompileError {
    /// Source larger than the limit.
    #[error("policy source too large")]
    SourceTooLarge,
    /// Lexical nesting too deep.
    #[error("lexical nesting too deep")]
    NestingTooDeep,
    /// A policy has too many tokens.
    #[error("policy has too many tokens")]
    TooManyTokens,
    /// Too many policies.
    #[error("too many policies")]
    TooManyPolicies,
    /// Cedar rejected the source.
    #[error("parse error")]
    Parse,
    /// Templates are not allowed.
    #[error("templates are not allowed")]
    Template,
    /// A `permit` policy (OP-104 m.1 via OP-103 criterion 1).
    #[error("permit is not allowed")]
    PermitNotAllowed,
    /// Missing, repeated or invalid `@id`.
    #[error("bad or duplicate @id")]
    BadId,
    /// An annotation outside `@id`, `@require`, `@undisclosed`, `@doc`, or a bad value.
    #[error("bad annotation")]
    BadAnnotation,
    /// AST deeper than the limit.
    #[error("policy AST too deep")]
    AstTooDeep,
    /// Weighted cost above the limit.
    #[error("policy cost too high")]
    CostTooHigh,
    /// Strict schema validation failed.
    #[error("validation failed")]
    Validation,
    /// The schema is not accepted.
    #[error("bad schema")]
    Schema,
}

impl CompileError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::SourceTooLarge => "policy-source-too-large",
            Self::NestingTooDeep => "policy-nesting-too-deep",
            Self::TooManyTokens => "policy-too-many-tokens",
            Self::TooManyPolicies => "policy-too-many-policies",
            Self::Parse => "policy-parse",
            Self::Template => "policy-template",
            Self::PermitNotAllowed => "policy-permit",
            Self::BadId => "policy-bad-id",
            Self::BadAnnotation => "policy-bad-annotation",
            Self::AstTooDeep => "policy-ast-too-deep",
            Self::CostTooHigh => "policy-cost-too-high",
            Self::Validation => "policy-validation",
            Self::Schema => "policy-schema",
        }
    }
}

/// Why a request is not evaluated: a protocol rejection, not a decision (OP-104 m.5, OP-108 m.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("input rejected")]
pub struct InputRejected;

/// A DENY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    /// Unannotated `forbid` policies matched.
    Forbid {
        /// `@id`s of the matching policies, sorted.
        policies: Vec<String>,
        /// Whether any of them is `@undisclosed`.
        undisclosed: bool,
    },
    /// Cedar reported an evaluation error; an error is never "no match" (OP-104 m.2).
    EvaluationError,
    /// Any other engine state.
    Internal,
}

/// Engine output; there is no positive outcome (INV-6, TI-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No objection.
    NoObjection,
    /// Denied; deny overrides require.
    Deny(Denial),
    /// Allowed once all these requirement references are met (OP-104 m.4).
    Require(Vec<String>),
}

/// A request in Cedar JSON form.
#[derive(Clone, Copy, Debug)]
pub struct RequestJson<'a> {
    /// Principal entity uid, e.g. `Actor::"a1"`.
    pub principal: &'a str,
    /// Action entity uid, e.g. `Action::"transfer"`.
    pub action: &'a str,
    /// Resource entity uid.
    pub resource: &'a str,
    /// Context object.
    pub context: &'a str,
    /// Entities array.
    pub entities: &'a str,
}

struct Meta {
    id: String,
    require: Option<String>,
    undisclosed: bool,
}

/// A compiled user policy with its annotations, for the control-plane SMT analysis (OP-105).
#[derive(Clone, Copy, Debug)]
pub struct PolicyView<'a> {
    /// `@id`.
    pub id: &'a str,
    /// `@require` reference; `None` for a plain DENY `forbid`.
    pub require: Option<&'a str>,
    /// The Cedar policy under its engine-internal id.
    pub policy: &'a Policy,
}

const BASE_PERMIT: &str = "access-base-permit";

/// A compiled forbid-only policy set.
pub struct Engine {
    schema: Schema,
    policies: PolicySet,
    meta: BTreeMap<String, Meta>,
    limits: Limits,
}

fn valid_ref(s: &str) -> bool {
    s.len() <= 64
        && s.strip_prefix("rs-").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && s != BASE_PERMIT
}

fn meta_of(policy: &Policy) -> Result<Meta, CompileError> {
    let (mut id, mut require, mut undisclosed) = (None, None, false);
    for (k, v) in policy.annotations() {
        match k {
            "id" if valid_id(v) => id = Some(v.to_owned()),
            "id" => return Err(CompileError::BadId),
            "require" if valid_ref(v) => require = Some(v.to_owned()),
            "undisclosed" if v.is_empty() || v == "true" => undisclosed = true,
            "doc" => {}
            _ => return Err(CompileError::BadAnnotation),
        }
    }
    Ok(Meta {
        id: id.ok_or(CompileError::BadId)?,
        require,
        undisclosed,
    })
}

impl Engine {
    /// Compiles a schema (Cedar schema syntax) and a forbid-only policy source (OP-104 m.2).
    ///
    /// # Errors
    /// [`CompileError`].
    pub fn compile(schema: &str, source: &str, limits: Limits) -> Result<Self, CompileError> {
        if source.len() > limits.source {
            return Err(CompileError::SourceTooLarge);
        }
        lexical::check(source, limits.nesting, limits.tokens)?;
        let (schema, _) = Schema::from_cedarschema_str(schema).map_err(|_| CompileError::Schema)?;
        let parsed = PolicySet::from_str(source).map_err(|_| CompileError::Parse)?;
        if parsed.templates().next().is_some() {
            return Err(CompileError::Template);
        }
        let mut policies = PolicySet::new();
        let mut meta = BTreeMap::new();
        let mut total: u64 = 0;
        for (n, policy) in parsed.policies().enumerate() {
            if n >= limits.policies {
                return Err(CompileError::TooManyPolicies);
            }
            if policy.effect() != Effect::Forbid {
                return Err(CompileError::PermitNotAllowed);
            }
            let m = meta_of(policy)?;
            let est = policy.to_json().map_err(|_| CompileError::Parse)?;
            let c = cost::of(&est, limits.ast_depth)?;
            if c > limits.policy_cost {
                return Err(CompileError::CostTooHigh);
            }
            total = total.checked_add(c).ok_or(CompileError::CostTooHigh)?;
            let internal = format!("p{n}");
            let renamed = policy.new_id(PolicyId::new(&internal));
            if meta.values().any(|x: &Meta| x.id == m.id) {
                return Err(CompileError::BadId);
            }
            policies.add(renamed).map_err(|_| CompileError::Parse)?;
            meta.insert(internal, m);
        }
        if total > limits.set_cost {
            return Err(CompileError::CostTooHigh);
        }
        let validation = Validator::new(schema.clone()).validate_with_level(
            &policies,
            ValidationMode::Strict,
            limits.deref,
        );
        if !validation.validation_passed() {
            return Err(CompileError::Validation);
        }
        let base = Policy::parse(
            Some(PolicyId::new(BASE_PERMIT)),
            "permit(principal, action, resource);",
        )
        .map_err(|_| CompileError::Parse)?;
        policies.add(base).map_err(|_| CompileError::Parse)?;
        Ok(Self {
            schema,
            policies,
            meta,
            limits,
        })
    }

    /// The schema the set was validated against.
    #[must_use]
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// The fixed base `permit` (OP-103 criterion 1).
    #[must_use]
    pub fn base_permit(&self) -> Option<&Policy> {
        self.policies.policy(&PolicyId::new(BASE_PERMIT))
    }

    /// The user `forbid` policies, ordered by internal id; `None` if the engine state is
    /// inconsistent.
    #[must_use]
    pub fn policies(&self) -> Option<Vec<PolicyView<'_>>> {
        self.meta
            .iter()
            .map(|(internal, m)| {
                self.policies
                    .policy(&PolicyId::new(internal))
                    .map(|policy| PolicyView {
                        id: &m.id,
                        require: m.require.as_deref(),
                        policy,
                    })
            })
            .collect()
    }

    /// Evaluates one request (OP-104 m.2, m.4, m.5).
    ///
    /// # Errors
    /// [`InputRejected`]: input outside the limits or the schema.
    pub fn evaluate(&self, req: &RequestJson<'_>) -> Result<Outcome, InputRejected> {
        let l = &self.limits;
        if req
            .context
            .len()
            .checked_add(req.entities.len())
            .is_none_or(|n| n > l.input_bytes)
        {
            return Err(InputRejected);
        }
        let context: serde_json::Value =
            serde_json::from_str(req.context).map_err(|_| InputRejected)?;
        let entities: serde_json::Value =
            serde_json::from_str(req.entities).map_err(|_| InputRejected)?;
        cost::check_input(&context, l)?;
        cost::check_input(&entities, l)?;
        if entities
            .as_array()
            .is_none_or(|a| a.len() > l.input_entities)
        {
            return Err(InputRejected);
        }
        let uid = |s: &str| EntityUid::from_str(s).map_err(|_| InputRejected);
        let (principal, action, resource) =
            (uid(req.principal)?, uid(req.action)?, uid(req.resource)?);
        let context = Context::from_json_value(context, Some((&self.schema, &action)))
            .map_err(|_| InputRejected)?;
        let entities =
            Entities::from_json_value(entities, Some(&self.schema)).map_err(|_| InputRejected)?;
        let request = Request::new(principal, action, resource, context, Some(&self.schema))
            .map_err(|_| InputRejected)?;
        let response = Authorizer::new().is_authorized(&request, &self.policies, &entities);
        let diagnostics = response.diagnostics();
        if diagnostics.errors().next().is_some() {
            return Ok(Outcome::Deny(Denial::EvaluationError));
        }
        let reasons: BTreeSet<String> = diagnostics.reason().map(ToString::to_string).collect();
        Ok(match response.decision() {
            Decision::Allow if reasons.iter().all(|r| r == BASE_PERMIT) => Outcome::NoObjection,
            Decision::Deny => self.classify(&reasons),
            Decision::Allow => Outcome::Deny(Denial::Internal),
        })
    }

    fn classify(&self, reasons: &BTreeSet<String>) -> Outcome {
        let mut forbids = Vec::new();
        let mut undisclosed = false;
        let mut refs = BTreeSet::new();
        for r in reasons {
            let Some(m) = self.meta.get(r) else {
                return Outcome::Deny(Denial::Internal);
            };
            if let Some(reference) = &m.require {
                refs.insert(reference.clone());
            } else {
                forbids.push(m.id.clone());
                undisclosed |= m.undisclosed;
            }
        }
        if !forbids.is_empty() {
            forbids.sort();
            Outcome::Deny(Denial::Forbid {
                policies: forbids,
                undisclosed,
            })
        } else if refs.is_empty() {
            Outcome::Deny(Denial::Internal)
        } else {
            Outcome::Require(refs.into_iter().collect())
        }
    }
}

#[cfg(test)]
mod tests;
