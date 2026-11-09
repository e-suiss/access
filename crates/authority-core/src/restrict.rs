//! Restriction policies on the commit path (OP-104, OP-141 m.27): Access's Cedar schema, the
//! request it gives the engine, and the engine's answer as Kernel policy results.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, PolicyResult, Rejection};
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::{Actor, ContentState, RESTRICTION_SCHEMA};
use access_kernel::model::{Id, RequirementTerm};
use access_kernel::restriction::{PolicyDeny, RestrictionOutcome};
use suiss_crypto::dcbor::{self, Limits as Cbor, Value};
use suiss_restriction::{Denial, Engine, Limits, Outcome, RequestJson};

pub mod patterns;

/// Access's restriction schema `access/restriction/v1` (OP-141 m.27 (a)).
pub const SCHEMA: &str = r#"entity Instance = { party: String };
entity Anonymous;
entity Resource = { namespace: String, path: String };
action "exercise" appliesTo {
  principal: [Instance, Anonymous],
  resource: [Resource],
  context: {
    now: Long,
    action: String,
    capacity: String,
    untrusted: Set<String>,
    actor: String,
    tier: Long,
  }
};"#;

/// What the decision path knows about a request beyond its intent (E54 (1), §11.19): whether
/// the actor is an agent and the intent's consequence tier. The restriction context names them
/// `actor` (`agent`, `person` or `anonymous`) and `tier` (0 to 3), beside `untrusted`, the typed
/// parameters whose provenance is `untrusted-external`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// The actor is an agent Instance.
    pub agent: bool,
    /// The consequence tier, 0 to 3.
    pub tier: u8,
}

/// Compiled policies by version; `None` marks a policy that does not compile.
#[derive(Default)]
pub struct Cache(Mutex<BTreeMap<[u8; 32], Option<Arc<Engine>>>>);

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cache")
    }
}

/// A policy's version: the digest of its content under `access/policy/v1` (L0-META-29).
#[must_use]
pub fn version(content: &Value) -> Digest {
    let bytes = dcbor::encode(content, Cbor::CEILING).unwrap_or_default();
    Digest(suiss_crypto::digest::context_digest("access/policy/v1", &bytes).0)
}

/// Compiles a policy's source against Access's schema.
///
/// # Errors
/// The engine's compile error code.
pub fn compile(content: &Value) -> Result<Engine, &'static str> {
    match content.get("schema") {
        Some(Value::Text(s)) if s == RESTRICTION_SCHEMA => {}
        _ => return Err("policy-schema"),
    }
    let Some(Value::Text(source)) = content.get("source") else {
        return Err("policy-source");
    };
    let engine = Engine::compile(SCHEMA, source, Limits::default()).map_err(|e| e.code())?;
    let known = requirement_sets(content);
    let missing = engine.policies().is_none_or(|ps| {
        ps.iter()
            .any(|p| p.require.is_some_and(|r| !known.contains_key(r)))
    });
    if missing {
        return Err("policy-require");
    }
    Ok(engine)
}

fn requirement_sets(content: &Value) -> BTreeMap<String, BTreeSet<RequirementTerm>> {
    let mut out = BTreeMap::new();
    if let Some(Value::Map(refs)) = content.get("requirements") {
        for (k, v) in refs {
            if let (Value::Text(name), Value::Array(terms)) = (k, v) {
                let set: BTreeSet<RequirementTerm> = terms
                    .iter()
                    .filter_map(|t| RequirementTerm::from_value(t).ok())
                    .collect();
                out.insert(name.clone(), set);
            }
        }
    }
    out
}

impl Cache {
    fn engine(&self, version: &Digest, content: &Value) -> Option<Arc<Engine>> {
        let mut map = self.0.lock().ok()?;
        map.entry(version.0)
            .or_insert_with(|| compile(content).ok().map(Arc::new))
            .clone()
    }
}

fn quoted(s: &str) -> String {
    serde_json::Value::from(s).to_string()
}

/// The restriction context of a request (OP-141 m.27 (a), E54 (1), §11.19).
fn context(
    intent: &IntentEnvelope,
    (actor, capacity): (Option<&Actor>, Capacity),
    facts: Facts,
    now: u64,
) -> String {
    let untrusted: Vec<&String> = intent
        .params
        .keys()
        .filter(|k| intent.provenance_of(k) == access_kernel::intent::Provenance::UntrustedExternal)
        .collect();
    let who = match (actor, facts.agent) {
        (None, _) => "anonymous",
        (Some(_), true) => "agent",
        (Some(_), false) => "person",
    };
    serde_json::json!({
        "now": i64::try_from(now / 1_000).unwrap_or(i64::MAX),
        "action": format!("{}:{}", intent.action.namespace, intent.action.name),
        "capacity": if capacity == Capacity::Own { "own" } else { "for" },
        "untrusted": untrusted,
        "actor": who,
        "tier": facts.tier,
    })
    .to_string()
}

/// The engine's answer for each live policy that applies, as Kernel policy results
/// (L0-EVAL-18, OP-141 m.27 (c)–(f)).
///
/// # Errors
/// [`Rejection::Input`] when the engine refuses the input.
pub fn results(
    policies: &[(Id, ContentState)],
    intent: &IntentEnvelope,
    actor: Option<&Actor>,
    capacity: Capacity,
    now: u64,
    cache: &Cache,
) -> Result<Vec<PolicyResult>, Rejection> {
    results_with(
        policies,
        intent,
        (actor, capacity),
        Facts::default(),
        now,
        cache,
    )
}

/// [`results`] with what the decision path knows about the actor and the tier.
///
/// # Errors
/// [`Rejection::Input`] when the engine refuses the input.
pub fn results_with(
    policies: &[(Id, ContentState)],
    intent: &IntentEnvelope,
    (actor, capacity): (Option<&Actor>, Capacity),
    facts: Facts,
    now: u64,
    cache: &Cache,
) -> Result<Vec<PolicyResult>, Rejection> {
    if policies.is_empty() {
        return Ok(Vec::new());
    }
    let resource = intent.resources.first().ok_or(Rejection::Input)?;
    let path = resource.path.join("/");
    let resource_id = format!("{}/{path}", resource.namespace);
    let hex = |id: &Id| {
        id.0.iter().fold(String::with_capacity(32), |mut out, b| {
            let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
            out
        })
    };
    let (principal, principal_entity) = match actor {
        Some(a) => (
            format!("Instance::{}", quoted(&hex(&a.instance))),
            serde_json::json!({
                "uid": { "type": "Instance", "id": hex(&a.instance) },
                "attrs": { "party": hex(&a.party) },
                "parents": []
            }),
        ),
        None => (
            String::from(r#"Anonymous::"anonymous""#),
            serde_json::json!({ "uid": { "type": "Anonymous", "id": "anonymous" }, "attrs": {}, "parents": [] }),
        ),
    };
    let entities = serde_json::json!([
        principal_entity,
        {
            "uid": { "type": "Resource", "id": resource_id },
            "attrs": { "namespace": resource.namespace, "path": path },
            "parents": []
        }
    ])
    .to_string();
    let context = context(intent, (actor, capacity), facts, now);
    let request = RequestJson {
        principal: &principal,
        action: r#"Action::"exercise""#,
        resource: &format!("Resource::{}", quoted(&resource_id)),
        context: &context,
        entities: &entities,
    };
    let mut out = Vec::with_capacity(policies.len());
    for (id, state) in policies {
        let version = version(&state.content);
        let deny = |undisclosed| {
            RestrictionOutcome::Deny(PolicyDeny {
                policy: *id,
                version,
                undisclosed,
            })
        };
        // OP-104 m.2
        let outcome = match cache.engine(&version, &state.content) {
            None => deny(false),
            Some(engine) => match engine.evaluate(&request).map_err(|_| Rejection::Input)? {
                Outcome::NoObjection => RestrictionOutcome::NoObjection,
                Outcome::Deny(Denial::Forbid { undisclosed, .. }) => deny(undisclosed),
                Outcome::Deny(_) => deny(false),
                Outcome::Require(refs) => {
                    let sets = requirement_sets(&state.content);
                    let mut terms = BTreeSet::new();
                    let mut unknown = false;
                    for r in refs {
                        match sets.get(&r) {
                            Some(set) => terms.extend(set.iter().cloned()),
                            None => unknown = true,
                        }
                    }
                    if unknown {
                        deny(false)
                    } else {
                        RestrictionOutcome::Require(terms)
                    }
                }
            },
        };
        out.push(PolicyResult {
            policy: *id,
            version,
            outcome,
        });
    }
    Ok(out)
}
