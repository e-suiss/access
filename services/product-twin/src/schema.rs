//! A product's seam schema (§7.9.10.3): its action namespace with typed Action Schemas and their
//! parameter classes, and the Claim classes it issues with the Acceptance use each one asks of a
//! domain. The files are data, `conformance/seams/schemas/<product>.toml`; nothing in Access is
//! hardcoded to a product (OP-156 m.3 (u)).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::claim::{ACTOR_BINDING, PREDICATE_INPUT, SUBJECT_SELECTION};
use access_kernel::codec::Canonical as _;
use access_kernel::model::{ActionRef, Id};
use access_kernel::schema::{ActionSchema, EffectClass, Reversibility, Spp, action_digest};
use serde::Deserialize;
use serde_json::{Value as Json, json};

/// Why a seam schema does not load.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// Not TOML of this shape.
    #[error("schema file: {0}")]
    File(String),
    /// A value outside the Kernel's types: a seam needs no new primitive (§7.9.10.3).
    #[error("schema {0}: {1}")]
    Invalid(String, &'static str),
}

/// The parameter classes of the publication contract (L1-ADP-18, E12).
const PARAM_CLASSES: [&str; 6] = ["opaque", "recipient", "amount", "count", "choice", "flag"];

/// The Claim value types a seam Claim may carry.
const VALUE_TYPES: [&str; 5] = ["bool", "text", "int", "bytes", "none"];

/// The Acceptance uses a product Claim may ask for; `schema-definition` is the schema itself and
/// `foreign-authority` is another domain's, never a product's (§7.9.10.3).
const CLAIM_USES: [&str; 3] = [PREDICATE_INPUT, SUBJECT_SELECTION, ACTOR_BINDING];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    product: String,
    namespace: String,
    catalog_version: u64,
    #[serde(default)]
    truth: Vec<String>,
    #[serde(default)]
    actions: Vec<ActionFile>,
    #[serde(default)]
    claims: Vec<ClaimFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionFile {
    name: String,
    major: u64,
    effect_class: String,
    #[serde(default)]
    reserved: bool,
    #[serde(default)]
    consumption_bearing: bool,
    #[serde(default)]
    params: BTreeMap<String, String>,
    #[serde(default)]
    classes: BTreeMap<String, String>,
    #[serde(default)]
    resource_types: BTreeSet<String>,
    render: Option<String>,
    reversibility: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimFile {
    class: String,
    value: String,
    #[serde(rename = "use")]
    use_: String,
    #[serde(default)]
    meaning: String,
}

/// A Claim class the product issues as its own issuer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimClass {
    /// The class name: an untabled Claim class, a general value Claim (OP-156 m.3 (b)).
    pub class: String,
    /// Its value type.
    pub value: String,
    /// The Acceptance use a domain gives it.
    pub use_: String,
    /// What it means, in the product's words.
    pub meaning: String,
}

/// A loaded seam schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schema {
    /// The product's display name.
    pub product: String,
    /// The action namespace.
    pub namespace: String,
    /// Its catalog version.
    pub catalog_version: u64,
    /// The domain truth the product keeps (§2.6 Test A); informational.
    pub truth: Vec<String>,
    /// The Action Schemas.
    pub actions: Vec<ActionSchema>,
    /// Each action's parameter classes.
    pub classes: BTreeMap<String, BTreeMap<String, String>>,
    /// The Claim classes it issues.
    pub claims: Vec<ClaimClass>,
}

fn effect(word: &str) -> Option<EffectClass> {
    match word {
        "none" => Some(EffectClass::None),
        "reversible" => Some(EffectClass::Reversible),
        "irreversible" => Some(EffectClass::Irreversible),
        _ => None,
    }
}

fn action(
    a: ActionFile,
    at: &str,
) -> Result<(ActionSchema, BTreeMap<String, String>), SchemaError> {
    let bad = |why| SchemaError::Invalid(format!("{at}.{}", a.name), why);
    let effect = effect(&a.effect_class).ok_or_else(|| bad("effect_class"))?;
    let reversibility = a
        .reversibility
        .as_deref()
        .map(|r| Reversibility::of_name(r).ok_or_else(|| bad("reversibility")))
        .transpose()?;
    if a.params.keys().collect::<BTreeSet<_>>() != a.classes.keys().collect::<BTreeSet<_>>() {
        return Err(bad("classes"));
    }
    if a.classes
        .values()
        .any(|c| !PARAM_CLASSES.contains(&c.as_str()))
    {
        return Err(bad("classes"));
    }
    let schema = ActionSchema {
        name: a.name.clone(),
        major: a.major,
        effect,
        reserved: a.reserved,
        consumption_bearing: a.consumption_bearing,
        params: a.params,
        resource_types: a.resource_types,
        render: a.render,
        reversibility,
    };
    // §7.9.10.3
    let round = ActionSchema::from_value(&schema.to_value()).map_err(|_| bad("kernel"))?;
    if round != schema {
        return Err(bad("kernel"));
    }
    Ok((schema, a.classes))
}

impl Schema {
    /// Loads a seam schema file's text.
    ///
    /// # Errors
    /// [`SchemaError`].
    pub fn parse(text: &str) -> Result<Self, SchemaError> {
        let f: File = toml::from_str(text).map_err(|e| SchemaError::File(e.to_string()))?;
        let at = f.namespace.clone();
        let mut actions = Vec::new();
        let mut classes = BTreeMap::new();
        for a in f.actions {
            let (schema, c) = action(a, &at)?;
            if classes.insert(schema.name.clone(), c).is_some() {
                return Err(SchemaError::Invalid(at, "duplicate action"));
            }
            actions.push(schema);
        }
        let mut claims = Vec::new();
        for c in f.claims {
            if !VALUE_TYPES.contains(&c.value.as_str()) || !CLAIM_USES.contains(&c.use_.as_str()) {
                return Err(SchemaError::Invalid(format!("{at}:{}", c.class), "claim"));
            }
            if access_kernel::claim::body::Class::parse(&c.class).is_some() {
                return Err(SchemaError::Invalid(format!("{at}:{}", c.class), "tabled"));
            }
            claims.push(ClaimClass {
                class: c.class,
                value: c.value,
                use_: c.use_,
                meaning: c.meaning,
            });
        }
        let s = Self {
            product: f.product,
            namespace: f.namespace,
            catalog_version: f.catalog_version,
            truth: f.truth,
            actions,
            classes,
            claims,
        };
        if !s.actions.is_empty() {
            s.spp(Id([0; 16]))
                .ok_or(SchemaError::Invalid(at, "package"))?;
        }
        Ok(s)
    }

    /// The Schema Publication Package `publisher` publishes (OP-141 m.35 (a)); `None` when the
    /// Kernel refuses it.
    #[must_use]
    pub fn spp(&self, publisher: Id) -> Option<Spp> {
        let spp = Spp {
            publisher,
            namespace: self.namespace.clone(),
            catalog_version: self.catalog_version,
            actions: self.actions.clone(),
            retirements: BTreeSet::new(),
            core_spec_min: None,
        };
        Spp::from_value(&spp.to_value()).ok()
    }

    /// The `package` member of a publish request (L1-ADP-18).
    #[must_use]
    pub fn package(&self) -> Json {
        let actions: Vec<Json> = self.actions.iter().map(action_json).collect();
        let classes: Vec<Json> = self
            .classes
            .iter()
            .flat_map(|(a, ps)| {
                ps.iter()
                    .map(move |(p, c)| json!({ "action": a, "parameter": p, "class": c }))
            })
            .collect();
        json!({
            "namespace": self.namespace,
            "catalog_version": self.catalog_version,
            "actions": actions,
            "classes": classes,
        })
    }

    /// The reference of action `name`, pinned by its schema digest.
    #[must_use]
    pub fn action(&self, name: &str) -> Option<ActionRef> {
        self.actions
            .iter()
            .find(|a| a.name == name)
            .map(|a| ActionRef {
                namespace: self.namespace.clone(),
                name: a.name.clone(),
                major: a.major,
                schema: action_digest(a),
            })
    }

    /// The Claim class `class` the product issues.
    #[must_use]
    pub fn claim(&self, class: &str) -> Option<&ClaimClass> {
        self.claims.iter().find(|c| c.class == class)
    }
}

fn action_json(a: &ActionSchema) -> Json {
    let mut o = serde_json::Map::new();
    o.insert(String::from("name"), json!(a.name));
    o.insert(String::from("major"), json!(a.major));
    o.insert(
        String::from("effect_class"),
        json!(match a.effect {
            EffectClass::None => "none",
            EffectClass::Reversible => "reversible",
            EffectClass::Irreversible => "irreversible",
        }),
    );
    if a.reserved {
        o.insert(String::from("reserved"), json!(true));
    }
    if a.consumption_bearing {
        o.insert(String::from("consumption_bearing"), json!(true));
    }
    if !a.params.is_empty() {
        o.insert(String::from("params"), json!(a.params));
    }
    if !a.resource_types.is_empty() {
        o.insert(String::from("resource_types"), json!(a.resource_types));
    }
    if let Some(r) = &a.render {
        o.insert(String::from("render"), json!(r));
    }
    if let Some(r) = a.reversibility {
        o.insert(String::from("reversibility"), json!(r.name()));
    }
    Json::Object(o)
}
