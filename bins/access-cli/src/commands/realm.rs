//! `access-cli realm apply-template` (OP-153 m.3 (r), §10.9.2): a realm template is data
//! (`deploy/realm-templates/*.toml`), a list of realm settings writes. Each step is its own
//! Exercise signed with the Instance key, and the first failure stops the run; a step already
//! committed stays committed. Rules a template carries that the settings cannot express yet are
//! printed, never silently dropped.

use std::path::Path;

use clap::{Args, Subcommand};
use figment::Figment;
use figment::providers::{Format as _, Toml};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::admin::write;
use super::{Connect, load_key, note};
use crate::api::{self, Method, Operation};
use crate::client::{Client, System};
use crate::exit::{self, Code};
use crate::http::Https;

/// The templates shipped with this command line, by name (OP-153 m.3 (r)).
pub(crate) const TEMPLATES: [(&str, &str); 10] = [
    (
        "b2c",
        include_str!("../../../../deploy/realm-templates/b2c.toml"),
    ),
    (
        "b2b-saas",
        include_str!("../../../../deploy/realm-templates/b2b-saas.toml"),
    ),
    (
        "workforce",
        include_str!("../../../../deploy/realm-templates/workforce.toml"),
    ),
    (
        "finance",
        include_str!("../../../../deploy/realm-templates/finance.toml"),
    ),
    (
        "health",
        include_str!("../../../../deploy/realm-templates/health.toml"),
    ),
    (
        "public",
        include_str!("../../../../deploy/realm-templates/public.toml"),
    ),
    (
        "ecommerce",
        include_str!("../../../../deploy/realm-templates/ecommerce.toml"),
    ),
    (
        "mobile",
        include_str!("../../../../deploy/realm-templates/mobile.toml"),
    ),
    (
        "devplatform",
        include_str!("../../../../deploy/realm-templates/devplatform.toml"),
    ),
    (
        "tr-payment",
        include_str!("../../../../deploy/realm-templates/tr-payment.toml"),
    ),
];

/// `realm` arguments.
#[derive(Debug, Args)]
pub(crate) struct RealmArgs {
    #[command(subcommand)]
    pub(crate) verb: RealmVerb,
}

/// What to do with the realm.
#[derive(Debug, Subcommand)]
pub(crate) enum RealmVerb {
    /// Applies a realm template: each setting its own Exercise, stopping at the first failure.
    ApplyTemplate {
        #[command(flatten)]
        connect: Connect,
        /// A shipped template's name (`b2c`, `b2b-saas`, `workforce`, `finance`, `health`,
        /// `public`, `ecommerce`, `mobile`, `devplatform`, `tr-payment`) or a template file.
        template: String,
    },
}

/// A realm template.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Template {
    /// Its name.
    pub(crate) name: String,
    /// What it is for.
    pub(crate) description: String,
    /// Rules the realm settings cannot express yet.
    #[serde(default)]
    pub(crate) notes: Vec<String>,
    /// The writes, in order.
    pub(crate) step: Vec<Step>,
}

/// One settings write of a template.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Step {
    /// The settings resource, such as `settings/signin-policy`.
    pub(crate) resource: String,
    /// The replacement body.
    pub(crate) body: Map<String, Value>,
}

/// Parses a template's TOML.
pub(crate) fn parse(text: &str) -> Result<Template, String> {
    let t: Template = Figment::from(Toml::string(text))
        .extract()
        .map_err(|e| e.to_string())?;
    if t.step.is_empty() {
        return Err(String::from("a template has at least one step"));
    }
    Ok(t)
}

/// The template `name` names: a shipped one, else a file.
fn load(name: &str) -> Result<Template, Code> {
    let text = match TEMPLATES.iter().find(|(n, _)| *n == name) {
        Some((_, t)) => (*t).to_owned(),
        None => std::fs::read_to_string(Path::new(name)).map_err(|e| {
            note(&format!("access-cli: template `{name}`: {e}"));
            exit::CONFIG
        })?,
    };
    parse(&text).map_err(|e| {
        note(&format!("access-cli: template `{name}`: {e}"));
        exit::CONFIG
    })
}

/// The replacing write of a settings step, from the contract.
pub(crate) fn operation(step: &Step) -> Option<&'static Operation> {
    api::contract()
        .find(&step.resource, Method::Put, false, "")
        .filter(|op| op.writes())
}

/// Runs `realm`.
pub(crate) async fn run(args: RealmArgs) -> Code {
    let RealmVerb::ApplyTemplate { connect, template } = args.verb;
    let template = match load(&template) {
        Ok(t) => t,
        Err(c) => return c,
    };
    let mut ops = Vec::with_capacity(template.step.len());
    for step in &template.step {
        let Some(op) = operation(step) else {
            note(&format!(
                "access-cli: template `{}`: no settings write `{}`",
                template.name, step.resource
            ));
            return exit::CONFIG;
        };
        ops.push(op);
    }
    note(&format!(
        "access-cli: applying `{}`: {}",
        template.name, template.description
    ));
    for n in &template.notes {
        note(&format!(
            "access-cli: not expressible yet, apply by hand: {n}"
        ));
    }
    let target = match connect.target() {
        Ok(t) => t,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::USAGE;
        }
    };
    let instance = match load_key(&connect) {
        Ok(k) => k,
        Err(c) => return c,
    };
    let https = match Https::new(&connect.ca) {
        Ok(h) => h,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::CONFIG;
        }
    };
    let client = Client::new(&https, &instance, &target, &System);
    for (step, op) in template.step.iter().zip(ops) {
        let path = op.url_path(&target.realm, None);
        let code = write(&client, op, None, &step.body, &path).await;
        if code != exit::OK {
            note(&format!(
                "access-cli: stopped at `{}`; the steps before it stay committed",
                step.resource
            ));
            return code;
        }
    }
    exit::OK
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-153 m.3 (r), §10.9.2, Ek B 3581, 3582
    #[test]
    fn every_shipped_template_is_a_list_of_valid_settings_writes() {
        let declared = access_identity_oauth::adapters::outbound::DeclaredTargets::default();
        let ids = access_crypto::opaque_id::IdKey::new(access_crypto::Secret::new([1; 32]));
        for (name, text) in TEMPLATES {
            let t = parse(text).unwrap();
            assert_eq!(t.name, name);
            for step in &t.step {
                let op = operation(step).unwrap_or_else(|| panic!("{name}: {}", step.resource));
                let rest = access_identity_admin::app::rest::Op::from_operation(&op.id).unwrap();
                let change = access_identity_admin::app::rest::compile(
                    rest,
                    None,
                    &Value::Object(step.body.clone()),
                    &ids,
                )
                .unwrap_or_else(|e| panic!("{name}: {}: {e}", step.resource));
                change
                    .check(&declared)
                    .unwrap_or_else(|e| panic!("{name}: {}: {e}", step.resource));
            }
        }
        // OP-153 m.3 (r): the payment template carries the GKD rules it cannot express yet
        let tr = parse(TEMPLATES[9].1).unwrap();
        assert!(tr.notes.iter().any(|n| n.contains("biometrics alone")));
        assert!(tr.notes.iter().any(|n| n.contains("SMS")));
        assert!(tr.notes.iter().any(|n| n.contains("90 days")));
        assert!(parse("name = \"x\"\ndescription = \"y\"\nstep = []\n").is_err());
    }
}
