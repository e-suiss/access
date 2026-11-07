//! `access-cli admin`: a generic client of the realm-admin surface (OP-151 m.3 (h)). Resource
//! names come from the compiled-in contract (`admin-v1.json`); a name it does not list is
//! refused before anything is sent. Reads use the DPoP-bound read token; `create`, `update` and
//! `retire` draft the write, check the draft, sign the AIS with the Instance key and send it:
//! one Exercise each (TN-110). A reserved write is refused here with a pointer to the proposal
//! path (`apply`), because this command line has no quorum (TN-122, E11).

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde_json::{Map, Value};

use super::{Connect, failed, load_key, note, out};
use crate::api::{self, Method, Operation};
use crate::client::{Client, System};
use crate::exit::{self, Code};
use crate::http::Https;

/// `admin` arguments.
#[derive(Debug, Args)]
pub(crate) struct AdminArgs {
    #[command(flatten)]
    pub(crate) connect: Connect,
    #[command(subcommand)]
    pub(crate) verb: Verb,
}

/// What to do with a resource.
#[derive(Debug, Subcommand)]
pub(crate) enum Verb {
    /// Reads one resource by its natural key, or a singleton such as `settings`.
    Get {
        /// The resource (`clients`, `groups`, `upstream-idps`, `accounts`, `settings`).
        resource: String,
        /// The natural key.
        key: Option<String>,
    },
    /// Lists a resource collection, every page.
    List {
        /// The resource.
        resource: String,
    },
    /// Creates a resource from a JSON body file: `POST` on the collection, or `PUT` by key.
    Create {
        /// The resource.
        resource: String,
        /// The natural key, when the resource is addressed by one.
        key: Option<String>,
        /// The JSON body file.
        #[arg(long, value_name = "PATH")]
        body: PathBuf,
    },
    /// Replaces (`PUT`) or merge-patches (`--patch`) a resource; the current `ETag` is read
    /// first and sent as `If-Match`.
    Update {
        /// The resource, or a settings section such as `settings/branding`.
        resource: String,
        /// The natural key.
        key: Option<String>,
        /// The JSON body file.
        #[arg(long, value_name = "PATH")]
        body: PathBuf,
        /// JSON Merge Patch (RFC 7396) instead of a replacement.
        #[arg(long)]
        patch: bool,
    },
    /// Retires a resource (`…/{key}/retire`): narrowing, CT1; nothing is deleted (OP-73).
    Retire {
        /// The resource.
        resource: String,
        /// The natural key.
        key: String,
    },
}

/// Why a command line names no operation.
fn unknown(resource: &str) -> Code {
    let known: Vec<&str> = api::contract().resources().into_iter().collect();
    note(&format!(
        "access-cli: no such operation on `{resource}`; the realm surface has: {}",
        known.join(", ")
    ));
    exit::USAGE
}

/// The operation a verb names, from the contract.
pub(crate) fn resolve(verb: &Verb) -> Result<(&'static Operation, Option<String>), Code> {
    let c = api::contract();
    let (resource, key, method, action) = match verb {
        Verb::Get { resource, key } => (resource, key.clone(), Method::Get, ""),
        Verb::List { resource } => (resource, None, Method::Get, ""),
        Verb::Create { resource, key, .. } => (
            resource,
            key.clone(),
            if key.is_some() {
                Method::Put
            } else {
                Method::Post
            },
            "",
        ),
        Verb::Update {
            resource,
            key,
            patch,
            ..
        } => (
            resource,
            key.clone(),
            if *patch { Method::Patch } else { Method::Put },
            "",
        ),
        Verb::Retire { resource, key } => (resource, Some(key.clone()), Method::Post, "/retire"),
    };
    let found = c.find(resource, method, key.is_some(), action);
    match (verb, found) {
        (Verb::List { .. }, Some(op)) if !op.writes() => Ok((op, None)),
        (Verb::List { .. }, _) => Err(unknown(resource)),
        (Verb::Get { .. }, Some(op)) if !op.writes() => Ok((op, key)),
        (_, Some(op)) if op.writes() || matches!(verb, Verb::Get { .. }) => Ok((op, key)),
        _ => Err(unknown(resource)),
    }
}

fn read_body(path: &PathBuf) -> Result<Map<String, Value>, Code> {
    let text = std::fs::read(path).map_err(|e| {
        note(&format!("access-cli: {}: {e}", path.display()));
        exit::CONFIG
    })?;
    if let Ok(Value::Object(m)) = serde_json::from_slice(&text) {
        Ok(m)
    } else {
        note(&format!(
            "access-cli: {}: not a JSON object",
            path.display()
        ));
        Err(exit::CONFIG)
    }
}

/// Runs `admin`.
pub(crate) async fn run(args: AdminArgs) -> Code {
    let (op, key) = match resolve(&args.verb) {
        Ok(x) => x,
        Err(c) => return c,
    };
    let target = match args.connect.target() {
        Ok(t) => t,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::USAGE;
        }
    };
    let instance = match load_key(&args.connect) {
        Ok(k) => k,
        Err(c) => return c,
    };
    let https = match Https::new(&args.connect.ca) {
        Ok(h) => h,
        Err(e) => {
            note(&format!("access-cli: {e}"));
            return exit::CONFIG;
        }
    };
    let client = Client::new(&https, &instance, &target, &System);
    let path = op.url_path(&target.realm, key.as_deref());
    match &args.verb {
        Verb::Get { .. } => match client.get(&path).await {
            Ok((v, _)) => out(&format!("{v:#}\n")),
            Err(e) => failed(&e),
        },
        Verb::List { .. } => match client.list(&path).await {
            Ok(items) => out(&format!("{:#}\n", Value::Array(items))),
            Err(e) => failed(&e),
        },
        Verb::Create { body, .. } | Verb::Update { body, .. } => {
            let body = match read_body(body) {
                Ok(b) => b,
                Err(c) => return c,
            };
            write(&client, op, key.as_deref(), &body, &path).await
        }
        Verb::Retire { .. } => write(&client, op, key.as_deref(), &Map::new(), &path).await,
    }
}

async fn write<T: crate::http::Transport, E: crate::client::Env>(
    client: &Client<'_, T, E>,
    op: &Operation,
    key: Option<&str>,
    body: &Map<String, Value>,
    path: &str,
) -> Code {
    let exists = matches!(op.method, Method::Patch) || op.action() == "/retire";
    let conditional = matches!(op.method, Method::Put | Method::Patch);
    let etag = if conditional {
        let get_path = if op.keyed() {
            path.to_owned()
        } else {
            path.rsplit_once('/').map_or(path, |(p, _)| p).to_owned()
        };
        match client.read(Method::Get, &get_path, None).await {
            Ok(r) if r.status == 200 => r.header("etag").map(String::from),
            Ok(r) if r.status == 404 && op.method == Method::Put => None,
            Ok(r) => {
                note(&format!(
                    "access-cli: reading the current version: {}",
                    r.status
                ));
                return exit::REMOTE;
            }
            Err(e) => return failed(&e),
        }
    } else {
        None
    };
    let exists = exists || etag.is_some();
    // TN-122, E11: a reserved write needs a quorum; this command line only proposes it
    if api::reserved(&op.id, exists) {
        note(&format!(
            "access-cli: `{}` is reserved (CT3); write a proposal with `access-cli apply` and have the quorum sign it",
            op.id
        ));
        return exit::FAILED;
    }
    match client.write(op, key, body, etag.as_deref()).await {
        Ok(w) => {
            note(&format!(
                "access-cli: committed as Exercise {} at position {}",
                w.exercise_id, w.position
            ));
            out(&format!("{:#}\n", w.body))
        }
        Err(e) => failed(&e),
    }
}
