//! One module per subcommand. Each exposes its `Args` (clap) and a `run` that returns an exit
//! code; `migrate` reads [`crate::config`], the management commands share [`Connect`] and the
//! runtime read.

pub(crate) mod admin;
pub(crate) mod apply;
pub(crate) mod diff;
pub(crate) mod export;
pub(crate) mod incident;
pub(crate) mod migrate;
pub(crate) mod realm;
pub(crate) mod relay;
pub(crate) mod replay;
pub(crate) mod ssh;

use std::io::Write as _;
use std::path::PathBuf;

use access_kernel::json::b64url_decode;
use access_kernel::meta::{ExerciseBasis, HoldingRef};
use access_kernel::model::Id;
use clap::Args;
use serde_json::{Map, Value};

use crate::client::{Client, ClientError, Env, Target};
use crate::exit::{self, Code};
use crate::gitops::{KINDS, Runtime};
use crate::http::Transport;
use crate::keys::{InstanceKey, KeySource, Pkcs11Uri};

/// Where the realm's management surface is and which Instance key the command line acts with
/// (OP-151 m.3 (c), (h)). There is deliberately no token option: reads use a DPoP-bound token the
/// key obtains, writes an AIS the key signs (TN-130).
#[derive(Debug, Args)]
pub(crate) struct Connect {
    /// The management API origin (`suiss.management_api`), `https://host[:port]`.
    #[arg(long, value_name = "URL")]
    pub(crate) api: String,
    /// The realm slug.
    #[arg(long, value_name = "SLUG")]
    pub(crate) realm: String,
    /// The realm issuer; its metadata names the token endpoint and the governing domain.
    #[arg(long, value_name = "URL")]
    pub(crate) issuer: String,
    /// PEM file of the CA the management API and the issuer chain to.
    #[arg(long, value_name = "PATH")]
    pub(crate) ca: PathBuf,
    #[command(flatten)]
    pub(crate) key: KeyArgs,
    /// The basis every AIS declares: `public:<GrantID>`, `anchor:<AnchorID>` or
    /// `holding:<GrantID>:<HolderPartyID>:<since>` (base64url ids). Reads carry an AIS too: the
    /// read token is exchanged for one.
    #[arg(long, value_name = "BASIS")]
    pub(crate) basis: String,
}

/// The Instance key: a file or a PKCS#11 object, exactly one.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub(crate) struct KeyArgs {
    /// PKCS#8 PEM file of the Instance's P-256 (or Ed25519) key.
    #[arg(long, value_name = "PATH")]
    pub(crate) key_file: Option<PathBuf>,
    /// RFC 7512 URI of the key in a PKCS#11 token:
    /// `pkcs11:token=…;object=…?module-path=…&pin-source=file:…`.
    #[arg(long, value_name = "URI")]
    pub(crate) pkcs11: Option<String>,
}

fn id16(text: &str) -> Option<Id> {
    let b = b64url_decode(text).ok()?;
    <[u8; 16]>::try_from(b.as_slice()).ok().map(Id)
}

/// Parses `--basis`.
pub(crate) fn basis(text: &str) -> Option<ExerciseBasis> {
    let mut parts = text.split(':');
    match (
        parts.next()?,
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        ("public", Some(g), None, None, None) => Some(ExerciseBasis::Public(id16(g)?)),
        ("anchor", Some(a), None, None, None) => Some(ExerciseBasis::Anchor(id16(a)?)),
        ("holding", Some(g), Some(h), Some(s), None) => Some(ExerciseBasis::Holding(HoldingRef {
            grant: id16(g)?,
            holder: id16(h)?,
            since: s.parse().ok()?,
        })),
        _ => None,
    }
}

impl Connect {
    /// The key source.
    pub(crate) fn key_source(&self) -> Result<KeySource, String> {
        match (&self.key.key_file, &self.key.pkcs11) {
            (Some(p), None) => Ok(KeySource::File(p.clone())),
            (None, Some(u)) => Pkcs11Uri::parse(u)
                .map(KeySource::Pkcs11)
                .map_err(|e| e.to_string()),
            _ => Err(String::from("exactly one of --key-file and --pkcs11")),
        }
    }

    /// The target.
    pub(crate) fn target(&self) -> Result<Target, String> {
        let basis =
            basis(&self.basis).ok_or_else(|| format!("--basis {} is not a basis", self.basis))?;
        if !self.api.starts_with("https://") || !self.issuer.starts_with("https://") {
            return Err(String::from("--api and --issuer must be https URLs"));
        }
        Ok(Target {
            api: self.api.clone(),
            realm: self.realm.clone(),
            issuer: self.issuer.clone(),
            basis,
        })
    }
}

/// Writes `text` to standard output.
pub(crate) fn out(text: &str) -> Code {
    let mut o = std::io::stdout().lock();
    if o.write_all(text.as_bytes())
        .and_then(|()| o.flush())
        .is_err()
    {
        return exit::FAILED;
    }
    exit::OK
}

/// Writes one line to standard error.
pub(crate) fn note(text: &str) {
    let _ = writeln!(std::io::stderr().lock(), "{text}");
}

/// The exit code and message of a client failure.
pub(crate) fn failed(e: &ClientError) -> Code {
    note(&format!("access-cli: {e}"));
    match e {
        ClientError::Problem { .. } | ClientError::Token(_) | ClientError::Http(_) => exit::REMOTE,
        _ => exit::FAILED,
    }
}

/// Reads the realm's runtime configuration: every resource list and the settings with their
/// `ETag` (reads only, TN-123 item 4).
pub(crate) async fn runtime<T: Transport, E: Env>(
    client: &Client<'_, T, E>,
    realm: &str,
) -> Result<Runtime, ClientError> {
    let base = format!("/admin/v1/realms/{}", crate::api::segment(realm));
    let mut lists = Map::new();
    for kind in KINDS {
        let items = client
            .list(&format!("{base}/{}?page%5Bsize%5D=100", kind.resource))
            .await?;
        lists.insert(kind.member.to_owned(), Value::Array(items));
    }
    let (settings, tag) = client.get(&format!("{base}/settings")).await?;
    let mut etags = Map::new();
    if let Some(t) = tag {
        etags.insert(String::from("settings"), Value::String(t));
    }
    Ok(Runtime {
        lists,
        settings,
        etags,
    })
}

/// Loads the key named by `connect`, or reports why not.
pub(crate) fn load_key(connect: &Connect) -> Result<InstanceKey, Code> {
    let source = connect.key_source().map_err(|e| {
        note(&format!("access-cli: {e}"));
        exit::USAGE
    })?;
    InstanceKey::load(&source).map_err(|e| {
        note(&format!("access-cli: {e}"));
        exit::CONFIG
    })
}
