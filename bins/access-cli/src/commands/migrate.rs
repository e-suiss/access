//! `access-cli migrate` (OP-55, OP-138, OP-50): applies the schema migrations as the
//! `access_migrator` login, from a job of its own and never at server start, then prints the
//! migrations this run applied as one JSON line on standard output. Applied migrations are
//! skipped, so a second run applies nothing. Migrations are expand/contract: a release only adds
//! what the running version ignores, and removes nothing the running version still reads; an
//! index on a live table is built `CONCURRENTLY` in a migration of its own that starts with
//! `-- no-transaction` (`cargo xtask check`, rule `migration-hygiene`).

use std::io::Write as _;
use std::path::Path;

use access_crypto::secret_file::SecretFile;
use access_store::connect::{
    Applied, Durability as StoreDurability, Target, check_server, migrate_listed, options, pool,
};

use crate::config::{Durability, File};
use crate::exit::{self, Code};

/// `migrate` takes no options of its own.
#[derive(Debug, clap::Args)]
pub(crate) struct Args {}

/// Why the job stopped.
#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("configuration: {0}")]
    Config(String),
    #[error("database: {0}")]
    Database(String),
    #[error("migration: {0}")]
    Migration(String),
}

impl Failure {
    const fn code(&self) -> Code {
        match self {
            Self::Config(_) => exit::CONFIG,
            Self::Database(_) => exit::DATABASE,
            Self::Migration(_) => exit::FAILED,
        }
    }
}

const fn durability(d: Durability) -> StoreDurability {
    match d {
        Durability::Replicated => StoreDurability::Replicated,
        Durability::SingleNode => StoreDurability::SingleNode,
    }
}

/// The JSON line the job prints: the applied migrations, oldest first; versions are strings
/// (OP-65: 64-bit integers).
pub(crate) fn report(applied: &[Applied]) -> String {
    let items: Vec<serde_json::Value> = applied
        .iter()
        .map(|a| serde_json::json!({ "version": a.version.to_string(), "description": a.description }))
        .collect();
    serde_json::json!({ "applied": items }).to_string()
}

async fn apply(config: &Path) -> Result<Vec<Applied>, Failure> {
    let file = File::load(config).map_err(|e| Failure::Config(e.to_string()))?;
    let (db, role) = file
        .migration()
        .map_err(|e| Failure::Config(e.to_string()))?;
    let root = std::fs::read(&db.root_cert_file)
        .map_err(|e| Failure::Config(format!("{}: {}", db.root_cert_file.display(), e.kind())))?;
    let password =
        SecretFile::load(&role.password_file).map_err(|e| Failure::Config(e.to_string()))?;
    let target = Target {
        host: &db.host,
        port: db.port,
        database: &db.name,
        user: &role.user,
        password: password.value().expose(),
        root_cert: &root,
    };
    let migrator = pool(options(&target), 1)
        .await
        .map_err(|e| Failure::Database(format!("{}: {e}", role.user)))?;
    // OP-52
    check_server(&migrator, 1, true, durability(db.durability), None)
        .await
        .map_err(|e| Failure::Database(e.to_string()))?;
    migrate_listed(&migrator)
        .await
        .map_err(|e| Failure::Migration(e.to_string()))
}

/// Runs the job with the configuration at `config`.
pub(crate) fn run(config: &Path, _: &Args) -> Code {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return exit::FAILED;
        }
    };
    match runtime.block_on(apply(config)) {
        Ok(applied) => {
            tracing::info!(
                applied = applied.len(),
                known = access_store::MIGRATOR.iter().count(),
                "schema migrated (OP-55)"
            );
            let mut out = std::io::stdout().lock();
            if writeln!(out, "{}", report(&applied)).is_err() {
                return exit::FAILED;
            }
            exit::OK
        }
        Err(failure) => {
            tracing::error!(error = %failure, "migration job failed");
            failure.code()
        }
    }
}
