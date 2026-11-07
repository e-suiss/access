#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;
use crate::config::{ConfigError, Durability, File};

// OP-151 m.3 (h): `migrate` is a subcommand; the configuration is named by path
#[test]
fn the_command_line_names_files_not_secrets() {
    let cli =
        Cli::try_parse_from(["access-cli", "migrate", "--config", "/etc/access.toml"]).unwrap();
    assert!(matches!(cli.command, Command::Migrate(_)));
    assert_eq!(cli.config, PathBuf::from("/etc/access.toml"));
    let defaults = Cli::try_parse_from(["access-cli", "migrate"]).unwrap();
    assert_eq!(defaults.config, PathBuf::from("access.toml"));
    for args in [
        &["access-cli"][..],
        &["access-cli", "migrate", "--password", "x"],
        &[
            "access-cli",
            "migrate",
            "--database-url",
            "postgres://u:p@h/db",
        ],
        &["access-cli", "serve"],
    ] {
        assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
    }
}

fn config(text: &str) -> tempfile_like::Path {
    tempfile_like::write(text)
}

/// A file under the system temporary directory, removed when dropped.
mod tempfile_like {
    pub(super) struct Path(pub(super) std::path::PathBuf);

    impl Drop for Path {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    pub(super) fn write(text: &str) -> Path {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("access-cli-{}-{n}.toml", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        std::io::Write::write_all(&mut f, text.as_bytes()).unwrap();
        Path(p)
    }
}

const DATABASE: &str = r#"
listen = "127.0.0.1:8443"
[telemetry]
log_format = "json"
[database]
host = "db.internal"
port = 5432
name = "access"
root_cert_file = "/run/tls/db-root.pem"
durability = "single-node"
"#;

// OP-55: the server's own configuration serves the job; the migration role must be named
#[test]
fn the_job_reads_the_servers_configuration() {
    let without = config(DATABASE);
    let f = File::load(&without.0).unwrap();
    assert!(matches!(
        f.migration(),
        Err(ConfigError::Missing("database.migrator"))
    ));
    let with = config(&format!(
        "{DATABASE}[database.migrator]\nuser = \"access_migrator_login\"\npassword_file = \"/run/secrets/migrator\"\n"
    ));
    let f = File::load(&with.0).unwrap();
    let (db, role) = f.migration().unwrap();
    assert_eq!(db.durability, Durability::SingleNode);
    assert_eq!(role.user, "access_migrator_login");
    let none = config("listen = \"127.0.0.1:8443\"\n");
    assert!(matches!(
        File::load(&none.0).unwrap().migration(),
        Err(ConfigError::Missing("database"))
    ));
}

// OP-55: a configuration that cannot be used stops the job with its own exit code, before any
// connection
#[test]
fn an_unusable_configuration_exits_with_the_config_code() {
    let missing = std::env::temp_dir().join(format!("access-cli-none-{}.toml", std::process::id()));
    assert_eq!(
        commands::migrate::run(&missing, &commands::migrate::Args {}),
        exit::CONFIG
    );
    let no_role = config(DATABASE);
    assert_eq!(
        commands::migrate::run(&no_role.0, &commands::migrate::Args {}),
        exit::CONFIG
    );
}

// OP-55, OP-65: the job prints one JSON line; versions are strings
#[test]
fn the_report_is_one_json_line() {
    let applied = [access_store::connect::Applied {
        version: 20_261_107_160_000,
        description: String::from("m2 \"sandbox\" domains"),
    }];
    let line = commands::migrate::report(&applied);
    assert!(!line.contains('\n'));
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["applied"][0]["version"], "20261107160000");
    assert_eq!(v["applied"][0]["description"], "m2 \"sandbox\" domains");
    assert_eq!(commands::migrate::report(&[]), r#"{"applied":[]}"#);
}
