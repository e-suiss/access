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

/// The management commands (OP-151 m.3 (h), TN-130).
mod management {
    use clap::{CommandFactory, Parser};

    use super::super::Cli;

    const CONNECT: [&str; 10] = [
        "--api",
        "https://mgmt.example:9443",
        "--realm",
        "acme",
        "--issuer",
        "https://login.example/realms/acme",
        "--basis",
        "public:AAAAAAAAAAAAAAAAAAAAAA",
        "--ca",
        "ca.pem",
    ];

    fn args(extra: &[&str]) -> Vec<String> {
        let mut v = vec!["access-cli".to_owned(), "admin".to_owned()];
        v.extend(CONNECT.iter().map(|s| (*s).to_owned()));
        v.extend(extra.iter().map(|s| (*s).to_owned()));
        v
    }

    // TN-130, MD-14, Ek B 3315: there is no bearer management token; clap rejects any token option
    #[test]
    fn no_bearer_or_token_option_exists() {
        for flag in ["--bearer", "--token", "--access-token", "--read-token"] {
            let a = args(&["--key-file", "k.pem", flag, "x", "list", "clients"]);
            assert!(Cli::try_parse_from(a).is_err(), "{flag} must not parse");
        }
        let mut cmd = Cli::command();
        for sub in ["admin", "export", "diff", "apply"] {
            let help = cmd
                .find_subcommand_mut(sub)
                .unwrap()
                .render_long_help()
                .to_string()
                .to_ascii_lowercase();
            assert!(
                !help.contains("--bearer") && !help.contains("--token"),
                "{sub}"
            );
        }
    }

    // TN-130, PI-11: automation is an Instance: exactly one key source, a file or PKCS#11
    #[test]
    fn the_instance_key_is_required_and_comes_from_one_source() {
        assert!(Cli::try_parse_from(args(&["list", "clients"])).is_err());
        assert!(
            Cli::try_parse_from(args(&[
                "--key-file",
                "k.pem",
                "--pkcs11",
                "pkcs11:token=a",
                "list",
                "clients"
            ]))
            .is_err()
        );
        assert!(Cli::try_parse_from(args(&["--key-file", "k.pem", "list", "clients"])).is_ok());
        assert!(
            Cli::try_parse_from(args(&[
                "--pkcs11",
                "pkcs11:token=a;object=b?module-path=/m&pin-source=file:/p",
                "get",
                "settings"
            ]))
            .is_ok()
        );
    }

    // TN-130, OP-151 m.18 (b): every read is exchanged for an AIS, so the basis is always
    // required, and there is no client id: the exchange takes no client authentication
    #[test]
    fn the_basis_is_required_and_no_client_id_exists() {
        let without: Vec<&str> = CONNECT
            .iter()
            .copied()
            .filter(|a| *a != "--basis" && !a.starts_with("public:"))
            .collect();
        let mut a = vec!["access-cli", "admin"];
        a.extend(&without);
        a.extend(["--key-file", "k.pem", "list", "clients"]);
        assert!(Cli::try_parse_from(&a).is_err());
        let a = args(&["--key-file", "k.pem", "--client-id", "x", "list", "clients"]);
        assert!(Cli::try_parse_from(a).is_err());
    }

    #[test]
    fn release_is_an_apply_option_that_excludes_a_document() {
        let mut a = vec!["access-cli".to_owned(), "apply".to_owned()];
        a.extend(CONNECT.iter().map(|s| (*s).to_owned()));
        a.extend(["--key-file", "k.pem"].map(String::from));
        let mut release = a.clone();
        release.extend(["--release", "clients/c-1"].map(String::from));
        assert!(Cli::try_parse_from(&release).is_ok());
        let mut both = release.clone();
        both.extend(["--file", "realm.yaml"].map(String::from));
        assert!(Cli::try_parse_from(&both).is_err());
        assert!(Cli::try_parse_from(&a).is_err());
    }
}
