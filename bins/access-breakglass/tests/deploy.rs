//! The operator role's shipped configuration (SEC19, SA-51, OP-157 m.3 (k)).

#![allow(clippy::unwrap_used, reason = "test code")]

use std::path::Path;

fn read(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(name),
    )
    .unwrap()
}

// SEC19, OP-157 m.3 (k), OP-54-RL10
#[test]
fn sec19_operator_database_reads_are_logged_and_never_a_standing_admin() {
    let sql = read("crates/store/bootstrap/operator.sql");
    for setting in [
        "ALTER ROLE access_operator SET log_statement = 'all';",
        "ALTER ROLE access_operator SET log_connections = 'on';",
        "ALTER ROLE access_operator SET log_disconnections = 'on';",
        "ALTER ROLE access_operator SET default_transaction_read_only = 'on';",
        "ALTER ROLE access_operator PASSWORD NULL;",
    ] {
        assert!(sql.contains(setting), "{setting}");
    }
    let create = sql
        .lines()
        .skip_while(|l| !l.contains("CREATE ROLE access_operator"))
        .take(2)
        .collect::<String>();
    for word in [
        "NOSUPERUSER",
        "NOCREATEROLE",
        "NOBYPASSRLS",
        "NOREPLICATION",
    ] {
        assert!(create.contains(word), "{word}");
    }
    let upper = sql
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_uppercase();
    for never in ["GRANT ", "SUPERUSER LOGIN", "PASSWORD '"] {
        assert!(!upper.contains(never), "{never}");
    }
    let hba = read("deploy/breakglass/pg_hba-operator.conf");
    let rules: Vec<&str> = hba
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .collect();
    assert_eq!(rules.len(), 2);
    for rule in rules {
        let f: Vec<&str> = rule.split_whitespace().collect();
        assert_eq!(f.first(), Some(&"hostssl"), "{rule}");
        assert_eq!(f.get(2), Some(&"access_operator"), "{rule}");
        assert_eq!(f.get(4), Some(&"cert"), "{rule}");
    }
}
