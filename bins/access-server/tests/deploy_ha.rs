//! Configuration-output tests of the cell's HA and backup deployment (OP-24, OP-25, OP-57,
//! SA-47, FA-13, OP-158 m.3 (n), (r)): the `CloudNativePG` and Patroni templates and the `pgBackRest`
//! configuration say what the spec asks. The multi-zone cluster and the object store are the
//! operator's; these tests check what Access ships.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::path::PathBuf;

fn read(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
    std::fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn has(text: &str, line: &str) -> bool {
    text.lines().any(|l| l.trim() == line)
}

fn value(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(&format!("{key}: ")))
        .and_then(|v| v.trim().parse().ok())
}

// OP-24, OP-25, FA-1, FA-13, SA-47, Ek B 5989, 5991, 5994, 6092, 6093
#[test]
fn op_25_cnpg_fails_over_inside_the_cluster_with_a_quorum_of_two_standbys() {
    let c = read("k8s/cnpg/cluster.yaml");
    assert!(has(&c, "kind: Cluster"));
    assert_eq!(value(&c, "instances"), Some(3));
    for line in [
        "method: any",
        "number: 1",
        "dataDurability: required",
        "synchronous_commit: \"on\"",
        "podAntiAffinityType: required",
        "topologyKey: topology.kubernetes.io/zone",
        "whenUnsatisfiable: DoNotSchedule",
    ] {
        assert!(has(&c, line), "{line}");
    }
    assert_eq!(value(&c, "failoverDelay"), Some(30));
    assert!(
        !c.lines().any(|l| l.trim_start().starts_with("replica:")),
        "no replica cluster"
    );
    assert!(!c.contains("externalClusters"), "no cross-cluster source");
    assert!(c.contains("archive_command: \"pgbackrest --stanza=access-cell archive-push %p\""));
}

// OP-24, OP-25, FA-13, SA-47, Ek B 5991, 5994, 6092
#[test]
fn op_25_patroni_runs_strict_quorum_sync_with_the_failsafe_and_no_standby_cluster() {
    let p = read("patroni/patroni.yml");
    for line in [
        "synchronous_mode: quorum",
        "synchronous_mode_strict: true",
        "synchronous_node_count: 1",
        "failsafe_mode: true",
        "maximum_lag_on_failover: 0",
        "synchronous_commit: \"on\"",
        "nosync: false",
    ] {
        assert!(has(&p, line), "{line}");
    }
    let failover = ["ttl", "loop_wait", "retry_timeout"]
        .iter()
        .map(|k| value(&p, k).unwrap())
        .sum::<u64>();
    assert_eq!(failover, 30, "SA-47: failover in 30 s");
    assert!(
        !p.lines()
            .any(|l| l.trim_start().starts_with("standby_cluster:")),
        "no cross-cluster failover"
    );
}

// OP-57, §17.10.3, Ek B 6009
#[test]
fn op_57_backups_go_to_two_encrypted_verified_repositories_with_the_wal_archive() {
    let b = read("backup/pgbackrest.conf");
    for line in [
        "repo1-type=posix",
        "repo2-type=s3",
        "repo1-cipher-type=aes-256-cbc",
        "repo2-cipher-type=aes-256-cbc",
        "archive-async=y",
        "[access-cell]",
    ] {
        assert!(has(&b, line), "{line}");
    }
    assert!(
        !b.contains("cipher-pass="),
        "passphrases come from the secret store"
    );
    let s = read("backup/schedule.yaml");
    for kind in ["--type=full", "--type=diff", "--type=incr"] {
        assert!(s.contains(kind), "{kind}");
    }
    assert!(s.contains(r#"args: ["--stanza=access-cell", "verify"]"#));
    let readme = read("backup/README.md");
    // HL-32, OP-59, Ek B 6013, 6095
    assert!(readme.contains("There is no row-level restore of a tenant or a realm."));
    assert!(readme.contains("side restore and a logical copy"));
}

// HL-32, N-58, OP-59, Ek B 6095
#[test]
fn hl_32_no_api_restores_a_tenant_or_a_realm_row_by_row() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi");
    let mut seen = 0;
    for entry in std::fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for (route, ops) in doc["paths"].as_object().into_iter().flatten() {
            seen += 1;
            let lower = route.to_ascii_lowercase();
            assert!(!lower.contains("restore"), "{}: {route}", path.display());
            for op in ops.as_object().into_iter().flatten().map(|(_, o)| o) {
                let id = op["operationId"]
                    .as_str()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                assert!(!id.contains("restore"), "{}: {id}", path.display());
            }
        }
    }
    assert!(seen > 100);
}
