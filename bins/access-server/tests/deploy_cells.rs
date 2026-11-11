//! Configuration-output tests of the cell's deployment forms (OP-48, OP-50, OP-51, OP-53, HL-40,
//! T36, OP-158 m.3 (p)): the Helm chart's committed renders (`just helm-check` keeps them equal
//! to what the chart renders), the kustomize base, the small-provider profile, and the refusal to
//! start on SQLite. The multi-zone cluster, the hosted stack and the admission-enabled cluster
//! are the operator's; these tests check what Access ships.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::path::PathBuf;
use std::process::Command;

fn read(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
    std::fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn has(text: &str, line: &str) -> bool {
    text.lines().any(|l| l.trim() == line)
}

fn count(text: &str, line: &str) -> usize {
    text.lines().filter(|l| l.trim() == line).count()
}

// OP-50, OP-51, T36, Ek B 5969, 5979
#[test]
fn op_50_the_rendered_chart_carries_the_lifecycle_and_the_hard_zone_spread() {
    let r = read("helm/access/rendered/default.yaml");
    for line in [
        "kind: StatefulSet",
        "replicas: 3",
        "terminationGracePeriodSeconds: 45",
        "seconds: 5",
        "topologyKey: topology.kubernetes.io/zone",
        "whenUnsatisfiable: DoNotSchedule",
        "minDomains: 3",
        "topologyKey: kubernetes.io/hostname",
        "whenUnsatisfiable: ScheduleAnyway",
        "kind: PodDisruptionBudget",
        "maxUnavailable: 1",
        "durability = \"replicated\"",
        "[cells]",
        "this = \"pool-default\"",
        "kind: Job",
    ] {
        assert!(has(&r, line), "{line}");
    }
    // CMP-22, OP-158 m.3 (y)
    assert_eq!(
        count(&r, "restartPolicy: Always"),
        3,
        "two native sidecars and the pod"
    );
    assert!(r.contains("image: ghcr.io/e-suiss/access@sha256:"));
    assert!(!r.contains(":latest"));
    let k = read("k8s/statefulset.yaml");
    for line in [
        "whenUnsatisfiable: DoNotSchedule",
        "minDomains: 3",
        "terminationGracePeriodSeconds: 45",
        "seconds: 5",
    ] {
        assert!(has(&k, line), "kustomize: {line}");
    }
}

// OP-50, OP-53
#[test]
fn op_50_the_chart_values_name_the_servers_drain_and_shutdown_bounds() {
    let v = read("helm/access/values.yaml");
    for line in [
        "preStopSeconds: 5",
        "drainSeconds: 2",
        "shutdownSeconds: 15",
        "terminationGracePeriodSeconds: 45",
    ] {
        assert!(has(&v, line), "{line}");
    }
}

// OP-144, §5.12, OP-158 m.3 (p), Ek B 6147
#[test]
fn op_144_the_plane_split_profile_gives_each_signer_its_own_key_custody() {
    let r = read("helm/access/rendered/plane-split.yaml");
    for line in [
        "name: access-authority-plane",
        "name: access-identity-plane",
        "roleName: access-authority-plane",
        "roleName: access-identity-plane",
        "secretProviderClass: access-authority-plane",
        "secretProviderClass: access-identity-plane",
        "- name: authority-secrets",
        "- name: identity-secrets",
    ] {
        assert!(has(&r, line), "{line}");
    }
    assert!(!read("helm/access/rendered/default.yaml").contains("access-authority-plane"));
}

// HL-40, OP-48, T8, T36, Ek B 5887, 5968
#[test]
fn hl_40_the_small_provider_profile_declares_single_node() {
    let r = read("helm/access/rendered/small-provider.yaml");
    for line in [
        "replicas: 1",
        "durability = \"single-node\"",
        "this = \"small-provider\"",
    ] {
        assert!(has(&r, line), "{line}");
    }
    assert!(!has(&r, "minDomains: 3"), "one node spreads over no zones");
    let toml = read("small-provider/access.toml");
    assert!(has(&toml, "durability = \"single-node\""));
    assert!(has(&toml, "this = \"small-provider\""));
    let install = read("small-provider/install.sh");
    assert!(install.contains("access-signer init"));
    assert!(install.contains("access-identity-signer init"));
    assert!(install.contains("access-server migrate"));
    for unit in ["access-signer", "access-identity-signer", "access-server"] {
        let u = read(&format!("small-provider/systemd/{unit}.service"));
        assert!(has(&u, "User=access"), "{unit}");
    }
    let server = read("small-provider/systemd/access-server.service");
    assert!(has(&server, "TimeoutStopSec=45s"));
    assert!(has(
        &server,
        "Requires=access-signer.service access-identity-signer.service"
    ));
}

/// Starts `access-server migrate` with the small-provider configuration whose database `host`
/// is `host`.
fn start_with_host(host: &str) -> std::process::Output {
    let dir = std::env::temp_dir().join(format!("access-sqlite-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("access.toml");
    let toml = read("small-provider/access.toml")
        .replace("host = \"127.0.0.1\"", &format!("host = \"{host}\""));
    std::fs::write(&config, toml).unwrap();
    Command::new(env!("CARGO_BIN_EXE_access-server"))
        .arg("migrate")
        .env("ACCESS_CONFIG", &config)
        .output()
        .unwrap()
}

// OP-48, OP-66, T8, OP-158 m.3 (p), Ek B 6164
#[test]
fn op_48_access_server_refuses_to_start_on_sqlite() {
    for host in [
        "sqlite:///var/lib/access/access.db",
        "file:access.sqlite3",
        "/var/lib/access/access.db",
    ] {
        let out = start_with_host(host);
        assert!(!out.status.success(), "{host}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("SQLite is not supported"), "{host}: {err}");
    }
}
