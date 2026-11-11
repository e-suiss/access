//! `access-server upgrade-check` as a process (OP-56, §17.10.2, OP-158 m.3 (q)): the build's own
//! manifest, and the exit codes 0 (rolling), 3 (recreate) and 4 (rolling upgrades switched off).

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::path::Path;
use std::process::{Command, Output};

fn run(dir: &Path, rolling: bool, args: &[&str]) -> Output {
    let config = dir.join("access.toml");
    std::fs::write(&config, format!("[upgrade]\nrolling = {rolling}\n")).unwrap();
    Command::new(env!("CARGO_BIN_EXE_access-server"))
        .args(args)
        .env("ACCESS_CONFIG", &config)
        .output()
        .unwrap()
}

fn manifest(dir: &Path, name: &str, value: &serde_json::Value) -> String {
    let path = dir.join(name);
    std::fs::write(&path, value.to_string()).unwrap();
    path.display().to_string()
}

// OP-56, G64, Ek B 5816, 6036
#[test]
fn op_56_upgrade_check_answers_0_3_or_4() {
    let dir = std::env::temp_dir().join(format!("access-upgrade-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let own = run(&dir, true, &["upgrade-check", "--manifest"]);
    assert!(own.status.success());
    let me: serde_json::Value = serde_json::from_slice(&own.stdout).unwrap();
    assert_eq!(me["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(me["core"], 1);

    let same = manifest(&dir, "same.json", &me);
    assert_eq!(
        run(&dir, true, &["upgrade-check", "--to", &same])
            .status
            .code(),
        Some(0)
    );
    assert_eq!(
        run(&dir, false, &["upgrade-check", "--to", &same])
            .status
            .code(),
        Some(4)
    );

    let mut far = me.clone();
    far["version"] = serde_json::json!("9.0.0");
    far["rolling_from"] = serde_json::json!("8.0.0");
    let far = manifest(&dir, "far.json", &far);
    assert_eq!(
        run(&dir, true, &["upgrade-check", "--to", &far])
            .status
            .code(),
        Some(3)
    );

    let mut next = me.clone();
    next["version"] = serde_json::json!("9.0.0");
    next["rolling_from"] = me["version"].clone();
    next["core"] = serde_json::json!(2);
    let next = manifest(&dir, "next.json", &next);
    let out = run(&dir, true, &["upgrade-check", "--to", &next]);
    assert_eq!(out.status.code(), Some(0));
    let verdict: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(verdict["verdict"], "rolling");

    let mut drops = me.clone();
    drops["version"] = serde_json::json!("9.0.0");
    drops["rolling_from"] = me["version"].clone();
    drops["core"] = serde_json::json!(0);
    let drops = manifest(&dir, "drops.json", &drops);
    assert_eq!(
        run(&dir, true, &["upgrade-check", "--to", &drops])
            .status
            .code(),
        Some(3)
    );

    let broken = dir.join("broken.json");
    std::fs::write(&broken, "{").unwrap();
    assert_eq!(
        run(
            &dir,
            true,
            &["upgrade-check", "--to", &broken.display().to_string()]
        )
        .status
        .code(),
        Some(3)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
