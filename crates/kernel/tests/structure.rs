//! Structural rules of the Kernel's own source (OP-154 m.3 (b)): an agent is an ordinary actor
//! with no authority primitive of its own, and no Kernel type holds a plan's progress.

#![cfg(not(any(target_family = "wasm", target_os = "android")))]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs,
    reason = "test code"
)]

use std::path::{Path, PathBuf};

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && path.file_name().is_none_or(|n| n != "tests.rs")
        {
            out.push(path);
        }
    }
}

fn kernel() -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut paths,
    );
    paths
        .into_iter()
        .map(|p| {
            let text = std::fs::read_to_string(&p).unwrap();
            let code: Vec<&str> = text
                .lines()
                .map(|l| l.find("//").map_or(l, |at| &l[..at]))
                .collect();
            (p, code.join("\n"))
        })
        .collect()
}

fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
}

// §11.9.1, AG-19, C5, F15
#[test]
fn there_is_no_principal_type_and_no_agent_only_meta_action() {
    for (path, text) in kernel() {
        let mut prev = "";
        for w in words(&text) {
            if matches!(prev, "struct" | "enum" | "type" | "trait" | "union") {
                assert!(
                    w != "Principal" && !w.starts_with("Agent"),
                    "{}: `{prev} {w}`",
                    path.display()
                );
            }
            prev = w;
        }
    }
    let meta =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/meta.rs")).unwrap();
    let names = meta.split("const NAMES:").nth(1).unwrap();
    let names = &names[..names.find("];").unwrap()];
    let listed: Vec<&str> = names.split('"').skip(1).step_by(2).collect();
    assert_eq!(listed.len(), 27);
    assert!(listed.iter().all(|n| !n.contains("agent")), "{listed:?}");
    for name in listed {
        assert!(access_kernel::meta::is_meta(
            access_kernel::meta::NAMESPACE,
            name
        ));
    }
    assert!(!access_kernel::meta::is_meta(
        access_kernel::meta::NAMESPACE,
        "agent_register"
    ));
}

/// Identifiers that would hold where a plan stands.
const PROGRESS: [&str; 9] = [
    "progress",
    "plan_progress",
    "step_progress",
    "current_step",
    "next_step",
    "completed_steps",
    "steps_done",
    "step_state",
    "plan_state",
];

// MUST-NEVER-6, F10
#[test]
fn no_kernel_type_holds_plan_progress() {
    for (path, text) in kernel() {
        for w in words(&text) {
            assert!(
                !PROGRESS.contains(&w.to_ascii_lowercase().as_str()),
                "{}: `{w}`",
                path.display()
            );
        }
    }
    let plan = access_kernel::intent::ContextRefs {
        plan: Some(access_kernel::digest::Digest([1; 32])),
        ..access_kernel::intent::ContextRefs::default()
    };
    assert_eq!(plan.plan.map(|d| d.0.len()), Some(32));
}
