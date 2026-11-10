//! `ci-gates` (OP-68, F-6, F-7, F-14, SA-23, OP-66): the pipeline properties that keep an
//! unchecked commit from being released, signed or imaged, read from the workflow files.

use std::path::{Path, PathBuf};

use crate::{Check, Violation};

pub(crate) fn checks() -> Vec<Check> {
    vec![Check {
        name: "ci-gates",
        run: ci_gates,
    }]
}

const RULE: &str = "ci-gates";

/// The lines of the job `name` under `jobs:` (two-space indented key), or `None`.
fn job(workflow: &str, name: &str) -> Option<String> {
    let head = format!("  {name}:");
    let mut lines = workflow.lines().skip_while(|l| l.trim_end() != head);
    let first = lines.next()?;
    let body: Vec<&str> = lines
        .take_while(|l| l.is_empty() || l.starts_with("    ") || l.starts_with("  #"))
        .collect();
    Some(format!("{first}\n{}", body.join("\n")))
}

fn needs(job: &str, dependency: &str) -> bool {
    job.lines().any(|l| {
        let t = l.trim();
        t.strip_prefix("needs:").is_some_and(|rest| {
            rest.trim()
                .trim_matches(|c| c == '[' || c == ']')
                .split(',')
                .any(|d| d.trim() == dependency)
        })
    })
}

fn timeout(job: &str) -> Option<u32> {
    job.lines()
        .find_map(|l| l.trim().strip_prefix("timeout-minutes:"))
        .and_then(|v| v.trim().parse().ok())
}

/// The `on:` block of a workflow.
fn triggers(workflow: &str) -> String {
    workflow
        .lines()
        .skip_while(|l| l.trim_end() != "on:")
        .skip(1)
        .take_while(|l| l.is_empty() || l.starts_with(' '))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The tagged commit is an ancestor of main and its CI run on main passed.
fn checks_main_and_ci(text: &str) -> bool {
    text.contains("compare/main...$SHA")
        && text.contains("actions/workflows/ci.yml/runs?head_sha=$SHA")
}

pub(crate) fn release_findings(release: &str) -> Vec<String> {
    let mut out = Vec::new();
    match job(release, "gate") {
        Some(gate) => {
            if !checks_main_and_ci(&gate) {
                out.push(
                    "release gate must require the tag on main with a passed CI run (T-6)"
                        .to_owned(),
                );
            }
            if !gate.contains("run: just rules") {
                out.push("release gate must run `just rules` (rule coverage, T-4)".to_owned());
            }
        }
        None => out.push("release.yml has no `gate` job (T-6)".to_owned()),
    }
    for name in ["build", "test", "image"] {
        if !job(release, name).is_some_and(|j| needs(&j, "gate")) {
            out.push(format!("release job `{name}` must need `gate` (T-6)"));
        }
    }
    // OP-155 m.3 (q)
    let gated = job(release, "conformance").is_some_and(|j| {
        needs(&j, "gate")
            && j.contains("uses: ./.github/workflows/conformance.yml")
            && j.contains("release: true")
    });
    if !gated {
        out.push(
            "release job `conformance` must need `gate` and call conformance.yml with `release: true` (OP-155 m.3 (q))"
                .to_owned(),
        );
    }
    if !job(release, "publish").is_some_and(|j| needs(&j, "conformance")) {
        out.push("release job `publish` must need `conformance` (OP-155 m.3 (q))".to_owned());
    }
    out
}

pub(crate) fn semantics_release_findings(text: &str) -> Vec<String> {
    let gate = job(text, "gate").unwrap_or_default();
    let mut out = Vec::new();
    if !checks_main_and_ci(&gate) {
        out.push(
            "semantics gate must require the tag on main with a passed CI run (T-6)".to_owned(),
        );
    }
    if !(gate.contains("lake build") && gate.contains("./check-axioms.sh")) {
        out.push("semantics gate must build the Lean model and run check-axioms (T-6)".to_owned());
    }
    out
}

/// The main image is a reusable workflow that CI calls after its checks (T-18).
pub(crate) fn image_findings(image: &str, ci: &str) -> Vec<String> {
    let mut out = Vec::new();
    let on = triggers(image);
    if on.trim() != "workflow_call:" {
        out.push(format!(
            "image.yml must run only when CI calls it, not on `{}` (T-18)",
            on.trim()
        ));
    }
    let caller = job(ci, "image").unwrap_or_default();
    if !caller.contains("uses: ./.github/workflows/image.yml") {
        out.push("ci.yml must call image.yml from its `image` job (T-18)".to_owned());
    }
    for check in ["fast", "test", "sqlx", "web-e2e"] {
        if !caller.lines().any(|l| l.trim() == format!("- {check}")) {
            out.push(format!("ci.yml `image` must need `{check}` (T-18)"));
        }
    }
    if !job(ci, "sqlx").is_some_and(|j| j.contains("run: just sqlx-check")) {
        out.push("ci.yml must check the sqlx offline metadata (`just sqlx-check`, D-5)".to_owned());
    }
    if !job(ci, "fast").is_some_and(|j| j.contains("run: just ci-scripts-test")) {
        out.push("ci.yml `fast` must run the CI script tests (T-16)".to_owned());
    }
    out
}

pub(crate) fn dockerfile_findings(dockerfile: &str, dockerignore: &str) -> Vec<String> {
    let mut out = Vec::new();
    let joined = dockerfile.replace("\\\n", " ");
    let build = joined
        .lines()
        .find(|l| l.trim_start().starts_with("RUN cargo") && l.contains(" build "));
    match build {
        Some(b) if b.contains("cargo auditable build") && b.contains("--locked") => {
            if !b.contains("scripts/checksec.sh") {
                out.push(
                    "the image build must run scripts/checksec.sh on its binaries (T-10)"
                        .to_owned(),
                );
            }
        }
        _ => out.push(
            "the image binaries must be built with `cargo auditable build --locked` (T-10)"
                .to_owned(),
        ),
    }
    let patterns: Vec<&str> = dockerignore
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if !patterns.contains(&".*") {
        out.push(
            ".dockerignore must keep every hidden entry out of the context (`.*`, T-17)".to_owned(),
        );
    }
    out
}

pub(crate) fn schedule_findings(codeql: &str, nightly: &str) -> Vec<String> {
    let mut out = Vec::new();
    if job(codeql, "codeql").and_then(|j| timeout(&j)).unwrap_or(0) < 30 {
        out.push("CodeQL needs at least 30 minutes (T-3)".to_owned());
    }
    if job(nightly, "supply-chain-watch")
        .and_then(|j| timeout(&j))
        .unwrap_or(0)
        < 30
    {
        out.push("the nightly supply-chain watch needs at least 30 minutes (T-8)".to_owned());
    }
    if !job(nightly, "npm-audit").is_some_and(|j| j.contains("run: just web-audit")) {
        out.push("the nightly must npm audit the web packages (T-12)".to_owned());
    }
    out
}

/// OP-3 merge gates: cargo-deny and cargo-vet run on every CI run, the OIDF suite every night
/// (the nightly calls conformance.yml, whose `oidf-conformance` job runs it; OP-155 m.3 (q)).
pub(crate) fn op_3_findings(ci: &str, nightly: &str, conformance: &str) -> Vec<String> {
    let mut out = Vec::new();
    let supply = job(ci, "supply-chain").unwrap_or_default();
    for (run, tool) in [
        ("run: just deny", "cargo-deny"),
        ("run: just vet", "cargo-vet"),
    ] {
        if !supply.contains(run) {
            out.push(format!(
                "ci.yml `supply-chain` must run {tool} (`{run}`, OP-3)"
            ));
        }
    }
    let called = job(nightly, "conformance")
        .is_some_and(|j| j.contains("uses: ./.github/workflows/conformance.yml"));
    let runs = job(conformance, "oidf-conformance")
        .is_some_and(|j| j.contains(".github/scripts/oidf-conformance.py"));
    if !(called && runs) {
        out.push("the nightly must run the OIDF conformance suite (OP-3)".to_owned());
    }
    out
}

/// AG-17: the MCP conformance suite runs on the deployed image against its authorization server
/// and the reference MCP resource server, beside the OIDF suite and the Access vectors.
pub(crate) fn ag_17_findings(image: &str) -> Vec<String> {
    let Some(j) = job(image, "mcp-conformance") else {
        return vec!["image.yml has no `mcp-conformance` job (AG-17)".to_owned()];
    };
    let mut out = Vec::new();
    if !needs(&j, "image") {
        out.push("`mcp-conformance` must run on the pushed local image (AG-17)".to_owned());
    }
    for (text, what) in [
        (
            "npm ci --ignore-scripts",
            "install the pinned suite from its lockfile",
        ),
        (
            "conformance authorization",
            "run the suite against the authorization server",
        ),
        (
            "examples/mcp_reference",
            "run the reference MCP resource server",
        ),
    ] {
        if !j.contains(text) {
            out.push(format!("`mcp-conformance` must {what} (AG-17)"));
        }
    }
    out
}

fn read(root: &Path, file: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(file)).map_err(|e| format!("{file}: {e}"))
}

fn ci_gates(root: &Path) -> Result<Vec<Violation>, String> {
    let wf = |name: &str| read(root, &format!(".github/workflows/{name}"));
    let ci = wf("ci.yml")?;
    let groups = [
        ("release.yml", release_findings(&wf("release.yml")?)),
        (
            "semantics-release.yml",
            semantics_release_findings(&wf("semantics-release.yml")?),
        ),
        ("image.yml", image_findings(&wf("image.yml")?, &ci)),
        ("image.yml", ag_17_findings(&wf("image.yml")?)),
        (
            "deploy/docker/Dockerfile",
            dockerfile_findings(
                &read(root, "deploy/docker/Dockerfile")?,
                &read(root, ".dockerignore")?,
            ),
        ),
        (
            "nightly.yml",
            schedule_findings(&wf("codeql.yml")?, &wf("nightly.yml")?),
        ),
        (
            "ci.yml",
            op_3_findings(&ci, &wf("nightly.yml")?, &wf("conformance.yml")?),
        ),
    ];
    Ok(groups
        .into_iter()
        .flat_map(|(file, messages)| {
            messages.into_iter().map(move |message| Violation {
                rule: RULE,
                path: PathBuf::from(file),
                message,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECK: &str = "        run: |\n          gh api \"repos/$R/compare/main...$SHA\"\n          gh api \"repos/$R/actions/workflows/ci.yml/runs?head_sha=$SHA&status=success\"\n";

    // T-6, T-4, OP-155 m.3 (q)
    #[test]
    fn a_release_waits_for_main_ci_and_the_rules() {
        let gated = format!(
            "jobs:\n  gate:\n    steps:\n{CHECK}        run: just rules\n\n  conformance:\n    needs: gate\n    uses: ./.github/workflows/conformance.yml\n    with:\n      release: true\n  build:\n    needs: gate\n  test:\n    needs: gate\n  image:\n    needs: [gate]\n  publish:\n    needs: [build, test, conformance]\n"
        );
        assert_eq!(release_findings(&gated), Vec::<String>::new());
        let old =
            "jobs:\n  build:\n    runs-on: x\n  test:\n    runs-on: x\n  image:\n    runs-on: x\n";
        assert_eq!(release_findings(old).len(), 6);
        let ungated = gated.replace("release: true", "release: false");
        assert_eq!(release_findings(&ungated).len(), 1);
        let semantics = format!(
            "jobs:\n  gate:\n    steps:\n{CHECK}        run: lake build --wfail A\n        run: ./check-axioms.sh\n"
        );
        assert_eq!(semantics_release_findings(&semantics), Vec::<String>::new());
        let labels =
            "jobs:\n  gate:\n    steps:\n        run: python3 f0-drt.py lean proofs.toml\n";
        assert_eq!(semantics_release_findings(labels).len(), 2);
    }

    // T-18, D-5, T-16
    #[test]
    fn the_main_image_waits_for_ci() {
        let ci = "jobs:\n  fast:\n    steps:\n      - run: just ci-scripts-test\n  sqlx:\n    steps:\n      - run: just sqlx-check\n  image:\n    needs:\n      - fast\n      - test\n      - sqlx\n      - web-e2e\n    uses: ./.github/workflows/image.yml\n";
        let called = "name: Image\n\non:\n  workflow_call:\n\njobs:\n";
        assert_eq!(image_findings(called, ci), Vec::<String>::new());
        let pushed =
            "name: Image\n\non:\n  push:\n    branches: [main]\n  workflow_dispatch:\n\njobs:\n";
        assert_eq!(image_findings(pushed, ci).len(), 1);
        assert_eq!(
            image_findings(called, "jobs:\n  fast:\n    x: 1\n").len(),
            7
        );
    }

    // OP-3-G3, OP-3-G5
    #[test]
    fn deny_and_vet_gate_ci_and_the_oidf_suite_runs_nightly() {
        let ci = "jobs:\n  supply-chain:\n    steps:\n      - name: cargo-deny (F-1)\n        run: just deny\n      - name: cargo-vet (F-1)\n        run: just vet\n";
        let nightly = "jobs:\n  conformance:\n    uses: ./.github/workflows/conformance.yml\n";
        let conformance = "jobs:\n  oidf-conformance:\n    steps:\n      - run: >-\n          python3 -I .github/scripts/oidf-conformance.py\n";
        assert_eq!(
            op_3_findings(ci, nightly, conformance),
            Vec::<String>::new()
        );
        let no_vet = ci.replace("run: just vet", "run: just audit");
        assert_eq!(op_3_findings(&no_vet, nightly, conformance).len(), 1);
        assert_eq!(op_3_findings("jobs:\n", "jobs:\n", "jobs:\n").len(), 3);
        assert_eq!(op_3_findings(ci, "jobs:\n", conformance).len(), 1);
    }

    // AG-17, OP-154 m.3 (gg)
    #[test]
    fn the_mcp_suite_runs_on_the_image_beside_the_others() {
        let image = "jobs:\n  mcp-conformance:\n    needs: image\n    steps:\n      - run: npm ci --ignore-scripts\n      - run: cargo build --example mcp_reference && target/debug/examples/mcp_reference\n      - run: npx --no-install conformance authorization --url x\n";
        assert_eq!(ag_17_findings(image), Vec::<String>::new());
        assert_eq!(ag_17_findings("jobs:\n").len(), 1);
        assert_eq!(
            ag_17_findings(&image.replace("needs: image", "needs: other")).len(),
            1
        );
        assert_eq!(
            ag_17_findings(&image.replace("conformance authorization", "conformance server")).len(),
            1
        );
    }

    // T-10, T-17, OP-3-G3
    #[test]
    fn the_image_is_auditable_hardened_and_its_context_hides_dot_entries() {
        let good = "FROM x AS builder\nRUN cargo auditable build --release --locked \\\n      --package a \\\n && scripts/checksec.sh target/release/a\n";
        assert_eq!(
            dockerfile_findings(good, ".*\n!.cargo\n"),
            Vec::<String>::new()
        );
        let old = "FROM x AS builder\nRUN cargo chef cook --release\nRUN cargo build --release --locked \\\n      --package a\n";
        assert_eq!(dockerfile_findings(old, ".git\n.github\n").len(), 2);
    }

    // T-3, T-8, T-12
    #[test]
    fn scheduled_jobs_have_room_and_the_npm_audit_runs() {
        let codeql = "jobs:\n  codeql:\n    timeout-minutes: 30\n";
        let nightly = "jobs:\n  npm-audit:\n    steps:\n      - run: just web-audit\n  supply-chain-watch:\n    timeout-minutes: 30\n";
        assert_eq!(schedule_findings(codeql, nightly), Vec::<String>::new());
        let short = "jobs:\n  codeql:\n    timeout-minutes: 10\n";
        let old = "jobs:\n  supply-chain-watch:\n    timeout-minutes: 10\n";
        assert_eq!(schedule_findings(short, old).len(), 3);
    }
}
