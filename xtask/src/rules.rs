//! Architecture and code rules (OP-62, OP-63, OP-64, OP-66, OP-73, TI-9, R-2,
//! SA-21, CR-3, CR-11, CR-13, SA-32, U48, TI-10, INV-26, INV-36, §9.7A.7, OP-150 (e), TN-113, OP-47, OP-67, MUST-NEVER-6, IDI-11). Each check lives in a `rules_*` module.

#[path = "rules_adjacent.rs"]
mod adjacent;
#[path = "rules_advisories.rs"]
pub(crate) mod advisories;
#[path = "rules_attention.rs"]
mod attention;
#[path = "rules_breakglass.rs"]
mod breakglass;
#[path = "rules_comments.rs"]
mod comments;
#[path = "rules_compliance_map.rs"]
mod compliance_map;
#[path = "rules_conformance_profiles.rs"]
mod conformance_profiles;
#[path = "rules_constant_time_points.rs"]
mod constant_time_points;
#[path = "rules_crypto.rs"]
mod crypto;
#[path = "rules_custody.rs"]
mod custody;
#[path = "rules_degraded_paths.rs"]
mod degraded_paths;
#[path = "rules_deps.rs"]
pub(crate) mod deps;
#[path = "rules_dit_coverage.rs"]
mod dit_coverage;
#[path = "rules_edge.rs"]
mod edge;
#[path = "rules_files.rs"]
pub(crate) mod files;
#[path = "rules_fluent.rs"]
mod fluent;
#[path = "rules_formal_manifest.rs"]
mod formal_manifest;
#[path = "rules_interop.rs"]
pub(crate) mod interop;
#[path = "rules_iys.rs"]
mod iys;
#[path = "rules_kill_switch.rs"]
mod kill_switch;
#[path = "rules_kyc.rs"]
mod kyc;
#[path = "rules_language_profiles.rs"]
mod language_profiles;
#[path = "rules_layer_order.rs"]
mod layer_order;
#[path = "rules_lex.rs"]
pub(crate) mod lex;
#[path = "rules_limits.rs"]
mod limits;
#[path = "rules_manifest.rs"]
mod manifest;
#[path = "rules_money.rs"]
mod money;
#[path = "rules_pending.rs"]
mod pending;
#[path = "rules_personal.rs"]
mod personal;
#[path = "rules_privileged.rs"]
pub(crate) mod privileged;
#[path = "rules_profile.rs"]
mod profile;
#[path = "rules_progress.rs"]
mod progress;
#[path = "rules_proxy.rs"]
mod proxy;
#[path = "rules_recovery_custody.rs"]
mod recovery_custody;
#[path = "rules_replica_reads.rs"]
mod replica_reads;
#[path = "rules_reputation.rs"]
mod reputation;
#[path = "rules_restriction.rs"]
mod restriction;
#[path = "rules_seam.rs"]
mod seam;
#[path = "rules_security_model.rs"]
pub(crate) mod security_model;
#[path = "rules_security_txt.rs"]
mod security_txt;
#[path = "rules_shared_layers.rs"]
mod shared_layers;
#[path = "rules_source.rs"]
pub(crate) mod source;
#[path = "rules_standing.rs"]
mod standing;
#[path = "rules_support.rs"]
mod support;
#[path = "rules_support_policy.rs"]
pub(crate) mod support_policy;
#[path = "rules_switches.rs"]
pub(crate) mod switches;
#[path = "rules_sync_commit.rs"]
mod sync_commit;
#[path = "rules_telemetry.rs"]
mod telemetry;
#[path = "rules_test_layers.rs"]
mod test_layers;
#[path = "rules_tofu_infra_only.rs"]
mod tofu_infra_only;
#[path = "rules_trust_model.rs"]
pub(crate) mod trust_model;
#[path = "rules_ui_terms.rs"]
pub(crate) mod ui_terms;
#[path = "rules_validity_paths.rs"]
mod validity_paths;
#[path = "rules_vectors.rs"]
mod vectors;
#[path = "rules_witness_independence.rs"]
mod witness_independence;
#[path = "rules_write_permit.rs"]
mod write_permit;

use crate::Check;

/// `dependency-direction` with its source half, `no-authority-to-identity-write` (§5.12).
fn planes(root: &std::path::Path) -> Result<Vec<crate::Violation>, String> {
    let mut out = deps::check(root)?;
    out.extend(seam::check(root)?);
    Ok(out)
}

#[expect(clippy::too_many_lines, reason = "one entry per rule, in report order")]
pub(crate) fn checks() -> Vec<Check> {
    let mut all = telemetry::checks();
    all.extend(vec![
        Check {
            name: "dependency-direction",
            run: planes,
        },
        Check {
            name: "edge-isolation",
            run: edge::check,
        },
        Check {
            name: "kernel-purity",
            run: source::check_purity,
        },
        Check {
            name: "sql-only-in-store",
            run: source::check_sql,
        },
        Check {
            name: "no-physical-delete",
            run: source::check_delete,
        },
        Check {
            name: "personal-data",
            run: personal::check,
        },
        Check {
            name: "migration-hygiene",
            run: source::check_migrations,
        },
        Check {
            name: "no-dev-mode",
            run: switches::check,
        },
        Check {
            name: "unsafe-allowlist",
            run: source::check_unsafe,
        },
        Check {
            name: "todo-has-issue",
            run: source::check_todo,
        },
        Check {
            name: "comment-ids",
            run: comments::check,
        },
        Check {
            name: "panic-profile",
            run: profile::check,
        },
        Check {
            name: "secret-compare",
            run: source::check_secret_compare,
        },
        Check {
            name: "fail-closed",
            run: switches::check_fail_closed,
        },
        Check {
            name: "crypto-provider",
            run: crypto::check_provider,
        },
        Check {
            name: "no-batch-verify",
            run: crypto::check_batch,
        },
        Check {
            name: "hmac-scope",
            run: crypto::check_hmac,
        },
        Check {
            name: "no-rsa-authority",
            run: crypto::check_rsa,
        },
        Check {
            name: "regex-limits",
            run: limits::check_regex,
        },
        Check {
            name: "parser-preallocation",
            run: limits::check_prealloc,
        },
        Check {
            name: "no-semantic-timers",
            run: limits::check_timers,
        },
        Check {
            name: "no-external-authz",
            run: restriction::check_engines,
        },
        Check {
            name: "cedar-scope",
            run: restriction::check_cedar,
        },
        Check {
            name: "restriction-language",
            run: restriction::check_language,
        },
        Check {
            name: "solver-confinement",
            run: restriction::check_confine,
        },
        Check {
            name: "no-custody-key",
            run: custody::check,
        },
        Check {
            name: "shared-vectors",
            run: vectors::check,
        },
        Check {
            name: "endpoint-manifest",
            run: manifest::check,
        },
        Check {
            name: "forbidden-ui-terms",
            run: ui_terms::check,
        },
        Check {
            name: "ui-text-nodes",
            run: ui_terms::check_text_nodes,
        },
        Check {
            name: "fluent-catalog",
            run: fluent::check,
        },
        Check {
            name: "no-plan-progress",
            run: progress::check,
        },
        Check {
            name: "interop-profile-tests",
            run: interop::check_tests,
        },
        Check {
            name: "interop-lab",
            run: interop::check_lab,
        },
        // PI-14, OP-156 m.2 Q1
        Check {
            name: "no-privileged-path",
            run: privileged::check,
        },
        // IDP-37 (4), B23, E42, OP-156 m.2 Q9
        Check {
            name: "no-iys-client",
            run: iys::check,
        },
        // IDP-30 (2), B22, OP-156 m.3 (m), Ek B 5369
        Check {
            name: "proxy-engine",
            run: proxy::check,
        },
        // IDP-34, §10.3.1, OP-156 m.2 Q15
        Check {
            name: "kyc-boundary",
            run: kyc::check,
        },
        // E22, IDP-39, L28, OP-156 m.3 (x), Ek B 5366
        Check {
            name: "adjacent-products",
            run: adjacent::check,
        },
        // MUST-NEVER-7, OP-156 m.3 (u)
        Check {
            name: "no-money-state",
            run: money::check,
        },
        // MD-9, TN-71, OP-157 m.3 (c)
        Check {
            name: "support-template",
            run: support::check,
        },
        // OP-46, G63, OP-157 m.3 (j)
        Check {
            name: "breakglass-isolation",
            run: breakglass::check,
        },
        // OP-54-RL10, OP-157 m.3 (j)
        Check {
            name: "no-standing-admin",
            run: standing::check,
        },
        // CI-13, OP-157 m.3 (i)
        Check {
            name: "no-kill-switch",
            run: kill_switch::check,
        },
        // OP-157 m.3 (m)
        Check {
            name: "attention-model",
            run: attention::check,
        },
        // MUST-NEVER-8, OP-157 m.3 (m)
        Check {
            name: "no-reputation-score",
            run: reputation::check,
        },
        // X5, C26, OP-157 m.3 (u)
        Check {
            name: "no-pending-queue",
            run: pending::check,
        },
        // P2, OP-157 m.3 (s)
        Check {
            name: "conformance-profiles",
            run: conformance_profiles::check,
        },
        // SEC20, U16, OP-158 m.3 (m)
        Check {
            name: "recovery-custody",
            run: recovery_custody::check,
        },
        // OPI-2, OP-54-RL2, OP-158 m.3 (n)
        Check {
            name: "replica-reads",
            run: replica_reads::check,
        },
        // TI-9, SEC27, SI-22, OP-158 m.3 (s)
        Check {
            name: "degraded-paths",
            run: degraded_paths::check,
        },
        // EP-1…EP-10, OP-158 m.3 (t)
        Check {
            name: "validity-paths",
            run: validity_paths::check,
        },
        // GHSA-84jc-3hj2-hwc7, OP-158 m.3 (v)
        Check {
            name: "layer-order",
            run: layer_order::check,
        },
        // OP-158 m.3 (p)
        Check {
            name: "tofu-infra-only",
            run: tofu_infra_only::check,
        },
        // OP-54-RL6, OP-158 m.3 (n)
        Check {
            name: "sync-commit",
            run: sync_commit::check,
        },
        // SI-12, B13, OP-158 m.3 (d)
        Check {
            name: "witness-independence",
            run: witness_independence::check,
        },
        // SEC5, SA-7, OP-159 m.3 (gg), m.4 (b) (J8)
        Check {
            name: "trust-model",
            run: trust_model::check,
        },
        // SEC1, RT28, §13.9, OP-159 m.3 (gg), m.4 (b) (J8)
        Check {
            name: "security-model",
            run: security_model::check,
        },
        // CR-46, CR-50, OP-159 m.3 (y)
        Check {
            name: "formal-manifest",
            run: formal_manifest::check,
        },
        // SA-59, OP-159 m.3 (bb)
        Check {
            name: "test-layers",
            run: test_layers::check,
        },
        // MD-2, SA-20, OP-159 m.3 (dd)
        Check {
            name: "language-profiles",
            run: language_profiles::check,
        },
        // OP-91, INV-12, OP-159 m.3 (ee)
        Check {
            name: "write-permit",
            run: write_permit::check,
        },
        // CR-39, OP-159 m.3 (s)
        Check {
            name: "constant-time-points",
            run: constant_time_points::check,
        },
        // CR-39, OP-159 m.3 (s)
        Check {
            name: "dit-coverage",
            run: dit_coverage::check,
        },
        // SA-53, OP-159 m.3 (ii)
        Check {
            name: "compliance-map",
            run: compliance_map::check,
        },
        // OP-68, OP-159 m.3 (jj)
        Check {
            name: "support-policy",
            run: support_policy::check,
        },
        // OP-159 m.3 (jj)
        Check {
            name: "security-txt",
            run: security_txt::check,
        },
        // OP-159 m.3 (jj)
        Check {
            name: "advisories",
            run: advisories::check,
        },
        // PI-18, OP-70, OP-159 m.3 (kk)
        Check {
            name: "shared-layers",
            run: shared_layers::check,
        },
    ]);
    all
}
