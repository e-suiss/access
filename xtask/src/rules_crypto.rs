//! Cryptography rules: one provider per side (CR-13, CR-54, CR-14, F-1), no batch
//! signature verification (CR-11), HMAC only where CR-3 allows it, and no RSA in
//! authority code (§10.4.5, §13.2 G46, MD-3).

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{find_token, in_regions, lex, line_at, test_regions};
use crate::supply_chain::banned_in_lock;
use crate::supply_chain::metadata::{DepKind, Metadata};

fn at(rule: &'static str, path: &str, line: usize, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(format!("{path}:{line}")),
        message,
    }
}

fn rust_sources(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    Ok(walk(root)?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .map(|p| (rel(root, &p), p))
        .filter(|(r, _)| !r.starts_with("xtask/"))
        .collect())
}

const PROVIDER: &str = "crypto-provider";

/// CR-13, CR-14, F-1: crypto providers other than aws-lc-rs (server) and the pure
/// Kernel verify path (CR-54, CR-55) never enter the lockfile.
pub(crate) const OTHER_PROVIDERS: &[&str] = &[
    "ring",
    "ring-compat",
    "openssl",
    "openssl-sys",
    "boring",
    "boring-sys",
    "native-tls",
    "mbedtls",
    "mbedtls-sys-auto",
    "wolfssl",
    "wolfssl-sys",
    "botan",
    "botan-sys",
    "nettle",
    "nettle-sys",
    "sodiumoxide",
    "libsodium-sys",
    "libsodium-sys-stable",
    "orion",
    "ed25519-compact",
    "ed25519-zebra",
    "rsa",
];

/// Which workspace crates may depend directly (normal or build) on a crypto crate.
/// Dev-dependencies are free: tests use them to sign vectors and as oracles.
pub(crate) const PROVIDER_SCOPE: &[(&str, &[&str], &str)] = &[
    (
        "aws-lc-rs",
        &["crates/crypto"],
        "server and signer adapters only (CR-13, CR-54)",
    ),
    (
        "aws-lc-sys",
        &["crates/crypto"],
        "server and signer adapters only (CR-13, CR-54)",
    ),
    (
        "aws-lc-fips-sys",
        &["crates/crypto"],
        "server and signer adapters only (CR-13, CR-54)",
    ),
    (
        "ed25519-dalek",
        &["crates/kernel"],
        "the Kernel verify path for no_std, Wasm and mobile (CR-54)",
    ),
    (
        "curve25519-dalek",
        &["crates/kernel"],
        "the Kernel verify path (CR-53, CR-54)",
    ),
    (
        "p256",
        &["crates/kernel"],
        "the Kernel verify path (CR-55 m.1)",
    ),
    (
        "ecdsa",
        &["crates/kernel"],
        "the Kernel verify path (CR-55 m.1)",
    ),
    (
        "elliptic-curve",
        &["crates/kernel"],
        "the Kernel verify path (CR-55 m.1)",
    ),
    (
        "sha2",
        &[
            "crates/kernel",
            "crates/restriction-analysis",
            "crates/suiss-ledger",
        ],
        "the Kernel digest path; the cvc5 pin check (OP-105); the no_std ledger Merkle tree (OP-130 m.1)",
    ),
    (
        "subtle",
        &["crates/crypto"],
        "comparisons aws-lc-rs does not offer (CR-39, §15 provider table)",
    ),
    ("hmac", &[], "HMAC comes from aws-lc-rs (CR-13, CR-3)"),
    ("hkdf", &[], "KDFs come from aws-lc-rs (CR-13)"),
    ("pbkdf2", &[], "KDFs come from aws-lc-rs (CR-13)"),
    ("aes-gcm", &[], "AEAD comes from aws-lc-rs (CR-13)"),
    ("chacha20poly1305", &[], "AEAD comes from aws-lc-rs (CR-13)"),
    (
        "x25519-dalek",
        &[],
        "key agreement comes from aws-lc-rs (CR-13)",
    ),
    ("sha1", &[], "hashes come from aws-lc-rs (CR-13)"),
    ("md-5", &[], "hashes come from aws-lc-rs (CR-13)"),
    ("sha3", &[], "hashes come from aws-lc-rs (CR-13)"),
];

/// Direct dependencies outside their [`PROVIDER_SCOPE`].
pub(crate) fn provider_scope_violations(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        for dep in pkg.deps.iter().filter(|d| d.kind != DepKind::Dev) {
            let Some((_, allowed, why)) =
                PROVIDER_SCOPE.iter().find(|(name, _, _)| *name == dep.name)
            else {
                continue;
            };
            if !allowed.contains(&dir.as_str()) {
                out.push(Violation {
                    rule: PROVIDER,
                    path: PathBuf::from(format!("{dir}/Cargo.toml")),
                    message: format!("`{}` is for {why}", dep.name),
                });
            }
        }
    }
    out
}

pub(crate) fn check_provider(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    let mut out = banned_providers(&md);
    out.extend(provider_scope_violations(root, &md));
    Ok(out)
}

/// Other crypto providers anywhere in the resolved graph, any platform (CR-13, CR-14, CR-54).
pub(crate) fn banned_providers(md: &Metadata) -> Vec<Violation> {
    md.packages
        .iter()
        .filter(|p| OTHER_PROVIDERS.contains(&p.name.as_str()))
        .map(|p| Violation {
            rule: PROVIDER,
            path: PathBuf::from("Cargo.lock"),
            message: format!(
                "`{}` {} is banned: aws-lc-rs is the only server provider and the Kernel verifies with ed25519-dalek and p256 (CR-13, CR-14, CR-54)",
                p.name, p.version
            ),
        })
        .collect()
}

const BATCH: &str = "no-batch-verify";

/// CR-11: batch verification APIs.
const BATCH_TOKENS: &[&str] = &[
    "verify_batch",
    "batch_verify",
    "ed25519_dalek::batch",
    "BatchVerifier",
    "batch::Verifier",
    "batch::verify",
];

/// Batch-verification calls in one file, test code included: the acceptance set is
/// the single-signature equation everywhere (CR-11, CR-53).
pub(crate) fn batch_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let code = lex(src).code;
    let mut out = Vec::new();
    for t in BATCH_TOKENS {
        for p in find_token(&code, t) {
            out.push(at(
                BATCH,
                rel_path,
                line_at(&code, p),
                format!("`{t}`: batch signature verification is off (CR-11)"),
            ));
        }
    }
    out
}

/// Crates whose `batch` feature turns on batch verification.
const BATCH_FEATURES: &[&str] = &["ed25519-dalek", "curve25519-dalek"];

pub(crate) fn batch_feature_violations(md: &Metadata) -> Vec<Violation> {
    md.packages
        .iter()
        .filter(|p| BATCH_FEATURES.contains(&p.name.as_str()))
        .filter(|p| {
            md.features
                .get(&p.id)
                .is_some_and(|f| f.iter().any(|x| x == "batch"))
        })
        .map(|p| Violation {
            rule: BATCH,
            path: PathBuf::from("Cargo.lock"),
            message: format!(
                "{} {} has the `batch` feature on (CR-11)",
                p.name, p.version
            ),
        })
        .collect()
}

pub(crate) fn check_batch(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for (rel_path, path) in rust_sources(root)? {
        out.extend(batch_violations(&rel_path, &read(&path)?));
    }
    out.extend(batch_feature_violations(
        &*crate::supply_chain::metadata::load(root)?,
    ));
    Ok(out)
}

const HMAC: &str = "hmac-scope";

/// CR-3: the only places HMAC may appear, as (file, CR-3 clause). (a) keyed
/// derivation: `basis_ref`, HMAC event id, PII pairwise, double-HMAC compare;
/// (b) one-party tokens one component both issues and verifies. `client_secret_jwt`
/// is two-party and also allowed. Each entry needs Adem's review. Empty until the
/// first such feature lands.
pub(crate) const HMAC_ALLOWED: &[(&str, &str)] =
    &[("crates/crypto/src/event_id.rs", "CR-3 (a): HMAC event id")];

const HMAC_TOKENS: &[&str] = &[
    "hmac::",
    "Hmac<",
    "Hmac::",
    "HMAC_SHA256",
    "HMAC_SHA384",
    "HMAC_SHA512",
];

const HS_ALGS: &[&str] = &["HS256", "HS384", "HS512"];

/// HMAC use in one file's non-test code.
pub(crate) fn hmac_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    if HMAC_ALLOWED.iter().any(|(p, _)| *p == rel_path) {
        return Vec::new();
    }
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut out = Vec::new();
    for t in HMAC_TOKENS {
        for p in find_token(&lexed.code, t) {
            let line = line_at(&lexed.code, p);
            if !in_regions(&tests, line) {
                out.push(at(
                    HMAC,
                    rel_path,
                    line,
                    format!("`{t}`: HMAC only for keyed derivation and one-party tokens; list the file in HMAC_ALLOWED with its CR-3 clause"),
                ));
            }
        }
    }
    for lit in lexed.strings.iter().filter(|l| !in_regions(&tests, l.line)) {
        if HS_ALGS.contains(&lit.text.as_str()) {
            out.push(at(
                HMAC,
                rel_path,
                lit.line,
                format!(
                    "`{}`: no symmetric MAC in multi-party tokens (CR-3)",
                    lit.text
                ),
            ));
        }
    }
    out
}

pub(crate) fn check_hmac(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for (rel_path, path) in rust_sources(root)? {
        if !is_test_file(&rel_path) {
            out.extend(hmac_violations(&rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

const RSA: &str = "no-rsa-authority";

/// Authority code: the Kernel, the shared Suiss crates and the authority plane. The
/// identity plane may sign identity claims with RS256 (§10.4.5); authority never.
pub(crate) fn is_authority_path(rel_path: &str) -> bool {
    let mut parts = rel_path.split('/');
    match (parts.next(), parts.next()) {
        (Some("crates"), Some(name)) => {
            name == "kernel" || name.starts_with("suiss-") || name.starts_with("authority-")
        }
        (Some("sdks"), Some("bindings")) => true,
        _ => false,
    }
}

const RSA_ALGS: &[&str] = &[
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "RSA1_5",
    "RSA-OAEP",
    "RSA-OAEP-256",
];

const RSA_TOKENS: &[&str] = &[
    "Rs256", "Rs384", "Rs512", "Ps256", "Ps384", "Ps512", "rsa::",
];

/// RSA algorithm names in authority code outside tests (G46, MD-3).
pub(crate) fn rsa_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut out = Vec::new();
    for t in RSA_TOKENS {
        for p in find_token(&lexed.code, t) {
            let line = line_at(&lexed.code, p);
            if !in_regions(&tests, line) {
                out.push(at(
                    RSA,
                    rel_path,
                    line,
                    format!("`{t}`: authority artefacts are never RSA (G46, MD-3)"),
                ));
            }
        }
    }
    for lit in lexed.strings.iter().filter(|l| !in_regions(&tests, l.line)) {
        if RSA_ALGS.contains(&lit.text.as_str()) {
            out.push(at(
                RSA,
                rel_path,
                lit.line,
                format!(
                    "`{}`: authority artefacts are never RSA (G46, MD-3)",
                    lit.text
                ),
            ));
        }
    }
    out
}

pub(crate) fn check_rsa(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = banned_in_lock(
        &read(&root.join("Cargo.lock"))?,
        &["rsa"],
        RSA,
        "Marvin timing side channel; RSA comes from aws-lc-rs for identity claims only (CR-14, §10.4.5)",
    )?;
    for (rel_path, path) in rust_sources(root)? {
        if is_authority_path(&rel_path) && !is_test_file(&rel_path) {
            out.extend(rsa_violations(&rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::metadata::{fixture, parse, retain_built};

    fn member_with(dir: &str, dep: &str, kind: Option<&str>) -> serde_json::Value {
        let mut m = fixture::member(dir, &[]);
        if let Some(deps) = m.get_mut("dependencies").and_then(|d| d.as_array_mut()) {
            deps.push(serde_json::json!({"name": dep, "kind": kind}));
        }
        m
    }

    // CR-13, CR-54
    #[test]
    fn provider_outside_its_scope_is_rejected() {
        let md = parse(&fixture::metadata(
            &[
                member_with("crates/kernel", "aws-lc-rs", None),
                member_with("crates/crypto", "aws-lc-rs", None),
                member_with("sdks/bindings/wasm", "ed25519-dalek", None),
                member_with("crates/identity-oauth", "hmac", None),
                member_with("crates/http", "p256", Some("dev")),
            ],
            &[],
        ))
        .unwrap();
        let v = provider_scope_violations(Path::new("/ws"), &md);
        let paths: Vec<String> = v.iter().map(|x| x.path.display().to_string()).collect();
        assert_eq!(
            paths,
            vec![
                "crates/kernel/Cargo.toml",
                "sdks/bindings/wasm/Cargo.toml",
                "crates/identity-oauth/Cargo.toml"
            ]
        );
    }

    // CR-14, F-2
    #[test]
    fn other_providers_in_the_built_graph_are_rejected() {
        let packages = [
            fixture::external("ring", "0.17.8", true),
            fixture::external("aws-lc-rs", "1.15.0", true),
        ];
        let mut md = parse(&fixture::metadata(&packages, &[])).unwrap();
        retain_built(&mut md, "ring v0.17.8\naws-lc-rs v1.15.0\n");
        assert_eq!(banned_providers(&md).len(), 1);
        // only named by a weak feature: listed, never built
        let mut md = parse(&fixture::metadata(&packages, &[])).unwrap();
        retain_built(&mut md, "aws-lc-rs v1.15.0\n");
        assert!(banned_providers(&md).is_empty());
    }

    // CR-11
    #[test]
    fn batch_verification_is_rejected_in_any_code() {
        let src = "use ed25519_dalek::batch;\n#[test]\nfn t() { verify_batch(&m, &s, &k); }\n";
        assert_eq!(batch_violations("crates/kernel/src/a.rs", src).len(), 2);
        let ok = "// verify_batch is off\nfn verify(m: &[u8]) {}\n";
        assert!(batch_violations("crates/kernel/src/a.rs", ok).is_empty());
    }

    // CR-11
    #[test]
    fn batch_feature_is_rejected() {
        let id = "registry+https://github.com/rust-lang/crates.io-index#ed25519-dalek@3.0.0";
        let md = parse(&fixture::metadata(
            &[fixture::external("ed25519-dalek", "3.0.0", false)],
            &[(id, &["alloc", "batch"])],
        ))
        .unwrap();
        assert_eq!(batch_feature_violations(&md).len(), 1);
        let md = parse(&fixture::metadata(
            &[fixture::external("ed25519-dalek", "3.0.0", false)],
            &[(id, &["alloc"])],
        ))
        .unwrap();
        assert!(batch_feature_violations(&md).is_empty());
    }

    // CR-3
    #[test]
    fn hmac_outside_the_allowlist_is_rejected() {
        let src =
            "use aws_lc_rs::hmac::{self, HMAC_SHA256};\nfn alg() -> &'static str { \"HS256\" }\n";
        assert_eq!(
            hmac_violations("crates/authority-core/src/a.rs", src).len(),
            3
        );
        let test_only = "#[cfg(test)]\nmod tests { const A: &str = \"HS256\"; }\n";
        assert!(hmac_violations("crates/kernel/src/a.rs", test_only).is_empty());
    }

    // G46, MD-3
    #[test]
    fn rsa_in_authority_code_is_rejected() {
        assert!(is_authority_path("crates/kernel/src/verify/jws.rs"));
        assert!(is_authority_path("crates/authority-core/src/lib.rs"));
        assert!(!is_authority_path("crates/identity-oauth/src/jwks.rs"));
        let src = "enum Alg { Rs256 }\nconst A: &str = \"PS256\";\n";
        assert_eq!(rsa_violations("crates/kernel/src/a.rs", src).len(), 2);
        let test_only = "#[cfg(test)]\nmod tests { const A: &str = \"RS256\"; }\n";
        assert!(rsa_violations("crates/kernel/src/a.rs", test_only).is_empty());
    }
}
