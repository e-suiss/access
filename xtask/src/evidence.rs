//! `cargo xtask evidence-pack <dir>` (OP-159 m.3 (ii), NIS2/DORA, F-6): the release's evidence
//! in one deterministic tarball with a manifest and `SHA256SUMS`.
//!
//! - The pack holds the SBOMs given with `--sbom`, `SECURITY-MODEL.md`, the compliance mappings,
//!   the formal manifest, the test layers, the advisories, the support policy with
//!   `SECURITY.md`, the CRA Art. 14 reporting periods and the declared SLOs; nothing commercial.
//! - Entries are sorted, owned by 0:0, mode 0644, dated 0; the same inputs give the same bytes.
//! - `<dir>/access-evidence-<release>.tar` and `<dir>/SHA256SUMS` are written.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::rules::support_policy;

/// The prefix of every path in the tarball.
pub(crate) const ROOT: &str = "evidence";

/// The declared SLO file (OP-32).
pub(crate) const SLO: &str = "deploy/observability/slo.toml";

const BLOCK: usize = 512;

/// One file of the pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) path: String,
    pub(crate) kind: &'static str,
    pub(crate) bytes: Vec<u8>,
}

/// What `evidence-pack` was asked for.
#[derive(Debug, Default)]
pub(crate) struct Args {
    pub(crate) dir: PathBuf,
    pub(crate) release: Option<String>,
    pub(crate) commit: Option<String>,
    pub(crate) sboms: Vec<PathBuf>,
}

pub(crate) fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args::default();
    let mut dir = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |flag: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match a.as_str() {
            "--release" => out.release = Some(value("--release")?),
            "--commit" => out.commit = Some(value("--commit")?),
            "--sbom" => out.sboms.push(PathBuf::from(value("--sbom")?)),
            other if other.starts_with("--") => return Err(format!("unknown argument {other}")),
            other if dir.is_none() => dir = Some(PathBuf::from(other)),
            other => return Err(format!("unexpected argument {other}")),
        }
    }
    out.dir = dir.ok_or_else(|| {
        String::from(
            "usage: cargo xtask evidence-pack <dir> [--release TAG] [--commit SHA] [--sbom FILE]...",
        )
    })?;
    Ok(out)
}

fn read(root: &Path, rel: &str) -> Result<Vec<u8>, String> {
    std::fs::read(root.join(rel)).map_err(|e| format!("{rel}: {e}"))
}

fn files_in(root: &Path, dir: &str, ext: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = std::fs::read_dir(root.join(dir))
        .map_err(|e| format!("{dir}: {e}"))?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter(|n| n.ends_with(ext))
        .map(|n| format!("{dir}/{n}"))
        .collect();
    out.sort();
    Ok(out)
}

/// The CRA Art. 14 reporting periods from the support policy (SA-16).
pub(crate) fn psirt_periods(root: &Path) -> Result<Vec<u8>, String> {
    let cra = support_policy::load(root)?.cra;
    let doc = json!({
        "v": 1,
        "source": support_policy::FILE,
        "early_warning_hours": cra.early_warning_hours,
        "notification_hours": cra.notification_hours,
        "final_report_vulnerability_days": cra.final_report_vulnerability_days,
        "final_report_incident_months": cra.final_report_incident_months,
    });
    let mut text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    text.push('\n');
    Ok(text.into_bytes())
}

/// Every entry of the pack but the manifest and the sums, sorted by path.
pub(crate) fn entries(root: &Path, sboms: &[PathBuf]) -> Result<Vec<Entry>, String> {
    let mut out = Vec::new();
    let mut add = |path: String, kind: &'static str, bytes: Vec<u8>| {
        out.push(Entry {
            path: format!("{ROOT}/{path}"),
            kind,
            bytes,
        });
    };
    for s in sboms {
        let name = s
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{}: not a file name", s.display()))?;
        let bytes = std::fs::read(s).map_err(|e| format!("{}: {e}", s.display()))?;
        add(format!("sbom/{name}"), "sbom", bytes);
    }
    add(
        String::from("SECURITY-MODEL.md"),
        "security-model",
        read(root, "conformance/SECURITY-MODEL.md")?,
    );
    for f in files_in(root, super::rules::compliance_map::DIR, ".toml")? {
        let name = f.rsplit('/').next().unwrap_or_default().to_owned();
        add(
            format!("compliance/{name}"),
            "compliance-map",
            read(root, &f)?,
        );
    }
    add(
        String::from("compliance/README.md"),
        "compliance-map",
        read(root, super::rules::compliance_map::README)?,
    );
    add(
        String::from("formal/manifest.toml"),
        "formal-manifest",
        read(root, "conformance/formal/manifest.toml")?,
    );
    add(
        String::from("test-layers.toml"),
        "test-layers",
        read(root, "conformance/catalog/test-layers.toml")?,
    );
    for f in files_in(root, "security/advisories", ".json")? {
        let name = f.rsplit('/').next().unwrap_or_default().to_owned();
        add(format!("advisories/{name}"), "advisories", read(root, &f)?);
    }
    add(
        String::from("support-policy.toml"),
        "support-policy",
        read(root, support_policy::FILE)?,
    );
    add(
        String::from("SECURITY.md"),
        "support-policy",
        read(root, "SECURITY.md")?,
    );
    add(
        String::from("psirt-deadlines.json"),
        "psirt-deadlines",
        psirt_periods(root)?,
    );
    add(String::from("slo.toml"), "slo", read(root, SLO)?);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    if let Some([a, _]) = out
        .windows(2)
        .find(|w| matches!(w, [a, b] if a.path == b.path))
    {
        return Err(format!("{}: given twice", a.path));
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The manifest (`evidence-pack.schema.json`).
pub(crate) fn manifest(release: &str, commit: &str, entries: &[Entry]) -> Result<Vec<u8>, String> {
    let doc = json!({
        "v": 1,
        "release": release,
        "commit": commit,
        "files": entries.iter().map(|e| json!({
            "path": e.path,
            "kind": e.kind,
            "sha256": sha256(&e.bytes),
        })).collect::<Vec<_>>(),
    });
    let mut text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    text.push('\n');
    Ok(text.into_bytes())
}

fn sums(entries: &[(String, &[u8])]) -> Vec<u8> {
    let mut out = String::new();
    for (path, bytes) in entries {
        let _ = writeln!(out, "{}  {path}", sha256(bytes));
    }
    out.into_bytes()
}

fn octal(field: &mut [u8], value: u64) -> Result<(), String> {
    let width = field.len().saturating_sub(1);
    let text = format!("{value:0width$o}");
    if text.len() != width {
        return Err(format!("{value} does not fit a tar header field"));
    }
    field
        .get_mut(..width)
        .ok_or("tar header field")?
        .copy_from_slice(text.as_bytes());
    Ok(())
}

/// One ustar header for a regular file of `size` bytes at `path`.
pub(crate) fn header(path: &str, size: u64) -> Result<[u8; BLOCK], String> {
    let mut h = [b'\0'; BLOCK];
    let name = path.as_bytes();
    if name.len() > 100 {
        return Err(format!("{path}: longer than 100 bytes"));
    }
    h.get_mut(..name.len())
        .ok_or("tar name")?
        .copy_from_slice(name);
    octal(h.get_mut(100..108).ok_or("mode")?, 0o644)?;
    octal(h.get_mut(108..116).ok_or("uid")?, 0)?;
    octal(h.get_mut(116..124).ok_or("gid")?, 0)?;
    octal(h.get_mut(124..136).ok_or("size")?, size)?;
    octal(h.get_mut(136..148).ok_or("mtime")?, 0)?;
    h.get_mut(148..156).ok_or("chksum")?.fill(b' ');
    *h.get_mut(156).ok_or("typeflag")? = b'0';
    h.get_mut(257..263)
        .ok_or("magic")?
        .copy_from_slice(b"ustar\0");
    h.get_mut(263..265).ok_or("version")?.copy_from_slice(b"00");
    let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
    let text = format!("{sum:06o}\0 ");
    h.get_mut(148..156)
        .ok_or("chksum")?
        .copy_from_slice(text.as_bytes());
    Ok(h)
}

/// A ustar archive of `files`, in the given order.
pub(crate) fn tar(files: &[(String, &[u8])]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for (path, bytes) in files {
        let size = u64::try_from(bytes.len()).map_err(|e| e.to_string())?;
        out.extend_from_slice(&header(path, size)?);
        out.extend_from_slice(bytes);
        let rest = bytes.len().checked_rem(BLOCK).unwrap_or(0);
        let pad = BLOCK.saturating_sub(rest).checked_rem(BLOCK).unwrap_or(0);
        out.resize(out.len().saturating_add(pad), 0);
    }
    out.resize(out.len().saturating_add(2 * BLOCK), 0);
    Ok(out)
}

/// The tarball's bytes for `release` at `commit`.
pub(crate) fn build(
    root: &Path,
    release: &str,
    commit: &str,
    sboms: &[PathBuf],
) -> Result<Vec<u8>, String> {
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "commit {commit:?} is not a 40-digit lowercase hex SHA-1"
        ));
    }
    if release.is_empty() || release.contains('/') {
        return Err(format!("release {release:?} is not a tag"));
    }
    let entries = entries(root, sboms)?;
    let manifest = manifest(release, commit, &entries)?;
    let mut files: Vec<(String, &[u8])> = entries
        .iter()
        .map(|e| (e.path.clone(), e.bytes.as_slice()))
        .collect();
    files.push((format!("{ROOT}/manifest.json"), manifest.as_slice()));
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let sums = sums(&files);
    files.push((format!("{ROOT}/SHA256SUMS"), sums.as_slice()));
    tar(&files)
}

fn workspace_version(root: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(root.join("Cargo.toml")).map_err(|e| e.to_string())?;
    let v: toml::Value = toml::from_str(&text).map_err(|e| e.to_string())?;
    v.get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str)
        .map(|s| format!("v{s}"))
        .ok_or_else(|| String::from("Cargo.toml: no workspace.package.version"))
}

fn head(root: &Path) -> Result<String, String> {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(String::from("git rev-parse HEAD failed; pass --commit"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// `cargo xtask evidence-pack <dir> [--release TAG] [--commit SHA] [--sbom FILE]...`.
pub(crate) fn run(root: &Path, args: &[String]) -> Result<String, String> {
    let a = parse(args)?;
    let release = match a.release {
        Some(r) => r,
        None => workspace_version(root)?,
    };
    let commit = match a.commit {
        Some(c) => c,
        None => head(root)?,
    };
    let bytes = build(root, &release, &commit, &a.sboms)?;
    std::fs::create_dir_all(&a.dir).map_err(|e| format!("{}: {e}", a.dir.display()))?;
    let name = format!("access-evidence-{release}.tar");
    let path = a.dir.join(&name);
    std::fs::write(&path, &bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let sums = format!("{}  {name}\n", sha256(&bytes));
    let sums_path = a.dir.join("SHA256SUMS");
    std::fs::write(&sums_path, &sums).map_err(|e| format!("{}: {e}", sums_path.display()))?;
    Ok(format!("{}\n{}", path.display(), sums.trim_end()))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "test code reading back a small archive"
    )]

    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    /// The paths and contents of a ustar archive.
    fn untar(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + BLOCK <= bytes.len() {
            let h = &bytes[at..at + BLOCK];
            if h.iter().all(|b| *b == 0) {
                break;
            }
            let name =
                String::from_utf8(h[..100].split(|b| *b == 0).next().unwrap().to_vec()).unwrap();
            let size_text = std::str::from_utf8(&h[124..135]).unwrap();
            let size = usize::from_str_radix(size_text, 8).unwrap();
            let stored = std::str::from_utf8(&h[148..154]).unwrap();
            let mut blank = h.to_vec();
            blank[148..156].fill(b' ');
            let sum: u64 = blank.iter().map(|b| u64::from(*b)).sum();
            assert_eq!(u64::from_str_radix(stored, 8).unwrap(), sum, "{name}");
            assert_eq!(&h[257..263], b"ustar\0");
            assert_eq!(&h[136..147], b"00000000000", "{name}: mtime 0");
            at += BLOCK;
            out.push((name, bytes[at..at + size].to_vec()));
            at += size.div_ceil(BLOCK) * BLOCK;
        }
        out
    }

    // OP-159 m.3 (ii), F-6, Ek B 6265
    #[test]
    fn the_evidence_pack_is_byte_identical_when_built_twice() {
        let r = root();
        let sbom = std::env::temp_dir().join(format!("j9-sbom-{}.cdx.json", std::process::id()));
        std::fs::write(
            &sbom,
            b"{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\"}\n",
        )
        .unwrap();
        let one = build(&r, "v0.7.0", COMMIT, std::slice::from_ref(&sbom)).unwrap();
        let two = build(&r, "v0.7.0", COMMIT, std::slice::from_ref(&sbom)).unwrap();
        let _ = std::fs::remove_file(&sbom);
        assert_eq!(one.len() % BLOCK, 0);
        assert!(one == two, "two builds differ");

        let files = untar(&one);
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        let mut sorted = names[..names.len() - 1].to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, names[..names.len() - 1]);
        assert_eq!(names.last(), Some(&"evidence/SHA256SUMS"));
        let manifest: serde_json::Value = serde_json::from_slice(
            &files
                .iter()
                .find(|(n, _)| n == "evidence/manifest.json")
                .unwrap()
                .1,
        )
        .unwrap();
        assert_eq!(manifest["v"], 1);
        assert_eq!(manifest["release"], "v0.7.0");
        assert_eq!(manifest["commit"], COMMIT);
        let kinds: std::collections::BTreeSet<&str> = manifest["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["kind"].as_str().unwrap())
            .collect();
        for k in [
            "sbom",
            "security-model",
            "compliance-map",
            "formal-manifest",
            "test-layers",
            "support-policy",
            "psirt-deadlines",
            "slo",
        ] {
            assert!(kinds.contains(k), "{k}");
        }
        for f in manifest["files"].as_array().unwrap() {
            let path = f["path"].as_str().unwrap();
            let (_, bytes) = files.iter().find(|(n, _)| n == path).unwrap();
            assert_eq!(f["sha256"].as_str().unwrap(), sha256(bytes), "{path}");
        }
        let listed = String::from_utf8(files.last().unwrap().1.clone()).unwrap();
        assert_eq!(listed.lines().count(), files.len() - 1);
        for (n, b) in &files[..files.len() - 1] {
            assert!(listed.contains(&format!("{}  {n}", sha256(b))), "{n}");
        }
    }

    // OP-159 m.3 (ii)
    #[test]
    fn a_bad_commit_release_or_argument_is_refused() {
        let r = root();
        assert!(build(&r, "v0.7.0", "abc", &[]).is_err());
        assert!(build(&r, "v0.7.0", &COMMIT.to_uppercase(), &[]).is_err());
        assert!(build(&r, "a/b", COMMIT, &[]).is_err());
        assert!(parse(&[]).is_err());
        assert!(parse(&[String::from("d"), String::from("--bogus")]).is_err());
        let a = parse(&[
            String::from("out"),
            String::from("--sbom"),
            String::from("x.json"),
            String::from("--release"),
            String::from("v1.0.0"),
        ])
        .unwrap();
        assert_eq!(a.dir, PathBuf::from("out"));
        assert_eq!(a.sboms, [PathBuf::from("x.json")]);
        assert_eq!(a.release.as_deref(), Some("v1.0.0"));
        assert!(header(&"x".repeat(101), 1).is_err());
    }

    // SA-16, OP-159 m.3 (ii)
    #[test]
    fn the_psirt_periods_come_from_the_support_policy() {
        let doc: serde_json::Value =
            serde_json::from_slice(&psirt_periods(&root()).unwrap()).unwrap();
        assert_eq!(doc["early_warning_hours"], 24);
        assert_eq!(doc["notification_hours"], 72);
        assert_eq!(doc["final_report_vulnerability_days"], 14);
        assert_eq!(doc["final_report_incident_months"], 1);
    }
}
