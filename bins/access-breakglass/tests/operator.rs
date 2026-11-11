//! The real `access-breakglass` process against a cell directory, with no database reachable
//! (OP-46, CMP-25, G63, OP-157 m.3 (j)).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::fmt::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use access_crypto::breakglass::{Directive, DirectiveState, Document, Op, OperatorKey, hex};

struct Cell {
    root: PathBuf,
    dir: PathBuf,
    ops: PathBuf,
    seeds: Vec<PathBuf>,
    directive_public: Vec<u8>,
}

fn tool(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_access-breakglass"))
        .args(args)
        // G63: the cell's database is not reachable, and the tool never asks for it
        .env("DATABASE_URL", "postgres://nobody@127.0.0.1:1/unreachable")
        .output()
        .unwrap()
}

fn ok(args: &[&str]) -> String {
    let o = tool(args);
    assert!(o.status.success(), "{args:?}: {o:?}");
    String::from_utf8(o.stdout).unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn keygen(root: &Path, name: &str) -> (PathBuf, String) {
    let seed = root.join(format!("{name}.seed"));
    let line = ok(&["keygen", s(&seed)]);
    (
        seed,
        line.trim().strip_prefix("ed25519 ").unwrap().to_owned(),
    )
}

fn keys_file(root: &Path, name: &str, generation: u64, publics: &[String]) -> PathBuf {
    let mut text = format!("generation {generation}\nthreshold 2\n");
    for (i, p) in publics.iter().enumerate() {
        let _ = writeln!(text, "ed25519 op{i} {p}");
    }
    let path = root.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

fn cell(name: &str, alarm_ok: bool) -> Cell {
    let root = std::env::temp_dir().join(format!("bg-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = root.join("etc/eu-1");
    let ops = root.join("ops");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&ops).unwrap();
    let mut seeds = Vec::new();
    let mut publics = Vec::new();
    for i in 0..3 {
        let (seed, public) = keygen(&root, &format!("op{i}"));
        seeds.push(seed);
        publics.push(public);
    }
    let keys = keys_file(&root, "keys-1", 1, &publics);
    std::fs::copy(keys, dir.join("keys")).unwrap();
    let (directive_seed, directive_public) = keygen(&root, "directive");
    std::fs::rename(directive_seed, dir.join("directive.key")).unwrap();
    let alarm = root.join("alarm.sh");
    std::fs::write(
        &alarm,
        format!(
            "#!/bin/sh\necho \"$@\" >> {}\nexit {}\n",
            s(&root.join("alarms")),
            u8::from(!alarm_ok)
        ),
    )
    .unwrap();
    std::fs::set_permissions(&alarm, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(
        root.join("access.toml"),
        "issuer = \"https://access.example\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("cell"),
        format!(
            "name eu-1\nops {}\nalarm {}\nsyslog udp:127.0.0.1:9\nsiem 127.0.0.1:9\nconfig {}\n",
            s(&ops),
            s(&alarm),
            s(&root.join("access.toml"))
        ),
    )
    .unwrap();
    Cell {
        directive_public: access_crypto::breakglass::unhex(&directive_public).unwrap(),
        root,
        dir,
        ops,
        seeds,
    }
}

fn approved(c: &Cell, name: &str, ops: &str, by: &[usize]) -> PathBuf {
    let doc = c.root.join(name);
    ok(&["document", "eu-1", ops, "15", s(&doc)]);
    for i in by {
        ok(&["approve", s(&doc), &format!("op{i}"), s(&c.seeds[*i])]);
    }
    doc
}

fn directives(c: &Cell) -> Vec<Directive> {
    let dir = c.ops.join("directives");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<Directive> = entries
        .map(|e| std::fs::read(e.unwrap().path()).unwrap())
        .map(|b| Directive::verify(&b, &c.directive_public).unwrap())
        .collect();
    out.sort_by_key(|d| d.seq);
    out
}

fn refused(o: &Output, code: &str) {
    assert_eq!(o.status.code(), Some(1), "{o:?}");
    assert!(String::from_utf8_lossy(&o.stderr).contains(code), "{o:?}");
}

// G63, CMP-25, OP-46: 2-of-3 verifies offline with no database; the directives verify under
// the cell's key and name only infrastructure operations; every use is trailed and alarmed
#[test]
fn g63_two_of_three_writes_signed_directives_without_a_database() {
    let c = cell("run", true);
    let doc = approved(
        &c,
        "d1",
        "config.read,epoch.floor,leader.unhealthy,flag:login.notice:on",
        &[0, 2],
    );
    let out = ok(&["run", s(&c.dir), s(&doc)]);
    assert!(out.contains("issuer = "), "{out}");
    let d = directives(&c);
    assert_eq!(
        d.iter().map(|d| d.op.name()).collect::<Vec<_>>(),
        ["epoch.floor", "leader.unhealthy", "flag:login.notice:on"]
    );
    assert!(d.iter().all(|d| d.cell == "eu-1"));
    let state = DirectiveState::fold(&d);
    assert!(state.leader_unhealthy && state.epoch_floor_ms.is_some() && state.flag("login.notice"));
    let alarms = std::fs::read_to_string(c.root.join("alarms")).unwrap();
    assert!(alarms.starts_with("used eu-1 "), "{alarms}");
    let trail = std::fs::read_to_string(c.dir.join("state/trail")).unwrap();
    for event in [" used ", " read ", " directive ", " spent "] {
        assert!(trail.contains(event), "{trail}");
    }
    ok(&["verify", s(&c.dir)]);
}

// §17.7.3 principle 8, OP-57 m.9: the same document twice is refused, and a new document under
// the spent key set is refused until a rotation installs fresh keys
#[test]
fn op_46_single_use_and_rotation_after_use() {
    let c = cell("rotate", true);
    let first = approved(&c, "d1", "leader.unhealthy", &[0, 1]);
    ok(&["run", s(&c.dir), s(&first)]);
    refused(&tool(&["run", s(&c.dir), s(&first)]), "replayed");
    let second = approved(&c, "d2", "leader.healthy", &[1, 2]);
    refused(&tool(&["run", s(&c.dir), s(&second)]), "rotation-required");
    assert_eq!(directives(&c).len(), 1);
    let same = keys_file(&c.root, "keys-same", 2, &[]);
    std::fs::write(
        &same,
        std::fs::read_to_string(c.dir.join("keys"))
            .unwrap()
            .replace("generation 1", "generation 2"),
    )
    .unwrap();
    refused(&tool(&["rotate", s(&c.dir), s(&same)]), "rotation-not-new");
    let mut publics = Vec::new();
    let mut seeds = Vec::new();
    for i in 0..3 {
        let (seed, public) = keygen(&c.root, &format!("new{i}"));
        seeds.push(seed);
        publics.push(public);
    }
    let fresh = keys_file(&c.root, "keys-2", 2, &publics);
    ok(&["rotate", s(&c.dir), s(&fresh)]);
    refused(&tool(&["run", s(&c.dir), s(&second)]), "approval");
    let third = c.root.join("d3");
    ok(&["document", "eu-1", "leader.healthy", "5", s(&third)]);
    for i in [0, 2] {
        ok(&["approve", s(&third), &format!("op{i}"), s(&seeds[i])]);
    }
    ok(&["run", s(&c.dir), s(&third)]);
    assert!(!DirectiveState::fold(&directives(&c)).leader_unhealthy);
}

// §17.7.3 principle 8: a window over 15 minutes is never made, and a document past its end is refused
#[test]
fn op_46_fifteen_minutes_at_most() {
    let c = cell("window", true);
    let long = c.root.join("long");
    refused(
        &tool(&["document", "eu-1", "health", "16", s(&long)]),
        "window",
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let now = u64::try_from(now).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap();
    let doc = Document::new(
        "eu-1",
        vec![Op::EpochFloor],
        nonce,
        now - 16 * 60_000,
        now - 60_000,
    )
    .unwrap();
    let path = c.root.join("old");
    std::fs::write(&path, doc.encode().unwrap()).unwrap();
    for i in [0, 1] {
        ok(&["approve", s(&path), &format!("op{i}"), s(&c.seeds[i])]);
    }
    refused(&tool(&["run", s(&c.dir), s(&path)]), "not-now");
    let other = c.root.join("other-cell");
    ok(&["document", "eu-2", "health", "5", s(&other)]);
    for i in [0, 1] {
        ok(&["approve", s(&other), &format!("op{i}"), s(&c.seeds[i])]);
    }
    refused(&tool(&["run", s(&c.dir), s(&other)]), "cell");
    let one = approved(&c, "one", "epoch.floor", &[0]);
    refused(&tool(&["run", s(&c.dir), s(&one)]), "quorum");
    assert_eq!(directives(&c), []);
    let alarms = std::fs::read_to_string(c.root.join("alarms")).unwrap();
    assert_eq!(
        alarms.lines().filter(|l| l.starts_with("refused ")).count(),
        3
    );
}

// §17.7.3 principle 6: a broken trail stops the tool before anything happens
#[test]
fn op_46_a_broken_trail_stops_the_tool() {
    let c = cell("trail", true);
    let first = approved(&c, "d1", "health", &[0, 1]);
    let o = tool(&["run", s(&c.dir), s(&first)]);
    assert!(!o.status.success(), "{o:?}");
    let trail = c.dir.join("state/trail");
    let text = std::fs::read_to_string(&trail).unwrap();
    std::fs::write(&trail, text.replacen(" used ", " drill ", 1)).unwrap();
    let doc = approved(&c, "d2", "epoch.floor", &[1, 2]);
    let o = tool(&["run", s(&c.dir), s(&doc)]);
    assert_eq!(o.status.code(), Some(3), "{o:?}");
    assert_eq!(tool(&["verify", s(&c.dir)]).status.code(), Some(3));
    assert_eq!(directives(&c), []);
}

// §17.7.3 principles 7 and 9: a drill runs the whole path and applies nothing; without a
// confirmed alarm nothing is applied either
#[test]
fn op_46_drill_and_alarm() {
    let c = cell("drill", true);
    let doc = approved(&c, "d1", "epoch.floor,leader.unhealthy", &[0, 1]);
    let out = ok(&["drill", s(&c.dir), s(&doc)]);
    assert!(out.contains("nothing applied"), "{out}");
    assert_eq!(directives(&c), []);
    let trail = std::fs::read_to_string(c.dir.join("state/trail")).unwrap();
    assert!(
        trail.contains(" drill ") && trail.contains(" drill-done "),
        "{trail}"
    );
    assert!(
        std::fs::read_to_string(c.root.join("alarms"))
            .unwrap()
            .starts_with("drill eu-1 ")
    );
    refused(&tool(&["run", s(&c.dir), s(&doc)]), "replayed");
    let silent = cell("silent", false);
    let doc = approved(&silent, "d1", "epoch.floor", &[0, 1]);
    assert_eq!(
        tool(&["run", s(&silent.dir), s(&doc)]).status.code(),
        Some(4)
    );
    assert_eq!(directives(&silent), []);
    let trail = std::fs::read_to_string(silent.dir.join("state/trail")).unwrap();
    assert!(trail.contains(" alarm-failed "), "{trail}");
}

// OP-129 m.3, OP-157: key material comes from owner-only files, never from the environment
#[test]
fn op_157_secrets_come_from_files_only() {
    let c = cell("secrets", true);
    let doc = approved(&c, "d1", "health", &[0]);
    let loose = c.root.join("loose.seed");
    std::fs::copy(&c.seeds[1], &loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = tool(&["approve", s(&doc), "op1", s(&loose)]);
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    let o = Command::new(env!("CARGO_BIN_EXE_access-breakglass"))
        .args(["verify", s(&c.dir)])
        .env("ACCESS_BREAKGLASS_PRIVATE_KEY", "x")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{o:?}");
    let (k, _) = OperatorKey::generate().unwrap();
    assert_eq!(hex(&k.public()).len(), 64);
}
