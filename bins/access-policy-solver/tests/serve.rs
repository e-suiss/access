//! The solver as a real process (OP-157 m.8 (a), OP-159 m.3 (aa)): it refuses an unsafe socket
//! directory, answers over its socket, and every failure is `Unknown`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use restriction_analysis::sibling::{Client, Relation};

const BIN: &str = env!("CARGO_BIN_EXE_access-policy-solver");

const SCHEMA: &str = r"
entity Actor { tenant: String, assurance: Long };
entity Resource { tenant: String, kind: String };
type Ctx = { amount: Long, risk: Long };
action transfer, read appliesTo { principal: [Actor], resource: [Resource], context: Ctx };
";
const NARROW: &str = r#"@id("cross-tenant") forbid(principal, action, resource) when { principal.tenant != resource.tenant };"#;
const NARROWER: &str = r#"@id("cross-tenant") forbid(principal, action, resource) when { principal.tenant != resource.tenant };
@id("risky") forbid(principal, action, resource) when { context.risk >= 70 };"#;

struct Solver {
    child: Child,
    dir: PathBuf,
}

impl Drop for Solver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn dir(name: &str, mode: u32) -> PathBuf {
    let d = std::env::temp_dir().join(format!("aps-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
    d
}

fn start(name: &str, dir_mode: u32, cvc5: &Path) -> (Solver, PathBuf) {
    let d = dir(name, dir_mode);
    let socket = d.join("s.sock");
    let config = d.join("solver.conf");
    std::fs::write(
        &config,
        format!(
            "socket = \"{}\"\ncvc5 = \"{}\"\n",
            socket.display(),
            cvc5.display()
        ),
    )
    .unwrap();
    let child = Command::new(BIN)
        .arg("serve")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    (Solver { child, dir: d }, socket)
}

fn wait_for(socket: &Path, solver: &mut Solver) -> bool {
    let until = Instant::now() + Duration::from_secs(20);
    while Instant::now() < until {
        if socket.exists() {
            return true;
        }
        if solver.child.try_wait().unwrap().is_some() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

// OP-159 m.3 (aa)
#[test]
fn an_unsafe_socket_directory_stops_the_solver_at_start() {
    let (mut s, socket) = start("unsafe", 0o777, Path::new("/nonexistent/cvc5"));
    let status = s.child.wait().unwrap();
    assert_eq!(status.code(), Some(1));
    let _ = socket;
}

// OP-157 m.8 (a), (b), OP-159 m.3 (aa)
#[test]
fn a_solver_that_cannot_run_cvc5_answers_unknown_and_a_stopped_one_is_unknown_too() {
    let (mut s, socket) = start("nocvc5", 0o700, Path::new("/nonexistent/cvc5"));
    assert!(wait_for(&socket, &mut s), "the solver did not listen");
    let client = Client::new(socket.clone(), None, Duration::from_secs(10));
    assert_eq!(client.check(), Ok(()));
    assert_eq!(client.compare(SCHEMA, NARROW, NARROWER), Relation::Unknown);
    s.child.kill().unwrap();
    s.child.wait().unwrap();
    assert_eq!(client.compare(SCHEMA, NARROW, NARROWER), Relation::Unknown);
}

// OP-105, OP-157 m.8 (a), OP-159 m.3 (aa), Ek B 5660
#[test]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5; run `just smt-test`"]
fn the_pinned_solver_answers_through_the_socket() {
    let cvc5 = PathBuf::from(std::env::var_os("ACCESS_CVC5").expect("ACCESS_CVC5"));
    let (mut s, socket) = start("cvc5", 0o700, &cvc5);
    assert!(wait_for(&socket, &mut s), "the solver did not listen");
    let client = Client::new(socket, None, Duration::from_secs(60));
    assert_eq!(
        client.compare(SCHEMA, NARROW, NARROWER),
        Relation::Narrowing
    );
    assert_eq!(client.compare(SCHEMA, NARROWER, NARROW), Relation::Widening);
}
