//! The `policy.set` analysis through the sibling `access-policy-solver` process (OP-157 m.8 (a),
//! (b), OP-159 m.3 (aa), Ek B 5660), on the real sequencer, store and authority signer: the
//! server starts no process, and a solver that cannot answer, or is stopped, raises a
//! structurally narrowing change to CT3.

use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use suiss_crypto::dcbor::{Limits as CborLimits, Value as Cbor};

use super::authzen::{Pdp, pdp_with};
use super::*;

const NARROW: &str = r#"@id("no-reads") forbid(principal, action, resource) when { context.action == "shop:read" };"#;
const NARROWER: &str = r#"@id("no-reads") forbid(principal, action, resource) when { context.action == "shop:read" };
@id("no-agents") forbid(principal, action, resource) when { context.actor == "agent" };"#;

/// The solver binary from this target directory, built when missing.
fn bin() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().and_then(Path::parent).unwrap().to_path_buf();
    let bin = dir.join("access-policy-solver");
    if !bin.exists() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let status = Command::new(cargo)
            .args(["build", "-p", "access-policy-solver"])
            .status()
            .unwrap();
        assert!(status.success(), "access-policy-solver did not build");
    }
    bin
}

struct Solver {
    child: Child,
    dir: PathBuf,
}

impl Solver {
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Solver {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A real solver process on a socket in a fresh private directory, with `cvc5`.
fn solver(label: &str, cvc5: &Path) -> (Solver, PathBuf) {
    let dir = std::env::temp_dir().join(format!("aps-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.join("s.sock");
    let config = dir.join("solver.conf");
    std::fs::write(
        &config,
        format!(
            "socket = \"{}\"\ncvc5 = \"{}\"\n",
            socket.display(),
            cvc5.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(bin())
        .arg("serve")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < until, "the solver did not listen");
        assert!(child.try_wait().unwrap().is_none(), "the solver exited");
        std::thread::sleep(Duration::from_millis(20));
    }
    (Solver { child, dir }, socket)
}

fn content(source: &str) -> Cbor {
    let v = Cbor::Map(vec![
        (Cbor::text("schema"), Cbor::text("access/restriction/v1")),
        (Cbor::text("source"), Cbor::text(source)),
        (Cbor::text("target"), Cbor::text("domain")),
    ]);
    suiss_crypto::dcbor::decode(
        &suiss_crypto::dcbor::encode(&v, CborLimits::CEILING).unwrap(),
        CborLimits::CEILING,
    )
    .unwrap()
}

async fn set(p: &Pdp, policy: Option<Id>, source: &str) -> (Vec<u8>, Result<u64, String>) {
    let declared = DeclaredTargets::default();
    let b = crate::bootstrap::Bootstrap {
        app: &p.w.db.app,
        router: &p.w.db.router,
        plane: &p.w.plane,
        realm_keys: &p.w.keyring,
        hsm: &p.w.keys,
        base: &p.w.base,
        declared: &declared,
        console: None,
    };
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let r = b
        .commit_meta(
            p.domain,
            &p.root,
            &nonce,
            meta::Payload::PolicySet {
                policy,
                content: content(source),
                defaults: None,
            },
            p.party,
        )
        .await
        .map_err(|e| e.to_string());
    (nonce, r)
}

async fn tier(p: &Pdp, nonce: &[u8]) -> Option<u8> {
    access_store::authority::find_nonce(&p.w.db.app, &DomainId::from_bytes(p.domain.0), nonce)
        .await
        .unwrap()
        .and_then(|n| n.tier)
}

/// The realm with one restriction policy, the solver behind its analysis port, and the policy.
async fn realm(label: &str, cvc5: &Path) -> (Pdp, Solver, Id) {
    let (s, socket) = solver(label, cvc5);
    let analysis = crate::analysis::Sibling::new(&socket, None).unwrap();
    let p = pdp_with(label, None, Arc::new(analysis)).await;
    let (nonce, first) = set(&p, None, NARROW).await;
    first.unwrap();
    let policy = meta::object_id(
        &meta::exercise_id(&p.domain, &nonce).unwrap(),
        meta::kind::POLICY,
        0,
    );
    (p, s, policy)
}

/// A change raised to CT3 asks this realm's root for more than its own signature.
fn raised(r: &Result<u64, String>) -> bool {
    matches!(r, Err(e) if e.contains("RequireAction"))
}

// OP-157 m.8 (a), (b), OP-159 m.3 (aa), Ek B 5660
#[tokio::test(flavor = "multi_thread")]
async fn without_a_solver_the_structural_rule_keeps_a_narrowing_ct1() {
    let control = pdp_with(
        "j6-solver-none",
        None,
        Arc::new(access_authority_core::ports::NoAnalysis),
    )
    .await;
    let (nonce, first) = set(&control, None, NARROW).await;
    first.unwrap();
    let policy = meta::object_id(
        &meta::exercise_id(&control.domain, &nonce).unwrap(),
        meta::kind::POLICY,
        0,
    );
    let (nonce, r) = set(&control, Some(policy), NARROWER).await;
    r.unwrap();
    assert_eq!(
        tier(&control, &nonce).await,
        Some(1),
        "without a solver the structural rule decides"
    );
    control.w.domains.release().await;
}

// OP-157 m.8 (a), (b), OP-159 m.3 (aa), Ek B 5660
#[tokio::test(flavor = "multi_thread")]
async fn a_solver_without_an_answer_or_stopped_raises_a_structural_narrowing() {
    let (p, mut s, policy) = realm("j6-solver-unknown", Path::new("/nonexistent/cvc5")).await;
    let r = set(&p, Some(policy), NARROWER).await.1;
    assert!(raised(&r), "no answer raises: {r:?}");
    s.stop();
    let r = set(&p, Some(policy), NARROWER).await.1;
    assert!(raised(&r), "a stopped solver raises: {r:?}");
    p.w.domains.release().await;
}

// OP-105, OP-157 m.8 (a), (b), OP-159 m.3 (aa), Ek B 5660
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the pinned cvc5 in ACCESS_CVC5 and the Linux solver sandbox; nightly `just test-full`"]
async fn the_sibling_solver_keeps_a_proved_narrowing_ct1_and_a_stopped_one_raises_it() {
    let cvc5 = PathBuf::from(std::env::var_os("ACCESS_CVC5").unwrap());
    let (p, mut s, policy) = realm("j6-solver-cvc5", &cvc5).await;
    let (nonce, r) = set(&p, Some(policy), NARROWER).await;
    r.unwrap();
    assert_eq!(
        tier(&p, &nonce).await,
        Some(1),
        "a proved narrowing stays CT1"
    );
    s.stop();
    let further = format!(
        "{NARROWER}\n@id(\"no-writes\") forbid(principal, action, resource) when {{ context.action == \"shop:write\" }};"
    );
    let r = set(&p, Some(policy), &further).await.1;
    assert!(raised(&r), "a stopped solver raises: {r:?}");
    p.w.domains.release().await;
}
