//! The Linux client on the real server (OP-156 m.3 (p), IDP-32, MD-8, OP-153 m.3 (gg)): the
//! server group and the host are registered by committed `idp.ssh.*` and `idp.linux.*`
//! decisions, the host named by the client certificate it presents on the public listener. The
//! `access-linuxd` daemon reaches Access only over that listener with the public crates and
//! answers the module channel on its own socket; the modules' side is the blocking client the
//! NSS and PAM shells use. P approves the daemon's device codes on the realm's verification
//! routes with a session whose assurance the test chooses: a passkey, or a push alone.

#![allow(
    clippy::too_many_lines,
    reason = "test code: one walk through the Linux client's rules"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use access_identity_admin::domain::Change;
use access_identity_admin::domain::linux::{HostSpec, LinuxChange};
use access_identity_session::domain::assurance::{Factor, MethodClass, vector};
use access_identity_session::domain::session::cookie_digest;
use access_identity_ssh::domain::change::SshChange;
use access_identity_ssh::domain::schema;
use access_kernel::model::Bound;
use access_linux_client::adapters::https::AccessHttps;
use access_linux_client::adapters::local::{NoKey, OsRandom, StateFile, SystemClock, bind, serve};
use access_linux_client::app::Daemon;
use access_linux_module::client::{TIMEOUT, Unanswered, ask};
use access_linux_module::wire::{Request, Response};
use access_store::sessions::NewSession;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value as JsonValue, json};

use super::*;

const HOUR_MS: u64 = 3_600_000;
const SESSION: &str = "__Host-access-session";

type LinuxDaemon = Daemon<AccessHttps, SystemClock, OsRandom, StateFile, NoKey>;

fn texts(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| String::from(*s)).collect()
}

/// `ssh.login` on server group `group` naming `principals`, for `life_ms`.
fn login_on(group: &str, principals: &[&str], now: u64, life_ms: u64) -> CanonicalAuthority {
    let mut a = authority(
        BTreeSet::from([schema::login_ref()]),
        schema::NAMESPACE,
        BTreeSet::new(),
    );
    a.authority.resource = ResourceSelector::Exact(schema::host_group(group));
    a.authority.params = BTreeMap::from([(
        String::from(schema::PRINCIPAL),
        Bound::Enum(texts(principals)),
    )]);
    a.constraints.validity = Window {
        from: now - 60_000,
        until: now + life_ms,
    };
    a
}

fn scratch(name: &str) -> PathBuf {
    let tag = b64url_encode(&access_crypto::random::bytes::<9>().unwrap());
    let dir = std::env::temp_dir().join(format!("q13-{name}-{tag}"));
    std::fs::create_dir_all(dir.join("break-glass")).unwrap();
    dir
}

fn my_uid(dir: &Path) -> u32 {
    std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(dir).unwrap())
}

/// The modules' side: one blocking request, as the NSS and PAM shells make it.
async fn module(socket: &Path, r: Request) -> Result<Response, Unanswered> {
    let socket = socket.to_path_buf();
    tokio::task::spawn_blocking(move || ask(&socket, &r, TIMEOUT))
        .await
        .unwrap()
}

impl Desk {
    async fn linux_change(&self, change: Change) {
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let declared = DeclaredTargets::default();
        let b = Bootstrap {
            app: &self.w.db.app,
            router: &self.w.db.router,
            plane: &self.w.plane,
            realm_keys: &self.w.keyring,
            hsm: &self.w.keys,
            base: &self.w.base,
            declared: &declared,
            console: None,
        };
        let ids = cell_ids(&self.w.db.app, &self.w.keys).await.unwrap();
        b.change(
            &b.admin(&ids, None),
            (route.tenant, route.realm),
            self.domain,
            &root_key(&self.w.keys).unwrap(),
            change,
        )
        .await
        .unwrap();
    }

    /// A browser session of P whose sign-in was `factor`, now.
    async fn linux_session(&self, factor: Factor) -> String {
        let value: [u8; 32] = access_crypto::random::bytes().unwrap();
        let at = server_time(&self.w.db.app).await.unwrap();
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&self.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        t.insert_session(&NewSession {
            cookie_hash: &cookie_digest(&value),
            subject: self.subject,
            session_epoch: 0,
            keep_signed_in: false,
            created_ms: i64::try_from(at).unwrap(),
            auth_time_ms: i64::try_from(at).unwrap(),
            idle_ms: i64::try_from(HOUR_MS).unwrap(),
            expires_ms: i64::try_from(at + HOUR_MS).unwrap(),
            assurance: &serde_json::to_vec(&vector(&[factor])).unwrap(),
        })
        .await
        .unwrap();
        t.commit().await.unwrap();
        b64url_encode(&value)
    }

    async fn device_page(
        &self,
        path: &str,
        cookie: &str,
        csrf: Option<&str>,
        body: &JsonValue,
    ) -> (u16, JsonValue) {
        let url = format!("{}{path}", self.user.issuer);
        let cookie = format!("{SESSION}={cookie}");
        let mut headers = vec![
            ("cookie", cookie.as_str()),
            ("origin", "https://access.test"),
            ("sec-fetch-site", "same-origin"),
        ];
        if let Some(c) = csrf {
            headers.push(("x-csrf-token", c));
        }
        let bytes = body.to_string().into_bytes();
        let r = self
            .http
            .request("POST", &url, &headers, Some(("application/json", &bytes)))
            .await
            .unwrap();
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(JsonValue::Null),
        )
    }

    /// P approves `user_code` in the browser session `cookie`.
    async fn approve_device(&self, cookie: &str, user_code: &str) {
        let (status, view) = self
            .device_page(
                "/v1/device/preview",
                cookie,
                None,
                &json!({ "user_code": user_code }),
            )
            .await;
        assert_eq!(status, 200, "{view}");
        let csrf = String::from(view["csrf"].as_str().unwrap());
        let (status, done) = self
            .device_page(
                "/v1/device/approval",
                cookie,
                Some(&csrf),
                &json!({ "user_code": user_code, "approve": true }),
            )
            .await;
        assert_eq!(status, 200, "{done}");
    }

    fn linux_daemon(&self, dir: &Path) -> LinuxDaemon {
        let mut roots = rustls::RootCertStore::empty();
        for c in CertificateDer::pem_slice_iter(self.tls.ca.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let chain = CertificateDer::pem_slice_iter(self.tls.pep_cert.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_slice(self.tls.pep_key.as_bytes()).unwrap();
        let access = AccessHttps::new(roots, chain, key, &self.user.issuer, &self.user.client_id)
            .unwrap()
            .resolving(self.addr);
        Daemon::new(
            access,
            SystemClock,
            OsRandom,
            StateFile(dir.join("state.json")),
            NoKey,
            Some(dir.join("break-glass")),
        )
    }
}

/// One sign-in or step-up through the module channel: the daemon's pending device code,
/// approved by P in `cookie`'s session, then polled once to its decision.
async fn through(d: &Desk, socket: &Path, r: Request, cookie: &str) -> Response {
    let Ok(Response::Pending(p)) = module(socket, r).await else {
        panic!("not pending");
    };
    d.approve_device(cookie, p.user_code.as_deref().unwrap())
        .await;
    module(socket, Request::Poll(p.attempt)).await.unwrap()
}

// IDP-32, OP-156 m.3 (p), MD-8, Ek B 5128, 5206, 5306
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_linux_host_resolves_only_granted_users_and_sudo_needs_a_phishing_resistant_step_up() {
    Box::pin(walk()).await;
}

async fn walk() {
    let d = Box::pin(Desk::open("q13-linux", false)).await;
    d.linux_change(Change::Ssh(SshChange::HostGroupRegister {
        name: String::from("prod-web"),
        description: String::from("Web servers"),
    }))
    .await;
    let certificate = b64url_encode(&suiss_crypto::digest::sha256(&d.leaf));
    d.linux_change(Change::Linux(LinuxChange::Register(HostSpec {
        name: String::from("web-1"),
        host_group: String::from("prod-web"),
        certificate,
        shell: String::from("/bin/bash"),
        sudo_ct: 2,
    })))
    .await;
    d.linux_change(Change::DeviceCode(true)).await;
    let now = server_time(&d.w.db.app).await.unwrap();
    root_grant(
        &d.w,
        d.domain,
        grant_of(
            &d.domain,
            d.person,
            login_on("prod-web", &["ayse"], now, 48 * HOUR_MS),
        ),
    )
    .await;
    // OP-141 m.22 (g)
    assert!(d.w.domains.derive().await.is_empty());

    let dir = scratch("walk");
    let socket = if modules() {
        PathBuf::from(access_linux_module::client::SOCKET)
    } else {
        dir.join("socket")
    };
    let daemon = Arc::new(d.linux_daemon(&dir));
    let server = tokio::spawn(serve(
        Arc::clone(&daemon),
        bind(&socket).unwrap(),
        my_uid(&dir),
    ));

    // IDP-32, OP-156 m.3 (p)
    let Ok(Response::Passwd(ayse)) = module(&socket, Request::Getpwnam(String::from("ayse"))).await
    else {
        panic!("ayse does not resolve");
    };
    assert!(ayse.uid >= 200_000);
    assert_eq!(
        (ayse.dir.as_str(), ayse.shell.as_str(), ayse.gecos.as_str()),
        ("/home/ayse", "/bin/bash", "")
    );
    assert_eq!(
        module(&socket, Request::Getpwuid(ayse.uid)).await,
        Ok(Response::Passwd(ayse.clone()))
    );
    assert_eq!(
        module(&socket, Request::Getpwnam(String::from("mert"))).await,
        Ok(Response::NotFound)
    );
    let Ok(Response::Group(group)) = module(&socket, Request::Getgrgid(ayse.gid)).await else {
        panic!("no group");
    };
    assert_eq!(
        (group.name.as_str(), group.members.clone()),
        ("prod-web", vec![String::from("ayse")])
    );
    assert_eq!(
        module(&socket, Request::Getgrouplist(String::from("ayse"))).await,
        Ok(Response::Groups(vec![ayse.gid]))
    );

    // IDP-32, OP-62
    let passkey = d
        .linux_session(Factor::passkey([1; 16], false, true, false, now))
        .await;
    let push = d.linux_session(Factor::email(MethodClass::Push, now)).await;
    let signin = Request::Authenticate {
        user: String::from("ayse"),
        service: String::from("login"),
        tty: Some(String::from("tty1")),
    };
    assert_eq!(
        through(&d, &socket, signin, &push).await,
        Response::Done {
            allow: true,
            offline: None
        }
    );
    assert!(daemon.state().await.console.contains_key("ayse"));
    assert_eq!(
        module(
            &socket,
            Request::Authenticate {
                user: String::from("mert"),
                service: String::from("login"),
                tty: None,
            }
        )
        .await,
        Ok(Response::Done {
            allow: false,
            offline: None
        })
    );

    // OP-156 m.3 (p), IDP-8
    let sudo = Request::Sudo {
        user: String::from("ayse"),
        command: suiss_crypto::digest::sha256(b"sudo\0systemctl\0restart\0nginx\0"),
    };
    assert_eq!(
        through(&d, &socket, sudo.clone(), &push).await,
        Response::Done {
            allow: false,
            offline: None
        }
    );
    assert_eq!(
        through(&d, &socket, sudo, &passkey).await,
        Response::Done {
            allow: true,
            offline: None
        }
    );

    if modules() {
        installed(&d, &passkey).await;
    }

    // OP-156 m.3 (p)
    server.abort();
    let _ = server.await;
    std::fs::remove_file(&socket).unwrap();
    assert_eq!(
        module(&socket, Request::Getpwnam(String::from("ayse"))).await,
        Err(Unanswered)
    );
    if modules() {
        let (ok, _) = run(&["getent", "passwd", "ayse"]).await;
        assert!(!ok);
        let (ok, _) = run(&["pamtester", "access-test", "ayse", "authenticate"]).await;
        assert!(!ok);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Whether the installed NSS and PAM modules are exercised too (the Linux CI job installs them
/// into the runner's glibc and PAM).
fn modules() -> bool {
    cfg!(target_os = "linux") && std::env::var("ACCESS_LINUX_MODULES").as_deref() == Ok("1")
}

async fn run(args: &[&str]) -> (bool, String) {
    let args: Vec<String> = args.iter().map(|a| String::from(*a)).collect();
    let out = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::task::spawn_blocking(move || {
            std::process::Command::new(&args[0])
                .args(&args[1..])
                .output()
                .unwrap()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

/// `getent` through `libnss_access.so.2` and `pamtester` through `pam_access.so`: the real
/// glibc and PAM, the daemon behind them.
async fn installed(d: &Desk, cookie: &str) {
    use std::io::BufRead as _;
    let (ok, text) = run(&["getent", "passwd", "ayse"]).await;
    assert!(ok && text.starts_with("ayse:x:"), "{text}");
    let (ok, _) = run(&["getent", "passwd", "mert"]).await;
    assert!(!ok);
    let (ok, text) = run(&["getent", "group", "prod-web"]).await;
    assert!(ok && text.trim_end().ends_with(":ayse"), "{text}");
    let mut child = std::process::Command::new("stdbuf")
        .args([
            "-oL",
            "pamtester",
            "-v",
            "access-test",
            "ayse",
            "authenticate",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (code_tx, code_rx) = std::sync::mpsc::channel::<String>();
    let seen = std::thread::spawn(move || {
        let mut all = Vec::new();
        for line in std::io::BufReader::new(stdout).lines() {
            let line = line.unwrap_or_default();
            if let Some((_, rest)) = line.split_once("enter ") {
                let _ = code_tx.send(String::from(rest.trim_end_matches('.').trim()));
            }
            all.push(line);
        }
        all.join("\n")
    });
    let errors = std::thread::spawn(move || {
        let mut all = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::BufReader::new(stderr), &mut all);
        all
    });
    let code = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::task::spawn_blocking(move || code_rx.recv().ok()),
    )
    .await
    .unwrap()
    .unwrap();
    if let Some(code) = &code {
        d.approve_device(cookie, code).await;
    }
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::task::spawn_blocking(move || child.wait().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let out = seen.join().unwrap();
    let err = errors.join().unwrap();
    assert!(
        code.is_some() && status.success(),
        "pamtester {status}\nstdout:\n{out}\nstderr:\n{err}"
    );
}
