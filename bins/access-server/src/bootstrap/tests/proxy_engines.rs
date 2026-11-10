//! The Access Proxy engines against the real forward-auth path (IDP-30 (1), (2), (3), B22,
//! OP-156 m.3 (m), m.15 (i), OP-153 m.3 (gg), Ek B 5203, 5304, 5360): `access-proxy` renders one
//! TOML file for Envoy, Caddy and Traefik, Nginx runs the documented `auth_request` example, and
//! each engine runs as its own process in front of an echo application. Access is the real
//! forward-auth router on the real mTLS listener over real Postgres, sequencer and `SoftHSM`; the
//! engine names itself with its client certificate. Every engine runs the same cases from
//! `services/proxy/tests/behaviour`, so the same file gives the same outcomes on each.
//!
//! CI only (job `proxy-engines`): `scripts/ci/proxy-engines.sh` exports the digest-pinned images
//! and `ACCESS_TEST_PROXY_RUNNER=docker`; with `local` the engines come from `PATH`.

#![allow(
    clippy::too_many_lines,
    reason = "test code: one walk through the engine cases"
)]

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use access_identity_admin::domain::Change;
use access_identity_oauth::ports::Keys as _;
use access_identity_proxy::app::Proxy;
use access_identity_proxy::domain::engine::Engine;
use access_identity_proxy::domain::registration::{ProxyChange, Registration};
use access_proxy::behaviour::{Case, Phase, cases};
use access_proxy::config::Config;
use access_proxy::render::{Target, render};
use access_sdk::resource::app_token::{
    APP_SKEW_MS, AppTokenRules, app_token_algorithms, verify_app_token,
};
use axum::body::Body;
use axum::http::{HeaderMap, Request as HttpRequest, StatusCode, header};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use super::management::send;
use super::proxy::{
    Forward, HOST, commit, header_of, login_session, oauth, path_of, proxy_client_for,
};
use super::vault::{Lab, revoke_grant};
use super::*;

/// The applications: policy, host, resource namespace. The Lab's Grant covers `work` only.
const APPS: [(&str, &str, &str); 2] = [
    ("wiki", "wiki.example.com", "work"),
    ("admin", "admin.example.com", "other"),
];

const WAIT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug)]
enum Under {
    Envoy,
    Caddy,
    Traefik,
    Nginx,
}

impl Under {
    const fn word(self) -> &'static str {
        match self {
            Self::Envoy => "envoy",
            Self::Caddy => "caddy",
            Self::Traefik => "traefik",
            Self::Nginx => "nginx",
        }
    }

    const fn engine(self) -> Engine {
        match self {
            Self::Envoy => Engine::Envoy,
            Self::Caddy => Engine::Caddy,
            Self::Traefik => Engine::Traefik,
            Self::Nginx => Engine::Nginx,
        }
    }

    const fn binary(self) -> &'static str {
        match self {
            Self::Envoy => "/usr/local/bin/envoy",
            Self::Caddy => "/usr/bin/caddy",
            Self::Traefik => "/usr/local/bin/traefik",
            Self::Nginx => "/usr/sbin/nginx",
        }
    }
}

struct Pki {
    pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

/// A subject of its own: a leaf whose subject is its issuer's reads as self-signed to `OpenSSL`
/// and `BoringSSL`, which then refuse it.
fn dn(common_name: &str) -> rcgen::DistinguishedName {
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, common_name);
    dn
}

fn pki() -> Pki {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = dn("Access Proxy test CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let key = rcgen::KeyPair::generate().unwrap();
    let pem = params.self_signed(&key).unwrap().pem();
    Pki {
        pem,
        issuer: rcgen::Issuer::new(params, key),
    }
}

/// A certificate under `ca` for `names`: its PEM, its key's PEM and its DER.
fn leaf(ca: &Pki, names: &[&str], client: bool) -> (String, String, Vec<u8>) {
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|n| String::from(*n)).collect::<Vec<_>>())
            .unwrap();
    params.distinguished_name = dn(names.first().copied().unwrap_or("leaf"));
    params.extended_key_usages = vec![if client {
        rcgen::ExtendedKeyUsagePurpose::ClientAuth
    } else {
        rcgen::ExtendedKeyUsagePurpose::ServerAuth
    }];
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    (cert.pem(), key.serialize_pem(), cert.der().to_vec())
}

/// A world-readable directory the engine's container mounts at the same path.
fn scratch(word: &str) -> PathBuf {
    let tag: [u8; 8] = access_crypto::random::bytes().unwrap();
    let dir = std::env::temp_dir().join(format!("access-proxy-{word}-{}", b64url_encode(&tag)));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn put(dir: &Path, name: &str, text: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    p.display().to_string()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[derive(Default)]
struct Echo {
    hits: AtomicUsize,
    last: std::sync::Mutex<BTreeMap<String, String>>,
}

/// The application behind the engine: it counts requests and keeps the last one's headers.
async fn echo() -> (u16, Arc<Echo>) {
    let seen = Arc::new(Echo::default());
    let state = Arc::clone(&seen);
    let app = axum::Router::new().fallback(move |headers: HeaderMap| {
        let state = Arc::clone(&state);
        async move {
            let map = headers
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_owned(),
                        v.to_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect();
            *state.last.lock().unwrap() = map;
            state.hits.fetch_add(1, Ordering::SeqCst);
            "application"
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (port, seen)
}

struct Running {
    name: String,
    docker: bool,
    child: Option<Child>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.docker {
            let _ = Command::new("docker")
                .args(["logs", &self.name])
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status();
            let _ = Command::new("docker")
                .args(["rm", "--force", &self.name])
                .stdout(Stdio::null())
                .status();
        }
        if let Some(c) = self.child.as_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Starts `under` with `args` on files in `dir`.
fn start(under: Under, dir: &Path, args: &[String]) -> Running {
    let runner = std::env::var("ACCESS_TEST_PROXY_RUNNER").unwrap_or_default();
    let name = format!(
        "access-proxy-{}-{}",
        under.word(),
        dir.file_name().unwrap().to_string_lossy()
    );
    if runner == "docker" {
        let var = format!(
            "ACCESS_TEST_PROXY_IMAGE_{}",
            under.word().to_ascii_uppercase()
        );
        let image = std::env::var(&var).unwrap_or_else(|_| panic!("{var} is not set"));
        let d = dir.display().to_string();
        let status = Command::new("docker")
            .args(["run", "--detach", "--name", &name, "--network", "host"])
            .args(["--volume", &format!("{d}:{d}:ro")])
            .args(["--entrypoint", under.binary(), &image])
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "docker run {}", under.word());
        Running {
            name,
            docker: true,
            child: None,
        }
    } else {
        assert_eq!(
            runner, "local",
            "ACCESS_TEST_PROXY_RUNNER is docker or local"
        );
        let bin = Path::new(under.binary()).file_name().unwrap();
        let child = Command::new(bin).args(args).spawn().unwrap();
        Running {
            name,
            docker: false,
            child: Some(child),
        }
    }
}

struct Got {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Got {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .filter(|(k, _)| k == "set-cookie")
            .find_map(|(_, v)| {
                let (k, val) = v.split(';').next()?.split_once('=')?;
                (k.trim() == name && !val.is_empty()).then(|| format!("{name}={val}"))
            })
    }
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(i) = body.windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(
            String::from_utf8_lossy(&body[..i])
                .split(';')
                .next()
                .unwrap()
                .trim(),
            16,
        )
        .unwrap_or(0);
        if size == 0 {
            break;
        }
        let start = i + 2;
        out.extend_from_slice(&body[start..(start + size).min(body.len())]);
        body = body.get(start + size + 2..).unwrap_or_default();
    }
    out
}

fn parse(raw: &[u8]) -> Got {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let rest = raw.get(split + 4..).unwrap_or_default();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let body = if chunked {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    Got {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// The browser: TLS to the engine with the application's name, one HTTP/1.1 request.
struct Browser {
    tls: TlsConnector,
    port: u16,
}

impl Browser {
    fn new(ca_pem: &str, port: u16) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
            .unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            tls: TlsConnector::from(Arc::new(config)),
            port,
        }
    }

    async fn ask(
        &self,
        host: &str,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        send: &BTreeMap<String, String>,
    ) -> Option<Got> {
        let tcp = TcpStream::connect(("127.0.0.1", self.port)).await.ok()?;
        let mut tls = self
            .tls
            .connect(ServerName::try_from(host.to_owned()).ok()?, tcp)
            .await
            .ok()?;
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: 0\r\n"
        );
        if let Some(c) = cookie {
            let _ = write!(req, "Cookie: {c}\r\n");
        }
        for (k, v) in send {
            let _ = write!(req, "{k}: {v}\r\n");
        }
        req.push_str("\r\n");
        tls.write_all(req.as_bytes()).await.ok()?;
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(15), tls.read_to_end(&mut raw)).await;
        (!raw.is_empty()).then(|| parse(&raw))
    }
}

/// Waits until the engine answers the first application with a sign-in.
async fn ready(b: &Browser) {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let seen = b.ask(APPS[0].1, "GET", "/", None, &BTreeMap::new()).await;
        if seen.as_ref().is_some_and(|g| g.status == 302) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the engine did not come up: last answer {:?}",
            seen.map(|g| (g.status, g.body))
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Signs the browser in on `host` through the engine: the sign-in redirect, Access's real
/// `/authorize` with the login session, and the callback the engine passes to the check.
async fn sign_in(b: &Browser, authorize: &axum::Router, session: &str, host: &str) -> String {
    let none = BTreeMap::new();
    let first = b.ask(host, "GET", "/page", None, &none).await.unwrap();
    assert_eq!(first.status, 302, "{host}: {}", first.body);
    let to = first.header("location").unwrap().to_owned();
    let state = first.cookie("__Host-access-proxy-state").unwrap();
    let (r, body) = send(
        authorize,
        HttpRequest::get(path_of(&to))
            .header(header::HOST, HOST)
            .header(header::COOKIE, format!("__Host-access-session={session}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        r.status(),
        StatusCode::SEE_OTHER,
        "{}",
        String::from_utf8_lossy(&body)
    );
    let back = header_of(&r, "location").unwrap();
    let callback = path_of(&back);
    let got = b
        .ask(host, "GET", &callback, Some(&state), &none)
        .await
        .unwrap();
    assert_eq!(got.status, 302, "{host} callback: {}", got.body);
    assert_eq!(
        got.header("location"),
        Some(format!("https://{host}/page").as_str())
    );
    got.cookie("__Host-access-proxy").unwrap()
}

fn nginx_conf(dir: &Path, access: u16, upstream: u16, listen: u16) -> String {
    let template = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/proxy/nginx/access-proxy.conf.template"),
    )
    .unwrap();
    let d = dir.display();
    let mut out = String::from(
        "pid /tmp/access-proxy-nginx.pid;\nerror_log stderr info;\nevents {}\nhttp {\n    access_log off;\n",
    );
    for (_, host, _) in APPS {
        let mut server = template.clone();
        for (k, v) in [
            ("ACCESS_PROXY_LISTEN", format!("127.0.0.1:{listen}")),
            ("ACCESS_PROXY_APP_HOST", String::from(host)),
            ("ACCESS_PROXY_APP_CERT", format!("{d}/apps.pem")),
            ("ACCESS_PROXY_APP_KEY", format!("{d}/apps-key.pem")),
            (
                "ACCESS_PROXY_ACCESS_URL",
                format!("https://127.0.0.1:{access}"),
            ),
            ("ACCESS_PROXY_ACCESS_HOST", String::from("localhost")),
            ("ACCESS_PROXY_ACCESS_CA", format!("{d}/access-ca.pem")),
            ("ACCESS_PROXY_CERT", format!("{d}/proxy.pem")),
            ("ACCESS_PROXY_KEY", format!("{d}/proxy-key.pem")),
            (
                "ACCESS_PROXY_UPSTREAM",
                format!("http://127.0.0.1:{upstream}"),
            ),
        ] {
            server = server.replace(&format!("${{{k}}}"), &v);
        }
        out.push_str(&server);
    }
    out.push_str("}\n");
    out
}

fn behaviour() -> Vec<(String, Case)> {
    cases(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../services/proxy/tests/behaviour"))
        .unwrap()
}

/// Runs every case against `under`.
async fn run(under: Under) {
    let l = Lab::open(&format!("proxy-engine-{}", under.word())).await;
    let ca = pki();
    let (proxy_pem, proxy_key, proxy_der) = leaf(&ca, &["access-proxy.example"], true);
    let pep = b64url_encode(&suiss_crypto::digest::sha256(&proxy_der));
    for (name, host, namespace) in APPS {
        let client =
            proxy_client_for(&l, &format!("https://{host}/access-proxy/v1/callback")).await;
        commit(
            &l,
            Change::Proxy(ProxyChange::Register(Registration {
                name: String::from(name),
                engine: under.engine(),
                host: String::from(host),
                upstream: None,
                client_id: client,
                pep: pep.clone(),
                action: l.action.clone(),
                namespace: String::from(namespace),
                routes: vec![String::from("/")],
            })),
        )
        .await;
    }
    assert!(
        l.w.domains.derive().await.is_empty(),
        "the derived index holds the Grant the check reads"
    );
    let service = oauth(&l.w);
    let proxy: Arc<Forward> = Arc::new(Proxy::new(crate::proxy::ServerPorts {
        router: l.w.db.router.clone(),
        app: l.w.db.app.clone(),
        oauth: service.clone(),
        domains: l.w.domains.clone(),
    }));
    let forward = access_http::harden(
        access_http::proxy::router(proxy.clone()),
        access_http::Limits::default(),
    );
    let authorize = access_http::oauth::shared_router(service.clone());

    let (server_pem, server_key, _) = leaf(&ca, &["localhost"], false);
    let tls =
        access_http::tls::mtls_server_config(server_pem.as_bytes(), server_key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let access = listener.local_addr().unwrap().port();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(access_http::tls::serve_mtls(
        listener,
        tls,
        forward,
        None,
        async {
            let _ = stopped.await;
        },
    ));

    let (upstream, seen) = echo().await;
    let dir = scratch(under.word());
    let hosts: Vec<&str> = APPS.iter().map(|(_, h, _)| *h).collect();
    let (apps_pem, apps_key, _) = leaf(&ca, &hosts, false);
    let ca_file = put(&dir, "access-ca.pem", &ca.pem);
    let cert_file = put(&dir, "proxy.pem", &proxy_pem);
    let key_file = put(&dir, "proxy-key.pem", &proxy_key);
    let apps_cert = put(&dir, "apps.pem", &apps_pem);
    let apps_key_file = put(&dir, "apps-key.pem", &apps_key);
    let listen = free_port();
    let mut toml = format!(
        "[access]\nurl = \"https://localhost:{access}\"\nca = \"{ca_file}\"\ncertificate = \"{cert_file}\"\nkey = \"{key_file}\"\n\n[listen]\naddress = \"127.0.0.1:{listen}\"\ncertificate = \"{apps_cert}\"\nkey = \"{apps_key_file}\"\n"
    );
    for (name, host, _) in APPS {
        let _ = write!(
            toml,
            "\n[[app]]\npolicy = \"{name}\"\nhost = \"{host}\"\nupstream = \"http://127.0.0.1:{upstream}\"\n"
        );
    }
    let config = Config::parse(&toml).unwrap();
    let args: Vec<String> = match under {
        Under::Envoy => {
            let f = put(&dir, "envoy.yaml", &render(&config, Target::Envoy).unwrap());
            vec![
                String::from("--config-path"),
                f,
                String::from("--log-level"),
                String::from("info"),
            ]
        }
        Under::Caddy => {
            let f = put(&dir, "Caddyfile", &render(&config, Target::Caddy).unwrap());
            vec![
                String::from("run"),
                String::from("--config"),
                f,
                String::from("--adapter"),
                String::from("caddyfile"),
            ]
        }
        Under::Traefik => {
            let f = put(
                &dir,
                "traefik.yaml",
                &render(&config, Target::Traefik).unwrap(),
            );
            vec![
                format!("--entryPoints.apps.address=127.0.0.1:{listen}"),
                format!("--providers.file.filename={f}"),
                String::from("--log.level=INFO"),
            ]
        }
        Under::Nginx => {
            let f = put(
                &dir,
                "nginx.conf",
                &nginx_conf(&dir, access, upstream, listen),
            );
            vec![
                String::from("-c"),
                f,
                String::from("-g"),
                String::from("daemon off;"),
            ]
        }
    };
    let _engine = start(under, &dir, &args);
    let browser = Browser::new(&ca.pem, listen);
    ready(&browser).await;

    let session = login_session(&l).await;
    let mut cookies: BTreeMap<&str, String> = BTreeMap::new();
    let all = behaviour();
    let jwks = SignerKeys::new(l.w.identity_signer.clone())
        .jwks(l.route.realm)
        .await
        .unwrap();
    let keys =
        access_sdk::resource::keys::key_set(jwks.as_bytes(), &app_token_algorithms()).unwrap();
    let mut outcomes = Vec::new();
    for phase in [Phase::Anonymous, Phase::SignedIn, Phase::Revoked] {
        match phase {
            Phase::SignedIn => {
                for (name, host, _) in APPS {
                    cookies.insert(name, sign_in(&browser, &authorize, &session, host).await);
                }
            }
            Phase::Revoked => {
                for b in
                    l.w.domains
                        .proxy_bases(l.domain, l.party, &l.action)
                        .await
                        .unwrap()
                {
                    let (ExerciseBasis::Holding(HoldingRef { grant, .. })
                    | ExerciseBasis::Public(grant)) = b.0
                    else {
                        continue;
                    };
                    revoke_grant(&l, grant).await;
                }
                assert!(l.w.domains.derive().await.is_empty());
                proxy.sweep().await;
            }
            Phase::Anonymous | Phase::AccessDown => {}
        }
        for (name, case) in all.iter().filter(|(_, c)| c.phase == phase) {
            outcomes.push(ask(&browser, &cookies, &seen, &keys, (name, case)).await);
        }
    }
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    for (name, case) in all.iter().filter(|(_, c)| c.phase == Phase::AccessDown) {
        outcomes.push(ask(&browser, &cookies, &seen, &keys, (name, case)).await);
    }
    assert_eq!(outcomes.len(), all.len());
    let _ = std::fs::remove_dir_all(&dir);
}

/// One case: the browser's request through the engine, and what the browser and the
/// application saw.
async fn ask(
    b: &Browser,
    cookies: &BTreeMap<&str, String>,
    seen: &Echo,
    keys: &access_kernel::verify::cose::KeySet,
    (name, case): (&str, &Case),
) -> String {
    let (_, host, _) = APPS.iter().find(|(p, _, _)| *p == case.app).unwrap();
    let cookie = (case.phase != Phase::Anonymous)
        .then(|| cookies.get(case.app.as_str()).map(String::as_str))
        .flatten();
    let before = seen.hits.load(Ordering::SeqCst);
    let got = b
        .ask(host, &case.method, &case.path, cookie, &case.send)
        .await
        .unwrap_or_else(|| panic!("{name}: no answer"));
    assert!(
        case.expect.status.contains(&got.status),
        "{name} ({}): status {} {}",
        case.rule,
        got.status,
        got.body
    );
    let reached = seen.hits.load(Ordering::SeqCst) > before;
    assert_eq!(reached, case.expect.upstream, "{name} ({})", case.rule);
    if let Some(prefix) = &case.expect.location {
        let to = got.header("location").unwrap_or_default();
        assert!(to.starts_with(prefix.as_str()), "{name}: {to}");
    }
    if reached {
        assert_eq!(got.body, "application", "{name}");
        let last = seen.last.lock().unwrap().clone();
        let token = last.get("access-identity").cloned().unwrap_or_default();
        let rules = AppTokenRules {
            issuer: "https://access.test/realms/acme",
            audience: &format!("https://{host}"),
            now: now_ms(),
            skew_ms: APP_SKEW_MS,
        };
        assert_eq!(
            verify_app_token(&token, keys, &rules).is_ok(),
            case.expect.identity,
            "{name} ({})",
            case.rule
        );
        let plain = last.contains_key("x-access-user") || last.contains_key("x-access-email");
        assert_eq!(plain, case.expect.plain, "{name} ({})", case.rule);
    }
    format!("{name}:{}", got.status)
}

// IDP-30 (2), B22, OP-156 m.3 (m), Ek B 5203, 5304, 5360
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI job proxy-engines: real Envoy in front of the real forward-auth path"]
async fn proxy_engines_envoy() {
    run(Under::Envoy).await;
}

// IDP-30 (2), B22, OP-156 m.3 (m), Ek B 5203, 5304, 5360
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI job proxy-engines: real Caddy in front of the real forward-auth path"]
async fn proxy_engines_caddy() {
    run(Under::Caddy).await;
}

// IDP-30 (1), (2), OP-156 m.3 (m), m.15 (i)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI job proxy-engines: real Traefik on the rendered dynamic configuration"]
async fn proxy_engines_traefik() {
    run(Under::Traefik).await;
}

// IDP-30 (1), OP-156 m.3 (m), m.15 (i)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI job proxy-engines: real Nginx on the documented auth_request example"]
async fn proxy_engines_nginx() {
    run(Under::Nginx).await;
}
