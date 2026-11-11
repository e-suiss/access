//! The adversary-in-the-middle and browser-in-the-middle lab on the real path (SA-12, N-41,
//! HL-23, OP-159 m.3 (hh), Ek B 6249): the hosted login served over TLS on a real database, and
//! a transparent reverse proxy on a phishing host in front of it. A passkey sign-in through the proxy is refused, because the
//! assertion names the proxy's origin and RP ID; a password with TOTP through the proxy completes,
//! and the session cookie the proxy relayed opens the account at the real server.

use access_local_client::http::{Http, Identity};
use access_local_client::login::{Credential, Jar, post_json, sign_in};
use access_local_client::passkey::{Passkey, relying_party};

use super::*;
use crate::bootstrap::TotpSeedFile;

#[path = "aitm/proxy.rs"]
mod proxy;

const REAL_HOST: &str = "access.test";
const PHISH_HOST: &str = "access-login.test";
const SESSION: &str = "__Host-access-session";

/// The test realm's hosted login and account routes served over TLS, and the deployment's
/// summary.
struct Lab {
    w: World,
    first: serde_json::Value,
    tls: TestTls,
    addr: std::net::SocketAddr,
    stop: tokio::sync::oneshot::Sender<()>,
    served: tokio::task::JoinHandle<std::io::Result<()>>,
    seed_dir: std::path::PathBuf,
}

async fn lab(name: &str) -> Lab {
    use access_http::login::{me_router, router as login_router};
    use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};
    use access_identity_account::app::claims::Courier;
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::app::local::LocalLimiter;
    use access_identity_account::app::login::LoginGate;
    use access_identity_account::domain::password::Argon2Params;
    use access_identity_account::domain::throttle::ThrottlePolicy;
    use access_identity_oauth::adapters::PgDirectory;
    use access_identity_oauth::app::Discovery as RealmDiscovery;
    use access_identity_session::domain::session::SessionPolicy;
    use access_identity_ui::adapters::Outbox;
    use access_identity_ui::app::{Devices, Hosted};

    use crate::login::{HsmKits, RealmKeks};

    let (w, signer) = World::open(name, true).await;
    let signer = signer.unwrap();
    schedule(&signer);
    schedule(&signer);
    crate::jobs::open_now(&w.db.app, &w.db.archive, name).await;
    let seed_dir = std::env::temp_dir().join(format!("abs-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&seed_dir).unwrap();
    let mut plan = local_plan();
    plan.test_user.as_mut().unwrap().totp =
        Some(TotpSeedFile::open(&seed_dir.join("totp")).unwrap());
    let first = serde_json::to_value(w.run(&plan).await).unwrap();
    schedule(&signer);
    schedule(&signer);

    let tls = test_tls(REAL_HOST);
    let hosted = Arc::new(Hosted {
        kits: HsmKits::new(
            RealmKeks::new(Arc::clone(&w.keys)),
            w.db.router.clone(),
            w.db.app.clone(),
            SessionPolicy::DEFAULT,
        ),
        db: w.db.app.clone(),
        products: w.db.reader.clone(),
        clock: SystemClock,
        messages: Outbox,
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(HasherConfig::sized(
            Argon2Params::CANONICAL,
            cores(),
            cgroup_memory_budget(),
        )),
        redirect_to: String::from("/"),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        risk: access_identity_session::app::RiskServices::without_sources(),
        signup: access_identity_ui::app::signup::Signup::without_providers().unwrap(),
    });
    let discovery = || {
        RealmDiscovery::new(
            PgDirectory::new(w.db.router.clone()),
            SignerKeys::new(w.identity_signer.clone()),
        )
    };
    let courier = Arc::new(Courier {
        app: w.db.app.clone(),
        reader: w.db.reader.clone(),
        signer: SignerKeys::new(w.identity_signer.clone()),
        ingest: access_authority_ingest::app::Ingest::new(
            w.domains.clone(),
            crate::ingest::PgSubmissions(w.db.app.clone()),
            crate::ingest::Trusted(tokio::sync::Mutex::new(SourcesClock::new(w.db.app.clone()))),
        ),
        clock: SystemClock,
    });
    let app = login_router(discovery(), hosted.clone(), None).merge(me_router(
        discovery(),
        hosted,
        Devices {
            signer: SignerKeys::new(w.identity_signer.clone()),
            instances: w.plane.clone(),
            approvals: w.plane.clone(),
            claims: courier,
            pep: String::from(IDENTITY_PEP),
        },
    ));
    let config = access_http::tls::server_config(
        tls.server_cert.as_bytes(),
        tls.server_key.as_bytes(),
        Some(tls.ca.as_bytes()),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(access_http::tls::serve(listener, config, app, async {
        let _ = stopped.await;
    }));
    Lab {
        w,
        first,
        tls,
        addr,
        stop,
        served,
        seed_dir,
    }
}

impl Lab {
    fn user(&self) -> &serde_json::Value {
        &self.first["test_user"]
    }

    fn issuer(&self) -> String {
        self.user()["issuer"].as_str().unwrap().to_owned()
    }

    /// A client of the real server, as the attacker replaying loot uses it.
    fn real(&self) -> Http {
        let identity = Identity {
            chain_pem: self.tls.pep_cert.clone().into_bytes(),
            key_pem: self.tls.pep_key.clone().into_bytes(),
        };
        Http::new(self.tls.ca.as_bytes(), Some(&identity), Some(self.addr)).unwrap()
    }

    /// The proxy on the phishing host, with a certificate the victim's browser trusts.
    async fn proxy(&self) -> (proxy::Proxy, Http) {
        let phish = test_tls(PHISH_HOST);
        let p = proxy::start(
            self.real(),
            REAL_HOST,
            PHISH_HOST,
            &phish.server_cert,
            &phish.server_key,
        )
        .await;
        let victim = Http::new(phish.ca.as_bytes(), None, Some(p.addr)).unwrap();
        (p, victim)
    }

    async fn close(self) {
        let _ = self.stop.send(());
        let _ = self.served.await;
        self.w.domains.release().await;
        let _ = std::fs::remove_dir_all(&self.seed_dir);
    }
}

fn base32_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0_u32, 0_u32);
    for c in text.trim().bytes().filter(|c| *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("not base32: {c}"),
        };
        buf = (buf << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}

fn step_of(r: &access_local_client::http::Response) -> String {
    r.json()["step"].as_str().unwrap_or_default().to_owned()
}

fn action(issuer: &str, r: &access_local_client::http::Response) -> String {
    format!("{issuer}{}", r.json()["action"].as_str().unwrap())
}

// SA-12, N-41, OP-159 m.3 (hh), Ek B 6249, OP-153 m.3 (gg)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_passkey_sign_in_through_a_reverse_proxy_is_refused() {
    let lab = lab("aitm-passkey").await;
    let issuer = lab.issuer();
    let phish_issuer = issuer.replace(REAL_HOST, PHISH_HOST);
    let identifier = lab.user()["identifier"].as_str().unwrap().to_owned();
    let pin = Secret::new(String::from(PIN));
    let token = KeyStore::open(&lab.w.module, &lab.w.label, &pin).unwrap();
    let key = token.signer(local::TEST_PASSKEY_LABEL).unwrap();
    let (proxy, victim) = lab.proxy().await;

    let (phish_rp, phish_origin) = relying_party(&phish_issuer).unwrap();
    let (real_rp, _) = relying_party(&issuer).unwrap();
    for (rp_id, origin) in [
        (phish_rp.as_str(), phish_origin.as_str()),
        (real_rp.as_str(), phish_origin.as_str()),
    ] {
        let passkey = Passkey {
            key: &key,
            rp_id,
            origin,
        };
        let relayed = sign_in(
            &victim,
            &phish_issuer,
            &identifier,
            Credential::Passkey(&passkey),
        )
        .await;
        let Err(access_local_client::ClientError::Unexpected { step, status, body }) = relayed
        else {
            panic!("{rp_id} {origin}: the relayed passkey sign-in was not refused");
        };
        assert_eq!(step, "passkey", "{status} {body}");
        assert_ne!(status, 200, "{body}");
    }
    assert!(proxy.captured(SESSION).is_empty(), "{:?}", proxy.loot);

    let (rp_id, origin) = relying_party(&issuer).unwrap();
    let passkey = Passkey {
        key: &key,
        rp_id: &rp_id,
        origin: &origin,
    };
    let direct = sign_in(
        &lab.real(),
        &issuer,
        &identifier,
        Credential::Passkey(&passkey),
    )
    .await;
    assert!(direct.is_ok());

    proxy.stop().await;
    lab.close().await;
}

// SA-12, N-41, HL-23, RR-29, OP-159 m.3 (hh), Ek B 6249, OP-153 m.3 (gg)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_and_totp_through_a_reverse_proxy_hand_over_the_session() {
    use access_crypto::totp::{TotpParams, hotp, step_of as totp_step};

    let lab = lab("aitm-totp").await;
    let issuer = lab.issuer();
    let phish_issuer = issuer.replace(REAL_HOST, PHISH_HOST);
    let identifier = lab.user()["identifier"].as_str().unwrap().to_owned();
    let seed = base32_decode(&std::fs::read_to_string(lab.seed_dir.join("totp")).unwrap());
    let (proxy, victim) = lab.proxy().await;

    let mut jar = Jar::default();
    let started = post_json(
        &victim,
        &format!("{phish_issuer}/v1/login/flows"),
        &mut jar,
        None,
    )
    .await
    .unwrap();
    assert_eq!(started.status, 201, "{}", started.text());
    let named = post_json(
        &victim,
        &action(&phish_issuer, &started),
        &mut jar,
        Some(serde_json::json!({ "method": "identifier", "fields": { "identifier": identifier } })),
    )
    .await
    .unwrap();
    assert_eq!(step_of(&named), "authenticate", "{}", named.text());
    let password = post_json(
        &victim,
        &action(&phish_issuer, &named),
        &mut jar,
        Some(serde_json::json!({ "method": "password", "fields": { "password": "correct horse battery staple" } })),
    )
    .await
    .unwrap();
    assert_eq!(step_of(&password), "second_factor", "{}", password.text());
    let params = TotpParams::DEFAULT;
    let now_s = access_authority_signer::adapters::now_ms() / 1000;
    let code = hotp(
        &seed,
        params.algorithm,
        totp_step(now_s, params.step_s) + 1,
        params.digits,
    );
    let done = post_json(
        &victim,
        &action(&phish_issuer, &password),
        &mut jar,
        Some(serde_json::json!({ "method": "totp", "fields": { "totp_code": code } })),
    )
    .await
    .unwrap();
    assert_eq!(step_of(&done), "complete", "{}", done.text());

    let loot = proxy.captured(SESSION);
    assert!(!loot.is_empty(), "{:?}", proxy.loot);
    let replayed = lab
        .real()
        .request(
            "GET",
            &format!("{issuer}/v1/sessions/current"),
            &[("Cookie", loot.last().unwrap().as_str())],
            None,
        )
        .await
        .unwrap();
    assert_eq!(replayed.status, 200, "{}", replayed.text());

    proxy.stop().await;
    lab.close().await;
}
