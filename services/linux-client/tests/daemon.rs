//! The daemon's offline rules over in-memory ports (OP-156 m.3 (p), MD-8, SI-22, Ek B 5207):
//! NSS data at most 12 hours, a console sign-in reused at most 8 hours and only with a security
//! key Access listed, both never past the horizon; no `sudo` offline; a clock that went back
//! answers nothing offline. The real-server walk is in `access-server`'s Linux walkthrough.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use access_linux_client::app::{Daemon, TEXT_UNAVAILABLE};
use access_linux_client::domain::fido::{Credential, EDDSA};
use access_linux_client::domain::state::State;
use access_linux_client::ports::{
    Access, Clock, DevicePoll, DeviceStart, Keep, Random, Reached, SecurityKey, SignIn,
};
use access_linux_module::wire::{Request, Response};
use ed25519_dalek::Signer as _;
use serde_json::json;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::sha256;

const HOUR: u64 = 3_600_000;
const T0: u64 = 1_800_000_000_000;
const RP: &str = "access.test";

struct Fake {
    online: AtomicBool,
    horizon: AtomicU64,
    now: AtomicU64,
    credential: Credential,
}

impl Access for &Fake {
    fn snapshot(&self) -> impl Future<Output = Reached<Vec<u8>>> + Send {
        let body = json!({
            "now_ms": self.now.load(Ordering::SeqCst),
            "horizon_ms": self.horizon.load(Ordering::SeqCst),
            "nss_ttl_s": 43_200,
            "console_ttl_s": 28_800,
            "users": [
                { "name": "ayse", "uid": 200_001, "gid": 200_000, "dir": "/home/ayse",
                  "shell": "/bin/bash", "until_ms": T0 + 100 * HOUR, "console": true },
                { "name": "deploy", "uid": 200_002, "gid": 200_000, "dir": "/home/deploy",
                  "shell": "/bin/bash", "until_ms": T0 + 100 * HOUR, "console": false },
            ],
            "groups": [ { "name": "prod-web", "gid": 200_000, "members": ["ayse", "deploy"] } ],
        });
        let online = self.online.load(Ordering::SeqCst);
        std::future::ready(if online {
            Reached::Answer(body.to_string().into_bytes())
        } else {
            Reached::Unreachable
        })
    }

    fn device_start(&self) -> impl Future<Output = Reached<DeviceStart>> + Send {
        let online = self.online.load(Ordering::SeqCst);
        std::future::ready(if online {
            Reached::Answer(DeviceStart {
                device_code: String::from("device"),
                user_code: String::from("BCDF-GHJK"),
                verification_uri: String::from("https://access.test/realms/acme/device"),
                expires_in: 600,
                interval: 5,
            })
        } else {
            Reached::Unreachable
        })
    }

    fn device_poll(&self, _code: &str) -> impl Future<Output = Reached<DevicePoll>> + Send {
        std::future::ready(Reached::Answer(DevicePoll::Token(String::from("token"))))
    }

    fn sign_in(&self, _t: &str, user: &str) -> impl Future<Output = Reached<SignIn>> + Send {
        std::future::ready(Reached::Answer(SignIn {
            allow: user == "ayse",
            credentials: vec![self.credential.clone()],
        }))
    }

    fn sudo(
        &self,
        _t: &str,
        _u: &str,
        _c: &[u8; 32],
    ) -> impl Future<Output = Reached<bool>> + Send {
        std::future::ready(Reached::Answer(true))
    }
}

impl Clock for &Fake {
    fn now_ms(&self) -> Option<u64> {
        Some(self.now.load(Ordering::SeqCst))
    }
}

struct Rng(AtomicU64);

impl Random for Rng {
    fn bytes<const N: usize>(&self) -> Option<[u8; N]> {
        let mut out = [0u8; N];
        for chunk in out.chunks_mut(32) {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_nanos();
            let mut seed = t.to_le_bytes().to_vec();
            seed.extend_from_slice(&n.to_le_bytes());
            let h = sha256(&seed);
            chunk.copy_from_slice(&h[..chunk.len()]);
        }
        Some(out)
    }
}

#[derive(Default)]
struct Memory(Mutex<State>);

impl Keep for &Memory {
    fn load(&self) -> State {
        self.0.lock().unwrap().clone()
    }

    fn save(&self, state: &State) -> bool {
        *self.0.lock().unwrap() = state.clone();
        true
    }
}

/// A software security key answering CTAP2 `authenticatorGetAssertion` with Ed25519.
struct SoftKey {
    key: ed25519_dalek::SigningKey,
    id: Vec<u8>,
    count: AtomicU64,
    present: AtomicBool,
}

impl SecurityKey for &SoftKey {
    fn get_assertion(&self, request: &[u8]) -> impl Future<Output = Option<Vec<u8>>> + Send {
        let answer = (|| {
            if !self.present.load(Ordering::SeqCst) {
                return None;
            }
            let Value::Map(m) = dcbor::decode(request.get(1..)?, Limits::CEILING).ok()? else {
                return None;
            };
            let get = |k: u64| {
                m.iter()
                    .find(|(key, _)| *key == Value::Unsigned(k))
                    .map(|(_, v)| v)
            };
            let (Some(Value::Text(rp)), Some(Value::Bytes(hash))) = (get(1), get(2)) else {
                return None;
            };
            let count = u32::try_from(self.count.fetch_add(1, Ordering::SeqCst) + 1).ok()?;
            let mut auth = sha256(rp.as_bytes()).to_vec();
            auth.push(0x05);
            auth.extend_from_slice(&count.to_be_bytes());
            let mut msg = auth.clone();
            msg.extend_from_slice(hash);
            let sig = self.key.sign(&msg).to_bytes().to_vec();
            let body = Value::Map(vec![
                (
                    Value::Unsigned(1),
                    Value::Map(vec![
                        (Value::text("id"), Value::Bytes(self.id.clone())),
                        (Value::text("type"), Value::text("public-key")),
                    ]),
                ),
                (Value::Unsigned(2), Value::Bytes(auth)),
                (Value::Unsigned(3), Value::Bytes(sig)),
            ]);
            let mut out = vec![0u8];
            out.extend(dcbor::encode(&body, Limits::CEILING).ok()?);
            Some(out)
        })();
        std::future::ready(answer)
    }
}

fn soft_key() -> SoftKey {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    SoftKey {
        key: ed25519_dalek::SigningKey::from_bytes(&sha256(&t.to_le_bytes())),
        id: vec![9; 16],
        count: AtomicU64::new(0),
        present: AtomicBool::new(true),
    }
}

fn fake(key: &SoftKey) -> Fake {
    Fake {
        online: AtomicBool::new(true),
        horizon: AtomicU64::new(T0 + 24 * HOUR),
        now: AtomicU64::new(T0),
        credential: Credential {
            id: key.id.clone(),
            alg: EDDSA,
            public_key: key.key.verifying_key().to_bytes().to_vec(),
            rp_id: String::from(RP),
            sign_count: 0,
        },
    }
}

fn login(user: &str) -> Request {
    Request::Authenticate {
        user: String::from(user),
        service: String::from("login"),
        tty: None,
    }
}

const fn allow(offline: bool) -> Response {
    Response::Done {
        allow: true,
        offline: if offline { Some(true) } else { None },
    }
}

fn unavailable() -> Response {
    Response::Unavailable(String::from(TEXT_UNAVAILABLE))
}

async fn sign_in_online<A: Access, C: Clock, R: Random, K: Keep, S: SecurityKey>(
    d: &Daemon<A, C, R, K, S>,
    user: &str,
) -> Response {
    let (Response::Pending(p), _) = d.handle(login(user)).await else {
        panic!("not pending");
    };
    d.handle(Request::Poll(p.attempt)).await.0
}

// OP-156 m.3 (p), MD-8, SI-22, Ek B 5207
#[tokio::test]
async fn an_offline_console_sign_in_needs_the_listed_key_and_ends_after_8_hours() {
    let key = soft_key();
    let f = fake(&key);
    let mem = Memory::default();
    let d = Daemon::new(&f, &f, Rng(AtomicU64::new(0)), &mem, &key, None);
    assert_eq!(sign_in_online(&d, "ayse").await, allow(false));
    f.online.store(false, Ordering::SeqCst);
    f.now.store(T0 + 2 * HOUR, Ordering::SeqCst);
    assert_eq!(d.handle(login("ayse")).await.0, allow(true));
    key.present.store(false, Ordering::SeqCst);
    assert_eq!(
        d.handle(login("ayse")).await.0,
        Response::Done {
            allow: false,
            offline: Some(true)
        }
    );
    key.present.store(true, Ordering::SeqCst);
    assert_eq!(d.handle(login("deploy")).await.0, unavailable());
    f.now.store(T0 + 8 * HOUR, Ordering::SeqCst);
    assert_eq!(d.handle(login("ayse")).await.0, unavailable());
}

// OP-156 m.3 (p), MD-8
#[tokio::test]
async fn nss_data_answers_offline_for_12_hours_and_never_past_the_horizon() {
    let key = soft_key();
    let f = fake(&key);
    let mem = Memory::default();
    let d = Daemon::new(&f, &f, Rng(AtomicU64::new(0)), &mem, &key, None);
    assert!(matches!(
        d.handle(Request::Getpwnam(String::from("ayse"))).await.0,
        Response::Passwd(_)
    ));
    f.online.store(false, Ordering::SeqCst);
    f.now.store(T0 + 12 * HOUR - 1, Ordering::SeqCst);
    assert!(matches!(
        d.handle(Request::Getpwnam(String::from("ayse"))).await.0,
        Response::Passwd(_)
    ));
    f.now.store(T0 + 12 * HOUR, Ordering::SeqCst);
    assert_eq!(
        d.handle(Request::Getpwnam(String::from("ayse"))).await.0,
        unavailable()
    );

    let key = soft_key();
    let f = fake(&key);
    f.horizon.store(T0 + HOUR, Ordering::SeqCst);
    let mem = Memory::default();
    let d = Daemon::new(&f, &f, Rng(AtomicU64::new(0)), &mem, &key, None);
    assert_eq!(sign_in_online(&d, "ayse").await, allow(false));
    f.online.store(false, Ordering::SeqCst);
    f.now.store(T0 + HOUR, Ordering::SeqCst);
    assert_eq!(d.handle(login("ayse")).await.0, unavailable());
    assert_eq!(
        d.handle(Request::Getgrnam(String::from("prod-web")))
            .await
            .0,
        unavailable()
    );
}

// OP-156 m.3 (p)
#[tokio::test]
async fn sudo_is_never_answered_offline() {
    let key = soft_key();
    let f = fake(&key);
    let mem = Memory::default();
    let d = Daemon::new(&f, &f, Rng(AtomicU64::new(0)), &mem, &key, None);
    assert_eq!(sign_in_online(&d, "ayse").await, allow(false));
    f.online.store(false, Ordering::SeqCst);
    let sudo = Request::Sudo {
        user: String::from("ayse"),
        command: sha256(b"sudo\0id\0"),
    };
    assert_eq!(d.handle(sudo).await.0, unavailable());
}

// OP-156 m.3 (p)
#[tokio::test]
async fn a_force_command_principal_resolves_but_signs_in_nowhere_else() {
    let key = soft_key();
    let f = fake(&key);
    let mem = Memory::default();
    let d = Daemon::new(&f, &f, Rng(AtomicU64::new(0)), &mem, &key, None);
    assert!(matches!(
        d.handle(Request::Getpwnam(String::from("deploy"))).await.0,
        Response::Passwd(_)
    ));
    assert_eq!(
        d.handle(login("deploy")).await.0,
        Response::Done {
            allow: false,
            offline: None
        }
    );
}

// OP-156 m.3 (p), T25
#[tokio::test]
async fn a_clock_that_went_back_or_a_cloned_key_is_refused_offline() {
    let key = soft_key();
    let f = fake(&key);
    let mem = Memory::default();
    let d = Daemon::new(&f, &f, Rng(AtomicU64::new(0)), &mem, &key, None);
    assert_eq!(sign_in_online(&d, "ayse").await, allow(false));
    f.online.store(false, Ordering::SeqCst);
    f.now.store(T0 + 3 * HOUR, Ordering::SeqCst);
    assert_eq!(d.handle(login("ayse")).await.0, allow(true));
    key.count.store(0, Ordering::SeqCst);
    assert_eq!(
        d.handle(login("ayse")).await.0,
        Response::Done {
            allow: false,
            offline: Some(true)
        }
    );
    f.now.store(T0 + HOUR, Ordering::SeqCst);
    assert_eq!(d.handle(login("ayse")).await.0, unavailable());
}
