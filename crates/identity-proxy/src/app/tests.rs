#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    clippy::assert_is_empty,
    clippy::ignored_unit_patterns,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use access_kernel::digest::Digest;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{ActionRef, Id};

use super::*;
use crate::domain::registration::Registration;
use crate::ports::Basis;

const PEP: &str = "cGVwLXRodW1icHJpbnQtb2YtdGhlLXByb3h5LTMyYnk";

#[derive(Default)]
struct Fake {
    pending: Mutex<BTreeMap<[u8; 32], Pending>>,
    sessions: Mutex<BTreeMap<[u8; 32], [u8; 16]>>,
    allowed: AtomicBool,
    down: AtomicBool,
    plain: AtomicBool,
    head: AtomicU64,
    now: AtomicU64,
    asked: AtomicU64,
    counter: AtomicU64,
}

fn registration() -> Registration {
    Registration {
        name: String::from("wiki"),
        engine: Engine::Traefik,
        host: String::from("wiki.example.com"),
        upstream: None,
        client_id: String::from("wiki-proxy"),
        pep: String::from(PEP),
        action: ActionRef {
            namespace: String::from("apps"),
            name: String::from("use"),
            major: 1,
            schema: Digest([9; 32]),
        },
        namespace: String::from("apps"),
        routes: vec![String::from("/")],
    }
}

impl Fake {
    fn up(&self) -> Result<(), Unavailable> {
        if self.down.load(Ordering::SeqCst) {
            Err(Unavailable)
        } else {
            Ok(())
        }
    }
}

impl Ports for Fake {
    type Realm = ();

    async fn registered(
        &self,
        pep: &str,
        host: &str,
    ) -> Result<Option<Registered<()>>, Unavailable> {
        self.up()?;
        Ok(
            (pep == PEP && host == "wiki.example.com").then(|| Registered {
                realm: (),
                registration: registration(),
                plain_headers: self.plain.load(Ordering::SeqCst),
            }),
        )
    }

    async fn begin(
        &self,
        _: &(),
        _: &str,
        state: &[u8; 32],
        pending: &Pending,
        _: u64,
    ) -> Result<(), Unavailable> {
        self.pending.lock().unwrap().insert(*state, pending.clone());
        Ok(())
    }

    async fn take(
        &self,
        _: &(),
        _: &str,
        state: &[u8; 32],
    ) -> Result<Option<Pending>, Unavailable> {
        Ok(self.pending.lock().unwrap().remove(state))
    }

    async fn open(
        &self,
        _: &(),
        _: &str,
        cookie: &[u8; 32],
        r: &Redeemed,
    ) -> Result<(), Unavailable> {
        self.sessions.lock().unwrap().insert(*cookie, r.sid);
        Ok(())
    }

    async fn session(
        &self,
        _: &(),
        _: &str,
        cookie: &[u8; 32],
    ) -> Result<Option<[u8; 16]>, Unavailable> {
        self.up()?;
        Ok(self.sessions.lock().unwrap().get(cookie).copied())
    }

    async fn authorize_url(
        &self,
        _: &(),
        client_id: &str,
        redirect_uri: &str,
        (state, _, challenge): (&str, &str, &str),
    ) -> Result<String, Unavailable> {
        Ok(format!(
            "https://access.test/authorize?client_id={client_id}&redirect_uri={redirect_uri}&state={state}&code_challenge={challenge}"
        ))
    }

    async fn redeem(
        &self,
        _: &(),
        _: &str,
        _: &str,
        (code, verifier): (&str, &str),
    ) -> Result<Option<Redeemed>, Unavailable> {
        Ok(
            (code == "good-code" && verifier.len() == 43).then_some(Redeemed {
                sid: [5; 16],
                expires_ms: 3_600_000,
            }),
        )
    }

    async fn holder(&self, _: &(), _: &str, sid: &[u8; 16]) -> Result<Option<Holder>, Unavailable> {
        self.up()?;
        Ok((*sid == [5; 16]).then(|| Holder {
            subject: [1; 16],
            party: Some(Id([2; 16])),
            domain: Digest([3; 32]),
            expires_ms: 3_600_000,
            user: String::from("pairwise-sub"),
            email: None,
        }))
    }

    async fn app_token(
        &self,
        _: &(),
        _: &str,
        h: &Holder,
        (aud, decision): (&str, &str),
    ) -> Result<String, Unavailable> {
        Ok(format!("{}|{aud}|{decision}", h.user))
    }

    async fn bases(&self, _: Digest, _: Id, _: &ActionRef) -> Result<Vec<Basis>, Unavailable> {
        self.up()?;
        Ok(vec![Basis {
            basis: ExerciseBasis::Public(Id([4; 16])),
            until_ms: 10_000_000,
        }])
    }

    async fn eligible(&self, asked: Asked<'_>) -> Result<bool, Unavailable> {
        self.up()?;
        self.asked.fetch_add(1, Ordering::SeqCst);
        assert_eq!(asked.pep, PEP);
        assert_eq!(asked.intent.resources[0].path, ["wiki"]);
        Ok(self.allowed.load(Ordering::SeqCst))
    }

    async fn head(&self, _: Digest) -> Result<u64, Unavailable> {
        self.up()?;
        Ok(self.head.load(Ordering::SeqCst))
    }

    fn now_ms(&self) -> Result<u64, Unavailable> {
        Ok(self.now.load(Ordering::SeqCst))
    }

    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst).to_be_bytes();
        for (i, b) in out.iter_mut().enumerate() {
            *b = n[i % 8] ^ u8::try_from(i % 251).unwrap();
        }
        Ok(())
    }
}

type Headers = BTreeMap<&'static str, String>;

async fn ask(p: &Proxy<Fake>, pep: Option<&str>, h: &Headers) -> Result<Answer, Refusal> {
    let h = h.clone();
    let header = move |n: &str| h.get(n).cloned();
    p.check(&Check {
        engine: Engine::Traefik,
        pep,
        method: "GET",
        suffix: None,
        query: None,
        header: &header,
    })
    .await
}

fn request(uri: &str, cookie: Option<String>) -> Headers {
    let mut h = Headers::new();
    h.insert("x-forwarded-method", String::from("GET"));
    h.insert("x-forwarded-uri", String::from(uri));
    h.insert("x-forwarded-host", String::from("wiki.example.com"));
    if let Some(c) = cookie {
        h.insert("cookie", c);
    }
    h
}

fn cookie_value(c: &str) -> (String, String) {
    let (k, v) = c.split(';').next().unwrap().split_once('=').unwrap();
    (String::from(k), String::from(v))
}

async fn signed_in(p: &Proxy<Fake>) -> String {
    let Answer::Redirect {
        location, cookies, ..
    } = ask(p, Some(PEP), &request("/page", None)).await.unwrap()
    else {
        panic!("no sign-in")
    };
    assert!(location.contains("redirect_uri=https://wiki.example.com/access-proxy/v1/callback"));
    let (name, state) = cookie_value(&cookies[0]);
    assert_eq!(name, STATE_COOKIE);
    assert!(location.contains(&format!("state={state}")));
    let cb = request(
        &format!("/access-proxy/v1/callback?code=good-code&state={state}"),
        Some(format!("{STATE_COOKIE}={state}")),
    );
    let Answer::Redirect {
        location, cookies, ..
    } = ask(p, Some(PEP), &cb).await.unwrap()
    else {
        panic!("no session")
    };
    assert_eq!(location, "https://wiki.example.com/page");
    let (name, value) = cookie_value(&cookies[0]);
    assert_eq!(name, SESSION_COOKIE);
    assert!(cookies[1].starts_with("__Host-access-proxy-state=;"));
    assert!(
        matches!(ask(p, Some(PEP), &cb).await.unwrap(), Answer::Deny { .. }),
        "a callback is taken once"
    );
    format!("{SESSION_COOKIE}={value}")
}

// IDP-30, B22
#[tokio::test]
async fn an_unregistered_proxy_is_refused() {
    let p = Proxy::new(Fake::default());
    assert_eq!(
        ask(&p, None, &request("/", None)).await,
        Err(Refusal::Unregistered)
    );
    assert_eq!(
        ask(&p, Some("b3RoZXI"), &request("/", None)).await,
        Err(Refusal::Unregistered)
    );
    let mut other_host = request("/", None);
    other_host.insert("x-forwarded-host", String::from("evil.example.com"));
    assert_eq!(
        ask(&p, Some(PEP), &other_host).await,
        Err(Refusal::Unregistered)
    );
}

// IDP-30, OP-156 m.3 (l)
#[tokio::test]
async fn a_callback_without_its_state_cookie_opens_nothing() {
    let p = Proxy::new(Fake::default());
    let Answer::Redirect { cookies, .. } = ask(&p, Some(PEP), &request("/", None)).await.unwrap()
    else {
        panic!()
    };
    let (_, state) = cookie_value(&cookies[0]);
    let forged = request(
        &format!("/access-proxy/v1/callback?code=good-code&state={state}"),
        Some(format!("{STATE_COOKIE}=other")),
    );
    assert!(matches!(
        ask(&p, Some(PEP), &forged).await.unwrap(),
        Answer::Deny { .. }
    ));
    assert!(p.ports().sessions.lock().unwrap().is_empty());
}

// IDP-30 (1), (3), OP-156 m.3 (l)
#[tokio::test]
async fn a_decision_is_reused_until_the_head_moves_and_never_past_thirty_seconds() {
    let p = Proxy::new(Fake::default());
    p.ports().allowed.store(true, Ordering::SeqCst);
    let session = signed_in(&p).await;
    let Answer::Allow {
        token,
        ttl_s,
        plain,
        ..
    } = ask(&p, Some(PEP), &request("/page", Some(session.clone())))
        .await
        .unwrap()
    else {
        panic!("not allowed")
    };
    assert!(token.starts_with("pairwise-sub|https://wiki.example.com|"));
    assert_eq!(ttl_s, 30);
    assert_eq!(plain, None);
    assert_eq!(p.ports().asked.load(Ordering::SeqCst), 1);
    ask(&p, Some(PEP), &request("/other", Some(session.clone())))
        .await
        .unwrap();
    assert_eq!(p.ports().asked.load(Ordering::SeqCst), 1, "cached");
    p.ports().allowed.store(false, Ordering::SeqCst);
    p.ports().now.store(30_000, Ordering::SeqCst);
    assert!(matches!(
        ask(&p, Some(PEP), &request("/page", Some(session.clone())))
            .await
            .unwrap(),
        Answer::Deny { .. }
    ));
    assert_eq!(p.ports().asked.load(Ordering::SeqCst), 2, "expired at 30 s");
    p.ports().allowed.store(true, Ordering::SeqCst);
    assert_eq!(p.sweep().await, 0);
    p.ports().head.store(1, Ordering::SeqCst);
    assert_eq!(p.sweep().await, 1, "the doorbell empties the domain");
    assert!(matches!(
        ask(&p, Some(PEP), &request("/page", Some(session)))
            .await
            .unwrap(),
        Answer::Allow { .. }
    ));
}

// MD-8, TI-9
#[tokio::test]
async fn an_unreachable_access_refuses() {
    let p = Proxy::new(Fake::default());
    p.ports().allowed.store(true, Ordering::SeqCst);
    let session = signed_in(&p).await;
    p.ports().down.store(true, Ordering::SeqCst);
    assert_eq!(
        ask(&p, Some(PEP), &request("/page", Some(session))).await,
        Err(Refusal::Unavailable)
    );
}

// OP-156 m.3 (l)
#[tokio::test]
async fn plain_headers_come_only_when_turned_on() {
    let p = Proxy::new(Fake::default());
    p.ports().allowed.store(true, Ordering::SeqCst);
    p.ports().plain.store(true, Ordering::SeqCst);
    let session = signed_in(&p).await;
    let Answer::Allow { plain, .. } = ask(&p, Some(PEP), &request("/", Some(session)))
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(plain.unwrap().user, "pairwise-sub");
}

// IDP-30
#[tokio::test]
async fn a_stale_session_signs_in_again() {
    let p = Proxy::new(Fake::default());
    let Answer::Redirect { cookies, .. } = ask(
        &p,
        Some(PEP),
        &request("/", Some(format!("{SESSION_COOKIE}=forged"))),
    )
    .await
    .unwrap() else {
        panic!()
    };
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("__Host-access-proxy=;"))
    );
}
