//! The identity side (T41, OP-151 m.3 (g)): OIDC discovery, PKCE, the callback, the token
//! response, the ID token, DPoP proofs, the in-memory replay store and the refresh
//! single-flight; and P15 for both modules.

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod support;

use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use access_kernel::combinator::BlockerClass;
use access_kernel::verify::PureBackend;
use access_kernel::verify::cose::{Algorithm, PublicKey};
use access_kernel::verify::dpop::{ProofRules, verify_proof};
use access_sdk::auth::discovery::{self, DiscoveryError, Metadata};
use access_sdk::auth::dpop::{self, ProofFor, ProofKey};
use access_sdk::auth::pkce::Verifier;
use access_sdk::auth::refresh::{RefreshError, Refresher};
use access_sdk::auth::replay::MemoryReplay;
use access_sdk::auth::request::{self, CallbackError, Client};
use access_sdk::auth::token::{
    self, IdTokenError, IdTokenRules, TokenError, TokenType, id_token_algorithms,
};
use access_sdk::auth::{OAuthClass, Random, RandomUnavailable};
use access_sdk::reason::{self, ReasonError, Subcode};
use access_sdk::resource::keys::key_set;
use access_sdk::resource::{Denied, Ports, Presented, Profile};
use access_sdk::transport::{Answer, FixedClock, Response};
use ed25519_dalek::Signer as _;
use support::{HOLDER_SEED, NOW, REQUEST_URI, TokenSpec, ed, ed_pub, intent, jwks_of, server};

const ISSUER: &str = "https://login.example/realms/acme";
const CLIENT: &str = "client-1";
const REDIRECT: &str = "https://app.example/cb";
const ID_SEED: u8 = 9;

struct Counter(Cell<u8>);

impl Random for Counter {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        for b in out.iter_mut() {
            self.0.set(self.0.get().wrapping_add(1));
            *b = self.0.get();
        }
        Ok(())
    }
}

struct NoRandom;

impl Random for NoRandom {
    fn fill(&self, _: &mut [u8]) -> Result<(), RandomUnavailable> {
        Err(RandomUnavailable)
    }
}

fn rng() -> Counter {
    Counter(Cell::new(0))
}

fn metadata_doc(extra: &str) -> String {
    format!(
        r#"{{"issuer":"{ISSUER}","authorization_endpoint":"{ISSUER}/authorize","token_endpoint":"{ISSUER}/token","jwks_uri":"{ISSUER}/jwks","code_challenge_methods_supported":["S256"],"response_types_supported":["code"],"authorization_response_iss_parameter_supported":true,"dpop_signing_alg_values_supported":["ES256","Ed25519"]{extra}}}"#
    )
}

fn metadata() -> Metadata {
    discovery::parse_document(metadata_doc("").as_bytes(), ISSUER).unwrap()
}

fn client() -> Client<'static> {
    Client {
        client_id: CLIENT,
        redirect_uri: REDIRECT,
        scope: "profile",
    }
}

// RFC 7636 Appendix B
#[test]
fn the_pkce_challenge_is_s256_of_the_verifier() {
    let v = Verifier::from_text("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap();
    assert_eq!(v.challenge(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    assert!(Verifier::from_text("short").is_none());
    assert_eq!(format!("{v:?}"), "Verifier(..)");
}

// RFC 8414 §3.3, RFC 9700 §2.1.1: mix-up defence and no plain PKCE
#[test]
fn discovery_refuses_another_issuer_a_server_without_s256_and_non_https_endpoints() {
    assert_eq!(metadata().token_endpoint, format!("{ISSUER}/token"));
    assert!(metadata().iss_parameter);
    assert_eq!(
        discovery::parse_document(metadata_doc("").as_bytes(), "https://evil.example"),
        Err(DiscoveryError::Issuer)
    );
    let plain = metadata_doc("").replace(r#"["S256"]"#, r#"["plain"]"#);
    assert_eq!(
        discovery::parse_document(plain.as_bytes(), ISSUER),
        Err(DiscoveryError::Pkce)
    );
    let http = metadata_doc("").replace(
        &format!("{ISSUER}/token"),
        "http://login.example/realms/acme/token",
    );
    assert_eq!(
        discovery::parse_document(http.as_bytes(), ISSUER),
        Err(DiscoveryError::Endpoint("token_endpoint"))
    );
    assert_eq!(
        discovery::parse(&Answer::Response(Response::new(503, Vec::new())), ISSUER),
        Err(DiscoveryError::Unavailable)
    );
    assert_eq!(
        discovery::well_known(ISSUER),
        format!("{ISSUER}/.well-known/openid-configuration")
    );
}

// OIDC Core §3.1.2.1, RFC 7636, RFC 9449 §10
#[test]
fn the_authorization_request_carries_s256_state_nonce_and_dpop_jkt() {
    let req = request::authorize(&metadata(), &client(), Some("jkt-1"), &rng()).unwrap();
    assert!(
        req.url
            .starts_with(&format!("{ISSUER}/authorize?response_type=code"))
    );
    for part in [
        "code_challenge_method=S256",
        "scope=openid%20profile",
        "dpop_jkt=jkt-1",
        "redirect_uri=https%3A%2F%2Fapp.example%2Fcb",
    ] {
        assert!(req.url.contains(part), "{part}");
    }
    assert!(req.url.contains("&state=") && req.url.contains("&nonce="));
    assert!(!format!("{:?}", req.pending).contains(req.pending.nonce()));
    assert_eq!(
        request::authorize(&metadata(), &client(), None, &NoRandom).unwrap_err(),
        RandomUnavailable
    );
}

fn query_param(url: &str, name: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    q.split('&')
        .find_map(|p| p.strip_prefix(&format!("{name}=")))
        .unwrap()
        .to_owned()
}

// RFC 9700 §4.7 (CSRF), RFC 9207 (mix-up), P15 (unknown OAuth error → parent class)
#[test]
fn the_callback_needs_this_state_this_issuer_and_a_code() {
    let req = request::authorize(&metadata(), &client(), None, &rng()).unwrap();
    let state = query_param(&req.url, "state");
    let iss = "https%3A%2F%2Flogin.example%2Frealms%2Facme";
    let p = &req.pending;
    assert!(
        p.callback(&format!("code=c1&state={state}&iss={iss}"))
            .is_ok()
    );
    assert_eq!(
        p.callback(&format!("code=c1&state=other&iss={iss}")),
        Err(CallbackError::State)
    );
    assert_eq!(
        p.callback(&format!("code=c1&state={state}")),
        Err(CallbackError::Issuer)
    );
    assert_eq!(
        p.callback(&format!(
            "code=c1&state={state}&iss=https%3A%2F%2Fevil.example"
        )),
        Err(CallbackError::Issuer)
    );
    assert_eq!(
        p.callback(&format!("error=access_denied&state={state}&iss={iss}")),
        Err(CallbackError::Refused(OAuthClass::AccessDenied))
    );
    assert_eq!(
        p.callback(&format!("error=brand_new_code&state={state}&iss={iss}")),
        Err(CallbackError::Refused(OAuthClass::Refused))
    );
    assert_eq!(
        p.callback(&format!("state={state}&iss={iss}")),
        Err(CallbackError::NoCode)
    );
    assert_eq!(
        p.callback(&format!("code=a&code=b&state={state}&iss={iss}")),
        Err(CallbackError::Malformed)
    );
    let code = p
        .callback(&format!("code=c1&state={state}&iss={iss}"))
        .unwrap();
    let body = p.token_request(&code);
    assert!(body.starts_with("grant_type=authorization_code&code=c1&"));
    assert!(body.contains("&code_verifier="));
}

fn answer(status: u16, body: &str) -> Answer {
    Answer::Response(Response::new(status, body.as_bytes().to_vec()))
}

// RFC 9449 §5, P15: a Bearer token is refused where DPoP was asked; unknown codes → parent
#[test]
fn the_token_response_is_refused_unbound_or_with_its_error_class() {
    let ok = r#"{"access_token":"at","token_type":"DPoP","expires_in":300,"refresh_token":"rt","id_token":"x.y.z"}"#;
    let t = token::parse_response(&answer(200, ok), true).unwrap();
    assert_eq!(t.token_type, TokenType::Dpop);
    assert_eq!(t.access_token.expose(), "at");
    assert!(!format!("{t:?}").contains("\"at\"") && !format!("{t:?}").contains("rt"));
    let bearer = ok.replace("DPoP", "Bearer");
    assert_eq!(
        token::parse_response(&answer(200, &bearer), true),
        Err(TokenError::Unbound)
    );
    assert_eq!(
        token::parse_response(&answer(400, r#"{"error":"invalid_grant"}"#), true),
        Err(TokenError::Refused {
            class: OAuthClass::InvalidGrant,
            status: 400
        })
    );
    assert_eq!(
        token::parse_response(&answer(400, r#"{"error":"something_new"}"#), true),
        Err(TokenError::Refused {
            class: OAuthClass::Refused,
            status: 400
        })
    );
    assert_eq!(
        token::parse_response(&answer(502, "<html>"), true),
        Err(TokenError::Refused {
            class: OAuthClass::Unavailable,
            status: 502
        })
    );
    assert_eq!(
        token::parse_response(
            &Answer::Unanswered(access_sdk::transport::Fault::Timeout),
            true
        ),
        Err(TokenError::Unavailable)
    );
}

fn id_token(claims: &str) -> String {
    support::jws(ID_SEED, "JWT", claims)
}

fn claims(aud: &str, nonce: &str, extra: &str) -> String {
    let now_s = NOW / 1000;
    format!(
        r#"{{"iss":"{ISSUER}","aud":{aud},"sub":"pairwise-7","nonce":"{nonce}","iat":{now_s},"exp":{}{extra}}}"#,
        now_s + 300
    )
}

fn rules<'a>(client_id: &'a str, nonce: &'a str) -> IdTokenRules<'a> {
    IdTokenRules {
        issuer: ISSUER,
        client_id,
        nonce,
        now: NOW,
        skew_ms: token::ID_SKEW_MS,
    }
}

// OIDC Core §3.1.3.7, §8.1 (pairwise sub)
#[test]
fn the_id_token_is_verified_and_its_subject_is_scoped_to_the_client() {
    let keys = key_set(&jwks_of(ID_SEED), &id_token_algorithms()).unwrap();
    let t = id_token(&claims(&format!(r#""{CLIENT}""#), "n-1", ""));
    let s = token::validate_id_token(&t, &keys, &rules(CLIENT, "n-1")).unwrap();
    assert_eq!(s.sub, "pairwise-7");
    let other = token::validate_id_token(
        &id_token(&claims(r#""client-2""#, "n-1", "")),
        &keys,
        &rules("client-2", "n-1"),
    )
    .unwrap();
    assert_ne!(s, other, "the same sub at two clients is two subjects");
    assert_eq!(
        token::validate_id_token(&t, &keys, &rules(CLIENT, "n-2")),
        Err(IdTokenError::Nonce)
    );
    assert_eq!(
        token::validate_id_token(&t, &keys, &rules("client-2", "n-1")),
        Err(IdTokenError::Claims)
    );
    let several = id_token(&claims(&format!(r#"["{CLIENT}","x"]"#), "n-1", ""));
    assert_eq!(
        token::validate_id_token(&several, &keys, &rules(CLIENT, "n-1")),
        Err(IdTokenError::Azp)
    );
    let azp = id_token(&claims(
        &format!(r#"["{CLIENT}","x"]"#),
        "n-1",
        &format!(r#","azp":"{CLIENT}""#),
    ));
    assert!(token::validate_id_token(&azp, &keys, &rules(CLIENT, "n-1")).is_ok());
    let foreign = support::jws(7, "JWT", &claims(&format!(r#""{CLIENT}""#), "n-1", ""));
    assert_eq!(
        token::validate_id_token(&foreign, &keys, &rules(CLIENT, "n-1")),
        Err(IdTokenError::Signature)
    );
    let expired = IdTokenRules {
        now: NOW + 3_600_000,
        ..rules(CLIENT, "n-1")
    };
    assert_eq!(
        token::validate_id_token(&t, &keys, &expired),
        Err(IdTokenError::Claims)
    );
}

struct EdKey(PublicKey, u8);

impl ProofKey for EdKey {
    fn public_key(&self) -> &PublicKey {
        &self.0
    }
    fn sign(&self, input: &[u8]) -> Option<Vec<u8>> {
        Some(ed(self.1).sign(input).to_bytes().to_vec())
    }
}

struct DeadKey(PublicKey);

impl ProofKey for DeadKey {
    fn public_key(&self) -> &PublicKey {
        &self.0
    }
    fn sign(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

// RFC 9449 §4.2, §4.3: a proof the SDK builds passes the Kernel check a server runs
#[test]
fn a_dpop_proof_built_here_verifies_with_the_kernel() {
    let key = EdKey(ed_pub(HOLDER_SEED), HOLDER_SEED);
    let p = dpop::proof(
        &key,
        &ProofFor {
            method: "POST",
            uri: "https://RS.example:443/doors/./1?x=1",
            access_token: Some("at"),
            nonce: Some("srv-nonce"),
        },
        NOW,
        &rng(),
    )
    .unwrap();
    let allowed = BTreeSet::from([Algorithm::Ed25519]);
    let checked = verify_proof(
        &PureBackend,
        &p,
        &ProofRules {
            method: "POST",
            uri: REQUEST_URI,
            allowed: &allowed,
            now: NOW,
            lifetime_ms: 60_000,
            skew_ms: 5_000,
            access_token: Some("at"),
            bound_jkt: None,
        },
    )
    .unwrap();
    assert_eq!(checked.nonce.as_deref(), Some("srv-nonce"));
    assert_eq!(
        dpop::jkt(&ed_pub(HOLDER_SEED)),
        access_kernel::json::b64url_encode(&checked.jkt)
    );
    assert_eq!(
        dpop::proof(
            &DeadKey(ed_pub(HOLDER_SEED)),
            &ProofFor {
                method: "GET",
                uri: REQUEST_URI,
                access_token: None,
                nonce: None
            },
            NOW,
            &rng()
        ),
        Err(dpop::ProofError::Signer)
    );
}

// §10.4.3 m.5, IDP-11 step 9, TN-30: the RS SDK refuses a replayed proof with the in-memory
// store, and a full store refuses instead of accepting unrecorded (MD-8)
#[test]
fn the_rs_sdk_refuses_a_replayed_dpop_proof_with_the_memory_store() {
    let token = TokenSpec::bounds_token().signed();
    let m = support::Memory::healthy();
    let replay = MemoryReplay::new(FixedClock(NOW), 1);
    let ports = Ports {
        keys: &m,
        replay: &replay,
        nonces: &m,
        status: &m,
        introspection: &m,
        revocations: &m,
    };
    let key = EdKey(ed_pub(HOLDER_SEED), HOLDER_SEED);
    let proof = |n: u8| {
        dpop::proof(
            &key,
            &ProofFor {
                method: "POST",
                uri: REQUEST_URI,
                access_token: Some(&token),
                nonce: None,
            },
            NOW,
            &Counter(Cell::new(n)),
        )
        .unwrap()
    };
    let s = server(Profile::Fast);
    let verify = |p: &str| {
        s.verify::<support::Door, support::Open, _, _, _, _, _, _>(
            &Presented {
                token: &token,
                method: "POST",
                uri: REQUEST_URI,
                proof: Some(p),
                certificate: None,
                content_position: None,
                satisfied: &[],
            },
            &intent(),
            &FixedClock(NOW),
            &ports,
        )
    };
    let first = proof(0);
    assert!(verify(&first).is_ok());
    assert_eq!(verify(&first).unwrap_err(), Denied::DpopReplay);
    assert_eq!(verify(&proof(100)).unwrap_err(), Denied::ReplayStore);
}

// P50, §9.9.3 k.6: N concurrent callers → one refresh, one result
#[tokio::test(flavor = "current_thread")]
async fn concurrent_refreshes_make_one_network_call() {
    const N: usize = 16;
    let refresher: Rc<Refresher<String, OAuthClass>> = Rc::new(Refresher::new());
    let calls = Arc::new(AtomicU32::new(0));
    let (open, gate) = tokio::sync::oneshot::channel::<()>();
    let gate = Rc::new(std::cell::RefCell::new(Some(gate)));
    let local = tokio::task::LocalSet::new();
    let mut handles = Vec::new();
    for _ in 0..N {
        let r = Rc::clone(&refresher);
        let calls = Arc::clone(&calls);
        let gate = Rc::clone(&gate);
        handles.push(local.spawn_local(async move {
            r.refresh(|| async move {
                calls.fetch_add(1, Ordering::SeqCst);
                let g = gate.borrow_mut().take().unwrap();
                g.await.unwrap();
                Ok::<_, OAuthClass>(String::from("rotated-1"))
            })
            .await
        }));
    }
    local
        .run_until(async {
            while refresher.waiting() < N - 1 {
                tokio::task::yield_now().await;
            }
            open.send(()).unwrap();
            for h in handles {
                assert_eq!(h.await.unwrap().unwrap(), "rotated-1");
            }
        })
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(refresher.waiting(), 0);
    let next = refresher
        .refresh(|| async { Ok::<_, OAuthClass>(String::from("rotated-2")) })
        .await;
    assert_eq!(
        next.unwrap(),
        "rotated-2",
        "a finished flight is not cached"
    );
}

// P50: a failed refresh fails every waiter; an abandoned one fails closed and the next starts
#[tokio::test(flavor = "current_thread")]
async fn a_failed_or_abandoned_refresh_gives_no_token() {
    let refresher: Rc<Refresher<String, OAuthClass>> = Rc::new(Refresher::new());
    let failed = refresher
        .refresh(|| async { Err::<String, _>(OAuthClass::InvalidGrant) })
        .await;
    assert_eq!(failed, Err(RefreshError::Failed(OAuthClass::InvalidGrant)));

    let local = tokio::task::LocalSet::new();
    let (_never, gate) = tokio::sync::oneshot::channel::<()>();
    let r = Rc::clone(&refresher);
    let leader = local.spawn_local(async move {
        r.refresh(|| async move {
            let _ = gate.await;
            Ok::<_, OAuthClass>(String::from("never"))
        })
        .await
    });
    let r = Rc::clone(&refresher);
    let follower = local.spawn_local(async move {
        r.refresh(|| async { Ok::<_, OAuthClass>(String::from("not-run")) })
            .await
    });
    local
        .run_until(async {
            while refresher.waiting() < 1 {
                tokio::task::yield_now().await;
            }
            leader.abort();
            assert_eq!(follower.await.unwrap(), Err(RefreshError::Abandoned));
        })
        .await;
    let again = refresher
        .refresh(|| async { Ok::<_, OAuthClass>(String::from("fresh")) })
        .await;
    assert_eq!(again.unwrap(), "fresh");
}

// P15: an unknown subcode is read as its parent class; there is no unknown class
#[test]
fn an_unknown_subcode_is_read_as_its_parent_class() {
    let r = reason::reason("ended", Some("ended/revoked")).unwrap();
    assert_eq!(r.subcode, Some(Subcode::Revoked));
    let r = reason::reason("ended", Some("ended/superseded-in-v9")).unwrap();
    assert_eq!((r.class, r.subcode), (BlockerClass::Ended, None));
    let r = reason::reason("restricted", Some("ended/revoked")).unwrap();
    assert_eq!((r.class, r.subcode), (BlockerClass::Restricted, None));
    let r = reason::reason("restricted", Some("restricted/policy:p-9")).unwrap();
    assert_eq!(r.subcode, Some(Subcode::Policy(String::from("p-9"))));
    assert!(reason::reason("brand-new-class", None).is_none());
    let body = br#"{"decision":false,"context":{"outcome":"deny","blockers":[{"class":"budget-exhausted","subcode":"budget-exhausted/new-thing"},{"class":"nonce-closed","subcode":"nonce-closed/pre-recovery"}]}}"#;
    let all = reason::reasons(body).unwrap();
    assert_eq!(all[0].class, BlockerClass::BudgetExhausted);
    assert_eq!(all[0].subcode, None);
    assert_eq!(all[1].subcode, Some(Subcode::PreRecovery));
    let unknown = br#"{"decision":false,"context":{"blockers":[{"class":"new-class"}]}}"#;
    assert_eq!(reason::reasons(unknown), Err(ReasonError::UnknownClass));
    assert_eq!(OAuthClass::of("never_seen_before"), OAuthClass::Refused);
}
