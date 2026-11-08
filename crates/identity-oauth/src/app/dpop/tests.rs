use std::collections::HashSet;
use std::future::Future;
use std::sync::Mutex;

use access_crypto::Secret;
use access_crypto::dpop::{MAX_STALE_MS, NonceKey, NoncePolicy, Role};
use access_kernel::json::b64url_encode;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::dpop::ath;
use access_kernel::verify::key_scope::thumbprint;

use super::*;
use crate::ports::dpop::{CacheUnavailable, ClockUnavailable};

const NOW: u64 = 1_800_000_000_000;
const HOUR: u64 = 60 * 60 * 1000;
const URI: &str = "https://login.example.com/token";
const REALM: [u8; 16] = [6; 16];

#[derive(Default)]
struct Memory(Mutex<HashSet<(u32, [u8; 32])>>);

impl ReplayCache for Memory {
    fn first_use(
        &self,
        day: u32,
        key: [u8; 32],
    ) -> impl Future<Output = Result<bool, CacheUnavailable>> + Send {
        std::future::ready(Ok(self.0.lock().unwrap().insert((day, key))))
    }
}

struct Broken;

impl ReplayCache for Broken {
    fn first_use(
        &self,
        _: u32,
        _: [u8; 32],
    ) -> impl Future<Output = Result<bool, CacheUnavailable>> + Send {
        std::future::ready(Err(CacheUnavailable))
    }
}

struct Fixed(Option<u64>);

impl Clock for Fixed {
    fn now(&self) -> Result<u64, ClockUnavailable> {
        self.0.ok_or(ClockUnavailable)
    }
}

fn ring(role: Role, key: u8) -> NonceRing {
    NonceRing::new(
        REALM,
        role,
        NoncePolicy::new(HOUR, MAX_STALE_MS).unwrap(),
        1,
        NonceKey::new(Secret::new([key; 32])),
    )
}

fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[11; 32])
}

fn jkt() -> Jkt {
    Jkt(thumbprint(&PublicKey::Ed25519(
        signing_key().verifying_key().to_bytes(),
    )))
}

fn proof(jti: &str, nonce: Option<&str>, extra: &str) -> String {
    use ed25519_dalek::Signer as _;
    let header = format!(
        r#"{{"typ":"dpop+jwt","alg":"Ed25519","jwk":{{"kty":"OKP","crv":"Ed25519","x":"{}"}}}}"#,
        b64url_encode(&signing_key().verifying_key().to_bytes())
    );
    let nonce = nonce
        .map(|n| format!(r#","nonce":"{n}""#))
        .unwrap_or_default();
    let payload = format!(
        r#"{{"jti":"{jti}","htm":"POST","htu":"{URI}","iat":{}{nonce}{extra}}}"#,
        NOW / 1000
    );
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = signing_key().sign(input.as_bytes()).to_bytes();
    format!("{input}.{}", b64url_encode(&sig))
}

fn request<'a>(proofs: &'a [&'a str]) -> DpopRequest<'a> {
    DpopRequest {
        proofs,
        method: "POST",
        uri: URI,
        access_token: None,
        bound: None,
    }
}

fn block<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(f)
}

// IDP-11, TN-29, TN-30: a proof with a current nonce is accepted once and the response carries a nonce
#[test]
fn accepted_once_with_a_fresh_nonce() {
    let profile = DpopProfile::default();
    let nonces = ring(Role::AuthorizationServer, 1);
    let cache = Memory::default();
    let clock = Fixed(Some(NOW));
    let checker = DpopChecker::new(&profile, &nonces, &cache, &clock);
    let nonce = checker.nonce().unwrap();
    let p = proof("j-1", Some(&nonce), "");
    let accepted = block(checker.check(&request(&[&p]))).unwrap();
    assert_eq!(accepted.jkt, jkt());
    assert_eq!(nonces.check(Some(&accepted.nonce), NOW), Ok(()));
    let replay = block(checker.check(&request(&[&p]))).unwrap_err();
    assert_eq!(
        replay,
        Failure::InvalidProof {
            step: Step::Jti,
            code: "dpop-replay"
        }
    );
}

// IDP-11 step 1, RFC 9449 §4.3: exactly one DPoP header
#[test]
fn step_1_one_dpop_header() {
    let profile = DpopProfile::default();
    let nonces = ring(Role::AuthorizationServer, 1);
    let (cache, clock) = (Memory::default(), Fixed(Some(NOW)));
    let checker = DpopChecker::new(&profile, &nonces, &cache, &clock);
    let nonce = checker.nonce().unwrap();
    let p = proof("j", Some(&nonce), "");
    for proofs in [&[][..], &[p.as_str(), p.as_str()][..]] {
        let err = block(checker.check(&request(proofs))).unwrap_err();
        assert!(matches!(
            err,
            Failure::InvalidProof {
                step: Step::Shape,
                ..
            }
        ));
    }
}

// TN-29, MD-18: a missing, foreign or expired nonce is answered with use_dpop_nonce and a new one;
// AS and RS nonces are separate
#[test]
fn step_10_nonce_is_required_and_renewed() {
    let profile = DpopProfile::default();
    let as_nonces = ring(Role::AuthorizationServer, 1);
    let rs_nonces = ring(Role::ResourceServer, 2);
    let (cache, clock) = (Memory::default(), Fixed(Some(NOW)));
    let as_checker = DpopChecker::new(&profile, &as_nonces, &cache, &clock);
    let rs_checker = DpopChecker::new(&profile, &rs_nonces, &cache, &clock);
    let as_nonce = as_checker.nonce().unwrap();
    let stale = as_nonces.issue(NOW - 3 * HOUR).unwrap();
    let (a, b, c) = (
        proof("a", None, ""),
        proof("b", Some(&as_nonce), ""),
        proof("c", Some(&stale), ""),
    );
    let cases = [
        (&as_checker, a.as_str(), &as_nonces),
        (&rs_checker, b.as_str(), &rs_nonces),
        (&as_checker, c.as_str(), &as_nonces),
    ];
    for (checker, p, ring) in cases {
        let err = block(checker.check(&request(&[p]))).unwrap_err();
        assert_eq!(err.error(), "use_dpop_nonce");
        assert_eq!(ring.check(err.nonce(), NOW), Ok(()));
    }
    assert!(cache.0.lock().unwrap().is_empty());
}

// TN-30, MD-8: an unavailable replay cache or clock rejects the proof
#[test]
fn state_failure_rejects() {
    let profile = DpopProfile::default();
    let nonces = ring(Role::AuthorizationServer, 1);
    let clock = Fixed(Some(NOW));
    let nonce = nonces.issue(NOW).unwrap();
    let p = proof("j", Some(&nonce), "");
    let broken = DpopChecker::new(&profile, &nonces, &Broken, &clock);
    assert_eq!(
        block(broken.check(&request(&[&p]))),
        Err(Failure::Unavailable)
    );
    let cache = Memory::default();
    let no_clock = Fixed(None);
    let timeless = DpopChecker::new(&profile, &nonces, &cache, &no_clock);
    assert_eq!(
        block(timeless.check(&request(&[&p]))),
        Err(Failure::Unavailable)
    );
    assert_eq!(timeless.nonce(), Err(Failure::Unavailable));
}

// IDP-11 steps 11 and 12, TN-31: the RS checks ath and the token's cnf.jkt
#[test]
fn resource_server_checks_ath_and_jkt() {
    let profile = DpopProfile::default();
    let nonces = ring(Role::ResourceServer, 2);
    let (cache, clock) = (Memory::default(), Fixed(Some(NOW)));
    let checker = DpopChecker::new(&profile, &nonces, &cache, &clock);
    let nonce = checker.nonce().unwrap();
    let token = "at.jwt.sig";
    let with_ath = format!(r#","ath":"{}""#, ath(token));
    let rs = |p: &str, bound: Jkt| {
        let proofs = [p];
        block(checker.check(&DpopRequest {
            proofs: &proofs,
            method: "POST",
            uri: URI,
            access_token: Some(token),
            bound: Some(bound),
        }))
    };
    assert!(rs(&proof("r1", Some(&nonce), &with_ath), jkt()).is_ok());
    let err = rs(&proof("r2", Some(&nonce), ""), jkt()).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidProof {
            step: Step::Ath,
            ..
        }
    ));
    let err = rs(&proof("r3", Some(&nonce), &with_ath), Jkt([0; 32])).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidProof {
            step: Step::Jkt,
            ..
        }
    ));
    assert_eq!(err.status(Role::ResourceServer), 401);
}

// IDP-11 steps 2–8: Kernel failures keep their step through the checker
#[test]
fn kernel_steps_surface_with_their_step() {
    let profile = DpopProfile::default();
    let nonces = ring(Role::AuthorizationServer, 1);
    let (cache, clock) = (Memory::default(), Fixed(Some(NOW)));
    let checker = DpopChecker::new(&profile, &nonces, &cache, &clock);
    let nonce = checker.nonce().unwrap();
    let p = proof("k", Some(&nonce), "");
    let method = [p.as_str()];
    let err = block(checker.check(&DpopRequest {
        method: "GET",
        ..request(&method)
    }))
    .unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidProof {
            step: Step::Method,
            ..
        }
    ));
    let err = block(checker.check(&DpopRequest {
        uri: "https://login.example.com/authorize",
        ..request(&method)
    }))
    .unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidProof {
            step: Step::Uri,
            ..
        }
    ));
    let late = Fixed(Some(NOW + profile.replay_ttl_ms().unwrap()));
    let later = DpopChecker::new(&profile, &nonces, &cache, &late);
    let err = block(later.check(&request(&method))).unwrap_err();
    assert!(matches!(
        err,
        Failure::InvalidProof {
            step: Step::Iat,
            ..
        }
    ));
    assert!(cache.0.lock().unwrap().is_empty());
}

// OP-64 (S-4): neither a DPoP request nor a token request prints its proofs, access token or
// `Authorization` credential
#[test]
fn requests_do_not_print_their_credentials() {
    let proofs = ["eyJ0eXAiOiJkcG9wK2p3dCJ9.proof.sig"];
    let request = DpopRequest {
        proofs: &proofs,
        method: "POST",
        uri: URI,
        access_token: Some("at-test-value"),
        bound: None,
    };
    let http = crate::app::oauth::TokenHttp {
        authorization: Some("Basic dGVzdC1jbGllbnQ6dGVzdC12YWx1ZQ=="),
        dpop: &proofs,
    };
    let printed = format!("{request:?} {http:?}");
    for secret in [
        "eyJ0eXAi",
        "at-test-value",
        "dGVzdC1jbGllbnQ6dGVzdC12YWx1ZQ",
    ] {
        assert!(!printed.contains(secret), "{printed}");
    }
    assert!(printed.contains(URI));
}
