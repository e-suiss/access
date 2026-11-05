#![allow(
    clippy::arithmetic_side_effects,
    reason = "simulated clocks in test code"
)]

use std::collections::BTreeMap;

use suiss_crypto::envelope::SoftKek;
use suiss_crypto::signer::SignError;

use super::*;
use crate::adapters::SealedFactory;

type Cell = std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>;

#[derive(Default, Clone)]
struct MemVault(
    std::sync::Arc<std::sync::Mutex<BTreeMap<Realm, Vec<u8>>>>,
    Cell,
    std::sync::Arc<std::sync::Mutex<BTreeMap<Realm, Vec<u8>>>>,
);

impl Vault for MemVault {
    fn all(&mut self) -> Result<Vec<Vec<u8>>, VaultError> {
        Ok(self.0.lock().unwrap().values().cloned().collect())
    }

    fn put(&mut self, realm: &Realm, bytes: &[u8]) -> Result<(), VaultError> {
        self.0.lock().unwrap().insert(*realm, bytes.to_vec());
        Ok(())
    }

    fn cell(&mut self) -> Result<Option<Vec<u8>>, VaultError> {
        Ok(self.1.lock().unwrap().clone())
    }

    fn put_cell(&mut self, bytes: &[u8]) -> Result<(), VaultError> {
        *self.1.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }

    fn issuer(&mut self, realm: &Realm) -> Result<Option<Vec<u8>>, VaultError> {
        Ok(self.2.lock().unwrap().get(realm).cloned())
    }

    fn put_issuer(&mut self, realm: &Realm, bytes: &[u8]) -> Result<(), VaultError> {
        self.2.lock().unwrap().insert(*realm, bytes.to_vec());
        Ok(())
    }
}

fn factory() -> SealedFactory<SoftKek> {
    SealedFactory::new(SoftKek::new("realm-kek", [5; 32]))
}

fn jwks(s: &mut Service<SealedFactory<SoftKek>, MemVault>, r: Realm) -> String {
    match s.handle(Request::Jwks(r), 0, 0) {
        Response::Jwks(d) => d,
        other => panic!("{other:?}"),
    }
}

const A: Realm = Realm([1; 16]);
const B: Realm = Realm([2; 16]);

// CMP-22b, CR-19, CR-27: opening a realm publishes its own key at once; realms share no key
#[test]
fn each_realm_has_its_own_published_keys() {
    let mut s = Service::start(factory(), MemVault::default(), Policy::REALM).unwrap();
    assert_eq!(s.handle(Request::Ping, 0, 0), Response::Pong);
    assert_eq!(
        s.handle(Request::Jwks(A), 0, 0),
        Response::Error(String::from(UNKNOWN_REALM))
    );
    for r in [A, B] {
        let open = Request::Open {
            realm: r,
            alg: JwsAlg::Es256,
        };
        assert_eq!(s.handle(open.clone(), 0, 7), Response::Opened);
        assert_eq!(s.handle(open, 0, 7), Response::Opened);
    }
    let (a, b) = (jwks(&mut s, A), jwks(&mut s, B));
    assert!(a.contains(r#""kty":"EC""#), "{a}");
    assert_ne!(a, b);
    assert_eq!(s.realms(), vec![A, B]);
}

// OP-146 m.8 (e), m.16 (m), MD-6: a realm's new JOSE algorithm reaches its open key set and
// survives a restart; the next keys use it and are published before use
#[test]
fn another_alg_applies_to_the_next_keys() {
    let vault = MemVault::default();
    let mut s = Service::start(factory(), vault.clone(), Policy::REALM).unwrap();
    let open = |alg| Request::Open { realm: A, alg };
    assert_eq!(s.handle(open(JwsAlg::Es256), 0, 7), Response::Opened);
    let first = jwks(&mut s, A);
    assert_eq!(s.handle(open(JwsAlg::Ed25519), 0, 7), Response::Opened);
    assert_eq!(jwks(&mut s, A), first);
    let mut again = Service::start(factory(), vault, Policy::REALM).unwrap();
    assert_eq!(again.rings.get(&A).map(|(a, _)| *a), Some(JwsAlg::Ed25519));
    let day = 86_400_000;
    let rotated = (1..=800_u64).any(|d| {
        assert_eq!(again.tick(d * day, 7), Vec::<Realm>::new());
        jwks(&mut again, A).contains(r#""kty":"OKP""#)
    });
    assert!(rotated);
}

// SAI-46, CR-25: nothing is signed before the lead has passed, then the active key signs
#[test]
fn signing_waits_for_the_publish_lead() {
    let mut s = Service::start(factory(), MemVault::default(), Policy::REALM).unwrap();
    let _ = s.handle(
        Request::Open {
            realm: A,
            alg: JwsAlg::Ed25519,
        },
        0,
        0,
    );
    let sign = |at| Request::Sign {
        realm: A,
        typ: String::from("JWT"),
        payload: b"{}".to_vec(),
        at,
    };
    assert_eq!(
        s.handle(sign(0), 0, 0),
        Response::Error(String::from("signer-no-key"))
    );
    let later = Policy::REALM.publish_lead_ms + 60_000;
    assert_eq!(s.tick(later, 0), Vec::<Realm>::new());
    assert!(matches!(
        s.handle(sign(later), later, 0),
        Response::Signed { .. }
    ));
    assert_eq!(
        s.handle(sign(later + MAX_SKEW_MS + 1), later, 0),
        Response::Error(String::from("signer-time"))
    );
}

// CR-23, OP-143 m.9 (e): a restarted signer restores every realm from its vault
#[test]
fn a_restart_restores_every_realm() {
    let vault = MemVault::default();
    let mut s = Service::start(factory(), vault.clone(), Policy::REALM).unwrap();
    for r in [A, B] {
        let _ = s.handle(
            Request::Open {
                realm: r,
                alg: JwsAlg::Es256,
            },
            0,
            0,
        );
    }
    let before = (jwks(&mut s, A), jwks(&mut s, B));
    let mut again = Service::start(factory(), vault, Policy::REALM).unwrap();
    assert_eq!((jwks(&mut again, A), jwks(&mut again, B)), before);
}

fn checkpoint(origin: &str, size: u64) -> String {
    suiss_crypto::note::Checkpoint {
        origin: String::from(origin),
        size,
        root: [7; 32],
        extensions: vec![String::from("issued_at 1000")],
    }
    .to_body()
    .unwrap()
}

// OP-150, CMP-22b, OP-143 m.10, L2-CKP-3: the cell key signs its own audit log's checkpoints
// as notes its published verifier key verifies; another origin or no cell is refused
#[test]
fn the_cell_key_signs_audit_checkpoints() {
    let mut s = Service::start(factory(), MemVault::default(), Policy::REALM).unwrap();
    let body = checkpoint("cell-a/identity-audit", 3);
    let sign = |body: &str| Request::SignCheckpoint {
        body: String::from(body),
    };
    assert_eq!(
        s.handle(sign(&body), 0, 0),
        Response::Error(String::from(NO_CELL))
    );
    s.open_cell("cell-a").unwrap();
    let Response::CellKey { origin, vkey } = s.handle(Request::CellKey, 0, 0) else {
        panic!("no cell key");
    };
    assert_eq!(origin, "cell-a/identity-audit");
    let Response::Noted { line } = s.handle(sign(&body), 0, 0) else {
        panic!("not signed");
    };
    let verifier = suiss_crypto::note::Verifier::parse(&vkey).unwrap();
    let note = format!("{body}\n{line}");
    let (cp, _) = suiss_crypto::note::verify_checkpoint(
        &access_crypto::AwsLcBackend,
        &note,
        &origin,
        &verifier,
        &[],
    )
    .unwrap();
    assert_eq!(cp.size, 3);
    assert_eq!(
        s.handle(sign(&checkpoint("cell-b/identity-audit", 3)), 0, 0),
        Response::Error(String::from("signer-note"))
    );
    assert_eq!(
        s.handle(sign("cell-a/identity-audit\n3\n"), 0, 0),
        Response::Error(String::from("signer-note"))
    );
}

// OP-150, CR-23: the cell key survives a restart and realm rotation; a vault holding another
// cell's key is refused
#[test]
fn the_cell_key_survives_a_restart() {
    let vault = MemVault::default();
    let mut s = Service::start(factory(), vault.clone(), Policy::REALM).unwrap();
    s.open_cell("cell-a").unwrap();
    let _ = s.handle(
        Request::Open {
            realm: A,
            alg: JwsAlg::Ed25519,
        },
        0,
        0,
    );
    let before = s.handle(Request::CellKey, 0, 0);
    let day = 86_400_000;
    for d in 1..=400_u64 {
        assert_eq!(s.tick(d * day, 7), Vec::<Realm>::new());
    }
    assert_eq!(s.handle(Request::CellKey, 0, 0), before);
    let mut again = Service::start(factory(), vault.clone(), Policy::REALM).unwrap();
    again.open_cell("cell-a").unwrap();
    assert_eq!(again.handle(Request::CellKey, 0, 0), before);
    let mut other = Service::start(factory(), vault, Policy::REALM).unwrap();
    assert_eq!(
        other.open_cell("cell-b").err(),
        Some(crate::cell::CellError::OtherCell)
    );
}

struct Flaky(
    SealedFactory<SoftKek>,
    std::sync::Arc<std::sync::atomic::AtomicBool>,
);

impl KeyFactory for Flaky {
    fn generate(&mut self, alg: JwsAlg) -> Result<crate::ports::Generated, SignError> {
        if self.1.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(SignError::Key);
        }
        self.0.generate(alg)
    }

    fn load(
        &mut self,
        alg: JwsAlg,
        sealed: &[u8],
    ) -> Result<Box<dyn suiss_crypto::signer::Signer + Send>, SignError> {
        self.0.load(alg, sealed)
    }
}

// CR-23, CR-27, OP-150, TN-12, TN-118: each round reports the realm key transitions, the realm audit events;
// while keys can be made no rotation is late, and a key-generation outage makes the round report
// the delayed rotation of that realm
#[test]
fn rounds_report_transitions_and_delays() {
    let down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut s = Service::start(
        Flaky(factory(), down.clone()),
        MemVault::default(),
        Policy::REALM,
    )
    .unwrap();
    let open = Request::Open {
        realm: A,
        alg: JwsAlg::Es256,
    };
    assert_eq!(s.handle(open, 0, 7), Response::Opened);
    let day = 86_400_000;
    let mut names = std::collections::BTreeSet::new();
    for d in 1..=400_u64 {
        let report = s.round(d * day, 7);
        assert_eq!(report.delayed, Vec::new(), "day {d}");
        names.extend(report.transitions.iter().map(|(r, step)| {
            assert_eq!(*r, A);
            step.name()
        }));
    }
    assert!(names.is_superset(&std::collections::BTreeSet::from([
        "publish", "activate", "retire", "drop"
    ])));
    down.store(true, std::sync::atomic::Ordering::Relaxed);
    let late = (401..=800_u64).find_map(|d| s.round(d * day, 7).delayed.first().copied());
    assert!(late.is_some_and(|(r, ms)| r == A && ms > 0));
}

// TN-118, §13.2, CR-23: decided rotation, emergency drop and policy reach the realm's key set
// and survive a restart; another realm is untouched
#[test]
fn decided_key_changes_survive_a_restart() {
    let vault = MemVault::default();
    let mut s = Service::start(factory(), vault.clone(), Policy::REALM).unwrap();
    for r in [A, B] {
        let _ = s.handle(
            Request::Open {
                realm: r,
                alg: JwsAlg::Es256,
            },
            0,
            0,
        );
    }
    let lead = Policy::REALM.publish_lead_ms;
    let now = 2 * lead + 60_000;
    assert_eq!(s.tick(lead, 1), Vec::<Realm>::new());
    assert_eq!(s.tick(now, 1), Vec::<Realm>::new());
    let b = jwks(&mut s, B);
    let Response::Signed { kid, .. } = s.handle(
        Request::Sign {
            realm: A,
            typ: String::from("JWT"),
            payload: b"{}".to_vec(),
            at: now,
        },
        now,
        0,
    ) else {
        panic!("not signed");
    };
    let Response::Rekeyed(after) = s.handle(Request::DropKey { realm: A, kid }, now, 2) else {
        panic!("not dropped");
    };
    assert!(!after.contains(&access_kernel::json::b64url_encode(&kid)));
    assert_eq!(
        s.handle(Request::DropKey { realm: A, kid }, now, 2),
        Response::Rekeyed(after.clone())
    );
    assert_eq!(
        s.handle(
            Request::DropKey {
                realm: A,
                kid: [0; 32]
            },
            now,
            2
        ),
        Response::Error(String::from("signer-unknown-key"))
    );
    let mut faster = Policy::REALM;
    faster.lifetime_ms = 30 * 86_400_000;
    faster.window_ms = 60 * 86_400_000;
    assert!(matches!(
        s.handle(
            Request::SetPolicy {
                realm: A,
                policy: faster
            },
            now,
            0
        ),
        Response::Rekeyed(_)
    ));
    let mut bad = Policy::REALM;
    bad.publish_lead_ms = 0;
    assert_eq!(
        s.handle(
            Request::SetPolicy {
                realm: A,
                policy: bad
            },
            now,
            0
        ),
        Response::Error(String::from("realm-key-lead"))
    );
    assert_eq!(
        s.handle(
            Request::Rotate {
                realm: Realm([9; 16]),
                retire: kid
            },
            now,
            0
        ),
        Response::Error(String::from(UNKNOWN_REALM))
    );
    let mut again = Service::start(factory(), vault, Policy::REALM).unwrap();
    assert_eq!(jwks(&mut again, A), after);
    assert_eq!(jwks(&mut again, B), b);
    assert_eq!(again.rings.get(&A).map(|(_, r)| r.policy()), Some(faster));
}
fn claim_payload(issuer: [u8; 16], at: u64) -> Vec<u8> {
    use access_kernel::codec::Canonical as _;
    access_kernel::claim::Statement {
        domain: access_kernel::digest::Digest([3; 32]),
        issuer: access_kernel::model::Id(issuer),
        subject: access_kernel::model::Id([9; 16]),
        class: String::from("account_status"),
        value: Some(access_kernel::model::EqValue::Text(String::from(
            "suspended",
        ))),
        issued_at: at,
        validity: access_kernel::model::Window {
            from: at,
            until: at + 10,
        },
        assurance: BTreeMap::new(),
        bound_intent: None,
        bound_instance: None,
        bound_resource: None,
        supersedes: None,
    }
    .to_bytes()
    .unwrap()
}

// OP-144 carry-over, §10.1.7, MD-6, CR-23: each realm's Claim issuer key is its own Ed25519
// key, apart from the realm's token keys, bound to the issuer Party it was opened for, and it
// survives a restart; the token key never signs a Claim
#[test]
fn the_claim_issuer_key_is_separate_and_survives_a_restart() {
    let vault = MemVault::default();
    let mut s = Service::start(factory(), vault.clone(), Policy::REALM).unwrap();
    let party = [4; 16];
    let sign = |party| Request::SignClaim {
        realm: A,
        payload: claim_payload(party, 100),
        at: 100,
    };
    assert_eq!(
        s.handle(sign(party), 100, 0),
        Response::Error(String::from(NO_ISSUER))
    );
    let open = |party| Request::OpenIssuer { realm: A, party };
    let Response::Issuer { key, kid, .. } = s.handle(open(party), 0, 0) else {
        panic!("not opened");
    };
    assert_eq!(s.handle(open(party), 0, 0), s.handle(open(party), 0, 0));
    assert_eq!(
        s.handle(open([5; 16]), 0, 0),
        Response::Error(String::from("signer-issuer-party"))
    );
    let Response::SignedCose { sign1, kid: k } = s.handle(sign(party), 100, 0) else {
        panic!("not signed");
    };
    assert_eq!(k, kid);
    let pk = suiss_crypto::cose::PublicKey::Ed25519(key);
    assert!(
        access_kernel::claim::verify(
            &sign1,
            &pk,
            &access_kernel::model::Id(party),
            &access_kernel::digest::Digest([3; 32]),
        )
        .is_ok()
    );
    assert_eq!(
        s.handle(sign([5; 16]), 100, 0),
        Response::Error(String::from("signer-payload"))
    );
    assert_eq!(
        s.handle(sign(party), 100 + MAX_SKEW_MS + 1, 0),
        Response::Error(String::from("signer-time"))
    );
    let _ = s.handle(
        Request::Open {
            realm: A,
            alg: JwsAlg::Ed25519,
        },
        0,
        0,
    );
    let later = Policy::REALM.publish_lead_ms + 60_000;
    assert_eq!(s.tick(later, 0), Vec::<Realm>::new());
    for ct in PROTOCOL_TYPES {
        let r = Request::SignCose {
            realm: A,
            content_type: String::from(ct),
            payload: claim_payload(party, later),
            at: later,
        };
        assert_eq!(
            s.handle(r, later, 0),
            Response::Error(String::from("signer-payload"))
        );
    }
    assert!(!jwks(&mut s, A).contains(&access_kernel::json::b64url_encode(&key)));
    let mut again = Service::start(factory(), vault, Policy::REALM).unwrap();
    assert!(matches!(
        again.handle(sign(party), 100, 0),
        Response::SignedCose { kid: k, .. } if k == kid
    ));
}
