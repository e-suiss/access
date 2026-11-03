#![allow(
    clippy::arithmetic_side_effects,
    reason = "simulated clocks in test code"
)]

use std::collections::BTreeMap;

use suiss_crypto::envelope::SoftKek;

use super::*;
use crate::adapters::SealedFactory;

#[derive(Default, Clone)]
struct MemVault(std::sync::Arc<std::sync::Mutex<BTreeMap<Realm, Vec<u8>>>>);

impl Vault for MemVault {
    fn all(&mut self) -> Result<Vec<Vec<u8>>, VaultError> {
        Ok(self.0.lock().unwrap().values().cloned().collect())
    }

    fn put(&mut self, realm: &Realm, bytes: &[u8]) -> Result<(), VaultError> {
        self.0.lock().unwrap().insert(*realm, bytes.to_vec());
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
