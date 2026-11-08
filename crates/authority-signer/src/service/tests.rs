//! The service over an in-memory vault, checked by the Kernel verifier.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "simulated clocks in test code"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::verify::key_scope::{KeyUsage, SpecVersions, operational_key, verify_metadata};
use suiss_crypto::cose::{Algorithm, KeySet, verify_sign1};
use suiss_crypto::secret::Secret;
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::{SignError, Signer, SoftSigner};

use super::*;
use crate::ports::Generated;

const MINUTE: u64 = 60_000;
const CT: &str = "application/access-receipt+cbor";

struct Soft;

impl KeyFactory for Soft {
    fn generate(&mut self, _: suiss_crypto::cose::Algorithm) -> Result<Generated, SignError> {
        let (signer, doc) = SoftSigner::generate_ed25519()?;
        Ok(Generated {
            signer: Box::new(signer),
            sealed: doc.expose().clone(),
        })
    }

    fn load(
        &mut self,
        _: suiss_crypto::cose::Algorithm,
        sealed: &[u8],
    ) -> Result<Box<dyn Signer + Send>, SignError> {
        Ok(Box::new(SoftSigner::ed25519_from_pkcs8(&Secret::new(
            sealed.to_vec(),
        ))?))
    }
}

struct Binding(Secret<Vec<u8>>);

impl Bindings for Binding {
    fn binding(&mut self, _: &Digest) -> Result<Box<dyn Signer + Send>, SignError> {
        Ok(Box::new(SoftSigner::ed25519_from_pkcs8(&self.0)?))
    }
}

#[derive(Clone, Default)]
struct Mem(std::rc::Rc<std::cell::RefCell<BTreeMap<Digest, Vec<u8>>>>);

impl Vault for Mem {
    fn all(&mut self) -> Result<Vec<Vec<u8>>, crate::ports::VaultError> {
        Ok(self.0.borrow().values().cloned().collect())
    }

    fn put(&mut self, domain: &Digest, bytes: &[u8]) -> Result<(), crate::ports::VaultError> {
        self.0.borrow_mut().insert(*domain, bytes.to_vec());
        Ok(())
    }
}

fn template() -> Template {
    Template {
        domain: Digest([7; 32]),
        genesis: Digest([8; 32]),
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_alg: Algorithm::Ed25519,
        operational_window_max_ms: 86_400_000,
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
    }
}

fn sign(at: u64) -> Request {
    Request::Sign {
        domain: Digest([7; 32]),
        usage: KeyUsage::Receipt,
        content_type: String::from(CT),
        payload: b"receipt".to_vec(),
        at,
    }
}

// OP-143 m.4, CR-23
#[test]
fn the_service_signs_and_survives_a_restart() {
    let (binding, doc) = SoftSigner::generate_ed25519().unwrap();
    let binding_key = binding.public_key();
    let vault = Mem::default();
    let mut s = Service::start(
        Soft,
        Binding(doc.clone()),
        vault.clone(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    assert_eq!(
        s.handle(Request::Open(Box::new(template())), 0),
        Response::Opened
    );
    let mut now = 0;
    while now <= Policy::AUTHORITY.publish_lead_ms + 2 * MINUTE {
        assert_eq!(s.tick(now, now), Vec::<Digest>::new());
        now += MINUTE;
    }
    let Response::Signed { sign1, excerpt } = s.handle(sign(now), now) else {
        panic!("signed");
    };
    assert_eq!(
        s.handle(sign(now + 2 * MINUTE), now),
        Response::Error(String::from("signer-time"))
    );
    let Response::Metadata(m) = s.handle(Request::Metadata(Digest([7; 32])), now) else {
        panic!("metadata");
    };
    let mut trusted = KeySet::default();
    trusted
        .insert(
            access_kernel::verify::key_scope::thumbprint(&binding_key),
            binding_key,
        )
        .unwrap();
    trusted.allowed.insert(Algorithm::Ed25519);
    let metadata = verify_metadata(&PureBackend, &m, &trusted).unwrap();
    let key = operational_key(
        &PureBackend,
        &metadata,
        &Digest([7; 32]),
        &excerpt,
        KeyUsage::Receipt,
        now,
    )
    .unwrap();
    verify_sign1(&PureBackend, &sign1, &key.key_set(), CT).unwrap();

    let mut again =
        Service::start(Soft, Binding(doc), vault, Policy::AUTHORITY, now + MINUTE).unwrap();
    let Response::Signed { excerpt: e2, .. } = again.handle(sign(now + MINUTE), now + MINUTE)
    else {
        panic!("signed after restart");
    };
    assert_eq!(e2, excerpt);
    assert_eq!(
        again.handle(Request::Metadata(Digest([9; 32])), now),
        Response::Error(String::from("signer-unknown-domain"))
    );
}

fn ready() -> (Service<Soft, Binding, Mem>, SoftSigner, u64) {
    let (binding, doc) = SoftSigner::generate_ed25519().unwrap();
    let mut s = Service::start(Soft, Binding(doc), Mem::default(), Policy::AUTHORITY, 0).unwrap();
    assert_eq!(
        s.handle(Request::Open(Box::new(template())), 0),
        Response::Opened
    );
    let mut now = 0;
    while now <= Policy::AUTHORITY.publish_lead_ms + 2 * MINUTE {
        s.tick(now, now);
        now += MINUTE;
    }
    (s, binding, now)
}

fn trusted(binding: &SoftSigner) -> KeySet {
    let key = binding.public_key();
    let mut trusted = KeySet::default();
    trusted
        .insert(access_kernel::verify::key_scope::thumbprint(&key), key)
        .unwrap();
    trusted.allowed.insert(Algorithm::Ed25519);
    trusted
}

// T20, L2-CKP-3, OP-143 m.1 E4
#[test]
fn the_service_signs_checkpoints_of_its_domain() {
    let (mut s, binding, now) = ready();
    let origin = crate::domain::origin(&Digest([7; 32]));
    let body = format!(
        "{origin}\n3\n{}\nrecorded_at 5\n",
        suiss_crypto::note::base64_encode(&[1; 32])
    );
    let note = |s: &mut Service<_, _, _>, body: &str, at| {
        s.handle(
            Request::SignNote {
                domain: Digest([7; 32]),
                body: String::from(body),
                at,
            },
            now,
        )
    };
    let Response::Noted { line, excerpt } = note(&mut s, &body, now) else {
        panic!("noted");
    };
    let Response::Metadata(m) = s.handle(Request::Metadata(Digest([7; 32])), now) else {
        panic!("metadata");
    };
    let metadata = verify_metadata(&PureBackend, &m, &trusted(&binding)).unwrap();
    let key = operational_key(
        &PureBackend,
        &metadata,
        &Digest([7; 32]),
        &excerpt,
        KeyUsage::Checkpoint,
        now,
    )
    .unwrap();
    let suiss_crypto::cose::PublicKey::Ed25519(k) = key.key else {
        panic!("ed25519");
    };
    let log = suiss_crypto::note::Verifier::ed25519(&origin, k).unwrap();
    let text = format!("{body}\n{line}");
    let (cp, _) =
        suiss_crypto::note::verify_checkpoint(&PureBackend, &text, &origin, &log, &[]).unwrap();
    assert_eq!((cp.size, cp.root), (3, [1; 32]));

    let other = body.replace(&origin, "example.com/log");
    assert_eq!(
        note(&mut s, &other, now),
        Response::Error(String::from("signer-note"))
    );
    assert_eq!(
        note(&mut s, "not a checkpoint", now),
        Response::Error(String::from("signer-note"))
    );
    assert_eq!(
        note(&mut s, &body, now + 2 * MINUTE),
        Response::Error(String::from("signer-time"))
    );
}

// CR-23, G42
#[test]
fn no_key_no_checkpoint() {
    let (_, doc) = SoftSigner::generate_ed25519().unwrap();
    let down = std::rc::Rc::new(std::cell::Cell::new(true));
    let mut s = Service::start(
        Flaky(down),
        Binding(doc),
        Mem::default(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    s.handle(Request::Open(Box::new(template())), 0);
    let origin = crate::domain::origin(&Digest([7; 32]));
    let body = format!(
        "{origin}\n1\n{}\n",
        suiss_crypto::note::base64_encode(&[1; 32])
    );
    assert_eq!(
        s.handle(
            Request::SignNote {
                domain: Digest([7; 32]),
                body,
                at: 0,
            },
            0,
        ),
        Response::Error(String::from("signer-no-key"))
    );
}

// CR-59, SAI-46, OP-143 m.4
#[test]
fn the_founding_key_signs_on_open_and_an_older_vault_has_none() {
    let (binding, doc) = SoftSigner::generate_ed25519().unwrap();
    let vault = Mem::default();
    let mut s = Service::start(
        Soft,
        Binding(doc.clone()),
        vault.clone(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    assert_eq!(
        s.handle(Request::Open(Box::new(template())), 0),
        Response::Opened
    );
    let Response::Signed { sign1, excerpt } = s.handle(sign(0), 0) else {
        panic!("not signed at Genesis");
    };
    let Response::Metadata(m) = s.handle(Request::Metadata(Digest([7; 32])), 0) else {
        panic!("metadata");
    };
    let metadata = verify_metadata(&PureBackend, &m, &trusted(&binding)).unwrap();
    let key = operational_key(
        &PureBackend,
        &metadata,
        &Digest([7; 32]),
        &excerpt,
        KeyUsage::Receipt,
        0,
    )
    .unwrap();
    verify_sign1(&PureBackend, &sign1, &key.key_set(), CT).unwrap();
    let keys = s.rings[&Digest([7; 32])].1.saved();
    assert_eq!(keys.iter().filter(|k| k.record.founding).count(), 1);

    let current = vault.0.borrow()[&Digest([7; 32])].clone();
    let older = Mem::default();
    older
        .0
        .borrow_mut()
        .insert(Digest([7; 32]), without_founding(&current));
    let mut restored = Service::start(Soft, Binding(doc), older, Policy::AUTHORITY, 0).unwrap();
    let keys = restored.rings[&Digest([7; 32])].1.saved();
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| !k.record.founding));
    assert_eq!(
        restored.handle(sign(0), 0),
        Response::Error(String::from("signer-no-key"))
    );
    let lead = Policy::AUTHORITY.publish_lead_ms;
    assert!(matches!(
        restored.handle(sign(lead), lead),
        Response::Signed { .. }
    ));
}

/// `bytes` with every `founding` entry of every key removed: a domain as a vault written before
/// CR-59 kept it.
fn without_founding(bytes: &[u8]) -> Vec<u8> {
    let Value::Map(top) = dcbor::decode(bytes, Limits::CEILING).unwrap() else {
        panic!("not a map");
    };
    let top = top
        .into_iter()
        .map(|(k, v)| match (&k, v) {
            (Value::Text(name), Value::Array(keys)) if name == "keys" => {
                let keys = keys
                    .into_iter()
                    .map(|key| {
                        let Value::Map(fields) = key else {
                            panic!("not a map");
                        };
                        Value::Map(
                            fields
                                .into_iter()
                                .filter(|(f, _)| !matches!(f, Value::Text(t) if t == "founding"))
                                .collect(),
                        )
                    })
                    .collect();
                (k, Value::Array(keys))
            }
            (_, v) => (k, v),
        })
        .collect();
    dcbor::encode(&Value::Map(top), Limits::CEILING).unwrap()
}

// T20, OP-143 m.1 E4
#[test]
fn the_genesis_statement_is_signed_on_open_and_kept() {
    let (binding, doc) = SoftSigner::generate_ed25519().unwrap();
    let vault = Mem::default();
    let mut s = Service::start(
        Soft,
        Binding(doc.clone()),
        vault.clone(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    s.handle(Request::Open(Box::new(template())), 5);
    let Response::Genesis(g) = s.handle(Request::Genesis(Digest([7; 32])), 9) else {
        panic!("genesis");
    };
    let statement =
        crate::genesis::verify(&PureBackend, &g, &trusted(&binding), &Digest([7; 32])).unwrap();
    assert_eq!(
        (statement.genesis, statement.issued_at),
        (Digest([8; 32]), 5)
    );
    assert!(
        crate::genesis::verify(&PureBackend, &g, &trusted(&binding), &Digest([9; 32])).is_err()
    );
    s.handle(Request::Open(Box::new(template())), 7);
    let again = Service::start(Soft, Binding(doc), vault, Policy::AUTHORITY, MINUTE)
        .unwrap()
        .handle(Request::Genesis(Digest([7; 32])), MINUTE);
    assert_eq!(again, Response::Genesis(g));
}

struct Flaky(std::rc::Rc<std::cell::Cell<bool>>);

impl KeyFactory for Flaky {
    fn generate(&mut self, alg: suiss_crypto::cose::Algorithm) -> Result<Generated, SignError> {
        if self.0.get() {
            return Err(SignError::Key);
        }
        Soft.generate(alg)
    }

    fn load(
        &mut self,
        alg: suiss_crypto::cose::Algorithm,
        sealed: &[u8],
    ) -> Result<Box<dyn Signer + Send>, SignError> {
        Soft.load(alg, sealed)
    }
}

const HOUR: u64 = 60 * MINUTE;

// CR-23, CR-27, OP-150, TN-12, TN-118
#[test]
fn rounds_report_transitions_and_delays() {
    let down = std::rc::Rc::new(std::cell::Cell::new(false));
    let (_, doc) = SoftSigner::generate_ed25519().unwrap();
    let mut s = Service::start(
        Flaky(down.clone()),
        Binding(doc),
        Mem::default(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    assert_eq!(
        s.handle(Request::Open(Box::new(template())), 0),
        Response::Opened
    );
    let mut names = BTreeSet::new();
    let mut now = 0;
    while now <= 6 * HOUR {
        let report = s.round(now, now);
        assert_eq!(report.delayed, Vec::new(), "{now}");
        names.extend(report.transitions.iter().map(|(d, step)| {
            assert_eq!(*d, Digest([7; 32]));
            step.name()
        }));
        now += MINUTE;
    }
    assert!(names.is_superset(&BTreeSet::from(["publish", "activate", "retire"])));
    down.set(true);
    let mut late = None;
    while now <= 12 * HOUR {
        let report = s.round(now, now);
        late = late.or_else(|| report.delayed.first().map(|(_, ms)| *ms));
        now += MINUTE;
    }
    assert!(late.is_some_and(|ms| ms > 0));
}

// CR-26, CR-27, OP-150
#[test]
fn dropped_keys_stay_archived() {
    let (_, doc) = SoftSigner::generate_ed25519().unwrap();
    let vault = Mem::default();
    let mut s = Service::start(
        Soft,
        Binding(doc.clone()),
        vault.clone(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    let _ = s.handle(Request::Open(Box::new(template())), 0);
    let mut now = 0;
    while now <= 120 * HOUR {
        let _ = s.tick(now, now);
        now += 10 * MINUTE;
    }
    let archived = |s: &Service<Soft, Binding, Mem>| -> Vec<OperationalKey> {
        s.rings[&Digest([7; 32])]
            .1
            .saved()
            .into_iter()
            .filter(|k| k.record.state == State::Dropped)
            .inspect(|k| assert!(k.sealed.is_none() && k.excerpt.is_some()))
            .map(|k| k.declared)
            .collect()
    };
    let dropped = archived(&s);
    assert_ne!(dropped.len(), 0);
    let again = Service::start(Soft, Binding(doc), vault, Policy::AUTHORITY, now).unwrap();
    assert_eq!(archived(&again), dropped);
}
