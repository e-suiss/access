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

/// Binding generations kept in memory, the first being generation 0.
#[derive(Clone, Default)]
struct Generations(std::rc::Rc<std::cell::RefCell<BTreeMap<u64, Secret<Vec<u8>>>>>);

impl Bindings for Generations {
    fn binding(&mut self, d: &Digest) -> Result<Box<dyn Signer + Send>, SignError> {
        self.generation(d, 0)
    }

    fn generation(&mut self, _: &Digest, g: u64) -> Result<Box<dyn Signer + Send>, SignError> {
        let doc = self
            .0
            .borrow_mut()
            .entry(g)
            .or_insert_with(|| SoftSigner::generate_ed25519().unwrap().1)
            .clone();
        Ok(Box::new(SoftSigner::ed25519_from_pkcs8(&doc)?))
    }
}

fn metadata_of(
    s: &mut Service<Soft, Generations, Mem>,
) -> access_kernel::verify::key_scope::DomainMetadata {
    let Response::Metadata(m) = s.handle(Request::Metadata(Digest([7; 32])), 0) else {
        panic!("metadata");
    };
    let msg = suiss_crypto::cose::parse_sign1(&m).unwrap();
    access_kernel::verify::key_scope::DomainMetadata::from_bytes(&msg.payload.unwrap()).unwrap()
}

// OP-60, §16.6.1 RB-2, RB-4, RB-6, OP-158 m.3 (l)
#[test]
#[expect(clippy::too_many_lines, reason = "one re-anchor walkthrough")]
fn a_re_anchor_moves_to_the_next_generation_and_keeps_the_old_binding_superseded() {
    let vault = Mem::default();
    let gens = Generations::default();
    let mut s = Service::start(Soft, gens.clone(), vault.clone(), Policy::AUTHORITY, 0).unwrap();
    assert_eq!(
        s.handle(Request::Open(Box::new(template())), 0),
        Response::Opened
    );
    let d = Digest([7; 32]);
    let Response::Binding(current) = s.handle(
        Request::Binding {
            domain: d,
            next: false,
        },
        0,
    ) else {
        panic!("binding");
    };
    let Response::Binding(next) = s.handle(
        Request::Binding {
            domain: d,
            next: true,
        },
        0,
    ) else {
        panic!("next binding");
    };
    assert_ne!(current.kid, next.kid);
    // RB-4
    let statement = |next| Request::Statement {
        domain: d,
        next,
        content_type: String::from(crate::handover::NO_WRITE),
        payload: vec![0xa0],
    };
    let Response::Statement(old_signed) = s.handle(statement(false), 0) else {
        panic!("statement");
    };
    let Response::Statement(new_signed) = s.handle(statement(true), 0) else {
        panic!("statement");
    };
    for (signed, key) in [(&old_signed, &current), (&new_signed, &next)] {
        assert!(
            crate::handover::verify(
                &PureBackend,
                signed,
                std::slice::from_ref(key),
                crate::handover::NO_WRITE
            )
            .is_ok()
        );
    }
    assert_eq!(
        s.handle(
            Request::Statement {
                domain: d,
                next: false,
                content_type: String::from("application/access-receipt+cbor"),
                payload: vec![0xa0],
            },
            0
        ),
        Response::Error(String::from("signer-usage"))
    );
    // RB-6
    assert_eq!(
        s.handle(
            Request::Rebind {
                domain: d,
                at: Digest([1; 32]),
                cited: Digest([2; 32]),
                transcript: Digest([3; 32]),
            },
            0
        ),
        Response::Opened
    );
    let m = metadata_of(&mut s);
    assert!(m.binding[&next.kid].superseded.is_none());
    assert_eq!(
        m.binding[&current.kid].superseded,
        Some(access_kernel::verify::key_scope::Superseded {
            at: Digest([1; 32]),
            cited: Digest([2; 32]),
            cause: Some(access_kernel::verify::key_scope::SupersededCause::ReAnchor),
        })
    );
    assert_eq!(m.declared.ceremony_transcript, Some(Digest([3; 32])));
    let Response::Signed { excerpt, .. } = s.handle(sign(0), 0) else {
        panic!("signed");
    };
    let mut keys = KeySet::default();
    keys.allowed.insert(Algorithm::Ed25519);
    keys.insert(next.kid, next.key.clone()).unwrap();
    assert!(
        verify_sign1(
            &PureBackend,
            &excerpt,
            &keys,
            access_kernel::verify::key_scope::EXCERPT_CONTENT_TYPE
        )
        .is_ok()
    );
    drop(s);
    let mut s = Service::start(Soft, gens, vault, Policy::AUTHORITY, 0).unwrap();
    let m = metadata_of(&mut s);
    assert!(m.binding[&next.kid].superseded.is_none());
    assert!(m.binding[&current.kid].superseded.is_some());
}

// HO-8
#[test]
fn an_incoming_install_publishes_the_outgoing_bindings_only_as_superseded() {
    let mut s = Service::start(
        Soft,
        Generations::default(),
        Mem::default(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    s.handle(Request::Open(Box::new(template())), 0);
    let d = Digest([7; 32]);
    let (k, _) = SoftSigner::generate_ed25519().unwrap();
    let mut old = crate::domain::binding(Algorithm::Ed25519, k.public_key());
    assert_eq!(
        s.handle(
            Request::Supersede {
                domain: d,
                keys: vec![old.clone()],
            },
            0
        ),
        Response::Error(String::from("signer-usage"))
    );
    old.superseded = Some(access_kernel::verify::key_scope::Superseded {
        at: Digest([4; 32]),
        cited: Digest([5; 32]),
        cause: None,
    });
    assert_eq!(
        s.handle(
            Request::Supersede {
                domain: d,
                keys: vec![old.clone()],
            },
            0
        ),
        Response::Opened
    );
    let m = metadata_of(&mut s);
    assert_eq!(m.binding[&old.kid].superseded, old.superseded);
    assert_eq!(
        m.binding
            .values()
            .filter(|b| b.superseded.is_none())
            .count(),
        1
    );
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
        declared: crate::domain::declared_default(),
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
    let Response::Signed { sign1, excerpt, .. } = s.handle(sign(now), now) else {
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
        None,
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
        None,
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
    let Response::Signed { sign1, excerpt, .. } = s.handle(sign(0), 0) else {
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
        None,
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

// CR-23, CR-27, OP-150, TN-12, TN-118, OP-157 m.3 (x)
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
    let mut rotated = BTreeSet::new();
    let mut now = 0;
    while now <= 6 * HOUR {
        let report = s.round(now, now);
        assert_eq!(report.delayed, Vec::new(), "{now}");
        // §10.1.7, OP-157 m.3 (x)
        rotated.extend(report.rotated().map(|(d, kid)| (*d, *kid)));
        names.extend(report.transitions.iter().map(|(d, step)| {
            assert_eq!(*d, Digest([7; 32]));
            step.name()
        }));
        now += MINUTE;
    }
    assert!(names.is_superset(&BTreeSet::from(["publish", "activate", "retire"])));
    assert!(rotated.len() >= 5, "{rotated:?}");
    assert_eq!(AUDIT_EVENT_ROTATED, "signer.rotated");
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

// OP-158 m.3 (b), (f)
#[test]
fn a_declaration_is_published_in_newly_signed_metadata() {
    let (mut s, binding, now) = ready();
    let (replica, _) = SoftSigner::generate_ed25519().unwrap();
    let mut declared = crate::domain::declared_default();
    declared
        .replicas
        .push(access_kernel::verify::key_scope::Replica::new(
            String::from("acme-replica"),
            replica.public_key(),
            String::from("Acme Replica Ltd"),
            true,
        ));
    assert_eq!(
        s.handle(
            Request::Declare {
                domain: Digest([9; 32]),
                declared: Box::new(declared.clone()),
            },
            now
        ),
        Response::Error(String::from("signer-unknown-domain"))
    );
    assert_eq!(
        s.handle(
            Request::Declare {
                domain: Digest([7; 32]),
                declared: Box::new(declared.clone()),
            },
            now + 1
        ),
        Response::Opened
    );
    let Response::Metadata(m) = s.handle(Request::Metadata(Digest([7; 32])), now + 1) else {
        panic!("metadata");
    };
    let metadata = verify_metadata(&PureBackend, &m, &trusted(&binding)).unwrap();
    assert_eq!(metadata.declared.replicas, declared.replicas);
    assert_eq!(metadata.issued_at, now + 1);
    let Response::Signed { .. } = s.handle(sign(now + 1), now + 1) else {
        panic!("still signs");
    };
}

struct Pq;

impl KeyFactory for Pq {
    fn generate(&mut self, alg: Algorithm) -> Result<Generated, SignError> {
        if access_kernel::verify::ml_dsa::is_ml_dsa(alg) {
            let (signer, seed) = suiss_crypto::signer::MlDsaSigner::generate(alg)?;
            return Ok(Generated {
                signer: Box::new(signer),
                sealed: seed.expose().to_vec(),
            });
        }
        Soft.generate(alg)
    }

    fn load(&mut self, alg: Algorithm, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError> {
        if access_kernel::verify::ml_dsa::is_ml_dsa(alg) {
            let seed: [u8; 32] = sealed.try_into().map_err(|_| SignError::Key)?;
            return Ok(Box::new(suiss_crypto::signer::MlDsaSigner::from_seed(
                alg,
                &Secret::new(seed),
            )?));
        }
        Soft.load(alg, sealed)
    }
}

fn pq_metadata(s: &mut Service<Pq, Generations, Mem>) -> (Vec<u8>, KeySet) {
    let Response::Metadata(m) = s.handle(Request::Metadata(Digest([7; 32])), 0) else {
        panic!("metadata");
    };
    let Response::Binding(b) = s.handle(
        Request::Binding {
            domain: Digest([7; 32]),
            next: false,
        },
        0,
    ) else {
        panic!("binding");
    };
    let mut trusted = KeySet::default();
    trusted.allowed.insert(b.alg);
    trusted.insert(b.kid, b.key).unwrap();
    (m, trusted)
}

fn allowlist(alg: Algorithm, retire: bool) -> Request {
    Request::Allowlist {
        domain: Digest([7; 32]),
        alg,
        retire,
    }
}

// CR-41, CR-42 m.4, OP-159 m.3 (d), (e), m.9 (h)
#[test]
fn an_admitted_ml_dsa_algorithm_signs_every_artefact_twice_and_the_kernel_wants_both() {
    use access_kernel::verify::hybrid::{self, Component, Expected, HybridError};
    use access_kernel::verify::key_scope::Hybrid;
    use suiss_crypto::aws::AwsLcBackend;
    let mut s = Service::start(
        Pq,
        Generations::default(),
        Mem::default(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    assert_eq!(
        s.handle(Request::Open(Box::new(template())), 0),
        Response::Opened
    );
    let Response::Signed { pq: None, .. } = s.handle(sign(0), 0) else {
        panic!("a classical domain signs once");
    };
    assert_eq!(
        s.handle(allowlist(Algorithm::MlDsa65, false), 0),
        Response::Opened
    );
    let (bytes, trusted) = pq_metadata(&mut s);
    let m = verify_metadata(&AwsLcBackend, &bytes, &trusted).unwrap();
    assert!(m.algorithms.contains(&Algorithm::MlDsa65));
    assert!(m.algorithms.contains(&Algorithm::Ed25519));
    assert_eq!(m.hybrid, Some(Hybrid::Both));
    assert!(
        m.operational_keys
            .iter()
            .any(|k| k.alg == Algorithm::MlDsa65)
    );
    let Response::Signed {
        sign1,
        excerpt,
        pq: Some((pq_sign1, pq_excerpt)),
    } = s.handle(sign(0), 0)
    else {
        panic!("a hybrid domain signs twice");
    };
    let d = Digest([7; 32]);
    let expected = Expected::new(&d, KeyUsage::Receipt, 0, CT);
    let classic = Component::new(&sign1, &excerpt);
    let post_quantum = Component::new(&pq_sign1, &pq_excerpt);
    let v = hybrid::verify(
        &AwsLcBackend,
        &m,
        Some(classic),
        Some(post_quantum),
        &expected,
    )
    .unwrap();
    assert_eq!(v.payload, b"receipt");
    // CR-42 m.2, SAI-44
    assert_eq!(
        hybrid::verify(&AwsLcBackend, &m, Some(classic), None, &expected).err(),
        Some(HybridError::Missing)
    );
    assert_eq!(
        hybrid::verify(&AwsLcBackend, &m, None, Some(post_quantum), &expected).err(),
        Some(HybridError::Missing)
    );
    assert!(operational_key(&AwsLcBackend, &m, &d, &excerpt, KeyUsage::Receipt, 0, None).is_err());
    // OP-159 m.3 (c)
    assert!(
        hybrid::verify(
            &PureBackend,
            &m,
            Some(classic),
            Some(post_quantum),
            &expected
        )
        .is_err()
    );
}

// CR-41 m.2, OP-159 m.3 (e)
#[test]
fn ml_dsa_87_is_the_cnsa_profile_and_ml_dsa_44_never_signs_the_domain() {
    let mut s = Service::start(
        Pq,
        Generations::default(),
        Mem::default(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    assert_eq!(
        s.handle(Request::Open(Box::new(template())), 0),
        Response::Opened
    );
    assert_eq!(
        s.handle(allowlist(Algorithm::MlDsa44, false), 0),
        Response::Opened
    );
    let Response::Signed { pq: None, .. } = s.handle(sign(0), 0) else {
        panic!("ML-DSA-44 is for offline projections only");
    };
    assert_eq!(
        s.handle(allowlist(Algorithm::MlDsa87, false), 0),
        Response::Opened
    );
    let Response::Signed {
        pq: Some((pq_sign1, _)),
        ..
    } = s.handle(sign(0), 0)
    else {
        panic!("signed");
    };
    let alg = access_kernel::verify::ml_dsa::algorithm_of(&pq_sign1).unwrap();
    assert_eq!(alg, Algorithm::MlDsa87);
}

// CR-44, OP-159 m.3 (r), m.9 (h)
#[test]
fn a_fips_domain_cannot_admit_ml_dsa() {
    let mut s = Service::start(
        Pq,
        Generations::default(),
        Mem::default(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    let mut t = template();
    t.declared.crypto_profile = Some(access_kernel::verify::key_scope::CryptoProfile::Fips);
    assert_eq!(s.handle(Request::Open(Box::new(t)), 0), Response::Opened);
    assert_eq!(
        s.handle(allowlist(Algorithm::MlDsa65, false), 0),
        Response::Error(String::from("algorithm-profile-conflict"))
    );
}

// §15.16, RA-6, OP-159 m.3 (d), (f)
#[test]
fn retiring_the_classical_algorithm_needs_a_re_anchor_and_an_ml_dsa_binding() {
    let mut s = Service::start(
        Pq,
        Generations::default(),
        Mem::default(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    assert_eq!(
        s.handle(Request::Open(Box::new(template())), 0),
        Response::Opened
    );
    assert_eq!(
        s.handle(allowlist(Algorithm::Ed25519, true), 0),
        Response::Error(String::from("reanchor-required"))
    );
    assert_eq!(
        s.handle(allowlist(Algorithm::MlDsa65, false), 0),
        Response::Opened
    );
    assert_eq!(
        s.handle(allowlist(Algorithm::MlDsa65, true), 0),
        Response::Error(String::from("algorithm-profile-conflict"))
    );
    let mut declared = crate::domain::declared_default();
    declared.pq_reanchor = Some(access_kernel::verify::key_scope::PqReanchor::new(
        3,
        0,
        vec![String::from("w")],
    ));
    assert_eq!(
        s.handle(
            Request::Declare {
                domain: Digest([7; 32]),
                declared: Box::new(declared),
            },
            0
        ),
        Response::Opened
    );
    assert_eq!(
        s.handle(allowlist(Algorithm::Ed25519, true), 0),
        Response::Error(String::from("pq-key-unavailable"))
    );
    let Response::Signed { pq: Some(_), .. } = s.handle(sign(0), 0) else {
        panic!("the classical algorithm still signs");
    };
}

// CR-45 RA-2, OP-159 m.3 (g)
#[test]
fn a_pq_re_anchor_checkpoint_is_a_cose_sign1_over_the_note_body() {
    use access_kernel::codec::Canonical as _;
    use access_kernel::verify::key_scope::{EXCERPT_CONTENT_TYPE, KeyExcerpt};
    use suiss_crypto::aws::AwsLcBackend;
    let mut s = Service::start(
        Pq,
        Generations::default(),
        Mem::default(),
        Policy::AUTHORITY,
        0,
    )
    .unwrap();
    assert_eq!(
        s.handle(Request::Open(Box::new(template())), 0),
        Response::Opened
    );
    let body = suiss_crypto::note::Checkpoint {
        origin: crate::domain::origin(&Digest([7; 32])),
        size: 3,
        root: [5; 32],
        extensions: vec![String::from("issued_at 0")],
    }
    .to_body()
    .unwrap();
    let request = Request::SignPqCheckpoint {
        domain: Digest([7; 32]),
        body: body.clone(),
        at: 0,
    };
    assert_eq!(
        s.handle(request.clone(), 0),
        Response::Error(String::from("pq-key-unavailable"))
    );
    assert_eq!(
        s.handle(allowlist(Algorithm::MlDsa65, false), 0),
        Response::Opened
    );
    let Response::Signed { sign1, excerpt, .. } = s.handle(request, 0) else {
        panic!("signed");
    };
    let (_, trusted) = pq_metadata(&mut s);
    let e = verify_sign1(&AwsLcBackend, &excerpt, &trusted, EXCERPT_CONTENT_TYPE).unwrap();
    let KeyExcerpt { key, .. } = KeyExcerpt::from_bytes(&e.payload).unwrap();
    assert_eq!(key.alg, Algorithm::MlDsa65);
    let v = access_kernel::verify::cose::verify_sign1(
        &AwsLcBackend,
        &sign1,
        &key.key_set(),
        access_kernel::verify::reanchor::CHECKPOINT_CONTENT_TYPE,
    )
    .unwrap();
    assert_eq!(v.payload, body.as_bytes());
    assert_eq!(
        s.handle(
            Request::SignPqCheckpoint {
                domain: Digest([7; 32]),
                body: String::from("not a checkpoint"),
                at: 0,
            },
            0
        ),
        Response::Error(String::from("signer-note"))
    );
}
