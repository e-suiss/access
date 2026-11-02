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

// OP-143 m.4, CR-23: open, sign and fetch metadata; a restart from the vault signs on with the
// same keys; a signing time far from the signer's clock is refused
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
