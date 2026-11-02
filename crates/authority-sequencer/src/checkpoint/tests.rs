//! Checkpoints over an in-memory head and an in-process signer service.

#![allow(
    clippy::unused_async_trait_impl,
    clippy::arithmetic_side_effects,
    reason = "the in-memory ports implement async traits without awaiting; test code"
)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use access_authority_signer::app::Noted;
use access_authority_signer::domain::default_template;
use access_authority_signer::ports::{Bindings, Generated, KeyFactory, Vault, VaultError};
use access_authority_signer::protocol::{Request, Response};
use access_authority_signer::service::Service;
use access_kernel::verify::key_scope::{thumbprint, verify_metadata};
use access_store::authority::HeadRow;
use suiss_crypto::cose::{Algorithm, KeySet};
use suiss_crypto::digest::{leaf_hash, root};
use suiss_crypto::rotation::Policy;
use suiss_crypto::secret::Secret;
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::{SignError, Signer, SoftSigner};
use suiss_ledger::merkle::Frontier;

use super::*;

const DOMAIN: Digest = Digest([7; 32]);
const LEAVES: [&[u8]; 3] = [b"genesis", b"one", b"two"];

struct Soft;

impl KeyFactory for Soft {
    fn generate(&mut self, _: Algorithm) -> Result<Generated, SignError> {
        let (signer, doc) = SoftSigner::generate_ed25519()?;
        Ok(Generated {
            signer: Box::new(signer),
            sealed: doc.expose().clone(),
        })
    }

    fn load(&mut self, _: Algorithm, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError> {
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

#[derive(Default)]
struct Mem(BTreeMap<Digest, Vec<u8>>);

impl Vault for Mem {
    fn all(&mut self) -> Result<Vec<Vec<u8>>, VaultError> {
        Ok(self.0.values().cloned().collect())
    }

    fn put(&mut self, domain: &Digest, bytes: &[u8]) -> Result<(), VaultError> {
        self.0.insert(*domain, bytes.to_vec());
        Ok(())
    }
}

/// The signer service in process; `down` makes it unreachable.
#[derive(Clone)]
struct InProcess {
    service: Arc<Mutex<Service<Soft, Binding, Mem>>>,
    down: bool,
    calls: Arc<Mutex<u32>>,
}

impl NoteSigner for InProcess {
    async fn sign_note(&self, domain: Digest, body: String, at: u64) -> Result<Noted, String> {
        *self.calls.lock().unwrap() += 1;
        if self.down {
            return Err(String::from("signer-unreachable"));
        }
        match self
            .service
            .lock()
            .unwrap()
            .handle(Request::SignNote { domain, body, at }, at)
        {
            Response::Noted { line, excerpt } => Ok(Noted { line, excerpt }),
            Response::Error(code) => Err(code),
            _ => Err(String::from("signer-frame")),
        }
    }
}

/// A committed head over [`LEAVES`], or a store that fails.
struct Committed(Option<HeadRow>);

impl Heads for Committed {
    async fn committed(&self, _: &Digest) -> Result<HeadRow, SequencerError> {
        self.0
            .clone()
            .ok_or(SequencerError::Store(access_store::StoreError::Corrupt))
    }
}

fn committed() -> Committed {
    let mut f = Frontier::default();
    for l in LEAVES {
        f.push(leaf_hash(l)).unwrap();
    }
    Committed(Some(HeadRow {
        pos: 2,
        epoch: 1,
        leaf_hash: leaf_hash(LEAVES[2]),
        recorded_at: 1_000,
        frontier: f.nodes().to_vec(),
    }))
}

/// A signer whose domain has an active key at the returned time.
fn signer() -> (InProcess, KeySet, u64) {
    let (binding, doc) = SoftSigner::generate_ed25519().unwrap();
    let mut s = Service::start(Soft, Binding(doc), Mem::default(), Policy::AUTHORITY, 0).unwrap();
    s.handle(Request::Open(Box::new(default_template(DOMAIN))), 0);
    let mut now = 0;
    while now <= Policy::AUTHORITY.publish_lead_ms + 120_000 {
        s.tick(now, now);
        now += 60_000;
    }
    let mut trusted = KeySet::default();
    trusted
        .insert(thumbprint(&binding.public_key()), binding.public_key())
        .unwrap();
    trusted.allowed.insert(Algorithm::Ed25519);
    let signer = InProcess {
        service: Arc::new(Mutex::new(s)),
        down: false,
        calls: Arc::default(),
    };
    (signer, trusted, now)
}

fn metadata(signer: &InProcess, trusted: &KeySet, now: u64) -> DomainMetadata {
    let Response::Metadata(m) = signer
        .service
        .lock()
        .unwrap()
        .handle(Request::Metadata(DOMAIN), now)
    else {
        panic!("metadata");
    };
    verify_metadata(&PureBackend, &m, trusted).unwrap()
}

fn versions() -> SpecVersions {
    default_template(DOMAIN).adopted
}

// T20, §16.4.4 m.18, L2-CKP-1, L2-CKP-3: the operational key signs the committed head's size and
// RFC 9162 root; the note verifies against the published key and names the domain as origin
#[tokio::test]
async fn a_checkpoint_of_the_committed_head_verifies() {
    let (signer, trusted, now) = signer();
    let made = checkpoint(&committed(), &signer, DOMAIN, &versions(), now)
        .await
        .unwrap();
    let metadata = metadata(&signer, &trusted, now);
    let (cp, ext) = verify(&PureBackend, &made.note, &metadata, &made.excerpt, &DOMAIN).unwrap();
    assert_eq!((cp.size, cp.root), (3, root(&LEAVES)));
    assert_eq!(cp, made.checkpoint);
    assert_eq!(cp.origin, origin(&DOMAIN));
    assert_eq!(
        ext,
        Extensions {
            recorded_at: 1_000,
            versions: versions_digest(&versions()).unwrap(),
            issued_at: now,
        }
    );
    assert!(matches!(
        verify(
            &PureBackend,
            &made.note,
            &metadata,
            &made.excerpt,
            &Digest([9; 32]),
        ),
        Err(CheckpointError::Origin)
    ));
    let forged = made.note.replacen("\n3\n", "\n4\n", 1);
    assert!(matches!(
        verify(&PureBackend, &forged, &metadata, &made.excerpt, &DOMAIN),
        Err(CheckpointError::Note(_))
    ));
}

// CR-23, G42: an unreachable signer, or one without a key that may sign, delays the checkpoint;
// no unsigned checkpoint is emitted
#[tokio::test]
async fn no_signature_no_checkpoint() {
    let (mut signer, _, now) = signer();
    signer.down = true;
    assert!(matches!(
        checkpoint(&committed(), &signer, DOMAIN, &versions(), now).await,
        Err(CheckpointError::Unsigned(code)) if code == "signer-unreachable"
    ));
    signer.down = false;
    assert!(matches!(
        checkpoint(&committed(), &signer, DOMAIN, &versions(), 0).await,
        Err(CheckpointError::Unsigned(code)) if code == "signer-no-key"
    ));
}

// CMP-6: without a committed head nothing is sent to the signer
#[tokio::test]
async fn only_a_committed_head_is_checkpointed() {
    let (signer, _, now) = signer();
    assert!(matches!(
        checkpoint(&Committed(None), &signer, DOMAIN, &versions(), now).await,
        Err(CheckpointError::Store(_))
    ));
    assert_eq!(*signer.calls.lock().unwrap(), 0);
}

// §16.4.4 m.18: the Access lines are exactly recorded_at, versions and issued_at
#[test]
fn extension_lines_are_strict() {
    let mut cp = Checkpoint {
        origin: origin(&DOMAIN),
        size: 1,
        root: [0; 32],
        extensions: vec![],
    };
    assert!(extensions(&cp).is_err());
    let v = format!(
        "versions sha-256:{}",
        access_kernel::json::b64url_encode(&[1; 32])
    );
    cp.extensions = vec![
        String::from("recorded_at 01"),
        v.clone(),
        String::from("issued_at 2"),
    ];
    assert!(extensions(&cp).is_err());
    cp.extensions = vec![
        String::from("recorded_at 1"),
        v,
        String::from("issued_at 2"),
    ];
    assert_eq!(extensions(&cp).unwrap().versions, Digest([1; 32]));
}
