#![allow(
    clippy::unwrap_used,
    clippy::unused_async_trait_impl,
    reason = "test code"
)]

use std::collections::BTreeSet;
use std::sync::Mutex;

use suiss_crypto::cose::PublicKey;
use suiss_crypto::signer::{Signer, SoftSigner};

use super::*;
use crate::domain::cert::Extension;
use crate::domain::key::Ed25519Public;
use crate::domain::projection::Holder;

struct Ring {
    keys: Mutex<Vec<SoftSigner>>,
    rotate_once: Mutex<bool>,
}

fn public(s: &SoftSigner) -> Ed25519Public {
    match s.public_key() {
        PublicKey::Ed25519(k) => Ed25519Public(k),
        _ => Ed25519Public([0; 32]),
    }
}

impl CaKey for Ring {
    async fn active(&self, _: [u8; 16]) -> Result<Option<Ed25519Public>, Unavailable> {
        Ok(self.keys.lock().unwrap().last().map(public))
    }

    async fn sign(
        &self,
        _: [u8; 16],
        key: Ed25519Public,
        data: Vec<u8>,
    ) -> Result<[u8; 64], CaRefusal> {
        if std::mem::take(&mut *self.rotate_once.lock().unwrap()) {
            self.keys
                .lock()
                .unwrap()
                .push(SoftSigner::generate_ed25519().unwrap().0);
        }
        let keys = self.keys.lock().unwrap();
        let signer = keys.last().ok_or(CaRefusal::Off)?;
        if public(signer) != key {
            return Err(CaRefusal::Changed);
        }
        <[u8; 64]>::try_from(signer.sign(&data).unwrap().as_slice())
            .map_err(|_| CaRefusal::Unavailable)
    }
}

struct Os;

impl Random for Os {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        aws_lc_rs::rand::fill(out).map_err(|_| Unavailable)
    }
}

struct Zero;

impl Random for Zero {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        out.fill(0);
        Ok(())
    }
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

fn projection() -> Projection {
    Projection {
        key_id: String::from("prj"),
        serial: 0,
        holder: Holder::Person,
        public_key: Ed25519Public([12; 32]),
        principals: BTreeSet::from([String::from("ayse")]),
        host_group: String::from("prod-web"),
        valid_after: 1_767_225_000,
        valid_before: 1_767_253_800,
        force_command: None,
        source_address: BTreeSet::new(),
        extensions: BTreeSet::from([Extension::Pty]),
    }
}

// OP-156 m.3 (o)
#[test]
fn a_certificate_is_signed_by_the_key_that_signs_now() {
    let ring = Ring {
        keys: Mutex::new(vec![SoftSigner::generate_ed25519().unwrap().0]),
        rotate_once: Mutex::new(true),
    };
    let issued = block_on(certify(&ring, &Os, [1; 16], &projection())).unwrap();
    let newest = public(ring.keys.lock().unwrap().last().unwrap());
    assert_eq!(issued.fields.ca, newest);
    assert_ne!(issued.fields.serial, 0);
    let (back, _, _) = issued.certificate.parse().unwrap();
    assert_eq!(back, issued.fields);
    let off = Ring {
        keys: Mutex::new(Vec::new()),
        rotate_once: Mutex::new(false),
    };
    assert_eq!(
        block_on(certify(&off, &Os, [1; 16], &projection())),
        Err(IssueError::Off)
    );
    assert_eq!(draw(&Zero), Err(Unavailable));
}
