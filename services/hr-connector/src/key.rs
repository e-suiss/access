//! The connector Instance's key (OP-156 m.3 (q), TN-110): it signs each write's Actor Intent
//! Statement and the DPoP proofs of the read token that drafts it. It is the connector's own
//! key; no system key writes (MD-14).

use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_kernel::meta::ExerciseBasis;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};

use crate::ports::{Clock, Sign};

/// The Instance key, the basis its writes are made under and the time they are signed at.
pub struct InstanceKey<C> {
    /// The key.
    pub signer: SoftSigner,
    /// Its public key.
    pub public: PublicKey,
    /// The basis the operator gave it, e.g. the realm's identity-plane Anchor.
    pub basis: ExerciseBasis,
    /// Time.
    pub clock: C,
}

impl<C: Clock> InstanceKey<C> {
    /// The key `signer` under `basis`.
    pub fn new(signer: SoftSigner, basis: ExerciseBasis, clock: C) -> Self {
        let public = signer.public_key();
        Self {
            signer,
            public,
            basis,
            clock,
        }
    }
}

impl<C: Clock> Sign for InstanceKey<C> {
    fn ais(
        &self,
        domain: [u8; 32],
        nonce: &[u8; 16],
        intent: [u8; 32],
        pep: &str,
    ) -> Option<String> {
        let s = Statement {
            domain: Digest(domain),
            nonce: nonce.to_vec(),
            intent: Digest(intent),
            mode: Mode::Commit,
            pep: String::from(pep),
            capacity: Capacity::Own,
            basis: self.basis,
            iat: self.clock.now()?,
            exercise: None,
        };
        let payload = dcbor::encode(&s.to_value(), Limits::CEILING).ok()?;
        let kid = thumbprint(&self.public);
        let signed = sign_sign1(&self.signer as &dyn Signer, kid, CONTENT_TYPE, &payload).ok()?;
        Some(b64url_encode(&signed))
    }
}

impl<C: Clock> access_sdk::auth::dpop::ProofKey for InstanceKey<C> {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, input: &[u8]) -> Option<Vec<u8>> {
        self.signer.sign(input).ok()
    }
}
