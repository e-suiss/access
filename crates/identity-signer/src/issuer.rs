//! A realm's identity Claim issuer key (§10.1.7, OP-144 carry-over, OP-150 L2): one Ed25519 key
//! per realm, apart from the realm's JOSE key set so that token rotation never touches it,
//! bound to the realm's issuer Party when it is made. It signs only `COSE_Sign1` Claims of the
//! identity issuer's classes about that Party's statements, and the two self-signed Exercises
//! that open the Party and its Instance in a governing domain (OP-149 m.16 (a)); never a token,
//! an AIS of anything else, or a regime Claim.

use access_crypto::jose::JwsAlg;
use access_internal_api::instances::{bootstrap_basis, self_signed_intent};
use access_kernel::ais;
use access_kernel::claim::{self, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::digest::Digest;
use access_kernel::intent::intent_digest;
use access_kernel::meta::{ActorKind, Payload, Root};
use access_kernel::model::{Id, Window};
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::signer::{Signer, sign_sign1};

use crate::SignerError;
use crate::ports::KeyFactory;

/// The key's purpose, its label in the vault and in the protocol.
pub const LABEL: &str = "claim-issuer";

/// The classes the identity issuer signs (§10.1.2, §10.1.5): authentication results, authenticator
/// and identity bindings, account status, device posture and the result of a recovery (OP-153
/// m.3 (c)), and the agent record's export: operator, sponsor and kind (OP-154 m.3 (c), AG-20).
/// Regime classes are never its own.
pub const CLASSES: [&str; 9] = [
    "authentication",
    "authenticator_binding",
    "account_status",
    "posture_device",
    "identity_binding_person",
    "recovery_result",
    "operated_by",
    "sponsored_by",
    "agent_kind",
];

/// The prefix of the identity plane's risk signal classes (§7.6 TN-O4, TN-63): signals, never
/// gates.
pub const RISK_PREFIX: &str = "risk_";

/// Whether the identity issuer may sign a Claim of `class`.
#[must_use]
pub fn issues(class: &str) -> bool {
    CLASSES.contains(&class)
        || class
            .strip_prefix(RISK_PREFIX)
            .is_some_and(|r| !r.is_empty())
}

/// Why the issuer key cannot be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IssuerError {
    /// The stored key belongs to another realm or another Party.
    #[error("vault holds another issuer's key")]
    OtherIssuer,
    /// The stored key cannot be read or loaded.
    #[error("stored key unusable")]
    Stored,
    /// No key could be created.
    #[error("no key")]
    Generate,
}

impl IssuerError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::OtherIssuer => "signer-issuer-party",
            Self::Stored => "signer-issuer-stored",
            Self::Generate => "signer-outage",
        }
    }
}

/// Which self-signed registration Exercise the key signs (OP-149 m.16 (a)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// `party_register` of the issuer Party, rooting itself, a system actor.
    Register,
    /// `instance_create` of the Instance this key is.
    Create,
}

impl Step {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Create => "create",
        }
    }

    /// The step of a wire name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Register, Self::Create]
            .into_iter()
            .find(|s| s.name() == name)
    }
}

/// One registration Exercise to sign: everything but the payload and intent, which the key
/// forms itself from its own Party and key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// The governing domain.
    pub domain: [u8; 32],
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The intent's validity.
    pub validity: (u64, u64),
    /// Signing time.
    pub iat: u64,
    /// The identity plane as PEP.
    pub pep: String,
    /// Which Exercise.
    pub step: Step,
}

/// A realm's Claim issuer key.
pub struct IssuerKey {
    realm: [u8; 16],
    party: [u8; 16],
    signer: Box<dyn Signer + Send>,
    key: [u8; 32],
    sealed: Vec<u8>,
}

fn ed25519(key: &PublicKey) -> Option<[u8; 32]> {
    match key {
        PublicKey::Ed25519(k) => Some(*k),
        _ => None,
    }
}

impl IssuerKey {
    fn of(
        realm: [u8; 16],
        party: [u8; 16],
        signer: Box<dyn Signer + Send>,
        sealed: Vec<u8>,
    ) -> Result<Self, IssuerError> {
        let key = ed25519(&signer.public_key()).ok_or(IssuerError::Stored)?;
        Ok(Self {
            realm,
            party,
            signer,
            key,
            sealed,
        })
    }

    /// A new key of `realm`'s issuer Party `party`, sealed by the factory (MD-3: Ed25519).
    ///
    /// # Errors
    /// [`IssuerError::Generate`].
    pub fn generate(
        realm: [u8; 16],
        party: [u8; 16],
        factory: &mut dyn KeyFactory,
    ) -> Result<Self, IssuerError> {
        let generated = factory
            .generate(JwsAlg::Ed25519)
            .map_err(|_| IssuerError::Generate)?;
        Self::of(realm, party, generated.signer, generated.sealed)
    }

    /// The key of `realm` from its stored form; the stored public key must match the unsealed
    /// one and the stored realm must be `realm`.
    ///
    /// # Errors
    /// [`IssuerError`].
    pub fn restore(
        realm: [u8; 16],
        stored: &[u8],
        factory: &mut dyn KeyFactory,
    ) -> Result<Self, IssuerError> {
        let v = dcbor::decode(stored, Limits::CEILING).map_err(|_| IssuerError::Stored)?;
        let (
            Some(Value::Text(label)),
            Some(Value::Bytes(r)),
            Some(Value::Bytes(party)),
            Some(Value::Bytes(key)),
            Some(Value::Bytes(sealed)),
        ) = (
            v.get("label"),
            v.get("realm"),
            v.get("party"),
            v.get("key"),
            v.get("sealed"),
        )
        else {
            return Err(IssuerError::Stored);
        };
        if label != LABEL || r.as_slice() != realm.as_slice() {
            return Err(IssuerError::OtherIssuer);
        }
        let party = <[u8; 16]>::try_from(party.as_slice()).map_err(|_| IssuerError::Stored)?;
        let signer = factory
            .load(JwsAlg::Ed25519, sealed)
            .map_err(|_| IssuerError::Stored)?;
        if ed25519(&signer.public_key()).map(|k| k.to_vec()).as_ref() != Some(key) {
            return Err(IssuerError::Stored);
        }
        Self::of(realm, party, signer, sealed.clone())
    }

    /// The stored form: label, realm, Party, public key and sealed private material, never
    /// plaintext.
    #[must_use]
    pub fn stored(&self) -> Option<Vec<u8>> {
        let v = Value::Map(vec![
            (Value::text("label"), Value::text(LABEL)),
            (Value::text("realm"), Value::Bytes(self.realm.to_vec())),
            (Value::text("party"), Value::Bytes(self.party.to_vec())),
            (Value::text("key"), Value::Bytes(self.key.to_vec())),
            (Value::text("sealed"), Value::Bytes(self.sealed.clone())),
        ]);
        dcbor::encode(&v, Limits::CEILING).ok()
    }

    /// The issuer Party the key is bound to.
    #[must_use]
    pub const fn party(&self) -> [u8; 16] {
        self.party
    }

    /// The Ed25519 public key.
    #[must_use]
    pub const fn key(&self) -> [u8; 32] {
        self.key
    }

    /// The key's RFC 7638 `kid` (CR-24), the one its Instance is found by.
    #[must_use]
    pub fn kid(&self) -> [u8; 32] {
        thumbprint(&PublicKey::Ed25519(self.key))
    }

    /// Signs `payload`, a canonical `claim-statement` of an identity issuer class issued by this
    /// key's Party at `at`, as a `COSE_Sign1` Claim (L2-CLM-1).
    ///
    /// # Errors
    /// [`SignerError::Payload`] for anything else; [`SignerError::Sign`].
    pub fn sign_claim(&self, payload: &[u8], at: u64) -> Result<Vec<u8>, SignerError> {
        let s = Statement::from_bytes(payload).map_err(|_| SignerError::Payload)?;
        if s.to_bytes().ok().as_deref() != Some(payload)
            || s.issuer != Id(self.party)
            || s.issued_at != at
            || !issues(&s.class)
        {
            return Err(SignerError::Payload);
        }
        sign_sign1(
            self.signer.as_ref(),
            self.kid(),
            claim::CONTENT_TYPE,
            payload,
        )
        .map_err(|_| SignerError::Sign)
    }

    /// The AIS of one self-signed registration Exercise of this key's Party under the bootstrap
    /// basis of `r.domain` (L0-META-7, OP-149 m.16 (a)): the Party roots itself as a system
    /// actor, and the Instance created is this key.
    ///
    /// # Errors
    /// [`SignerError::Payload`] for a window that ends before it starts; [`SignerError::Sign`].
    pub fn sign_registration(&self, r: &Registration) -> Result<Vec<u8>, SignerError> {
        let (from, until) = r.validity;
        if from > until || r.nonce.is_empty() {
            return Err(SignerError::Payload);
        }
        let party = Id(self.party);
        let payload = match r.step {
            Step::Register => Payload::PartyRegister {
                party,
                root: Root::Sole(party),
                actor_kind: ActorKind::System,
            },
            Step::Create => Payload::InstanceCreate {
                party,
                key: PublicKey::Ed25519(self.key),
                mandate: None,
            },
        };
        let intent = self_signed_intent(&payload, party, Window { from, until })
            .ok_or(SignerError::Payload)?;
        let digest = intent_digest(&intent).map_err(|_| SignerError::Payload)?;
        let domain = Digest(r.domain);
        let statement = ais::Statement {
            domain,
            nonce: r.nonce.clone(),
            intent: digest,
            mode: Mode::Commit,
            pep: r.pep.clone(),
            capacity: Capacity::Own,
            basis: bootstrap_basis(&domain),
            iat: r.iat,
            exercise: None,
        };
        let bytes = statement.to_bytes().map_err(|_| SignerError::Payload)?;
        sign_sign1(self.signer.as_ref(), self.kid(), ais::CONTENT_TYPE, &bytes)
            .map_err(|_| SignerError::Sign)
    }
}

#[cfg(test)]
mod tests;
