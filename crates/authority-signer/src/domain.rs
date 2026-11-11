//! The authority fields Domain Metadata carries besides its operational keys, and the
//! declaration of one operational key (CR-18, CR-58).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::{
    BindingKey, BindingScope, DomainMetadata, Hybrid, KeyUsage, OperationalKey, SpecVersions,
    VerifierCaps, thumbprint,
};
use suiss_crypto::cose::{Algorithm, PublicKey};
use suiss_crypto::rotation::Key;

/// Every usage an operational key signs by default (CR-58 m.2, OP-143 m.3).
pub const USAGES: [KeyUsage; 8] = [
    KeyUsage::Receipt,
    KeyUsage::Pap,
    KeyUsage::Token,
    KeyUsage::Checkpoint,
    KeyUsage::Set,
    KeyUsage::StatusList,
    KeyUsage::KeyLookup,
    KeyUsage::PartyLookup,
];

/// The fixed part of a domain's metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    /// Domain.
    pub domain: Digest,
    /// Genesis record digest.
    pub genesis: Digest,
    /// Algorithm allowlist.
    pub algorithms: BTreeSet<Algorithm>,
    /// Algorithm of new operational keys: Ed25519, or ESP256 under the FIPS profile (CR-2).
    pub operational_alg: Algorithm,
    /// Window ceiling of operational keys.
    pub operational_window_max_ms: u64,
    /// Minimum versions.
    pub min_versions: SpecVersions,
    /// Adopted versions.
    pub adopted: SpecVersions,
    /// Verifier ceilings.
    pub caps: Option<VerifierCaps>,
    /// Hybrid policy.
    pub hybrid: Option<Hybrid>,
    /// Discovery fields, opaque to the Kernel.
    pub discovery: Option<Vec<u8>>,
    /// The Stage 13 declarations the metadata publishes: the domain's witnesses and its MMD
    /// (OP-158 m.3 (b), (d), m.6 (e)).
    pub declared: access_kernel::verify::key_scope::Declarations,
}

/// The binding key a domain's metadata names (T20).
#[must_use]
pub fn binding(alg: Algorithm, key: PublicKey) -> BindingKey {
    BindingKey {
        kid: thumbprint(&key),
        alg,
        key,
        scope: BindingScope::Domain,
        superseded: None,
    }
}

/// The declaration of an operational key from its rotation record (T20, CR-24).
#[must_use]
pub fn declaration(record: &Key, alg: Algorithm, key: PublicKey) -> OperationalKey {
    OperationalKey {
        kid: record.kid,
        alg,
        key,
        valid_from: record.valid_from,
        valid_until: record.valid_until,
        usage: USAGES.into_iter().collect(),
    }
}

/// The metadata for `operational_keys`, issued at `issued_at`.
#[must_use]
pub fn metadata(
    template: &Template,
    binding: &BindingKey,
    operational_keys: Vec<OperationalKey>,
    issued_at: u64,
) -> DomainMetadata {
    DomainMetadata {
        domain: template.domain,
        genesis: template.genesis,
        issued_at,
        binding: BTreeMap::from([(binding.kid, binding.clone())]),
        algorithms: template.algorithms.clone(),
        operational_window_max_ms: template.operational_window_max_ms,
        operational_keys,
        min_versions: template.min_versions.clone(),
        adopted: template.adopted.clone(),
        caps: template.caps.clone(),
        hybrid: template.hybrid,
        discovery: template.discovery.clone(),
        declared: template.declared.clone(),
    }
}

/// The origin of a domain's log checkpoints: its `DomainID` in text form (§16.4.4 m.18,
/// L0-ENC-20).
#[must_use]
pub fn origin(domain: &Digest) -> String {
    format!("sha-256:{}", access_kernel::json::b64url_encode(&domain.0))
}

/// The template a decision point opens a domain's keyring with: Ed25519 operational keys, a
/// 24-hour window ceiling and version 1 of the core and meta-schema (OP-143 m.5, PD).
#[must_use]
pub fn default_template(domain: Digest) -> Template {
    let v1 = SpecVersions {
        core: 1,
        meta_schema: 1,
        ..SpecVersions::default()
    };
    Template {
        domain,
        genesis: domain,
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_alg: Algorithm::Ed25519,
        operational_window_max_ms: access_kernel::verify::key_scope::MAX_WINDOW_MS,
        min_versions: v1.clone(),
        adopted: v1,
        caps: None,
        hybrid: None,
        discovery: None,
        declared: declared_default(),
    }
}

/// What a new domain declares (§17.6.3, T16, OP-38, OP-158 m.3 (c)): the authority checkpoint
/// interval as its MMD, the identity audit's 1 s; no witnesses until the root names them.
#[must_use]
pub fn declared_default() -> access_kernel::verify::key_scope::Declarations {
    let mut d = access_kernel::verify::key_scope::Declarations::default();
    // T16, OP-38
    d.mmd = Some(access_kernel::verify::key_scope::Mmd::new(60_000, 1_000));
    d
}
