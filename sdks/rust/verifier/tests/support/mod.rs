//! Fixtures: a domain with PAP and status-list keys, a PAP for a door-style refund action, a
//! verifier profile, a witness checkpoint and an offline verifier over the emulator.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test fixtures shared by several test binaries"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::algebra::Catalog;
use access_kernel::claim::body::{VerifierId, VerifierProfile};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue, intent_digest};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Binding, Bound, Consumption, Id, Independence, ProofKind,
    RequirementTerm, ResourceRef, ResourceSelector, Structural, TrustedTime, Window,
};
use access_kernel::pap::{
    CONTENT_TYPE, Holder, PRESENTATION_CONTENT_TYPE, Pap, Presentation, holder_digest, pap_digest,
};
use access_kernel::schema::{ActionSchema, EffectClass};
use access_kernel::status::{CWT_CONTENT_TYPE, ListToken, StatusRef};
use access_kernel::validity::{OfflineSlice, ProfileVariant, Revalidation, ValidityContract};
use access_kernel::verify::cose::{Algorithm, PublicKey, to_be_signed};
use access_kernel::verify::key_scope::{
    BindingKey, BindingScope, DomainMetadata, EXCERPT_CONTENT_TYPE, KeyExcerpt, KeyUsage,
    OperationalKey, SpecVersions, thumbprint,
};
use access_verifier::caps::SECURE_CLOCK_CLASS;
use access_verifier::metadata::MetadataView;
use access_verifier::offline::{Identity, OfflineVerifier, Use};
use access_verifier::profile::LocalProfile;
use access_verifier::testing::{EmulatedClock, EmulatedCounter};
use access_verifier::time::{ClockGuard, DEFAULT_TOLERANCE_MS};
use ed25519_dalek::Signer as _;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::note::{self, Verifier};

pub(crate) const HOUR: u64 = 3_600_000;
pub(crate) const IAT: u64 = 10 * HOUR + HOUR / 2;
pub(crate) const NOW: u64 = 12 * HOUR;
pub(crate) const VERIFIER: &str = "verifier.example";
pub(crate) const LIST_URI: &str = "https://access.example/status/1";
pub(crate) const LOG: &str = "access.example/log";
pub(crate) const WITNESS: &str = "witness.example/w1";

pub(crate) fn d(n: u8) -> Digest {
    Digest([n; 32])
}

pub(crate) fn ed(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

pub(crate) fn ed_pub(seed: u8) -> PublicKey {
    PublicKey::Ed25519(ed(seed).verifying_key().to_bytes())
}

pub(crate) fn sign1(seed: u8, content_type: &str, payload: &[u8]) -> Vec<u8> {
    let kid = thumbprint(&ed_pub(seed));
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::int(Algorithm::Ed25519.cose())),
            (Value::Unsigned(3), Value::text(content_type)),
            (Value::Unsigned(4), Value::Bytes(kid.to_vec())),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let sig = ed(seed)
        .sign(&to_be_signed(&prot, payload).unwrap())
        .to_bytes()
        .to_vec();
    let body = Value::Array(vec![
        Value::Bytes(prot),
        Value::Map(vec![]),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(sig),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

/// The PAP key (seed 2) signs from 10:00 to 11:00; the status-list key (seed 4) from 11:30
/// to 12:30.
pub(crate) fn op_key(usage: KeyUsage) -> OperationalKey {
    let (seed, from) = if usage == KeyUsage::StatusList {
        (4, 11 * HOUR + HOUR / 2)
    } else {
        (2, 10 * HOUR)
    };
    let key = ed_pub(seed);
    OperationalKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        valid_from: from,
        valid_until: from + HOUR,
        usage: BTreeSet::from([usage]),
    }
}

pub(crate) fn binding() -> BindingKey {
    let key = ed_pub(1);
    BindingKey {
        kid: thumbprint(&key),
        alg: Algorithm::Ed25519,
        key,
        scope: BindingScope::Domain,
        superseded: None,
    }
}

pub(crate) fn metadata() -> DomainMetadata {
    let b = binding();
    DomainMetadata {
        domain: d(1),
        genesis: d(9),
        issued_at: 10 * HOUR,
        binding: BTreeMap::from([(b.kid, b)]),
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_window_max_ms: HOUR,
        operational_keys: vec![op_key(KeyUsage::Pap), op_key(KeyUsage::StatusList)],
        min_versions: SpecVersions::default(),
        adopted: SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
    }
}

pub(crate) fn excerpt(usage: KeyUsage) -> Vec<u8> {
    let e = KeyExcerpt {
        domain: d(1),
        key: op_key(usage),
    };
    sign1(1, EXCERPT_CONTENT_TYPE, &e.to_bytes().unwrap())
}

pub(crate) fn action(namespace: &str, name: &str) -> ActionRef {
    ActionRef {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        major: 1,
        schema: d(9),
    }
}

pub(crate) fn catalog() -> Catalog {
    Catalog {
        catalogs: BTreeMap::from([(d(20), BTreeSet::from([action("pay", "refund")]))]),
        ..Catalog::default()
    }
}

pub(crate) fn bounds() -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::new(),
            prefix: BTreeSet::from([("pay".to_owned(), d(20))]),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: "shop".to_owned(),
            prefix: vec!["orders".to_owned()],
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::from([(
            "amount".to_owned(),
            Bound::Range {
                min: None,
                max: Some(100),
                unit: "eur".to_owned(),
            },
        )]),
        recipient: None,
        purpose: None,
    }
}

pub(crate) fn term(class: &str) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Authentication,
        class: class.to_owned(),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: Some(300_000),
        independence: Independence::None,
        consumption: Consumption::SingleUse,
        source: None,
        assurance: BTreeMap::new(),
    }
}

pub(crate) fn holder() -> Holder {
    Holder {
        instance: Id([6; 16]),
        key: ed_pub(3),
    }
}

pub(crate) fn profile_body() -> VerifierProfile {
    VerifierProfile {
        verifier: VerifierId::Workload(VERIFIER.to_owned()),
        profiles: BTreeMap::from([
            (ProfileVariant::CheckpointedOffline, BTreeMap::new()),
            (ProfileVariant::BoundedStaleness, BTreeMap::new()),
            (ProfileVariant::RevalidateOnReconnect, BTreeMap::new()),
            (ProfileVariant::OnlineStrict, BTreeMap::new()),
            (
                ProfileVariant::CheckpointContinuation,
                BTreeMap::from([("checkpoint_ms".to_owned(), HOUR)]),
            ),
        ]),
        versions: SpecVersions::default(),
        clock_source: SECURE_CLOCK_CLASS.to_owned(),
        clock_skew_ms: 60_000,
        tamper_evident_counter: true,
        offline_report: true,
        content_position_check: true,
        status_access: BTreeSet::from([LIST_URI.to_owned()]),
        refresh_interval_ms: Some(5 * 60_000),
        attestation: Some(d(30)),
        cap_horizon: BTreeMap::new(),
        slice_max: BTreeMap::new(),
        conformance: BTreeSet::from(["offline-verifier".to_owned()]),
    }
}

pub(crate) fn profile() -> LocalProfile {
    LocalProfile::new(profile_body()).unwrap()
}

pub(crate) fn contract() -> ValidityContract {
    ValidityContract {
        issuing_exercise: d(3),
        basis_ref: dcbor::encode(
            &Value::Array(vec![d(1).to_value(), Value::Unsigned(41)]),
            Limits::CEILING,
        )
        .unwrap(),
        holder: holder_digest(&holder()).unwrap(),
        audience: BTreeSet::from([VERIFIER.to_owned()]),
        bounds: bounds(),
        class: ProfileVariant::CheckpointedOffline.class(),
        variant: ProfileVariant::CheckpointedOffline,
        profile_version: 1,
        params: BTreeMap::new(),
        horizon: 14 * HOUR,
        max_staleness_ms: None,
        freshness_sources: BTreeSet::new(),
        revalidation: Revalidation::default(),
        offline_slice: BTreeSet::from([
            OfflineSlice {
                budget_term: d(5),
                amount: 100,
                unit: "eur".to_owned(),
            },
            OfflineSlice {
                budget_term: d(6),
                amount: 3,
                unit: "count".to_owned(),
            },
        ]),
        local_requirements: BTreeSet::from([term("phishing_resistant")]),
        verifier_profile_ref: *profile().digest(),
        clock_source: SECURE_CLOCK_CLASS.to_owned(),
        clock_skew_ms: 60_000,
        must_understand: BTreeSet::new(),
        status: Some(StatusRef {
            idx: 9,
            uri: LIST_URI.to_owned(),
        }),
    }
}

pub(crate) fn pap_with(change: impl FnOnce(&mut Pap)) -> Pap {
    let mut p = Pap {
        domain: d(1),
        projection_exercise: d(3),
        holder: holder(),
        capacity: Capacity::Own,
        bounds: bounds(),
        local_requirements: BTreeSet::new(),
        validity: contract(),
        lineage_commitment: d(4),
        iat: IAT,
    };
    change(&mut p);
    p
}

pub(crate) fn signed(p: &Pap) -> Vec<u8> {
    sign1(2, CONTENT_TYPE, &p.to_bytes().unwrap())
}

pub(crate) fn intent(amount: i64, unit: &str) -> IntentEnvelope {
    IntentEnvelope {
        action: action("pay", "refund"),
        resources: vec![ResourceRef {
            namespace: "shop".to_owned(),
            path: vec!["orders".to_owned(), "o1".to_owned()],
            incarnation: 0,
        }],
        params: BTreeMap::from([(
            "amount".to_owned(),
            ParamValue::Amount {
                value: amount,
                unit: unit.to_owned(),
            },
        )]),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 11 * HOUR,
            until: 13 * HOUR,
        },
    }
}

pub(crate) fn present(
    pap: &[u8],
    intent: &IntentEnvelope,
    nonce: &[u8],
    iat: TrustedTime,
) -> Vec<u8> {
    let p = Presentation {
        pap: pap_digest(pap),
        intent: intent_digest(intent).unwrap(),
        audience: VERIFIER.to_owned(),
        nonce: nonce.to_vec(),
        iat,
    };
    sign1(3, PRESENTATION_CONTENT_TYPE, &p.to_bytes().unwrap())
}

/// An Action Schema for `pay/refund` with this effect class.
pub(crate) fn schema(effect: EffectClass, reserved: bool) -> ActionSchema {
    ActionSchema {
        name: "refund".to_owned(),
        major: 1,
        effect,
        reserved,
        consumption_bearing: true,
        params: BTreeMap::new(),
        resource_types: BTreeSet::new(),
        render: None,
    }
}

pub(crate) fn zlib(bits: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(bits, 6)
}

pub(crate) fn list(set: &[u64], iat_ms: u64) -> Vec<u8> {
    let mut bits = vec![0_u8; 4];
    for i in set {
        *bits.get_mut(usize::try_from(i / 8).unwrap()).unwrap() |= 1 << (i % 8);
    }
    let token = ListToken {
        uri: LIST_URI.to_owned(),
        iat: iat_ms / 1_000,
        exp: None,
        ttl: Some(300),
        lst: zlib(&bits),
        aggregation_uri: None,
        as_of: 41,
    };
    sign1(4, CWT_CONTENT_TYPE, &token.to_bytes().unwrap())
}

pub(crate) fn log_key() -> ed25519_dalek::SigningKey {
    ed(40)
}

pub(crate) fn witness_key() -> ed25519_dalek::SigningKey {
    ed(41)
}

pub(crate) fn log_verifier() -> Verifier {
    Verifier::ed25519(LOG, log_key().verifying_key().to_bytes()).unwrap()
}

pub(crate) fn witness_verifier() -> Verifier {
    Verifier::cosigner(WITNESS, witness_key().verifying_key().to_bytes()).unwrap()
}

/// The signed bytes the test metadata stands for; checkpoints name their digest (L2-CKP-5).
pub(crate) const SIGNED_METADATA: &[u8] = b"signed domain metadata";

/// A checkpoint of the domain log signed by the log and, at `cosigned_s` seconds, the witness.
pub(crate) fn checkpoint(cosigned_s: Option<u64>) -> String {
    checkpoint_of(SIGNED_METADATA, cosigned_s)
}

/// A checkpoint naming the metadata `signed`, cosigned at `cosigned_s` seconds.
pub(crate) fn checkpoint_of(signed: &[u8], cosigned_s: Option<u64>) -> String {
    let body = format!(
        "{LOG}\n7\n{}\nmetadata sha-256:{}\n",
        note::base64_encode(&[7; 32]),
        access_kernel::json::b64url_encode(&access_verifier::metadata::metadata_digest(signed)),
    );
    let log = log_verifier();
    let mut sig = log.id().to_be_bytes().to_vec();
    sig.extend(log_key().sign(body.as_bytes()).to_bytes());
    let mut out = format!("{body}\n\u{2014} {LOG} {}\n", note::base64_encode(&sig));
    if let Some(ts) = cosigned_s {
        let w = witness_verifier();
        let mut sig = w.id().to_be_bytes().to_vec();
        sig.extend(ts.to_be_bytes());
        sig.extend(
            witness_key()
                .sign(&note::cosigned_message(ts, &body))
                .to_bytes(),
        );
        out = format!("{out}\u{2014} {WITNESS} {}\n", note::base64_encode(&sig));
    }
    out
}

pub(crate) type Device = OfflineVerifier<EmulatedClock, EmulatedCounter>;

pub(crate) fn identity() -> Identity {
    Identity {
        audience: VERIFIER.to_owned(),
        instance: Some(Id([8; 16])),
        domain: d(1),
        profile: profile(),
        catalog: catalog(),
        understood: BTreeSet::new(),
    }
}

/// A verifier at `NOW` with fresh metadata, the status list installed and the PAP's slices
/// provisioned on fresh counters.
pub(crate) fn device(pap: &Pap) -> Device {
    device_with(metadata(), pap)
}

pub(crate) fn device_with(metadata: DomainMetadata, pap: &Pap) -> Device {
    let mut view = MetadataView::new(metadata, SIGNED_METADATA);
    view.witness(
        &checkpoint(Some(NOW / 1_000 - 60)),
        LOG,
        &log_verifier(),
        &[witness_verifier()],
    )
    .unwrap();
    let list = access_verifier::status::StatusList::verify(
        view.metadata(),
        &self::list(&[], NOW - 60_000),
        &excerpt(KeyUsage::StatusList),
    )
    .unwrap();
    let mut v = OfflineVerifier::new(
        identity(),
        view,
        EmulatedClock::new(NOW),
        ClockGuard::new(DEFAULT_TOLERANCE_MS),
    );
    v.install_list(list);
    for (i, s) in pap.validity.offline_slice.iter().enumerate() {
        let id = access_verifier::counter::CounterId([u8::try_from(i).unwrap() + 1; 16]);
        v.provision(
            pap.projection_exercise,
            s.budget_term,
            s.amount,
            EmulatedCounter::new(id),
        )
        .unwrap();
    }
    v
}

/// The inputs of one use, owned.
pub(crate) struct Inputs {
    pub(crate) pap: Vec<u8>,
    pub(crate) excerpt: Vec<u8>,
    pub(crate) presentation: Vec<u8>,
    pub(crate) intent: IntentEnvelope,
    pub(crate) nonce: Vec<u8>,
    pub(crate) satisfied: BTreeSet<RequirementTerm>,
    pub(crate) content_position: Option<u64>,
    pub(crate) schema: Option<ActionSchema>,
}

impl Inputs {
    pub(crate) fn new(pap: &Pap, intent: IntentEnvelope, now: TrustedTime) -> Self {
        let signed = signed(pap);
        let nonce = vec![7; 16];
        Self {
            presentation: present(&signed, &intent, &nonce, now),
            pap: signed,
            excerpt: excerpt(KeyUsage::Pap),
            intent,
            nonce,
            satisfied: BTreeSet::from([term("phishing_resistant")]),
            content_position: None,
            schema: None,
        }
    }

    pub(crate) fn use_(&self) -> Use<'_> {
        Use {
            pap: &self.pap,
            excerpt: &self.excerpt,
            presentation: &self.presentation,
            intent: &self.intent,
            nonce: &self.nonce,
            satisfied: &self.satisfied,
            schema: self.schema.as_ref(),
            content_position: self.content_position,
        }
    }
}
