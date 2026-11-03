//! A software authenticator on aws-lc-rs that produces real registration and assertion
//! responses (OP-146 m.4 (g)), plus a FIDO metadata blob signer.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::struct_excessive_bools,
    clippy::format_collect,
    clippy::needless_pass_by_value,
    reason = "test fixtures"
)]

use access_identity_webauthn::WebAuthnError;
use access_identity_webauthn::adapters::{MemoryRegistry, MemorySignals, RealmDecoyKeys};
use access_identity_webauthn::app::WebAuthn;
use access_identity_webauthn::domain::ids::RealmId;
use access_identity_webauthn::domain::rp::{Origin, RelyingParty, RpId};
use access_identity_webauthn::ports::{Clock, Random};
use access_kernel::json::b64url_encode;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256,
};
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair as RcKey,
    PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
};
use std::sync::atomic::{AtomicU64, Ordering};
use suiss_crypto::dcbor::{Limits, Value, encode};

pub const RP_ID: &str = "acme.example";
pub const ORIGIN: &str = "https://acme.example";
pub const REALM: RealmId = RealmId::from_bytes([7; 16]);
pub const NOW: u64 = 1_793_750_400;

pub fn rp() -> RelyingParty {
    RelyingParty {
        realm: REALM,
        rp_id: RpId::parse(RP_ID).unwrap(),
        name: "Acme".into(),
        pinned: true,
        related: vec![Origin::parse("https://acme-shop.example").unwrap()],
    }
}

pub struct FixedClock(pub AtomicU64);

impl FixedClock {
    pub fn at(t: u64) -> Self {
        Self(AtomicU64::new(t))
    }
    pub fn set(&self, t: u64) {
        self.0.store(t, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> Result<u64, WebAuthnError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

pub struct CountingRandom(AtomicU64);

impl Random for CountingRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), WebAuthnError> {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::try_from((n * 31 + i as u64) % 251).unwrap();
        }
        Ok(())
    }
}

pub type Service =
    WebAuthn<MemoryRegistry, FixedClock, CountingRandom, RealmDecoyKeys, MemorySignals>;

pub fn service() -> Service {
    use access_crypto::Secret;
    use access_crypto::webauthn::DecoyKey;
    WebAuthn {
        registry: MemoryRegistry::default(),
        clock: FixedClock::at(NOW),
        random: CountingRandom(AtomicU64::new(1)),
        decoys: RealmDecoyKeys::default().with(REALM, DecoyKey::new(Secret::new([9; 32]))),
        signals: MemorySignals::default(),
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    access_crypto::webauthn::sha256(data)
}

pub fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        b64url_encode(challenge)
    )
    .into_bytes()
}

pub enum Key {
    P256(EcdsaKeyPair, i64),
    Ed25519(Ed25519KeyPair, i64),
    Rsa(RsaKeyPair),
}

impl Key {
    pub fn es256() -> Self {
        Self::p256(-7)
    }
    pub fn p256(alg: i64) -> Self {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        Self::P256(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref()).unwrap(),
            alg,
        )
    }
    pub fn ed25519(alg: i64) -> Self {
        let rng = SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Self::Ed25519(Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap(), alg)
    }
    pub fn rsa() -> Self {
        Self::Rsa(RsaKeyPair::generate(KeySize::Rsa2048).unwrap())
    }

    pub fn cose(&self) -> Value {
        let map = |entries: Vec<(i64, Value)>| {
            Value::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| (Value::int(k), v))
                    .collect(),
            )
        };
        match self {
            Self::P256(k, alg) => {
                let pk = k.public_key().as_ref();
                map(vec![
                    (1, Value::int(2)),
                    (3, Value::int(*alg)),
                    (-1, Value::int(1)),
                    (-2, Value::Bytes(pk[1..33].to_vec())),
                    (-3, Value::Bytes(pk[33..].to_vec())),
                ])
            }
            Self::Ed25519(k, alg) => map(vec![
                (1, Value::int(1)),
                (3, Value::int(*alg)),
                (-1, Value::int(6)),
                (-2, Value::Bytes(k.public_key().as_ref().to_vec())),
            ]),
            Self::Rsa(k) => {
                let (n, e) = rsa_parts(k.public_key().as_ref());
                map(vec![
                    (1, Value::int(3)),
                    (3, Value::int(-257)),
                    (-1, Value::Bytes(n)),
                    (-2, Value::Bytes(e)),
                ])
            }
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match self {
            Self::P256(k, _) => k.sign(&rng, msg).unwrap().as_ref().to_vec(),
            Self::Ed25519(k, _) => k.sign(msg).as_ref().to_vec(),
            Self::Rsa(k) => {
                let mut sig = vec![0; k.public_modulus_len()];
                k.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig).unwrap();
                sig
            }
        }
    }
}

fn der_take(input: &[u8]) -> (&[u8], &[u8]) {
    let (len, at) = if input[1] & 0x80 == 0 {
        (usize::from(input[1]), 2)
    } else {
        let k = usize::from(input[1] & 0x7f);
        let mut n = 0_usize;
        for b in &input[2..2 + k] {
            n = n * 256 + usize::from(*b);
        }
        (n, 2 + k)
    };
    (&input[at..at + len], &input[at + len..])
}

fn rsa_parts(pkcs1: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (seq, _) = der_take(pkcs1);
    let (n, rest) = der_take(seq);
    let (e, _) = der_take(rest);
    let n = n.strip_prefix(&[0]).unwrap_or(n);
    (n.to_vec(), e.to_vec())
}

/// Packed full attestation: a leaf under a root that a metadata entry lists.
pub struct Attester {
    pub root_der: Vec<u8>,
    pub leaf_der: Vec<u8>,
    pub leaf_key: EcdsaKeyPair,
}

fn aaguid_extension(aaguid: [u8; 16]) -> CustomExtension {
    let mut content = vec![0x04, 0x10];
    content.extend_from_slice(&aaguid);
    CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4], content)
}

impl Attester {
    pub fn new(aaguid: [u8; 16], ou: &str) -> Self {
        let root_key = RcKey::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Attestation Root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = root_params.self_signed(&root_key).unwrap();
        let issuer = rcgen::Issuer::new(root_params, root_key);
        let leaf_key = RcKey::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CountryName, "TR");
        leaf_params
            .distinguished_name
            .push(DnType::OrganizationName, "Acme Keys");
        leaf_params
            .distinguished_name
            .push(DnType::OrganizationalUnitName, ou);
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Acme Key Attestation");
        leaf_params.custom_extensions.push(aaguid_extension(aaguid));
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let leaf_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &leaf_key.serialize_der())
                .unwrap();
        Self {
            root_der: root.der().to_vec(),
            leaf_der: leaf.der().to_vec(),
            leaf_key,
        }
    }
}

pub enum Attestation {
    None,
    PackedSelf,
    Packed(Attester),
}

pub struct Authenticator {
    pub aaguid: [u8; 16],
    pub key: Key,
    pub credential_id: Vec<u8>,
    pub counter: u32,
    pub uv: bool,
    pub be: bool,
    pub bs: bool,
    pub up: bool,
    pub attestation: Attestation,
    pub cred_protect: Option<u8>,
}

impl Authenticator {
    pub fn new(key: Key) -> Self {
        Self {
            aaguid: [0x11; 16],
            key,
            credential_id: vec![0xc1; 32],
            counter: 0,
            uv: true,
            be: false,
            bs: false,
            up: true,
            attestation: Attestation::None,
            cred_protect: Some(2),
        }
    }

    pub fn synced(key: Key) -> Self {
        Self {
            be: true,
            bs: true,
            aaguid: [0; 16],
            ..Self::new(key)
        }
    }

    fn flags(&self, attested: bool) -> u8 {
        let mut f = 0;
        if self.up {
            f |= 0x01;
        }
        if self.uv {
            f |= 0x04;
        }
        if self.be {
            f |= 0x08;
        }
        if self.bs {
            f |= 0x10;
        }
        if attested {
            f |= 0x40;
        }
        if attested && self.cred_protect.is_some() {
            f |= 0x80;
        }
        f
    }

    pub fn auth_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
        let mut out = sha256(rp_id.as_bytes()).to_vec();
        out.push(self.flags(attested));
        out.extend_from_slice(&self.counter.to_be_bytes());
        if attested {
            out.extend_from_slice(&self.aaguid);
            out.extend_from_slice(
                &u16::try_from(self.credential_id.len())
                    .unwrap()
                    .to_be_bytes(),
            );
            out.extend_from_slice(&self.credential_id);
            out.extend(encode(&self.key.cose(), Limits::CEILING).unwrap());
            if let Some(level) = self.cred_protect {
                let ext = Value::Map(vec![(
                    Value::text("credProtect"),
                    Value::int(i64::from(level)),
                )]);
                out.extend(encode(&ext, Limits::CEILING).unwrap());
            }
        }
        out
    }

    /// `(clientDataJSON, attestationObject)`.
    pub fn register(&mut self, rp_id: &str, origin: &str, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let cdj = client_data("webauthn.create", challenge, origin);
        let auth_data = self.auth_data(rp_id, true);
        let mut message = auth_data.clone();
        message.extend_from_slice(&sha256(&cdj));
        let (fmt, stmt) = match &self.attestation {
            Attestation::None => ("none", Value::Map(vec![])),
            Attestation::PackedSelf => (
                "packed",
                Value::Map(vec![
                    (Value::text("alg"), Value::int(-7)),
                    (Value::text("sig"), Value::Bytes(self.key.sign(&message))),
                ]),
            ),
            Attestation::Packed(a) => {
                let rng = SystemRandom::new();
                let sig = a.leaf_key.sign(&rng, &message).unwrap().as_ref().to_vec();
                (
                    "packed",
                    Value::Map(vec![
                        (Value::text("alg"), Value::int(-7)),
                        (Value::text("sig"), Value::Bytes(sig)),
                        (
                            Value::text("x5c"),
                            Value::Array(vec![Value::Bytes(a.leaf_der.clone())]),
                        ),
                    ]),
                )
            }
        };
        let object = Value::Map(vec![
            (Value::text("fmt"), Value::text(fmt)),
            (Value::text("attStmt"), stmt),
            (Value::text("authData"), Value::Bytes(auth_data)),
        ]);
        (cdj, encode(&object, Limits::CEILING).unwrap())
    }

    /// `(clientDataJSON, authenticatorData, signature)`; advances the counter unless BE = 1.
    pub fn assert(
        &mut self,
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        if !self.be {
            self.counter += 1;
        }
        let cdj = client_data("webauthn.get", challenge, origin);
        let auth_data = self.auth_data(rp_id, false);
        let mut message = auth_data.clone();
        message.extend_from_slice(&sha256(&cdj));
        let sig = self.key.sign(&message);
        (cdj, auth_data, sig)
    }
}

/// A FIDO MDS3 blob: RS256 JWS with an `x5c` chain to `root_der`.
pub struct MdsSigner {
    pub root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    leaf_key: RsaKeyPair,
}

impl MdsSigner {
    pub fn new() -> Self {
        let root_key = RcKey::generate_for(&PKCS_RSA_SHA256).unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test MDS Root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = root_params.self_signed(&root_key).unwrap();
        let issuer = rcgen::Issuer::new(root_params, root_key);
        let leaf_key = RcKey::generate_for(&PKCS_RSA_SHA256).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["mds.example".to_owned()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "mds.example");
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        Self {
            root_der: root.der().to_vec(),
            leaf_der: leaf.der().to_vec(),
            leaf_key: RsaKeyPair::from_pkcs8(&leaf_key.serialize_der()).unwrap(),
        }
    }

    pub fn blob(&self, payload: &serde_json::Value) -> Vec<u8> {
        let header = serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "x5c": [std_b64(&self.leaf_der)],
        });
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(payload.to_string().as_bytes())
        );
        let rng = SystemRandom::new();
        let mut sig = vec![0; self.leaf_key.public_modulus_len()];
        self.leaf_key
            .sign(&RSA_PKCS1_SHA256, &rng, input.as_bytes(), &mut sig)
            .unwrap();
        format!("{input}.{}", b64url_encode(&sig)).into_bytes()
    }
}

pub fn std_b64(data: &[u8]) -> String {
    let mut s: String = b64url_encode(data)
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    while !s.len().is_multiple_of(4) {
        s.push('=');
    }
    s
}

pub fn aaguid_text(a: [u8; 16]) -> String {
    let h: String = a.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

pub fn mds_payload(
    serial: u64,
    next_update: &str,
    entries: Vec<serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "legalHeader": "test",
        "no": serial,
        "nextUpdate": next_update,
        "entries": entries,
    })
}

pub fn mds_entry(aaguid: [u8; 16], root_der: &[u8], status: &str) -> serde_json::Value {
    serde_json::json!({
        "aaguid": aaguid_text(aaguid),
        "metadataStatement": {
            "description": "Acme Key",
            "attestationRootCertificates": [std_b64(root_der)],
            "upv": [{"major": 1, "minor": 0}],
            "selfAttestedFRR": 0.01,
        },
        "statusReports": [{"status": status, "effectiveDate": "2026-01-01"}],
        "timeOfLastStatusChange": "2026-01-01",
    })
}
