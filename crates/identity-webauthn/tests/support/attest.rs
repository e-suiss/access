//! Attestation statements of every `direct` format built at test time (OP-159 m.3 (ll)): a
//! runtime root and intermediate with CRL distribution points, the CRLs they sign, and `packed`,
//! `tpm`, `android-key`, `apple` and `fido-u2f` statements over a software credential. No key,
//! certificate or TPM structure is committed.

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CustomExtension, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod,
    KeyPair as RcKey, PKCS_ECDSA_P256_SHA256, RevokedCertParams, SerialNumber, date_time_ymd,
};
use suiss_crypto::dcbor::Value;

use super::{Attestation, Key, aaguid_text, sha256, std_b64};

const INTERMEDIATE_SERIAL: u64 = 0x1001;

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![u8::try_from(n).unwrap()]
    } else if n < 0x100 {
        vec![0x81, u8::try_from(n).unwrap()]
    } else {
        vec![
            0x82,
            u8::try_from(n >> 8).unwrap(),
            u8::try_from(n & 0xff).unwrap(),
        ]
    }
}

/// A DER element: `tag` (one or more octets) and `content`.
pub fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn aaguid_extension(aaguid: [u8; 16]) -> CustomExtension {
    CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4], tlv(&[0x04], &aaguid))
}

/// A software P-256 credential whose key can also be a certificate's subject key.
pub struct Credential {
    pub rc: RcKey,
}

impl Credential {
    pub fn new() -> Self {
        Self {
            rc: RcKey::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
        }
    }

    /// The credential key, `alg` −7 or −9.
    pub fn key(&self, alg: i64) -> Key {
        Key::P256(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.rc.serialize_der())
                .unwrap(),
            alg,
        )
    }
}

fn signer(rc: &RcKey) -> EcdsaKeyPair {
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rc.serialize_der()).unwrap()
}

fn sign(rc: &RcKey, message: &[u8]) -> Vec<u8> {
    signer(rc)
        .sign(&SystemRandom::new(), message)
        .unwrap()
        .as_ref()
        .to_vec()
}

/// A runtime root and an intermediate, each naming the CRL of its issuer.
pub struct Pki {
    pub root_der: Vec<u8>,
    pub intermediate_der: Vec<u8>,
    /// Where the root's CRL is published.
    pub root_url: String,
    /// Where the intermediate's CRL is published.
    pub intermediate_url: String,
    root: rcgen::Issuer<'static, RcKey>,
    intermediate: rcgen::Issuer<'static, RcKey>,
}

impl Pki {
    pub fn new() -> Self {
        Self::at("https://crl.test/")
    }

    /// A PKI whose CRLs are published under `base`.
    pub fn at(base: &str) -> Self {
        let root_url = format!("{base}root.crl");
        let intermediate_url = format!("{base}intermediate.crl");
        let root_key = RcKey::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
        root.distinguished_name
            .push(DnType::CommonName, "Test Attestation Root");
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root_der = root.self_signed(&root_key).unwrap().der().to_vec();
        let root = rcgen::Issuer::new(root, root_key);
        let key = RcKey::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut inter = CertificateParams::new(Vec::<String>::new()).unwrap();
        inter
            .distinguished_name
            .push(DnType::CommonName, "Test Attestation Intermediate");
        inter.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        inter.serial_number = Some(SerialNumber::from(INTERMEDIATE_SERIAL));
        inter.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![root_url.clone()],
        }];
        let intermediate_der = inter.signed_by(&key, &root).unwrap().der().to_vec();
        Self {
            root_der,
            intermediate_der,
            root_url,
            intermediate_url,
            root,
            intermediate: rcgen::Issuer::new(inter, key),
        }
    }

    /// A leaf for `key` under the intermediate (or the root), naming the intermediate's CRL.
    fn leaf(&self, mut params: CertificateParams, key: &RcKey, under_root: bool) -> Vec<u8> {
        if under_root {
            params.signed_by(key, &self.root).unwrap().der().to_vec()
        } else {
            params.crl_distribution_points = vec![CrlDistributionPoint {
                uris: vec![self.intermediate_url.clone()],
            }];
            params
                .signed_by(key, &self.intermediate)
                .unwrap()
                .der()
                .to_vec()
        }
    }

    fn crl(
        issuer: &rcgen::Issuer<'static, RcKey>,
        revoked: &[u64],
        next_update: (i32, u8, u8),
    ) -> Vec<u8> {
        CertificateRevocationListParams {
            this_update: date_time_ymd(2026, 10, 1),
            next_update: date_time_ymd(next_update.0, next_update.1, next_update.2),
            crl_number: SerialNumber::from(7_u64),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(*s),
                    revocation_time: date_time_ymd(2026, 10, 2),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(issuer)
        .unwrap()
        .der()
        .to_vec()
    }

    /// The root's CRL, revoking the intermediate when `revoke` is set.
    pub fn root_crl(&self, revoke: bool) -> Vec<u8> {
        let revoked: &[u64] = if revoke { &[INTERMEDIATE_SERIAL] } else { &[] };
        Self::crl(&self.root, revoked, (2027, 6, 1))
    }

    /// The intermediate's CRL, current until `next_update`.
    pub fn intermediate_crl(&self, next_update: (i32, u8, u8)) -> Vec<u8> {
        Self::crl(&self.intermediate, &[], next_update)
    }

    /// Both CRLs, current and revoking nothing.
    pub fn crls(&self) -> Vec<(String, Vec<u8>)> {
        vec![
            (self.root_url.clone(), self.root_crl(false)),
            (
                self.intermediate_url.clone(),
                self.intermediate_crl((2027, 6, 1)),
            ),
        ]
    }
}

/// A metadata entry naming `root_der` for `aaguid`.
pub fn entry(aaguid: [u8; 16], root_der: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "aaguid": aaguid_text(aaguid),
        "metadataStatement": {
            "description": "Acme Key",
            "attestationRootCertificates": [std_b64(root_der)],
        },
        "statusReports": [{"status": "FIDO_CERTIFIED_L1", "effectiveDate": "2026-01-01"}],
    })
}

/// A U2F metadata entry: no AAGUID, the attestation certificate's key identifier.
pub fn u2f_entry(key_id: &[u8], root_der: &[u8]) -> serde_json::Value {
    let hex: String = key_id.iter().map(|b| format!("{b:02x}")).collect();
    serde_json::json!({
        "attestationCertificateKeyIdentifiers": [hex],
        "metadataStatement": {
            "description": "Acme U2F",
            "attestationRootCertificates": [std_b64(root_der)],
        },
        "statusReports": [{"status": "FIDO_CERTIFIED", "effectiveDate": "2026-01-01"}],
    })
}

/// What a statement builder is given: `authenticatorData` and `clientDataHash`.
pub type Build = Arc<dyn Fn(&[u8], &[u8; 32]) -> (String, Value) + Send + Sync>;

fn text(k: &str) -> Value {
    Value::text(k)
}

/// How a statement is spoiled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flaw {
    /// Well formed and true.
    None,
    /// The signature or binding is over another message.
    Binding,
    /// A format-specific requirement on the certificate does not hold.
    Certificate,
}

fn other(hash: &[u8; 32]) -> [u8; 32] {
    sha256(hash)
}

/// `packed` under the intermediate.
pub fn packed(pki: &Arc<Pki>, aaguid: [u8; 16], flaw: Flaw) -> Attestation {
    let key = RcKey::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CountryName, "TR");
    p.distinguished_name
        .push(DnType::OrganizationName, "Acme Keys");
    let ou = if flaw == Flaw::Certificate {
        "Something Else"
    } else {
        "Authenticator Attestation"
    };
    p.distinguished_name
        .push(DnType::OrganizationalUnitName, ou);
    p.distinguished_name
        .push(DnType::CommonName, "Acme Key Attestation");
    p.custom_extensions.push(aaguid_extension(aaguid));
    let leaf = pki.leaf(p, &key, false);
    let inter = pki.intermediate_der.clone();
    Attestation::Statement(Arc::new(move |auth, cdh| {
        let hash = if flaw == Flaw::Binding {
            other(cdh)
        } else {
            *cdh
        };
        let mut m = auth.to_vec();
        m.extend_from_slice(&hash);
        (
            "packed".to_owned(),
            Value::Map(vec![
                (text("alg"), Value::int(-7)),
                (text("sig"), Value::Bytes(sign(&key, &m))),
                (
                    text("x5c"),
                    Value::Array(vec![
                        Value::Bytes(leaf.clone()),
                        Value::Bytes(inter.clone()),
                    ]),
                ),
            ]),
        )
    }))
}

fn tpm_public(point: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(0x0023_u16.to_be_bytes());
    p.extend(0x000b_u16.to_be_bytes());
    p.extend(0x0004_0072_u32.to_be_bytes());
    p.extend(0_u16.to_be_bytes());
    p.extend(0x0010_u16.to_be_bytes());
    p.extend(0x0010_u16.to_be_bytes());
    p.extend(0x0003_u16.to_be_bytes());
    p.extend(0x0010_u16.to_be_bytes());
    p.extend(32_u16.to_be_bytes());
    p.extend_from_slice(&point[1..33]);
    p.extend(32_u16.to_be_bytes());
    p.extend_from_slice(&point[33..]);
    p
}

fn tpm_cert_info(extra: &[u8; 32], pub_area: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend(0xff54_4347_u32.to_be_bytes());
    c.extend(0x8017_u16.to_be_bytes());
    c.extend(0_u16.to_be_bytes());
    c.extend(32_u16.to_be_bytes());
    c.extend_from_slice(extra);
    c.extend(std::iter::repeat_n(1_u8, 17));
    c.extend(std::iter::repeat_n(2_u8, 8));
    let mut name = 0x000b_u16.to_be_bytes().to_vec();
    name.extend(sha256(pub_area));
    c.extend(u16::try_from(name.len()).unwrap().to_be_bytes());
    c.extend(name);
    c.extend(0_u16.to_be_bytes());
    c
}

/// `tpm` with an attestation identity key under the intermediate; `credential` is the
/// certified key.
pub fn tpm(pki: &Arc<Pki>, aaguid: [u8; 16], credential: &Credential, flaw: Flaw) -> Attestation {
    let aik = RcKey::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name = DistinguishedName::new();
    p.is_ca = IsCa::ExplicitNoCa;
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(vec![2, 23, 133, 8, 3])];
    let attr = tlv(
        &[0x30],
        &[
            tlv(&[0x06], &[0x67, 0x81, 0x05, 0x02, 0x01]),
            tlv(&[0x0c], b"id:FFFFF1D0"),
        ]
        .concat(),
    );
    let name = tlv(&[0x30], &tlv(&[0x31], &attr));
    let mut san =
        CustomExtension::from_oid_content(&[2, 5, 29, 17], tlv(&[0x30], &tlv(&[0xa4], &name)));
    san.set_criticality(flaw != Flaw::Certificate);
    p.custom_extensions.push(san);
    p.custom_extensions.push(aaguid_extension(aaguid));
    let leaf = pki.leaf(p, &aik, false);
    let inter = pki.intermediate_der.clone();
    let pub_area = tpm_public(credential.rc.public_key_raw());
    Attestation::Statement(Arc::new(move |auth, cdh| {
        let mut m = auth.to_vec();
        m.extend_from_slice(cdh);
        let extra = if flaw == Flaw::Binding {
            other(&sha256(&m))
        } else {
            sha256(&m)
        };
        let info = tpm_cert_info(&extra, &pub_area);
        (
            "tpm".to_owned(),
            Value::Map(vec![
                (text("ver"), text("2.0")),
                (text("alg"), Value::int(-7)),
                (
                    text("x5c"),
                    Value::Array(vec![
                        Value::Bytes(leaf.clone()),
                        Value::Bytes(inter.clone()),
                    ]),
                ),
                (text("sig"), Value::Bytes(sign(&aik, &info))),
                (text("certInfo"), Value::Bytes(info)),
                (text("pubArea"), Value::Bytes(pub_area.clone())),
            ]),
        )
    }))
}

fn key_description(challenge: &[u8], all_applications: bool) -> Vec<u8> {
    let mut hardware = tlv(&[0xa1], &tlv(&[0x31], &tlv(&[0x02], &[2])));
    hardware.extend(tlv(&[0xbf, 0x85, 0x3e], &tlv(&[0x02], &[0])));
    if all_applications {
        hardware.extend(tlv(&[0xbf, 0x84, 0x58], &[0x05, 0x00]));
    }
    let body = [
        tlv(&[0x02], &[3]),
        tlv(&[0x0a], &[1]),
        tlv(&[0x02], &[4]),
        tlv(&[0x0a], &[1]),
        tlv(&[0x04], challenge),
        tlv(&[0x04], &[]),
        tlv(&[0x30], &[]),
        tlv(&[0x30], &hardware),
    ]
    .concat();
    tlv(&[0x30], &body)
}

/// `android-key`: the leaf holds `credential`; its `KeyDescription` binds the challenge, which
/// is only known when the statement is built, so the leaf is issued then.
pub fn android(pki: &Arc<Pki>, credential: Arc<Credential>, flaw: Flaw) -> Attestation {
    let pki = pki.clone();
    Attestation::Statement(Arc::new(move |auth, cdh| {
        let challenge = if flaw == Flaw::Binding {
            other(cdh)
        } else {
            *cdh
        };
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name
            .push(DnType::CommonName, "Android Keystore Key");
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description(&challenge, flaw == Flaw::Certificate),
        ));
        let leaf = pki.leaf(p, &credential.rc, false);
        let mut m = auth.to_vec();
        m.extend_from_slice(cdh);
        (
            "android-key".to_owned(),
            Value::Map(vec![
                (text("alg"), Value::int(-7)),
                (text("sig"), Value::Bytes(sign(&credential.rc, &m))),
                (
                    text("x5c"),
                    Value::Array(vec![
                        Value::Bytes(leaf),
                        Value::Bytes(pki.intermediate_der.clone()),
                    ]),
                ),
            ]),
        )
    }))
}

/// `apple`: the leaf holds `credential` (another key when the certificate is spoiled) and its
/// nonce extension binds the message.
pub fn apple(pki: &Arc<Pki>, credential: Arc<Credential>, flaw: Flaw) -> Attestation {
    let pki = pki.clone();
    Attestation::Statement(Arc::new(move |auth, cdh| {
        let mut m = auth.to_vec();
        m.extend_from_slice(cdh);
        let nonce = if flaw == Flaw::Binding {
            other(&sha256(&m))
        } else {
            sha256(&m)
        };
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name
            .push(DnType::CommonName, "Apple Anonymous Attestation");
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &[1, 2, 840, 113_635, 100, 8, 2],
            tlv(&[0x30], &tlv(&[0xa1], &tlv(&[0x04], &nonce))),
        ));
        let stranger = Credential::new();
        let holder = if flaw == Flaw::Certificate {
            &stranger.rc
        } else {
            &credential.rc
        };
        let leaf = pki.leaf(p, holder, false);
        (
            "apple".to_owned(),
            Value::Map(vec![(
                text("x5c"),
                Value::Array(vec![
                    Value::Bytes(leaf),
                    Value::Bytes(pki.intermediate_der.clone()),
                ]),
            )]),
        )
    }))
}

/// `fido-u2f`: one certificate issued by the root, and its subject key identifier for the
/// metadata entry.
pub fn u2f(
    pki: &Arc<Pki>,
    credential_id: Vec<u8>,
    point: Vec<u8>,
    flaw: Flaw,
) -> (Attestation, Vec<u8>) {
    let key = RcKey::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "Acme U2F");
    p.is_ca = IsCa::ExplicitNoCa;
    let leaf = pki.leaf(p, &key, true);
    let key_id = subject_key_id(&leaf);
    let st = Attestation::Statement(Arc::new(move |auth, cdh| {
        let hash = if flaw == Flaw::Binding {
            other(cdh)
        } else {
            *cdh
        };
        let mut m = vec![0x00];
        m.extend_from_slice(&auth[..32]);
        m.extend_from_slice(&hash);
        m.extend_from_slice(&credential_id);
        m.extend_from_slice(&point);
        (
            "fido-u2f".to_owned(),
            Value::Map(vec![
                (text("sig"), Value::Bytes(sign(&key, &m))),
                (text("x5c"), Value::Array(vec![Value::Bytes(leaf.clone())])),
            ]),
        )
    }));
    (st, key_id)
}

/// The subjectKeyIdentifier of `cert`, found by its OID.
fn subject_key_id(cert: &[u8]) -> Vec<u8> {
    let oid = [0x06, 0x03, 0x55, 0x1d, 0x0e];
    let at = cert.windows(oid.len()).position(|w| w == oid).unwrap() + oid.len();
    let rest = &cert[at..];
    let rest = if rest[0] == 0x01 { &rest[3..] } else { rest };
    assert_eq!(rest[0], 0x04);
    let inner = &rest[2..];
    assert_eq!(inner[0], 0x04);
    inner[2..2 + usize::from(inner[1])].to_vec()
}
