//! Certificate authorities, client certificates, CRLs and OCSP responses made at test time, so
//! no certificate or key is ever committed.

#![allow(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::collapsible_if,
    reason = "test fixtures; a failure here is a broken test, not a request path"
)]

use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CrlDistributionPoint,
    CustomExtension, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod,
    KeyPair, KeyUsagePurpose, OtherNameValue, RevokedCertParams, SanType, SerialNumber,
};
use time::OffsetDateTime;

use crate::domain::cert::Cert;
use crate::domain::der::{self, tlv};

/// The fixed test time, Unix seconds (2027-01-15).
pub const NOW: u64 = 1_800_000_000;

/// One day in seconds.
pub const DAY: u64 = 86_400;

fn at(s: u64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(i64::try_from(s).unwrap()).unwrap()
}

fn oid_arcs(dotted: &str) -> Vec<u64> {
    dotted.split('.').map(|a| a.parse().unwrap()).collect()
}

fn oid_der(dotted: &str) -> Vec<u8> {
    let arcs = oid_arcs(dotted);
    let mut out = Vec::new();
    let first = arcs[0] * 40 + arcs[1];
    for arc in std::iter::once(first).chain(arcs[2..].iter().copied()) {
        let mut stack = vec![u8::try_from(arc & 0x7f).unwrap()];
        let mut rest = arc >> 7;
        while rest > 0 {
            stack.push(u8::try_from(rest & 0x7f).unwrap() | 0x80);
            rest >>= 7;
        }
        stack.reverse();
        out.extend(stack);
    }
    tlv(der::OID, &out).unwrap()
}

fn generalized(s: u64) -> Vec<u8> {
    let t = at(s);
    let text = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    tlv(der::GENERALIZED_TIME, text.as_bytes()).unwrap()
}

fn sha1(b: &[u8]) -> Vec<u8> {
    access_crypto::ocsp::cert_id_sha1(b).to_vec()
}

/// What a client certificate carries.
#[derive(Clone, Debug, Default)]
pub struct LeafSpec<'a> {
    /// The subject common name.
    pub cn: &'a str,
    /// A subjectAltName `rfc822Name`.
    pub email: Option<&'a str>,
    /// A subjectAltName user principal name.
    pub upn: Option<&'a str>,
    /// Certificate policy OIDs.
    pub policies: &'a [&'a str],
    /// The OCSP responder URL.
    pub ocsp: Option<&'a str>,
    /// The CRL distribution point.
    pub crl: Option<&'a str>,
    /// The serial's last octet; 1 when zero.
    pub serial: u8,
    /// Whether it is for server authentication only.
    pub server_only: bool,
    /// Whether it expired a day before the CA's time.
    pub expired: bool,
}

/// A certificate and its key.
pub struct Issued {
    /// The certificate.
    pub der: Vec<u8>,
    /// Its key.
    pub key: KeyPair,
}

/// A certificate authority.
pub struct Ca {
    /// Its certificate.
    pub der: Vec<u8>,
    /// The time its certificates are made valid around, Unix seconds.
    pub now: u64,
    issuer: Issuer<'static, KeyPair>,
    key: KeyPair,
    key_bits: Vec<u8>,
}

fn ca_params(cn: &str, now: u64) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    p.not_before = at(now - 30 * DAY);
    p.not_after = at(now + 3650 * DAY);
    p.key_identifier_method = KeyIdMethod::Sha256;
    p
}

fn aia(ocsp: &str) -> CustomExtension {
    let access = der::seq(&[
        &oid_der("1.3.6.1.5.5.7.48.1"),
        &tlv(0x86, ocsp.as_bytes()).unwrap(),
    ])
    .unwrap();
    CustomExtension::from_oid_content(
        &oid_arcs("1.3.6.1.5.5.7.1.1"),
        der::seq(&[&access]).unwrap(),
    )
}

fn revocation_pointers(p: &mut CertificateParams, ocsp: Option<&str>, crl: Option<&str>) {
    if let Some(u) = ocsp {
        p.custom_extensions.push(aia(u));
    }
    if let Some(u) = crl {
        p.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![String::from(u)],
        }];
    }
}

impl Ca {
    /// A self-signed root valid around [`NOW`].
    pub fn root(cn: &str) -> Self {
        Self::root_at(cn, NOW)
    }

    /// A self-signed root valid around `now` (Unix seconds).
    pub fn root_at(cn: &str, now: u64) -> Self {
        let key = KeyPair::generate().unwrap();
        let params = ca_params(cn, now);
        let cert = params.self_signed(&key).unwrap();
        Self::of(cert.der().to_vec(), params, key, now)
    }

    fn of(der: Vec<u8>, params: CertificateParams, key: KeyPair, now: u64) -> Self {
        let key_bits = Cert::parse(&der).unwrap().public_key.to_vec();
        let own = KeyPair::try_from(key.serialize_der().as_slice()).unwrap();
        Self {
            der,
            now,
            issuer: Issuer::new(params, key),
            key: own,
            key_bits,
        }
    }

    /// An intermediate CA under this one, with its revocation pointers.
    pub fn intermediate(&self, cn: &str, ocsp: Option<&str>, crl: Option<&str>) -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = ca_params(cn, self.now);
        revocation_pointers(&mut params, ocsp, crl);
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Self::of(cert.der().to_vec(), params, key, self.now)
    }

    /// A client certificate under this CA.
    pub fn leaf(&self, s: &LeafSpec<'_>) -> Issued {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            if s.cn.is_empty() { "Client" } else { s.cn },
        );
        p.distinguished_name = dn;
        p.serial_number = Some(SerialNumber::from_slice(&[0x01, s.serial.max(1)]));
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![if s.server_only {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        if let Some(e) = s.email {
            p.subject_alt_names
                .push(SanType::Rfc822Name(e.try_into().unwrap()));
        }
        if let Some(u) = s.upn {
            p.subject_alt_names.push(SanType::OtherName((
                oid_arcs("1.3.6.1.4.1.311.20.2.3"),
                OtherNameValue::Utf8String(String::from(u)),
            )));
        }
        if !s.policies.is_empty() {
            let infos: Vec<Vec<u8>> = s
                .policies
                .iter()
                .map(|o| der::seq(&[&oid_der(o)]).unwrap())
                .collect();
            let refs: Vec<&[u8]> = infos.iter().map(Vec::as_slice).collect();
            p.custom_extensions.push(CustomExtension::from_oid_content(
                &oid_arcs("2.5.29.32"),
                der::seq(&refs).unwrap(),
            ));
        }
        revocation_pointers(&mut p, s.ocsp, s.crl);
        if s.expired {
            p.not_before = at(self.now - 30 * DAY);
            p.not_after = at(self.now - DAY);
        } else {
            p.not_before = at(self.now - DAY);
            p.not_after = at(self.now + 365 * DAY);
        }
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        Issued {
            der: cert.der().to_vec(),
            key,
        }
    }

    /// A delegated OCSP responder certificate of this CA (RFC 6960 §4.2.2.2).
    pub fn responder(&self, ocsp_signing: bool) -> Issued {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "OCSP Responder");
        p.distinguished_name = dn;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![if ocsp_signing {
            ExtendedKeyUsagePurpose::OcspSigning
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        p.custom_extensions.push(CustomExtension::from_oid_content(
            &oid_arcs("1.3.6.1.5.5.7.48.1.5"),
            vec![der::NULL, 0],
        ));
        p.not_before = at(self.now - DAY);
        p.not_after = at(self.now + 30 * DAY);
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        Issued {
            der: cert.der().to_vec(),
            key,
        }
    }

    /// This CA's CRL revoking the certificates whose serials are given, issued at
    /// `this_update` with `next_update`.
    pub fn crl(&self, revoked: &[&[u8]], this_update: u64, next_update: u64) -> Vec<u8> {
        let params = CertificateRevocationListParams {
            this_update: at(this_update),
            next_update: at(next_update),
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from_slice(s),
                    revocation_time: at(this_update - DAY),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        params.signed_by(&self.issuer).unwrap().der().to_vec()
    }

    /// An OCSP response about `cert` signed by this CA, or by `delegated` and carrying it.
    pub fn ocsp(&self, cert: &[u8], answer: &OcspAnswer, delegated: Option<&Issued>) -> Vec<u8> {
        let c = Cert::parse(cert).unwrap();
        let cert_id = der::seq(&[
            &der::seq(&[&oid_der("1.3.14.3.2.26"), &[der::NULL, 0]]).unwrap(),
            &tlv(der::OCTET_STRING, &sha1(c.issuer)).unwrap(),
            &tlv(der::OCTET_STRING, &sha1(&self.key_bits)).unwrap(),
            &tlv(der::INTEGER, c.serial).unwrap(),
        ])
        .unwrap();
        let status = match answer.status {
            Status::Good => vec![0x80, 0x00],
            Status::Revoked => tlv(0xa1, &generalized(answer.this_update - DAY)).unwrap(),
            Status::Unknown => vec![0x82, 0x00],
        };
        let mut single = vec![cert_id, status, generalized(answer.this_update)];
        if let Some(n) = answer.next_update {
            single.push(tlv(0xa0, &generalized(n)).unwrap());
        }
        let refs: Vec<&[u8]> = single.iter().map(Vec::as_slice).collect();
        let single = der::seq(&refs).unwrap();
        let (signer_bits, signer_key): (Vec<u8>, &KeyPair) = match delegated {
            Some(d) => (Cert::parse(&d.der).unwrap().public_key.to_vec(), &d.key),
            None => (self.key_bits.clone(), &self.key),
        };
        let responder = tlv(0xa2, &tlv(der::OCTET_STRING, &sha1(&signer_bits)).unwrap()).unwrap();
        let tbs = der::seq(&[
            &responder,
            &generalized(answer.this_update),
            &der::seq(&[&single]).unwrap(),
        ])
        .unwrap();
        let mut signed = tbs.clone();
        if answer.tamper {
            if let Some(last) = signed.last_mut() {
                *last ^= 1;
            }
        }
        let sig = rcgen::SigningKey::sign(signer_key, &tbs).unwrap();
        let mut sig_bits = vec![0];
        sig_bits.extend(sig);
        let mut basic = vec![
            signed,
            der::seq(&[&oid_der("1.2.840.10045.4.3.2")]).unwrap(),
            tlv(der::BIT_STRING, &sig_bits).unwrap(),
        ];
        if let Some(d) = delegated {
            basic.push(tlv(0xa0, &der::seq(&[&d.der]).unwrap()).unwrap());
        }
        let refs: Vec<&[u8]> = basic.iter().map(Vec::as_slice).collect();
        let basic = der::seq(&refs).unwrap();
        let bytes = der::seq(&[
            &oid_der("1.3.6.1.5.5.7.48.1.1"),
            &tlv(der::OCTET_STRING, &basic).unwrap(),
        ])
        .unwrap();
        der::seq(&[&[der::ENUMERATED, 1, 0], &tlv(0xa0, &bytes).unwrap()]).unwrap()
    }
}

/// A certificate status an OCSP responder states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// `good`.
    Good,
    /// `revoked`.
    Revoked,
    /// `unknown`.
    Unknown,
}

/// What a test OCSP response says.
#[derive(Clone, Copy, Debug)]
pub struct OcspAnswer {
    /// The status.
    pub status: Status,
    /// `thisUpdate`, Unix seconds.
    pub this_update: u64,
    /// `nextUpdate`, Unix seconds.
    pub next_update: Option<u64>,
    /// Whether the signed data is changed after signing.
    pub tamper: bool,
}

impl OcspAnswer {
    /// A current answer: issued an hour before [`NOW`], next update a day after.
    pub const fn current(status: Status) -> Self {
        Self::current_at(status, NOW)
    }

    /// A current answer at `now`: issued an hour before, next update a day after.
    pub const fn current_at(status: Status, now: u64) -> Self {
        Self {
            status,
            this_update: now - 3600,
            next_update: Some(now + DAY),
            tamper: false,
        }
    }
}

/// The OCSP `unauthorized` (6) response, unsigned.
pub fn ocsp_unauthorized() -> Vec<u8> {
    der::seq(&[&[der::ENUMERATED, 1, 6]]).unwrap()
}

/// The serial contents of `cert`.
pub fn serial(cert: &[u8]) -> Vec<u8> {
    Cert::parse(cert).unwrap().serial.to_vec()
}
