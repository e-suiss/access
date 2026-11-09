#![allow(clippy::unwrap_used, reason = "test code")]

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
use rcgen::{
    DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256, SanType,
};

use super::*;
use crate::domain::testing::Ca;

const NOW_S: u64 = 1_800_000_000;
const EXTRA: &[u8] = &[3; 32];

fn pub_area(attributes: u32, name_alg: u16) -> Vec<u8> {
    let mut p = ALG_ECC.to_be_bytes().to_vec();
    p.extend(name_alg.to_be_bytes());
    p.extend(attributes.to_be_bytes());
    p.extend([0, 0]);
    p.extend([0x00, 0x10, 0x00, 0x03, 0x00, 0x10]);
    p.extend([0, 32]);
    p.extend([1; 32]);
    p.extend([0, 32]);
    p.extend([2; 32]);
    p
}

fn cert_info(extra: &[u8], name: &[u8]) -> Vec<u8> {
    let mut c = TPM_GENERATED.to_be_bytes().to_vec();
    c.extend(ST_ATTEST_CERTIFY.to_be_bytes());
    c.extend([0, 2, 0, 0]);
    c.extend(u16::try_from(extra.len()).unwrap().to_be_bytes());
    c.extend_from_slice(extra);
    c.extend([0; 17]);
    c.extend([0; 8]);
    c.extend(u16::try_from(name.len()).unwrap().to_be_bytes());
    c.extend_from_slice(name);
    c.extend([0, 0]);
    c
}

fn name_of(area: &[u8]) -> Vec<u8> {
    let mut n = ALG_SHA256.to_be_bytes().to_vec();
    n.extend(sha256(area));
    n
}

const RESIDENT: u32 = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 18);

struct Aik {
    der: Vec<u8>,
    key: EcdsaKeyPair,
}

fn aik(ca: &Ca, aik_purpose: bool, empty_subject: bool) -> Aik {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let der = ca.leaf_for(&key, |p| {
        if empty_subject {
            p.distinguished_name = DistinguishedName::new();
        }
        p.subject_alt_names = vec![SanType::DnsName("tpm.example".try_into().unwrap())];
        if aik_purpose {
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(vec![2, 23, 133, 8, 3])];
        }
        p.is_ca = IsCa::ExplicitNoCa;
    });
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.serialize_der()).unwrap();
    Aik { der, key }
}

fn sign(a: &Aik, msg: &[u8]) -> Vec<u8> {
    a.key
        .sign(&SystemRandom::new(), msg)
        .unwrap()
        .as_ref()
        .to_vec()
}

// §12.2.1, L21, AG-31, Ek B 4125
#[test]
fn tpm_key_attestation_follows_its_checklist() {
    let ca = Ca::new(&PKCS_ECDSA_P256_SHA256);
    let roots = [ca.root.as_slice()];
    let a = aik(&ca, true, true);
    let area = pub_area(RESIDENT, ALG_SHA256);
    let info = cert_info(EXTRA, &name_of(&area));
    let x5c = vec![a.der.clone(), ca.root.clone()];
    let sig = sign(&a, &info);
    let good = Evidence {
        cert_info: &info,
        sig: &sig,
        alg: SigAlg::Es256,
        pub_area: &area,
        x5c: &x5c,
    };
    let ok = verify(&good, &roots, EXTRA, NOW_S).unwrap();
    assert_eq!(ok.key_type, ALG_ECC);
    assert_eq!(ok.name, name_of(&area));
    assert_eq!(
        verify(&good, &roots, &[4; 32], NOW_S),
        Err(AttestError::Challenge)
    );
    let exportable = pub_area(RESIDENT & !(1 << 1), ALG_SHA256);
    let info2 = cert_info(EXTRA, &name_of(&exportable));
    let sig2 = sign(&a, &info2);
    let e = Evidence {
        cert_info: &info2,
        sig: &sig2,
        pub_area: &exportable,
        ..good
    };
    assert_eq!(verify(&e, &roots, EXTRA, NOW_S), Err(AttestError::Policy));
    let sha1 = pub_area(RESIDENT, 0x0004);
    let e = Evidence {
        pub_area: &sha1,
        ..good
    };
    assert_eq!(verify(&e, &roots, EXTRA, NOW_S), Err(AttestError::Policy));
    let other = pub_area(RESIDENT | (1 << 6), ALG_SHA256);
    let e = Evidence {
        pub_area: &other,
        ..good
    };
    assert_eq!(verify(&e, &roots, EXTRA, NOW_S), Err(AttestError::Key));
    let forged = sign(&aik(&ca, true, true), &info);
    let e = Evidence {
        sig: &forged,
        ..good
    };
    assert_eq!(
        verify(&e, &roots, EXTRA, NOW_S),
        Err(AttestError::Signature)
    );
    for bad in [aik(&ca, false, true), aik(&ca, true, false)] {
        let x5c = vec![bad.der.clone()];
        let sig = sign(&bad, &info);
        let e = Evidence {
            sig: &sig,
            x5c: &x5c,
            ..good
        };
        assert_eq!(
            verify(&e, &roots, EXTRA, NOW_S),
            Err(AttestError::Certificate)
        );
    }
    assert_eq!(
        verify(&good, &crate::domain::roots::TPM, EXTRA, NOW_S),
        Err(AttestError::Chain)
    );
}
