#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use aws_lc_rs::signature::{self, UnparsedPublicKey};
use suiss_crypto::envelope::SoftKek;

use super::*;
use crate::adapters::SealedFactory;

fn factory() -> SealedFactory<SoftKek> {
    let mut k = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut k).unwrap();
    SealedFactory::new(SoftKek::new("realm-kek", k))
}

const REALM: Realm = Realm([3; 16]);

/// The `subjectPublicKeyInfo` and signature fields of a certificate this module wrote.
fn spki_and_tbs(cert: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use access_parse::der::{Reader, SEQUENCE};
    let mut outer = Reader::new(cert).unwrap();
    let c = outer.tagged(SEQUENCE).unwrap();
    let mut r = Reader::new(c).unwrap();
    let tbs_tlv = r.next_tlv().unwrap();
    let _alg = r.next_tlv().unwrap();
    let sig = r.tagged(0x03).unwrap()[1..].to_vec();
    let mut t = Reader::new(tbs_tlv.value).unwrap();
    for _ in 0..6 {
        t.next_tlv().unwrap();
    }
    let spki = t.tagged(SEQUENCE).unwrap();
    let mut s = Reader::new(spki).unwrap();
    let _ = s.tagged(SEQUENCE).unwrap();
    let key = s.tagged(0x03).unwrap()[1..].to_vec();
    let mut tbs = vec![0x30];
    der_len(&mut tbs, tbs_tlv.value.len());
    tbs.extend_from_slice(tbs_tlv.value);
    (key, tbs, sig)
}

// OP-155 m.3 (d), (e), HL-35: an RSA-3072 key is made once, its self-signed certificate verifies
// under its own key, and it signs SAML octets with SHA-256/384/512, never SHA-1.
#[test]
fn a_realm_rsa_key_signs_saml_octets_and_certifies_itself() {
    let mut f = factory();
    let mut ring = Ring::new(REALM);
    assert!(ring.open(SamlAlg::Rsa3072, 1_000, &mut f).unwrap());
    assert!(!ring.open(SamlAlg::Rsa3072, 2_000, &mut f).unwrap());
    let keys = ring.keys();
    assert_eq!(keys.len(), 1);
    let (pk, tbs, sig) = spki_and_tbs(&keys[0].cert);
    assert!(
        UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &pk)
            .verify(&tbs, &sig)
            .is_ok()
    );
    for (s, v) in [
        (SamlSig::RsaSha256, &signature::RSA_PKCS1_2048_8192_SHA256),
        (SamlSig::RsaSha384, &signature::RSA_PKCS1_2048_8192_SHA384),
        (SamlSig::RsaSha512, &signature::RSA_PKCS1_2048_8192_SHA512),
    ] {
        let (out, info) = ring.sign(s, b"<ds:SignedInfo/>").unwrap();
        assert_eq!(out.len(), 384);
        assert_eq!(info.kid, keys[0].kid);
        assert!(
            UnparsedPublicKey::new(v, &pk)
                .verify(b"<ds:SignedInfo/>", &out)
                .is_ok()
        );
    }
    assert_eq!(SamlSig::of("rsa-sha1"), None);
    assert_eq!(
        ring.sign(SamlSig::EcdsaSha256, b"x").err(),
        Some(SamlKeyError::NoKey)
    );
}

// §10.6.1, Ek B 4778: T0 add, T1 switch, then remove; out-of-order steps are refused; the ring
// survives a restart through the sealed vault form.
#[test]
fn two_phase_rotation_publishes_switches_and_removes() {
    let mut f = factory();
    let mut ring = Ring::new(REALM);
    ring.open(SamlAlg::Rsa3072, 0, &mut f).unwrap();
    assert_eq!(
        ring.rotate(SamlAlg::Rsa3072, Step::Switch, 1, &mut f),
        Err(SamlKeyError::Order)
    );
    ring.rotate(SamlAlg::Rsa3072, Step::Add, 1, &mut f).unwrap();
    let phases = |r: &Ring| r.keys().iter().map(|k| k.phase).collect::<Vec<_>>();
    assert_eq!(phases(&ring), [Phase::Active, Phase::Published]);
    let old = ring.keys()[0].kid;
    let new = ring.keys()[1].kid;
    assert_eq!(
        ring.rotate(SamlAlg::Rsa3072, Step::Add, 2, &mut f),
        Err(SamlKeyError::Order)
    );
    let stored = ring.stored().unwrap();
    let mut back = Ring::restore(REALM, &stored, &mut f).unwrap();
    back.rotate(SamlAlg::Rsa3072, Step::Switch, 3, &mut f)
        .unwrap();
    assert_eq!(phases(&back), [Phase::Retiring, Phase::Active]);
    assert_eq!(back.sign(SamlSig::RsaSha256, b"x").unwrap().1.kid, new);
    back.rotate(SamlAlg::Rsa3072, Step::Remove, 4, &mut f)
        .unwrap();
    assert_eq!(back.keys().len(), 1);
    assert!(back.keys().iter().all(|k| k.kid != old));
    assert!(Ring::restore(Realm([4; 16]), &stored, &mut f).is_err());
}

// OP-155 m.3 (e): the P-256 key signs ECDSA-SHA256 as r || s; an emergency replaces every key
// of the algorithm at once.
#[test]
fn a_p256_key_signs_ecdsa_and_an_emergency_replaces_it() {
    let mut f = factory();
    let mut ring = Ring::new(REALM);
    ring.open(SamlAlg::P256, 0, &mut f).unwrap();
    let k = ring.keys()[0].clone();
    let (pk, tbs, sig) = spki_and_tbs(&k.cert);
    assert!(
        UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &pk)
            .verify(&tbs, &sig)
            .is_ok()
    );
    let (out, _) = ring.sign(SamlSig::EcdsaSha256, b"m").unwrap();
    assert_eq!(out.len(), 64);
    assert!(
        UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &pk)
            .verify(b"m", &out)
            .is_ok()
    );
    ring.rotate(SamlAlg::P256, Step::Emergency, 5, &mut f)
        .unwrap();
    assert_eq!(ring.keys().len(), 1);
    assert_ne!(ring.keys()[0].kid, k.kid);
    let r = SamlRequest::Sign {
        realm: REALM,
        sig: SamlSig::RsaSha384,
        data: vec![1],
    };
    assert_eq!(SamlRequest::from_value(&r.to_value()).unwrap(), r);
}
