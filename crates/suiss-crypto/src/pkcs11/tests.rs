use std::path::PathBuf;
use std::sync::OnceLock;

use super::*;
use crate::cose::{KeySet, verify_sign1};
use crate::envelope::{DekKek, SoftKek};
use crate::sig::PureBackend;
use crate::signer::sign_sign1;

const PIN: &str = "1234-test-only";

/// `SoftHSM` (OP-69): `SUISS_PKCS11_MODULE`, or the usual install paths.
fn module() -> PathBuf {
    let candidates = [
        std::env::var("SUISS_PKCS11_MODULE").unwrap_or_default(),
        String::from("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"),
    ];
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .expect("SoftHSM is required for the PKCS#11 tests (OP-69); set SUISS_PKCS11_MODULE")
}

fn token() -> String {
    format!("suiss-test-{}", std::process::id())
}

/// One token per test process, in its own `SoftHSM` store (`SOFTHSM2_CONF`, OP-69).
fn store() -> &'static KeyStore {
    static STORE: OnceLock<KeyStore> = OnceLock::new();
    STORE.get_or_init(|| {
        assert!(
            std::env::var_os("SOFTHSM2_CONF").is_some(),
            "run the PKCS#11 tests through `just test`, which sets SOFTHSM2_CONF (OP-69)"
        );
        let out =
            super::token_tests::init_softhsm_token(None, &token(), PIN, "5678-test-only").unwrap();
        assert!(out.status.success(), "{out:?}");
        KeyStore::open(&module(), &token(), &Secret::new(String::from(PIN))).unwrap()
    })
}

fn keyset(signer: &dyn Signer) -> KeySet {
    let mut ks = KeySet::default();
    ks.insert([9; 32], signer.public_key()).unwrap();
    ks.allowed.extend([Algorithm::Ed25519, Algorithm::Esp256]);
    ks
}

// OP-94, OP-140 m.4: keys generated in the token sign COSE that verifies, and come back by label
#[test]
fn token_keys_sign_and_are_found_again() {
    let s = store();
    for (label, signer) in [
        ("sig-ed", s.generate_ed25519("sig-ed").unwrap()),
        ("sig-p256", s.generate_p256("sig-p256").unwrap()),
    ] {
        let msg = sign_sign1(&signer, [9; 32], "application/test+cbor", b"payload").unwrap();
        assert!(
            verify_sign1(
                &PureBackend,
                &msg,
                &keyset(&signer),
                "application/test+cbor"
            )
            .is_ok()
        );
        assert_eq!(s.signer(label).unwrap().public_key(), signer.public_key());
    }
    assert!(matches!(
        s.generate_ed25519("sig-ed"),
        Err(HsmError::Key(_))
    ));
    assert!(matches!(s.signer("missing"), Err(HsmError::Key(_))));
}

// OP-135 m.4: the token KEK wraps exactly like the in-process RFC 3394 KEK, so either can unwrap
#[test]
fn token_kek_matches_rfc_3394() {
    let s = store();
    let value = [0x42_u8; 32];
    let hsm = s.import_kek("kek-known", &Secret::new(value)).unwrap();
    let soft = SoftKek::new("kek-known", value);
    let dek = Dek::generate().unwrap();
    let wrapped = hsm.wrap(&dek).unwrap();
    assert_eq!(wrapped, soft.wrap(&dek).unwrap());
    assert!(soft.unwrap(&wrapped).unwrap().secret().ct_eq(dek.secret()));
    let generated = s.generate_kek("kek-new").unwrap();
    let w = generated.wrap(&dek).unwrap();
    assert!(generated.unwrap(&w).unwrap().secret().ct_eq(dek.secret()));
    assert!(hsm.unwrap(&w).is_err());
}

// CR-32, OP-74: a class DEK under the token KEK wraps part DEKs in process exactly like the
// token wraps under the same key
#[test]
fn token_and_class_dek_wrap_alike() {
    let s = store();
    let value = [0x24_u8; 32];
    let hsm = s.import_kek("kek-class", &Secret::new(value)).unwrap();
    let class = Dek::from_secret(Secret::new(value));
    let part = Dek::generate().unwrap();
    let wrapped = DekKek::new("class", &class).wrap(&part).unwrap();
    assert_eq!(wrapped, hsm.wrap(&part).unwrap());
    assert!(hsm.unwrap(&wrapped).unwrap().secret().ct_eq(part.secret()));
}

// OP-73: destroying a KEK crypto-shreds what it wrapped; only KEKs are destroyed this way
#[test]
fn a_destroyed_kek_unwraps_nothing() {
    let s = store();
    let kek = s.generate_kek("kek-shred").unwrap();
    let dek = Dek::generate().unwrap();
    let wrapped = kek.wrap(&dek).unwrap();
    s.destroy_kek("kek-shred").unwrap();
    assert!(kek.unwrap(&wrapped).is_err());
    assert!(matches!(s.kek("kek-shred"), Err(HsmError::Key(_))));
    assert!(matches!(s.destroy_kek("kek-shred"), Err(HsmError::Key(_))));
    s.generate_mac("mac-not-kek").unwrap();
    assert!(matches!(
        s.destroy_kek("mac-not-kek"),
        Err(HsmError::Key(_))
    ));
    assert!(s.mac("mac-not-kek").is_ok());
}

// OP-141 m.18
#[test]
fn token_mac_matches_hmac_sha256() {
    let s = store();
    let value = [0x24_u8; 32];
    let hsm = s.import_mac("mac-known", &Secret::new(value)).unwrap();
    let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, &value);
    let message = b"access/event/v1\0message";
    assert_eq!(
        hsm.mac(message).unwrap().as_slice(),
        aws_lc_rs::hmac::sign(&key, message).as_ref()
    );
    let generated = s.generate_mac("mac-new").unwrap();
    assert_ne!(generated.mac(message).unwrap(), hsm.mac(message).unwrap());
    assert_eq!(
        s.mac("mac-new").unwrap().mac(message).unwrap(),
        generated.mac(message).unwrap()
    );
    assert!(matches!(s.generate_mac("mac-new"), Err(HsmError::Key(_))));
}

// OP-141 m.22 (d)
#[test]
fn token_aead_seals_and_opens() {
    let s = store();
    let k = s.generate_aead("tokens").unwrap();
    let sealed = k.seal(b"aad", b"position 17").unwrap();
    assert_eq!(k.open(b"aad", &sealed).unwrap(), b"position 17");
    assert_ne!(k.seal(b"aad", b"position 17").unwrap(), sealed);
    assert!(k.open(b"other", &sealed).is_err());
    let mut flipped = sealed.clone();
    if let Some(last) = flipped.last_mut() {
        *last ^= 1;
    }
    assert!(k.open(b"aad", &flipped).is_err());
    assert!(k.open(b"aad", &sealed[..20]).is_err());
    let again = s.aead("tokens").unwrap();
    assert_eq!(again.open(b"aad", &sealed).unwrap(), b"position 17");
}

// OP-94: a wrong PIN or token is refused
#[test]
fn wrong_token_or_pin_is_refused() {
    let _ = store();
    assert!(matches!(
        KeyStore::open(&module(), "no-such-token", &Secret::new(String::from(PIN))),
        Err(HsmError::Token(_))
    ));
    assert!(matches!(
        KeyStore::open(&module(), &token(), &Secret::new(String::from("wrong"))),
        Err(HsmError::Session(_))
    ));
}

// OP-69, SA-59: each test process gets a SoftHSM store of its own, so token initialisation in
// one process never races key writes in another
#[test]
fn each_test_process_has_its_own_token_store() {
    let conf = PathBuf::from(std::env::var_os("SOFTHSM2_CONF").unwrap());
    let dir = conf.parent().unwrap();
    assert_eq!(
        dir.parent().and_then(|p| p.file_name()),
        Some(std::ffi::OsStr::new("process")),
        "run the PKCS#11 tests through nextest's softhsm-store wrapper (OP-69)"
    );
    let tokens = std::fs::read_to_string(&conf).unwrap();
    assert!(tokens.contains(&dir.join("tokens").display().to_string()));
}
