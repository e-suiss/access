use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use super::*;
use crate::cose::{KeySet, verify_sign1};
use crate::envelope::SoftKek;
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

/// One token per test process, in the `SoftHSM` store `just test` prepares (`SOFTHSM2_CONF`).
fn store() -> &'static KeyStore {
    static STORE: OnceLock<KeyStore> = OnceLock::new();
    STORE.get_or_init(|| {
        assert!(
            std::env::var_os("SOFTHSM2_CONF").is_some(),
            "run the PKCS#11 tests through `just test`, which sets SOFTHSM2_CONF (OP-69)"
        );
        let out = Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                &token(),
                "--pin",
                PIN,
                "--so-pin",
                "5678-test-only",
            ])
            .output()
            .unwrap();
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
