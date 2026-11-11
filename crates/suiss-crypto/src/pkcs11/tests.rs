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

// OP-94, OP-140 m.4
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

// OP-135 m.4
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

// CR-32, OP-74
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

// OP-73
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

// OP-94
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

// OP-69, SA-59
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

/// Fresh tokens of this process under `names`, made before the module is first initialised in
/// it (`SoftHSM` lists the tokens it finds then), for tests that need their own login state.
fn own_tokens(names: &[&str]) {
    for name in names {
        let label = format!("{name}-{}", std::process::id());
        let out =
            super::token_tests::init_softhsm_token(None, &label, PIN, "5678-test-only").unwrap();
        assert!(out.status.success(), "{out:?}");
    }
}

/// [`own_tokens`] for one token, opened.
fn own_store(name: &str) -> KeyStore {
    own_tokens(&[name]);
    own_reopen(name)
}

/// Runs the ignored test `name` in a child test process and returns how it exited.
fn in_child(name: &str) -> std::process::ExitStatus {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--ignored", "--nocapture"])
        .env("SUISS_PKCS11_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(60),
            "{name} did not exit"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn exercise(s: &KeyStore) -> (HsmKek, HsmSigner) {
    let kek = s.generate_kek("kek-shutdown").unwrap();
    let dek = Dek::generate().unwrap();
    assert!(kek.unwrap(&kek.wrap(&dek).unwrap()).is_ok());
    let signer = s.generate_p256("sig-shutdown").unwrap();
    assert!(signer.sign(b"in flight").is_ok());
    (kek, signer)
}

#[test]
#[ignore = "child of the_shutdown_order_exits_cleanly"]
fn child_orderly_shutdown() {
    if std::env::var_os("SUISS_PKCS11_CHILD").is_none() {
        return;
    }
    let s = own_store("shutdown");
    let (kek, signer) = exercise(&s);
    assert_eq!(s.open_handles(), 2);
    drop(signer);
    let s = match s.finalize() {
        Err(HsmError::Busy(1)) => own_reopen("shutdown"),
        other => panic!("{other:?}"),
    };
    drop(kek);
    assert_eq!(s.open_handles(), 0);
    s.finalize().unwrap();
}

fn own_reopen(name: &str) -> KeyStore {
    KeyStore::open(
        &module(),
        &format!("{name}-{}", std::process::id()),
        &Secret::new(String::from(PIN)),
    )
    .unwrap()
}

#[test]
#[ignore = "child of a_store_dropped_with_open_sessions_exits_cleanly"]
fn child_dropped_with_sessions() {
    if std::env::var_os("SUISS_PKCS11_CHILD").is_none() {
        return;
    }
    let s = own_store("dropped");
    let handles = exercise(&s);
    drop(s);
    drop(handles);
}

// OP-94, OP-158
#[test]
fn the_shutdown_order_exits_cleanly() {
    let status = in_child("pkcs11::tests::child_orderly_shutdown");
    assert!(status.success(), "{status:?}");
}

// OP-94
#[test]
fn a_store_dropped_with_open_sessions_exits_cleanly() {
    let status = in_child("pkcs11::tests::child_dropped_with_sessions");
    assert!(status.success(), "{status:?}");
}

// OP-138, OP-158
#[test]
fn a_kek_rotation_rewraps_inside_the_token() {
    let s = store();
    let (old_value, new_value) = (random_key(), random_key());
    let old = s.import_kek("kek-rot-1", &Secret::new(old_value)).unwrap();
    let new = s.import_kek("kek-rot-2", &Secret::new(new_value)).unwrap();
    let dek = Dek::generate().unwrap();
    let wrapped = old.wrap(&dek).unwrap();
    let moved = old.rewrap(&wrapped, &new).unwrap();
    let soft = crate::envelope::rewrap(
        &SoftKek::new("kek-rot-1", old_value),
        &SoftKek::new("kek-rot-2", new_value),
        &wrapped,
    )
    .unwrap();
    assert_eq!(moved, soft);
    assert!(new.unwrap(&moved).unwrap().secret().ct_eq(dek.secret()));
    assert!(old.unwrap(&moved).is_err());
    assert!(new.rewrap(&wrapped, &old).is_err());
}

// CR-30, OP-158
#[test]
fn a_binding_key_clones_to_the_dr_token() {
    own_tokens(&["primary0", "dr0", "other0", "primary1", "dr1", "other1"]);
    for (n, ed25519) in [(0, true), (1, false)] {
        let primary = own_reopen(&format!("primary{n}"));
        let dr = own_reopen(&format!("dr{n}"));
        let value = random_key();
        let so = Secret::new(String::from("5678-test-only"));
        for t in [&primary, &dr] {
            t.install_clone_key(&so, "clone", &Secret::new(value))
                .unwrap();
        }
        let binding = primary.generate_cloneable("binding", ed25519).unwrap();
        // OP-158 m.3 (y)
        let backup = match primary.export_clone("binding", "clone") {
            Ok(b) => b,
            Err(e) if not_wrappable(&e) => continue,
            Err(e) => panic!("{e:?}"),
        };
        assert_eq!(backup.public, binding.public_key());
        let clone = dr.import_clone("binding", "clone", &backup).unwrap();
        assert_eq!(clone.public_key(), binding.public_key());
        let sig = clone.sign(b"metadata").unwrap();
        let ok = match binding.public_key() {
            PublicKey::Ed25519(p) => crate::sig::ed25519(&PureBackend, &p, b"metadata", &sig),
            PublicKey::P256(p) => crate::sig::p256(&PureBackend, &p, b"metadata", &sig, true),
            other @ PublicKey::MlDsa(..) => panic!("{other:?}"),
        };
        assert!(ok.is_ok());
        assert!(matches!(
            dr.import_clone("binding", "clone", &backup),
            Err(HsmError::Key(_))
        ));
        primary.generate_kek("plain").unwrap();
        assert!(matches!(
            primary.export_clone("binding", "plain"),
            Err(HsmError::Operation(_))
        ));
        primary.generate_ed25519("fixed").unwrap();
        assert!(matches!(
            primary.export_clone("fixed", "clone"),
            Err(HsmError::Operation(_))
        ));
        let other = own_reopen(&format!("other{n}"));
        let wrong = random_key();
        other
            .install_clone_key(&so, "clone", &Secret::new(wrong))
            .unwrap();
        assert!(other.import_clone("binding", "clone", &backup).is_err());
        drop((binding, clone));
        for t in [primary, dr, other] {
            drop(t);
        }
    }
}

// CR-30
#[test]
fn the_clone_key_needs_the_security_officer_and_idle_handles() {
    let s = own_store("so");
    let value = Secret::new(random_key());
    assert!(matches!(
        s.install_clone_key(&Secret::new(String::from(PIN)), "clone", &value),
        Err(HsmError::Session(_))
    ));
    let held = s.generate_kek("held").unwrap();
    assert!(matches!(
        s.install_clone_key(
            &Secret::new(String::from("5678-test-only")),
            "clone",
            &value
        ),
        Err(HsmError::Busy(1))
    ));
    drop(held);
}

fn random_key() -> [u8; 32] {
    aws_lc_rs::rand::generate(&aws_lc_rs::rand::SystemRandom::new())
        .unwrap()
        .expose()
}

fn not_wrappable(e: &HsmError) -> bool {
    let text = format!("{e:?}");
    text.contains("KeyNotWrappable") || text.contains("unable to wrap the key")
}
