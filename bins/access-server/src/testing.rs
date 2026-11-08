//! Test helpers shared by this binary's unit tests.

#![allow(clippy::unwrap_used, reason = "test code")]

/// A fresh token in this test process's own `SoftHSM` store (`SOFTHSM2_CONF`, OP-69).
pub(crate) fn hsm(name: &str) -> (std::path::PathBuf, String) {
    assert!(
        std::env::var_os("SOFTHSM2_CONF").is_some(),
        "run the PKCS#11 tests through `just test`, which sets SOFTHSM2_CONF (OP-69)"
    );
    let module = [
        std::env::var("SUISS_PKCS11_MODULE").unwrap_or_default(),
        String::from("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"),
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .find(|p| p.is_file())
    .unwrap();
    let label = format!("{name}-{}", std::process::id());
    let out = suiss_crypto::pkcs11::token_tests::init_softhsm_token(
        None,
        &label,
        "1234-test-only",
        "5678-test-only",
    )
    .unwrap();
    assert!(out.status.success(), "{out:?}");
    (module, label)
}
