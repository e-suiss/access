//! Test helpers shared by this binary's unit tests.

#![allow(clippy::unwrap_used, reason = "test code")]

/// A fresh token in the `SoftHSM` store `just test` prepares (`SOFTHSM2_CONF`, OP-69).
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
    let out = std::process::Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            &label,
            "--pin",
            "1234-test-only",
            "--so-pin",
            "5678-test-only",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    (module, label)
}
