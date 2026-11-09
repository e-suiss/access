//! The embedded attestation roots (OP-154 m.3 (s), AG-31 model 1): pinned at build time from
//! `data/`, where `SOURCES` names each file's origin and `SHA256SUMS` its digest. Nothing is
//! fetched at build or run time; a new root is a new release.

/// Android hardware key attestation roots (Google).
pub const ANDROID: [&[u8]; 2] = [
    include_bytes!("../../data/google_hardware_attestation_root_2022.der"),
    include_bytes!("../../data/google_key_attestation_ca1.der"),
];

/// The Apple App Attest root.
pub const APPLE_APP_ATTEST: [&[u8]; 1] = [include_bytes!(
    "../../data/apple_app_attestation_root_ca.der"
)];

/// TPM 2.0 manufacturer roots (Infineon OPTIGA RSA and ECC, `STMicroelectronics`).
pub const TPM: [&[u8]; 3] = [
    include_bytes!("../../data/infineon_optiga_rsa_root_ca.der"),
    include_bytes!("../../data/infineon_optiga_ecc_root_ca.der"),
    include_bytes!("../../data/stmicro_tpm_ek_root_ca.der"),
];

/// The pinned digest lines (`sha256  file`).
pub const SHA256SUMS: &str = include_str!("../../data/SHA256SUMS");

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use std::fmt::Write as _;

    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    }

    // OP-154 m.3 (s), AG-31, Ek B 4125
    #[test]
    fn the_embedded_roots_are_the_pinned_files() {
        let files: [(&str, &[u8]); 6] = [
            ("apple_app_attestation_root_ca.der", APPLE_APP_ATTEST[0]),
            ("google_hardware_attestation_root_2022.der", ANDROID[0]),
            ("google_key_attestation_ca1.der", ANDROID[1]),
            ("infineon_optiga_ecc_root_ca.der", TPM[1]),
            ("infineon_optiga_rsa_root_ca.der", TPM[0]),
            ("stmicro_tpm_ek_root_ca.der", TPM[2]),
        ];
        let lines: Vec<Vec<&str>> = SHA256SUMS
            .lines()
            .map(|l| l.split_whitespace().collect())
            .collect();
        assert_eq!(lines.len(), files.len());
        for (name, der) in files {
            let digest = hex(&suiss_crypto::digest::sha256(der));
            assert!(
                lines
                    .iter()
                    .any(|l| l.as_slice() == [digest.as_str(), name]),
                "{name}"
            );
            assert!(
                webpki::anchor_from_trusted_cert(&rustls_pki_types::CertificateDer::from(der))
                    .is_ok(),
                "{name}"
            );
        }
    }
}
