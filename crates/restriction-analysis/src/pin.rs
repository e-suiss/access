use crate::AnalysisError;

// OP-105, F-2
const PIN: &str = include_str!("../../../supply-chain/cvc5.toml");

/// The platform key used in `supply-chain/cvc5.toml`.
pub(crate) fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// The pinned cvc5 version.
pub(crate) fn version() -> Result<String, AnalysisError> {
    let table: toml::Table = PIN.parse().map_err(|_| AnalysisError::Pin)?;
    table
        .get("version")
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or(AnalysisError::Pin)
}

/// The pinned sha256 of the cvc5 executable for `platform`.
pub(crate) fn binary_sha256(platform: &str) -> Result<[u8; 32], AnalysisError> {
    let table: toml::Table = PIN.parse().map_err(|_| AnalysisError::Pin)?;
    let hex = table
        .get("platform")
        .and_then(|p| p.get(platform))
        .ok_or(AnalysisError::UnsupportedPlatform)?
        .get("binary_sha256")
        .and_then(toml::Value::as_str)
        .ok_or(AnalysisError::Pin)?;
    decode_hex(hex).ok_or(AnalysisError::Pin)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => b.checked_sub(b'0'),
        b'a'..=b'f' => b.checked_sub(b'a')?.checked_add(10),
        _ => None,
    }
}

pub(crate) fn decode_hex(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (o, [hi, lo]) in out.iter_mut().zip(pairs) {
        *o = nibble(*hi)?.checked_mul(16)?.checked_add(nibble(*lo)?)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-105
    #[test]
    fn every_pinned_platform_has_a_well_formed_binary_hash() {
        for p in ["linux-x86_64", "linux-aarch64", "macos-aarch64"] {
            assert!(binary_sha256(p).is_ok(), "{p}");
        }
        assert_eq!(version().unwrap(), "1.3.1");
    }

    #[test]
    fn unknown_platform_has_no_pin() {
        assert!(matches!(
            binary_sha256("windows-x86_64"),
            Err(AnalysisError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn hex_decoding_is_strict() {
        let ok = "00".repeat(31) + "ff";
        assert_eq!(decode_hex(&ok).map(|h| h[31]), Some(0xff));
        assert!(decode_hex(&("00".repeat(31) + "FF")).is_none());
        assert!(decode_hex(&("00".repeat(31) + "f")).is_none());
        assert!(decode_hex(&("00".repeat(31) + "fg")).is_none());
    }
}
