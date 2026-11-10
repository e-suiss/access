//! The holder's side of a certificate (OP-156 m.3 (o)): the ephemeral Ed25519 key in the
//! OpenSSH private key format `ssh` reads from a file (`PROTOCOL.key`, unencrypted, the file
//! kept `0600` by the caller), and the `SSH2_AGENTC_ADD_ID_CONSTRAINED` message that hands the
//! key and its certificate to `ssh-agent` with a lifetime (draft-miller-ssh-agent).

use suiss_crypto::note::base64_encode;

use super::cert::{CERT_TYPE, Certificate};
use super::key::{ED25519, Ed25519Public};
use super::wire::Writer;
use crate::SshError;

/// `SSH2_AGENTC_ADD_ID_CONSTRAINED`.
pub const ADD_ID_CONSTRAINED: u8 = 25;

/// `SSH_AGENT_CONSTRAIN_LIFETIME`.
pub const CONSTRAIN_LIFETIME: u8 = 1;

/// `SSH_AGENT_SUCCESS`.
pub const AGENT_SUCCESS: u8 = 6;

/// The magic of the private key format.
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

fn private_part(seed: &[u8; 32], key: &Ed25519Public) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(seed);
    out.extend_from_slice(&key.0);
    out
}

/// The unencrypted OpenSSH private key file of `seed` (public key `key`), PEM-armoured;
/// `check` is a random value the format repeats to detect a wrong passphrase.
///
/// # Errors
/// [`SshError::TooLarge`] never in practice.
pub fn private_key_file(
    seed: &[u8; 32],
    key: &Ed25519Public,
    comment: &str,
    check: u32,
) -> Result<String, SshError> {
    let mut private = Writer::new();
    private
        .u32(check)
        .u32(check)
        .string(ED25519.as_bytes())?
        .string(&key.0)?
        .string(&private_part(seed, key))?
        .string(comment.as_bytes())?;
    let mut pad: u8 = 1;
    while !private.bytes().len().is_multiple_of(8) {
        private.byte(pad);
        pad = pad.wrapping_add(1);
    }
    let mut w = Writer::new();
    w.raw(AUTH_MAGIC)
        .string(b"none")?
        .string(b"none")?
        .string(&[])?
        .u32(1)
        .string(&key.blob())?
        .string(private.bytes())?;
    let b64 = base64_encode(w.bytes());
    let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(70) {
        out.push_str(core::str::from_utf8(line).map_err(|_| SshError::Malformed)?);
        out.push('\n');
    }
    out.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    Ok(out)
}

/// The framed agent message that adds `certificate` with its private key `seed`, removed by the
/// agent after `lifetime_s` seconds.
///
/// # Errors
/// [`SshError::TooLarge`].
pub fn add_identity(
    certificate: &Certificate,
    seed: &[u8; 32],
    key: &Ed25519Public,
    comment: &str,
    lifetime_s: u32,
) -> Result<Vec<u8>, SshError> {
    let mut body = Writer::new();
    body.byte(ADD_ID_CONSTRAINED)
        .string(CERT_TYPE.as_bytes())?
        .string(&certificate.0)?
        .string(&key.0)?
        .string(&private_part(seed, key))?
        .string(comment.as_bytes())?
        .byte(CONSTRAIN_LIFETIME)
        .u32(lifetime_s);
    let mut framed = Writer::new();
    framed.string(body.bytes())?;
    Ok(framed.finish())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    #[test]
    fn the_private_key_file_is_padded_and_armoured() {
        let file = private_key_file(&[1; 32], &Ed25519Public([2; 32]), "c", 7).unwrap();
        assert!(file.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(file.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        assert!(file.lines().all(|l| l.len() <= 70));
        let msg = add_identity(
            &Certificate(vec![0; 10]),
            &[1; 32],
            &Ed25519Public([2; 32]),
            "c",
            60,
        )
        .unwrap();
        assert_eq!(msg[4], ADD_ID_CONSTRAINED);
        assert_eq!(
            u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize,
            msg.len() - 4
        );
    }
}
