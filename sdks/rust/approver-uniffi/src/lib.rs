//! The approver module of the public SDK for Swift, Kotlin and Python (OP-156 m.3 (d)): an app
//! that embeds it answers push verifications with its app-bound P-256 key. The key stays in the
//! platform key store; these functions build what it signs and what the app sends. Signatures may
//! be raw `r ‖ s` or DER as key stores return them.

#![forbid(unsafe_code)]
#![allow(clippy::needless_pass_by_value)]

uniffi::setup_scaffolding!();

use access_sdk::approver::{
    Answer, Decision, PushRequest, answer_body, registration_body, registration_message,
    same_device_body, same_device_message, thumbprint, to_raw_signature,
};

/// Why an approver input was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum ApproverError {
    /// Not an uncompressed P-256 public key or a 32-byte thumbprint or challenge.
    #[error("key")]
    Key,
    /// Not an ECDSA P-256 signature.
    #[error("signature")]
    Signature,
    /// Not a `push_approval` body.
    #[error("push")]
    Push,
    /// Not `approve`, `deny` or `not_me`, or a number outside 10–99.
    #[error("answer")]
    Answer,
}

fn bytes32(v: &[u8]) -> Result<[u8; 32], ApproverError> {
    <[u8; 32]>::try_from(v).map_err(|_| ApproverError::Key)
}

fn raw(signature: &[u8]) -> Result<[u8; 64], ApproverError> {
    to_raw_signature(signature).ok_or(ApproverError::Signature)
}

/// A push as Relay delivered it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ApproverPush {
    /// The challenge id to answer.
    pub challenge: Vec<u8>,
    /// The application; show it as text.
    pub application: String,
    /// What is approved; show it as text.
    pub action: String,
    /// The coarse location, when known.
    pub location: Option<String>,
    /// RFC 3339.
    pub expires_at: String,
    /// The text to show; never the number, which the person reads from the sign-in page.
    pub prompt: String,
}

/// The RFC 7638 thumbprint of an uncompressed SEC1 P-256 key.
///
/// # Errors
/// [`ApproverError::Key`].
#[uniffi::export]
pub fn approver_thumbprint(public_key: Vec<u8>) -> Result<Vec<u8>, ApproverError> {
    thumbprint(&public_key)
        .map(|t| t.to_vec())
        .ok_or(ApproverError::Key)
}

/// What the key signs to register on `issuer`.
///
/// # Errors
/// [`ApproverError::Key`].
#[uniffi::export]
pub fn approver_registration_message(
    issuer: String,
    thumbprint: Vec<u8>,
) -> Result<Vec<u8>, ApproverError> {
    Ok(registration_message(&issuer, &bytes32(&thumbprint)?))
}

/// The JSON body of `POST /v1/approvers`.
///
/// # Errors
/// [`ApproverError`].
#[uniffi::export]
pub fn approver_registration_body(
    name: String,
    public_key: Vec<u8>,
    signature: Vec<u8>,
) -> Result<String, ApproverError> {
    thumbprint(&public_key).ok_or(ApproverError::Key)?;
    Ok(registration_body(&name, &public_key, &raw(&signature)?))
}

/// Reads the `data` of a `push_approval` message.
///
/// # Errors
/// [`ApproverError::Push`].
#[uniffi::export]
pub fn approver_parse_push(data: Vec<u8>) -> Result<ApproverPush, ApproverError> {
    let p = PushRequest::parse(&data).map_err(|_| ApproverError::Push)?;
    let prompt = p.prompt();
    Ok(ApproverPush {
        challenge: p.challenge.to_vec(),
        application: p.application,
        action: p.action,
        location: p.location,
        expires_at: p.expires_at,
        prompt,
    })
}

/// The deterministic CBOR the key signs to answer `challenge`.
///
/// # Errors
/// [`ApproverError`].
#[uniffi::export]
pub fn approver_answer(
    challenge: Vec<u8>,
    number: Option<u8>,
    decision: String,
    device_key: Vec<u8>,
    pin_verified: Option<bool>,
) -> Result<Vec<u8>, ApproverError> {
    let decision = match decision.as_str() {
        "approve" => Decision::Approve,
        "deny" => Decision::Deny,
        "not_me" => Decision::NotMe,
        _ => return Err(ApproverError::Answer),
    };
    if number.is_some_and(|n| !(10..=99).contains(&n)) {
        return Err(ApproverError::Answer);
    }
    Ok(Answer {
        challenge: bytes32(&challenge)?,
        number,
        decision,
        device_key: bytes32(&device_key)?,
        pin_verified,
    }
    .to_be_signed())
}

/// The JSON body of `POST /v1/push/answer`.
///
/// # Errors
/// [`ApproverError::Signature`].
#[uniffi::export]
pub fn approver_answer_body(answer: Vec<u8>, signature: Vec<u8>) -> Result<String, ApproverError> {
    Ok(answer_body(&answer, &raw(&signature)?))
}

/// What the key signs to say it started the sign-in flow `handle` on `issuer` itself.
#[uniffi::export]
#[must_use]
pub fn approver_same_device_message(issuer: String, handle: String) -> Vec<u8> {
    same_device_message(&issuer, &handle)
}

/// The JSON body of `POST /v1/push/challenge` for an in-app sign-in.
///
/// # Errors
/// [`ApproverError`].
#[uniffi::export]
pub fn approver_same_device_body(
    handle: String,
    thumbprint: Vec<u8>,
    signature: Vec<u8>,
) -> Result<String, ApproverError> {
    Ok(same_device_body(
        &handle,
        &bytes32(&thumbprint)?,
        &raw(&signature)?,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-156 m.3 (d)
    #[test]
    fn the_binding_refuses_what_the_sdk_refuses() {
        assert_eq!(
            approver_answer(vec![1; 32], Some(9), "approve".into(), vec![2; 32], None),
            Err(ApproverError::Answer)
        );
        assert_eq!(
            approver_answer(vec![1; 32], None, "maybe".into(), vec![2; 32], None),
            Err(ApproverError::Answer)
        );
        let signed =
            approver_answer(vec![1; 32], Some(42), "approve".into(), vec![2; 32], None).unwrap();
        assert_eq!(
            approver_answer_body(signed, vec![0; 64]),
            Err(ApproverError::Signature)
        );
        assert_eq!(approver_thumbprint(vec![2; 65]), Err(ApproverError::Key));
        assert_eq!(
            approver_parse_push(b"{}".to_vec()),
            Err(ApproverError::Push)
        );
    }
}
