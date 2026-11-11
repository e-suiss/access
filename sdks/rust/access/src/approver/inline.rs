//! CT1 approval inside the approver notification (OP-157 m.3 (m), m.17, §13.7.3, SEC26,
//! `approval-inline.cddl`). The app parses the `approval_inline` body, rebuilds the canonical
//! render with the Kernel, compares its digest and shows the render. A body whose render digest is
//! not the Kernel's own is refused here, on the device.
//!
//! - **Refuse**: [`deny_to_be_signed`] is what the device key signs, [`answer_body`] sends it.
//! - **Approve**: build the statement with [`statement`], then ask the platform passkey API
//!   (`ASAuthorizationPlatformPublicKeyCredentialProvider`, Android Credential Manager,
//!   `navigator.credentials.get`) for an assertion with the realm's RP ID and
//!   [`passkey_challenge`] as its challenge. This module never makes the assertion: it carries
//!   what the platform returned as a [`PasskeyAssertion`]. The device key signs
//!   [`approve_to_be_signed`], and [`approve_body`] sends both. Access verifies the assertion
//!   against the approver's registered passkey in the realm as it verifies a sign-in (user
//!   presence always, user verification when an open term asks for it), and only that makes the
//!   approval phishing resistant; a device key's signature alone is never a contribution.
//!
//! ```
//! use access_sdk::approver::inline::{InlineRequest, NotInline};
//!
//! assert_eq!(InlineRequest::parse(b"{}"), Err(NotInline));
//! ```

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::aas::{self, Act, ApprovalAct, EvidenceLevel, SurfaceClass};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::json::{self, Json, b64url_decode, b64url_encode};
use access_kernel::model::Id;
use access_kernel::render::{self, Render};
use suiss_crypto::dcbor::{self, Limits, Value};

/// The surface profile a statement signed here reports.
pub const SURFACE_PROFILE: &str = "suiss-approver-sdk";
/// Its version.
pub const SURFACE_VERSION: u64 = 1;

/// Largest `approval_inline` body read.
pub const MAX_INLINE: usize = 64 * 1024;

/// Why a body is not a valid `approval_inline`, or its render can't be trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not an inline approval")]
pub struct NotInline;

/// An `approval_inline` body as Relay delivered it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineRequest {
    /// The intent digest, the invitation's name.
    pub intent: Digest,
    /// The canonical render's bytes.
    pub render: Vec<u8>,
    /// The render digest the decision point computed.
    pub render_digest: Digest,
    /// Unix ms after which the approval is refused.
    pub expires_at_ms: u64,
}

fn hex32(text: &str) -> Option<Digest> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        let [hi, lo] = *pair;
        let hi = char::from(hi).to_digit(16)?;
        let lo = char::from(lo).to_digit(16)?;
        *slot = u8::try_from(hi.checked_mul(16)?.checked_add(lo)?).ok()?;
    }
    Some(Digest(out))
}

impl InlineRequest {
    /// Reads the `data` object of an `approval_inline` message.
    ///
    /// # Errors
    /// [`NotInline`].
    pub fn parse(data: &[u8]) -> Result<Self, NotInline> {
        let v = json::parse(data, MAX_INLINE).map_err(|_| NotInline)?;
        let text = |name: &str| v.get(name).and_then(Json::as_str).ok_or(NotInline);
        Ok(Self {
            intent: hex32(text("intent")?).ok_or(NotInline)?,
            render: b64url_decode(text("render")?).map_err(|_| NotInline)?,
            render_digest: hex32(text("render_digest")?).ok_or(NotInline)?,
            expires_at_ms: v
                .get("expires_at_ms")
                .and_then(Json::as_int)
                .and_then(|v| u64::try_from(v).ok())
                .ok_or(NotInline)?,
        })
    }

    /// The Kernel's render of these bytes, when its digest is the one the decision point computed
    /// and it is the render of the named intent. Show nothing else.
    ///
    /// # Errors
    /// [`NotInline`]: the device refuses a render it can't reproduce.
    pub fn verified(&self) -> Result<Render, NotInline> {
        let shown = render::decode(&self.render).map_err(|_| NotInline)?;
        let digest = render::digest(&shown).map_err(|_| NotInline)?;
        if digest != self.render_digest || shown.intent != self.intent {
            return Err(NotInline);
        }
        Ok(shown)
    }
}

/// What the app knows when it builds the statement: its own Instance, the pre-signed
/// contribution and trusted time.
#[derive(Clone, Debug)]
pub struct StatementFacts {
    /// The contribute class.
    pub class: String,
    /// The approver device Instance whose key signed the contribution.
    pub instance: Id,
    /// The approver's Party.
    pub party: Id,
    /// The contribution's capacity.
    pub capacity: Capacity,
    /// The governing domain.
    pub domain: Digest,
    /// The contribution's nonce.
    pub nonce: Vec<u8>,
    /// Now, Unix ms.
    pub issued_at: u64,
    /// At most 15 minutes after `issued_at` (§13.7.3).
    pub expires_at: u64,
}

/// The statement of an approval given on this device: a phone surface, a phishing-resistant
/// passkey assertion as its evidence and the material fields of the verified `render`. The
/// evidence is only a ceiling: Access lowers it to what the verified assertion established
/// (§10.3.1, E49).
#[must_use]
pub fn statement(request: &InlineRequest, render: &Render, facts: StatementFacts) -> ApprovalAct {
    ApprovalAct {
        act: Act::Contribution(facts.class),
        instance: facts.instance,
        party: facts.party,
        capacity: facts.capacity,
        target: request.intent,
        domain: facts.domain,
        nonce: facts.nonce,
        work_gate: None,
        surface_profile: String::from(SURFACE_PROFILE),
        surface_version: SURFACE_VERSION,
        surface_class: Some(SurfaceClass::Phone),
        evidence: Some(EvidenceLevel::PhishingResistant),
        surface_origin: None,
        render_digest: request.render_digest,
        material_fields: render::material_fields(render),
        issued_at: facts.issued_at,
        expires_at: facts.expires_at,
    }
}

/// H(AAS) of `act`: what the device key signs inside the answer.
///
/// # Errors
/// [`NotInline`]: the statement can't be encoded.
pub fn statement_digest(act: &ApprovalAct) -> Result<Digest, NotInline> {
    aas::digest(act).map_err(|_| NotInline)
}

/// The challenge to ask the platform passkey API for: the 32 bytes of H(AAS) (verifier name
/// binding, §10.3.1). Use the realm's RP ID with it.
///
/// # Errors
/// [`NotInline`]: the statement can't be encoded.
pub fn passkey_challenge(act: &ApprovalAct) -> Result<[u8; 32], NotInline> {
    statement_digest(act).map(|d| d.0)
}

/// The assertion the platform passkey API returned, as raw bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasskeyAssertion {
    /// `rawId`: the approver's registered passkey.
    pub credential_id: Vec<u8>,
    /// `response.authenticatorData`.
    pub authenticator_data: Vec<u8>,
    /// `response.clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// `response.signature`.
    pub signature: Vec<u8>,
    /// `response.userHandle`, when the platform returned one.
    pub user_handle: Option<Vec<u8>>,
}

fn answer(
    invite: &Digest,
    render_digest: &Digest,
    device_key: &[u8; 32],
    decision: &str,
    aas: Option<Value>,
) -> Vec<u8> {
    let mut entries = Vec::with_capacity(5);
    if let Some(aas) = aas {
        entries.push((Value::text("aas"), aas));
    }
    entries.push((Value::text("invite"), Value::Bytes(invite.0.to_vec())));
    entries.push((Value::text("decision"), Value::text(decision)));
    entries.push((Value::text("device_key"), Value::Bytes(device_key.to_vec())));
    entries.push((
        Value::text("render_digest"),
        Value::Bytes(render_digest.0.to_vec()),
    ));
    dcbor::encode(&Value::Map(entries), Limits::CEILING).unwrap_or_default()
}

/// The deterministic CBOR the device key signs to approve (`approval-inline-answer`).
#[must_use]
pub fn approve_to_be_signed(
    request: &InlineRequest,
    act: &ApprovalAct,
    device_key: &[u8; 32],
) -> Vec<u8> {
    answer(
        &request.intent,
        &request.render_digest,
        device_key,
        "approve",
        Some(act.to_value()),
    )
}

/// The deterministic CBOR the device key signs to refuse.
#[must_use]
pub fn deny_to_be_signed(request: &InlineRequest, device_key: &[u8; 32]) -> Vec<u8> {
    answer(
        &request.intent,
        &request.render_digest,
        device_key,
        "deny",
        None,
    )
}

/// The JSON body of `POST /v1/approve/inline` that refuses: the signed bytes and the raw
/// `r ‖ s` signature. Access answers an approval sent this way with
/// `approval-inline-assertion-required`.
#[must_use]
pub fn answer_body(to_be_signed: &[u8], signature: &[u8; 64]) -> String {
    format!(
        r#"{{"answer":"{}","signature":"{}"}}"#,
        b64url_encode(to_be_signed),
        b64url_encode(signature)
    )
}

/// The JSON body of `POST /v1/approve/inline` that approves: the signed bytes, the raw
/// `r ‖ s` signature and the passkey `assertion` over [`passkey_challenge`].
#[must_use]
pub fn approve_body(
    to_be_signed: &[u8],
    signature: &[u8; 64],
    assertion: &PasskeyAssertion,
) -> String {
    let user_handle = assertion
        .user_handle
        .as_deref()
        .map(|h| format!(r#","user_handle":"{}""#, b64url_encode(h)))
        .unwrap_or_default();
    format!(
        r#"{{"answer":"{}","signature":"{}","assertion":{{"credential_id":"{}","authenticator_data":"{}","client_data_json":"{}","signature":"{}"{user_handle}}}}}"#,
        b64url_encode(to_be_signed),
        b64url_encode(signature),
        b64url_encode(&assertion.credential_id),
        b64url_encode(&assertion.authenticator_data),
        b64url_encode(&assertion.client_data_json),
        b64url_encode(&assertion.signature),
    )
}
