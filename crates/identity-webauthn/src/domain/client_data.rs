//! `clientDataJSON` (WebAuthn L3 §5.8.1), parsed with the strict bounded JSON reader (CR-10).

use access_crypto::webauthn::sha256;
use access_kernel::json::{Json, b64url_decode, parse};
use access_parse::cbor::MAX_INPUT;

use super::Rejection;
use super::rp::{Origin, RelyingParty};

/// Which ceremony the client data must describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyType {
    /// `webauthn.create`.
    Create,
    /// `webauthn.get`.
    Get,
    /// `payment.get`: a Secure Payment Confirmation assertion (W3C SPC, OP-156 m.3 (g)).
    Payment,
}

impl CeremonyType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "webauthn.create",
            Self::Get => "webauthn.get",
            Self::Payment => "payment.get",
        }
    }
}

/// Checked client data.
#[derive(Clone, Debug)]
pub struct ClientData {
    /// The origin the browser reported, already checked against the RP.
    pub origin: Origin,
    /// SHA-256 of the raw JSON bytes, the second half of the signed message.
    pub hash: [u8; 32],
}

/// Parses and checks `clientDataJSON`: type, challenge, origin, and no cross-origin or
/// `topOrigin` context.
///
/// # Errors
/// [`Rejection`].
pub fn check_client_data(
    raw: &[u8],
    expected: CeremonyType,
    challenge: &[u8],
    rp: &RelyingParty,
) -> Result<ClientData, Rejection> {
    let json = parse(raw, MAX_INPUT).map_err(|_| Rejection::ClientData)?;
    let text = |name: &str| json.get(name).and_then(Json::as_str);
    let kind = text("type").ok_or(Rejection::ClientData)?;
    if kind != expected.as_str() {
        return Err(Rejection::CeremonyType);
    }
    let presented = text("challenge")
        .and_then(|c| b64url_decode(c).ok())
        .ok_or(Rejection::ClientData)?;
    // CR-39 m.1, m.4, SAI-42
    if !access_crypto::Secret::new(sha256(challenge)).ct_eq_bytes(&sha256(&presented)) {
        return Err(Rejection::Challenge);
    }
    let origin = text("origin")
        .and_then(Origin::parse)
        .ok_or(Rejection::Origin)?;
    if !rp.allows(&origin) {
        return Err(Rejection::Origin);
    }
    match json.get("crossOrigin") {
        None | Some(Json::Bool(false)) => {}
        Some(Json::Bool(true)) => return Err(Rejection::CrossOrigin),
        Some(_) => return Err(Rejection::ClientData),
    }
    if json.get("topOrigin").is_some() {
        return Err(Rejection::CrossOrigin);
    }
    Ok(ClientData {
        origin,
        hash: sha256(raw),
    })
}
