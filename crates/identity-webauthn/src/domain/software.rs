//! A software authenticator for local deployments (OP-149 m.26 (e), m.29 (b)): the registration
//! and assertion responses of a passkey whose Ed25519 key lives elsewhere, so a bootstrap can
//! register the test user's passkey through the hosted registration path and a headless client
//! can answer the same realm's assertion ceremonies. It is deterministic: user present and
//! user verified, device-bound (BE = 0), a fixed AAGUID, no counter, `none` attestation, and a
//! credential id that is the key's thumbprint. Nothing here weakens a verifier (TI-9): the
//! responses are checked by the same ceremony code as any authenticator's.

use access_crypto::webauthn::sha256;
use access_kernel::json::b64url_encode;
use access_kernel::verify::cose::PublicKey;
use access_kernel::verify::key_scope::thumbprint;
use serde_json::{Value, json};

use super::authenticator_data::Flags;
use super::ids::Aaguid;

/// The AAGUID every software authenticator of a local deployment reports.
pub const SOFTWARE_AAGUID: Aaguid = Aaguid(*b"suiss-local-pkey");

/// WebAuthn `clientDataJSON` of a ceremony `kind` over `challenge` at `origin`.
#[must_use]
pub fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    json!({
        "type": kind,
        "challenge": b64url_encode(challenge),
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string()
    .into_bytes()
}

/// A passkey on an Ed25519 key (`EdDSA`, −8) held outside this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SoftwareAuthenticator {
    /// The Ed25519 public key.
    pub public_key: [u8; 32],
    /// The credential id: the key's RFC 7638 thumbprint.
    pub credential_id: [u8; 32],
}

fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    match b.len() {
        n if n < 24 => out.push(0x40 | u8::try_from(n).unwrap_or(0)),
        n if n < 256 => out.extend_from_slice(&[0x58, u8::try_from(n).unwrap_or(0)]),
        n => {
            out.push(0x59);
            out.extend_from_slice(&u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes());
        }
    }
    out.extend_from_slice(b);
}

impl SoftwareAuthenticator {
    /// The passkey of `public_key`.
    #[must_use]
    pub fn ed25519(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            credential_id: thumbprint(&PublicKey::Ed25519(public_key)),
        }
    }

    /// The `COSE_Key` (OKP, Ed25519, `EdDSA`) as deterministic CBOR.
    #[must_use]
    pub fn cose_key(&self) -> Vec<u8> {
        let mut out = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
        cbor_bytes(&mut out, &self.public_key);
        out
    }

    /// Authenticator data for `rp_id`: UP and UV set, BE and BS clear, counter zero, with the
    /// attested credential when `attested`.
    #[must_use]
    pub fn authenticator_data(&self, rp_id: &str, attested: bool) -> Vec<u8> {
        let mut out = sha256(rp_id.as_bytes()).to_vec();
        let mut flags = Flags::UP | Flags::UV;
        if attested {
            flags |= Flags::AT;
        }
        out.push(flags);
        out.extend_from_slice(&0_u32.to_be_bytes());
        if attested {
            out.extend_from_slice(&SOFTWARE_AAGUID.0);
            out.extend_from_slice(
                &u16::try_from(self.credential_id.len())
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
            out.extend_from_slice(&self.credential_id);
            out.extend_from_slice(&self.cose_key());
        }
        out
    }

    /// The registration response over `challenge`: `clientDataJSON` and a `none` attestation
    /// object. No signature is involved, so the key itself is not needed.
    #[must_use]
    pub fn registration(&self, rp_id: &str, origin: &str, challenge: &[u8]) -> Registration {
        let client_data_json = client_data("webauthn.create", challenge, origin);
        let auth_data = self.authenticator_data(rp_id, true);
        let mut attestation_object = vec![
            0xa3, 0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e', 0x67, b'a', b't', b't',
            b'S', b't', b'm', b't', 0xa0, 0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a',
        ];
        cbor_bytes(&mut attestation_object, &auth_data);
        Registration {
            id: self.credential_id.to_vec(),
            client_data_json,
            attestation_object,
        }
    }

    /// The assertion over `challenge`: the message `authenticatorData ‖ SHA-256(clientDataJSON)`
    /// is given to `sign`, which holds the key.
    ///
    /// # Errors
    /// Whatever `sign` returns.
    pub fn assertion<E>(
        &self,
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    ) -> Result<Assertion, E> {
        let client_data_json = client_data("webauthn.get", challenge, origin);
        let authenticator_data = self.authenticator_data(rp_id, false);
        let mut message = authenticator_data.clone();
        message.extend_from_slice(&sha256(&client_data_json));
        let signature = sign(&message)?;
        Ok(Assertion {
            id: self.credential_id.to_vec(),
            client_data_json,
            authenticator_data,
            signature,
        })
    }
}

/// What `navigator.credentials.create()` would return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// `rawId`.
    pub id: Vec<u8>,
    /// `response.clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// `response.attestationObject`.
    pub attestation_object: Vec<u8>,
}

impl Registration {
    /// The `PublicKeyCredential` JSON (`toJSON()`), `internal` transport.
    #[must_use]
    pub fn json(&self) -> Value {
        let id = b64url_encode(&self.id);
        json!({
            "id": id, "rawId": id, "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(&self.client_data_json),
                "attestationObject": b64url_encode(&self.attestation_object),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
        })
    }
}

/// What `navigator.credentials.get()` would return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assertion {
    /// `rawId`.
    pub id: Vec<u8>,
    /// `response.clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// `response.authenticatorData`.
    pub authenticator_data: Vec<u8>,
    /// `response.signature`.
    pub signature: Vec<u8>,
}

impl Assertion {
    /// The `PublicKeyCredential` JSON (`toJSON()`), without a `userHandle`: the identifier-first
    /// and approval ceremonies know the account.
    #[must_use]
    pub fn json(&self) -> Value {
        let id = b64url_encode(&self.id);
        json!({
            "id": id, "rawId": id, "type": "public-key",
            "response": {
                "clientDataJSON": b64url_encode(&self.client_data_json),
                "authenticatorData": b64url_encode(&self.authenticator_data),
                "signature": b64url_encode(&self.signature),
            },
            "clientExtensionResults": {},
        })
    }
}
