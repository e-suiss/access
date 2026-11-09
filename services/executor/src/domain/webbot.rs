//! Web Bot Auth (E51, RFC 9421): an executor's request carries an HTTP Message Signature over
//! `@authority` and `Signature-Agent` by an Ed25519 key, its `keyid` the key's RFC 7638
//! thumbprint. `Signature-Agent` names the Suiss directory, never the person. Nothing about the
//! request is disguised: no borrowed browser identity, no proxy rotation, no CAPTCHA solving; a
//! block is a handoff (Ek B 4328).

use access_kernel::json::b64url_encode;

/// The `tag` parameter of a Web Bot Auth signature.
pub const TAG: &str = "web-bot-auth";

/// How long a signature holds.
pub const LIFETIME_S: u64 = 60;

/// The `User-Agent` every executor request names: the executor as itself.
pub const USER_AGENT: &str = "access-executor/1";

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, the encoding of an RFC 8941 byte sequence.
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let pick = |shift: u32| {
            char::from(
                STD.get(((n >> shift) & 0x3f) as usize)
                    .copied()
                    .unwrap_or(b'='),
            )
        };
        out.push(pick(18));
        out.push(pick(12));
        out.push(if chunk.len() > 1 { pick(6) } else { '=' });
        out.push(if chunk.len() > 2 { pick(0) } else { '=' });
    }
    out
}

/// The signature's covered components and parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// The request's `host[:port]`.
    pub authority: String,
    /// The directory URL `Signature-Agent` names.
    pub agent: String,
    /// The key's RFC 7638 thumbprint.
    pub thumbprint: [u8; 32],
    /// Creation, Unix seconds.
    pub created: u64,
    /// A fresh nonce.
    pub nonce: [u8; 16],
}

impl Params {
    /// The `Signature-Agent` header value: an RFC 8941 string.
    #[must_use]
    pub fn agent_header(&self) -> String {
        format!("\"{}\"", self.agent)
    }

    /// The `@signature-params` inner list.
    #[must_use]
    pub fn inner(&self) -> String {
        format!(
            "(\"@authority\" \"signature-agent\");created={};expires={};keyid=\"{}\";alg=\"ed25519\";nonce=\"{}\";tag=\"{TAG}\"",
            self.created,
            self.created.saturating_add(LIFETIME_S),
            b64url_encode(&self.thumbprint),
            b64url_encode(&self.nonce),
        )
    }

    /// The RFC 9421 §2.5 signature base.
    #[must_use]
    pub fn base(&self) -> String {
        format!(
            "\"@authority\": {}\n\"signature-agent\": {}\n\"@signature-params\": {}",
            self.authority.to_ascii_lowercase(),
            self.agent_header(),
            self.inner()
        )
    }

    /// The three headers for `signature`: `Signature-Agent`, `Signature-Input`, `Signature`.
    #[must_use]
    pub fn headers(&self, signature: &[u8]) -> [(String, String); 3] {
        [
            (String::from("Signature-Agent"), self.agent_header()),
            (
                String::from("Signature-Input"),
                format!("sig1={}", self.inner()),
            ),
            (
                String::from("Signature"),
                format!("sig1=:{}:", base64(signature)),
            ),
        ]
    }
}

/// The `host[:port]` of an `https` URL.
#[must_use]
pub fn authority(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty() && !host.contains('@')).then_some(host)
}
