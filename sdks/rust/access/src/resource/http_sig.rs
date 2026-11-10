//! HTTP Message Signatures (RFC 9421) at a resource server: the request side of FAPI 2.0
//! Message Signing (§10.4.3, OP-155 m.3 (k)). A request is accepted only when one signature
//! label covers every component the resource server requires, `created` is recent, the
//! algorithm is the key's own (`ecdsa-p256-sha256` or `ed25519`, never RSA or HMAC), and the
//! signature verifies over the rebuilt signature base. Anything else is refused (TI-9).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::verify::{PureBackend, ed25519, p256};

/// Longest `Signature-Input` or `Signature` field read.
pub const MAX_FIELD: usize = 4096;

/// Most components one signature may cover.
pub const MAX_COMPONENTS: usize = 32;

/// The client key a signature is verified with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SigKey {
    /// P-256, SEC1 uncompressed: `ecdsa-p256-sha256`.
    P256(Vec<u8>),
    /// Ed25519: `ed25519`.
    Ed25519([u8; 32]),
}

impl SigKey {
    const fn alg(&self) -> &'static str {
        match self {
            Self::P256(_) => "ecdsa-p256-sha256",
            Self::Ed25519(_) => "ed25519",
        }
    }
}

/// The request as the resource server received it.
#[derive(Clone, Copy, Debug)]
pub struct SignedRequest<'a> {
    /// `@method`, upper case.
    pub method: &'a str,
    /// `@target-uri`: the absolute request URI.
    pub target_uri: &'a str,
    /// `@authority`, lower case host and port.
    pub authority: &'a str,
    /// `@path`.
    pub path: &'a str,
    /// `@query` with its leading `?`, `?` when empty.
    pub query: &'a str,
    /// Header fields, names in any case, in the order received.
    pub headers: &'a [(&'a str, &'a str)],
}

/// What the resource server requires of a signature.
#[derive(Clone, Copy, Debug)]
pub struct SigRules<'a> {
    /// Components that must be covered, lower case: derived components with their `@`.
    pub required: &'a [&'a str],
    /// Now, Unix milliseconds.
    pub now_ms: u64,
    /// Oldest accepted `created`, as an age in milliseconds.
    pub max_age_ms: u64,
    /// Allowed clock skew for a `created` in the future, milliseconds.
    pub skew_ms: u64,
    /// The `keyid` the key is registered under, when the resource server pins it.
    pub keyid: Option<&'a str>,
}

/// Why a request signature is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HttpSigError {
    /// A field is missing, too large or not RFC 8941 structured as RFC 9421 needs.
    #[error("malformed signature fields")]
    Malformed,
    /// No label covers every required component, or a covered component is missing.
    #[error("components")]
    Components,
    /// `created` is missing, too old or in the future, or `expires` has passed.
    #[error("time")]
    Time,
    /// `alg` or `keyid` is not the registered key's.
    #[error("key")]
    Key,
    /// The signature does not verify.
    #[error("signature")]
    Signature,
}

/// What a verified signature showed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSignature {
    /// The label it was found under.
    pub label: String,
    /// The components it covers, in order.
    pub components: Vec<String>,
    /// `created`, Unix seconds.
    pub created: u64,
}

struct Params {
    components: Vec<String>,
    created: Option<u64>,
    expires: Option<u64>,
    keyid: Option<String>,
    alg: Option<String>,
    raw: String,
}

fn quoted(s: &str) -> Option<(&str, &str)> {
    let rest = s.strip_prefix('"')?;
    let end = rest.find('"')?;
    let value = rest.get(..end)?;
    if value.contains('\\') {
        return None;
    }
    Some((value, rest.get(end.checked_add(1)?..)?))
}

/// The `label=(...);params` members of a `Signature-Input` field.
fn inputs(field: &str) -> Option<Vec<(String, Params)>> {
    let mut out = Vec::new();
    let mut rest = field.trim();
    while !rest.is_empty() {
        let (label, after) = rest.split_once('=')?;
        let label = label.trim();
        if label.is_empty()
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return None;
        }
        let after = after.trim_start();
        let inner_end = after.find(')')?;
        let list = after.strip_prefix('(')?.get(..inner_end.checked_sub(1)?)?;
        let mut components = Vec::new();
        let mut l = list.trim();
        while !l.is_empty() {
            let (c, r) = quoted(l)?;
            if c.is_empty()
                || c.bytes().any(|b| b.is_ascii_uppercase())
                || components.iter().any(|x| x == c)
            {
                return None;
            }
            components.push(String::from(c));
            l = r.trim_start();
        }
        if components.len() > MAX_COMPONENTS {
            return None;
        }
        let mut tail = after.get(inner_end.checked_add(1)?..)?;
        let member_end = tail.find(',').unwrap_or(tail.len());
        let params_text = tail.get(..member_end)?;
        let raw = format!("{}{}", after.get(..=inner_end)?, params_text.trim_end());
        let mut p = Params {
            components,
            created: None,
            expires: None,
            keyid: None,
            alg: None,
            raw,
        };
        for kv in params_text.split(';').skip(1) {
            let (k, v) = kv.trim().split_once('=')?;
            match k {
                "created" => p.created = Some(v.parse().ok()?),
                "expires" => p.expires = Some(v.parse().ok()?),
                "keyid" => p.keyid = Some(String::from(quoted(v)?.0)),
                "alg" => p.alg = Some(String::from(quoted(v)?.0)),
                "nonce" | "tag" => {
                    quoted(v)?;
                }
                _ => return None,
            }
        }
        out.push((String::from(label), p));
        tail = tail.get(member_end..)?;
        rest = tail.strip_prefix(',').unwrap_or(tail).trim_start();
    }
    Some(out)
}

fn b64_std(s: &str) -> Option<Vec<u8>> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let body = s.trim_end_matches('=');
    if !s.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(body.len());
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    for c in body.bytes() {
        let v = u32::try_from(A.iter().position(|a| *a == c)?).ok()?;
        acc = (acc.wrapping_shl(6) | v) & 0xffff;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from(acc.wrapping_shr(bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// The `label=:bytes:` member of a `Signature` field.
fn signature_of(field: &str, label: &str) -> Option<Vec<u8>> {
    for member in field.split(',') {
        let (l, v) = member.trim().split_once('=')?;
        if l == label {
            return b64_std(v.trim().strip_prefix(':')?.strip_suffix(':')?);
        }
    }
    None
}

fn component(req: &SignedRequest<'_>, name: &str) -> Option<String> {
    Some(match name {
        "@method" => String::from(req.method),
        "@target-uri" => String::from(req.target_uri),
        "@authority" => String::from(req.authority),
        "@path" => String::from(req.path),
        "@query" => String::from(req.query),
        n if n.starts_with('@') => return None,
        n => {
            let values: Vec<&str> = req
                .headers
                .iter()
                .filter(|(h, _)| h.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.trim())
                .collect();
            if values.is_empty() {
                return None;
            }
            values.join(", ")
        }
    })
}

/// The RFC 9421 §2.5 signature base of `p` over `req`.
fn base(req: &SignedRequest<'_>, p: &Params) -> Option<String> {
    let mut out = String::new();
    for c in &p.components {
        let v = component(req, c)?;
        if v.contains('\n') {
            return None;
        }
        out.push('"');
        out.push_str(c);
        out.push_str("\": ");
        out.push_str(&v);
        out.push('\n');
    }
    out.push_str("\"@signature-params\": ");
    out.push_str(&p.raw);
    Some(out)
}

/// RFC 9421 §3.2: verifies the request's signature with `key` under `rules`, from its
/// `Signature-Input` and `Signature` field values. Of the labels present, the first that covers
/// every required component is the one checked.
///
/// # Errors
/// [`HttpSigError`].
pub fn verify(
    req: &SignedRequest<'_>,
    signature_input: &str,
    signature: &str,
    key: &SigKey,
    rules: &SigRules<'_>,
) -> Result<VerifiedSignature, HttpSigError> {
    if signature_input.len() > MAX_FIELD || signature.len() > MAX_FIELD {
        return Err(HttpSigError::Malformed);
    }
    let all = inputs(signature_input).ok_or(HttpSigError::Malformed)?;
    let (label, p) = all
        .into_iter()
        .find(|(_, p)| {
            rules
                .required
                .iter()
                .all(|r| p.components.iter().any(|c| c == r))
        })
        .ok_or(HttpSigError::Components)?;
    if p.alg.as_deref().is_some_and(|a| a != key.alg())
        || rules.keyid.is_some_and(|k| p.keyid.as_deref() != Some(k))
    {
        return Err(HttpSigError::Key);
    }
    let created = p.created.ok_or(HttpSigError::Time)?;
    let created_ms = created.checked_mul(1000).ok_or(HttpSigError::Time)?;
    if created_ms > rules.now_ms.saturating_add(rules.skew_ms)
        || rules.now_ms.saturating_sub(created_ms) > rules.max_age_ms
        || p.expires
            .is_some_and(|e| e.saturating_mul(1000) <= rules.now_ms)
    {
        return Err(HttpSigError::Time);
    }
    let base = base(req, &p).ok_or(HttpSigError::Components)?;
    let sig = signature_of(signature, &label).ok_or(HttpSigError::Malformed)?;
    let ok = match key {
        SigKey::P256(sec1) => p256(&PureBackend, sec1, base.as_bytes(), &sig, false).is_ok(),
        SigKey::Ed25519(pk) => ed25519(&PureBackend, pk, base.as_bytes(), &sig).is_ok(),
    };
    if !ok {
        return Err(HttpSigError::Signature);
    }
    Ok(VerifiedSignature {
        label,
        components: p.components,
        created,
    })
}
