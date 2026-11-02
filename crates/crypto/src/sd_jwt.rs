//! SD-JWT production (RFC 9901, L0-SIG-50…52, CR-6 (c)): the issuer-signed JWT with
//! selectively disclosable top-level claims, and the holder's presentation with a key binding
//! JWT. Verification is the Kernel's (`verify::sd_jwt`).

use std::collections::BTreeSet;

use access_kernel::json::{Json, b64url_encode};
use access_kernel::model::TrustedTime;
use access_kernel::verify::key_scope::thumbprint;
use aws_lc_rs::digest::{SHA256, digest};
use suiss_crypto::signer::Signer;

use crate::jose::output::{self, JsonOutError};
use crate::jose::{JoseError, sign_compact, sign_compact_unkeyed};
use crate::random::RandomError;

/// `typ` of the key binding JWT (RFC 9901 §4.3).
pub const KB_TYP: &str = "kb+jwt";

/// Salt length in bytes (RFC 9901 §9.3: at least 128 bits).
pub const SALT_LEN: usize = 16;

// L0-SIG-51, L0-SIG-52
const NEVER_DISCLOSABLE: [&str; 5] = ["iss", "exp", "nbf", "iat", "cnf"];
const RESERVED: [&str; 3] = ["_sd", "_sd_alg", "..."];

/// Why an SD-JWT or a presentation could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SdJwtIssueError {
    /// Signing failed.
    #[error("jose: {0}")]
    Jose(#[from] JoseError),
    /// A claim has no JSON form.
    #[error("json: {0}")]
    Json(#[from] JsonOutError),
    /// A reserved or repeated claim name, a disclosable claim that is not issued, or one that
    /// must stay in the clear.
    #[error("claim")]
    Claim,
    /// The holder asked to reveal a disclosure the SD-JWT does not have.
    #[error("disclosure")]
    Disclosure,
    /// No randomness for a salt.
    #[error("no randomness")]
    Random,
}

impl SdJwtIssueError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Jose(e) => e.code(),
            Self::Json(_) => "sd-jwt-json",
            Self::Claim => "sd-jwt-claim",
            Self::Disclosure => "sd-jwt-disclosure",
            Self::Random => "sd-jwt-random",
        }
    }
}

/// One disclosure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    /// The claim name it discloses.
    pub name: String,
    /// The base64url disclosure.
    pub encoded: String,
}

/// An issued SD-JWT: the issuer-signed JWT and every disclosure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issued {
    /// The issuer-signed JWT.
    pub jwt: String,
    /// The disclosures, in claim order.
    pub disclosures: Vec<Disclosure>,
}

impl Issued {
    /// The SD-JWT with every disclosure and no key binding, `<jwt>~<disclosure>~…~`.
    #[must_use]
    pub fn serialize(&self) -> String {
        let mut out = self.jwt.clone();
        for d in &self.disclosures {
            out.push('~');
            out.push_str(&d.encoded);
        }
        out.push('~');
        out
    }
}

fn digest_of(disclosure: &str) -> String {
    b64url_encode(digest(&SHA256, disclosure.as_bytes()).as_ref())
}

/// Issues an SD-JWT over `claims` signed by `signer`, with `kid` the key's RFC 7638
/// thumbprint (CR-24). Each claim named in `disclosable` becomes a disclosure with a fresh
/// salt from `salt`; `_sd` lists their digests sorted, and `_sd_alg` is always written
/// (L0-SIG-50). `iss`, `exp`, `nbf`, `iat` and `cnf` are never disclosable.
///
/// # Errors
/// [`SdJwtIssueError`].
pub fn issue(
    signer: &dyn Signer,
    typ: &str,
    claims: Vec<(String, Json)>,
    disclosable: &BTreeSet<String>,
    salt: &mut dyn FnMut() -> Result<[u8; SALT_LEN], RandomError>,
) -> Result<Issued, SdJwtIssueError> {
    let mut names = BTreeSet::new();
    for (name, _) in &claims {
        if RESERVED.contains(&name.as_str()) || !names.insert(name.as_str()) {
            return Err(SdJwtIssueError::Claim);
        }
    }
    if disclosable
        .iter()
        .any(|d| !names.contains(d.as_str()) || NEVER_DISCLOSABLE.contains(&d.as_str()))
    {
        return Err(SdJwtIssueError::Claim);
    }
    let mut payload = Vec::new();
    let mut digests = Vec::new();
    let mut disclosures = Vec::new();
    for (name, value) in claims {
        if disclosable.contains(&name) {
            let salt = salt().map_err(|_| SdJwtIssueError::Random)?;
            let array = Json::Array(vec![
                Json::Str(b64url_encode(&salt)),
                Json::Str(name.clone()),
                value,
            ]);
            let encoded = b64url_encode(output::to_string(&array).as_bytes());
            digests.push(digest_of(&encoded));
            disclosures.push(Disclosure { name, encoded });
        } else {
            payload.push((name, value));
        }
    }
    if !digests.is_empty() {
        digests.sort();
        payload.push((
            String::from("_sd"),
            Json::Array(digests.into_iter().map(Json::Str).collect()),
        ));
    }
    payload.push((String::from("_sd_alg"), output::text("sha-256")));
    let kid = thumbprint(&signer.public_key());
    let jwt = sign_compact(
        signer,
        &kid,
        typ,
        output::to_string(&Json::Object(payload)).as_bytes(),
    )?;
    Ok(Issued { jwt, disclosures })
}

/// The holder's proof of possession for one verifier (RFC 9901 §4.3, L0-SIG-52).
#[derive(Clone, Copy)]
pub struct KeyBinding<'a> {
    /// The holder's key, the one in `cnf.jwk`.
    pub signer: &'a dyn Signer,
    /// The verifier.
    pub audience: &'a str,
    /// The verifier's nonce.
    pub nonce: &'a str,
    /// Signing time in milliseconds; written in seconds.
    pub iat: TrustedTime,
}

/// A presentation revealing the disclosures of the claims in `reveal`, with a key binding JWT
/// over it when `binding` is given.
///
/// # Errors
/// [`SdJwtIssueError`].
pub fn present(
    issued: &Issued,
    reveal: &BTreeSet<String>,
    binding: Option<&KeyBinding<'_>>,
) -> Result<String, SdJwtIssueError> {
    if reveal
        .iter()
        .any(|r| !issued.disclosures.iter().any(|d| d.name == *r))
    {
        return Err(SdJwtIssueError::Disclosure);
    }
    let mut out = issued.jwt.clone();
    for d in issued
        .disclosures
        .iter()
        .filter(|d| reveal.contains(&d.name))
    {
        out.push('~');
        out.push_str(&d.encoded);
    }
    out.push('~');
    if let Some(kb) = binding {
        let payload = Json::Object(vec![
            (String::from("iat"), output::int(kb.iat / 1000)?),
            (String::from("aud"), output::text(kb.audience)),
            (String::from("nonce"), output::text(kb.nonce)),
            (String::from("sd_hash"), Json::Str(digest_of(&out))),
        ]);
        let jwt = sign_compact_unkeyed(kb.signer, KB_TYP, output::to_string(&payload).as_bytes())?;
        out.push_str(&jwt);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
