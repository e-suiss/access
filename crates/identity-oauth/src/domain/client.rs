//! Registered clients as the authorization server reads them (TN-15, IDP-7): how each
//! authenticates at the token endpoint, the exact redirect URIs with the RFC 8252 loopback
//! exception, and how a request presents its client credentials (RFC 6749 §2.3).

use access_crypto::oauth::secret_matches;
use access_store::idp::ClientRow;

use crate::domain::dpop::ClientType;

/// How a client authenticates at the token endpoint (§11.4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientAuth {
    /// A public client: PKCE and DPoP only.
    None,
    /// `private_key_jwt` against the client's published JWKS (RFC 7523).
    PrivateKeyJwt {
        /// The JWKS URI.
        jwks_uri: String,
    },
    /// `client_secret_basic` with a server-generated secret stored as a digest (CR-38).
    SecretBasic {
        /// The secret's digest.
        digest: [u8; 32],
    },
}

/// An active client of the realm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    /// Internal id; the pairwise sector (OP-146 m.5 (b)).
    pub uuid: [u8; 16],
    /// The opaque `client_id`.
    pub id: String,
    /// The display name, for consent and sign-out pages.
    pub name: String,
    /// Token endpoint authentication.
    pub auth: ClientAuth,
    /// Redirect URIs, exact strings.
    pub redirect_uris: Vec<String>,
    /// Post-logout redirect URIs, exact strings.
    pub post_logout_redirect_uris: Vec<String>,
    /// The back-channel logout endpoint.
    pub backchannel_logout_uri: Option<String>,
}

impl Client {
    /// The client of a stored row; `None` for a retired client or a row that does not match
    /// the model (fail-closed).
    #[must_use]
    pub fn from_row(row: ClientRow) -> Option<Self> {
        if !row.active {
            return None;
        }
        let auth = match (row.auth_method.as_str(), row.jwks_uri, row.secret_hash) {
            ("none", None, None) => ClientAuth::None,
            ("private_key_jwt", Some(jwks_uri), None) => ClientAuth::PrivateKeyJwt { jwks_uri },
            ("client_secret_basic", None, Some(digest)) => ClientAuth::SecretBasic { digest },
            _ => return None,
        };
        Some(Self {
            uuid: row.client_uuid,
            id: row.client_id,
            name: row.display_name,
            auth,
            redirect_uris: row.redirect_uris,
            post_logout_redirect_uris: row.post_logout_redirect_uris,
            backchannel_logout_uri: row.backchannel_logout_uri,
        })
    }

    /// Whether the client can keep a secret (RFC 6749 §2.1).
    #[must_use]
    pub const fn client_type(&self) -> ClientType {
        match self.auth {
            ClientAuth::None => ClientType::Public,
            _ => ClientType::Confidential,
        }
    }

    /// Whether `presented` is one of the client's redirect URIs (IDP-7).
    #[must_use]
    pub fn redirect_allowed(&self, presented: &str) -> bool {
        self.redirect_uris
            .iter()
            .any(|r| redirect_matches(r, presented))
    }

    /// Whether `presented` is one of the client's post-logout redirect URIs, compared as an
    /// exact string (§10.4.6).
    #[must_use]
    pub fn post_logout_allowed(&self, presented: &str) -> bool {
        self.post_logout_redirect_uris
            .iter()
            .any(|r| r == presented)
    }
}

const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "[::1]", "localhost"];

fn loopback(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix("http://")?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = match authority.strip_prefix("[::1]") {
        Some(port) => (port.is_empty() || port.starts_with(':')).then_some("[::1]")?,
        None => authority.split_once(':').map_or(authority, |(h, _)| h),
    };
    let port_ok = authority
        .get(host.len()..)
        .is_some_and(|p| p.is_empty() || p.strip_prefix(':').is_some_and(port_digits));
    (LOOPBACK_HOSTS.contains(&host) && port_ok).then_some((host, tail))
}

fn port_digits(p: &str) -> bool {
    (1..=5).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_digit())
}

/// IDP-7, OP-146 m.5 (h), RFC 8252 §7.3: a redirect URI matches by exact string comparison;
/// for an `http` loopback URI only the port is free: scheme, host, path and query still match
/// exactly. No pattern, no wildcard, no "semantically equal" URI.
#[must_use]
pub fn redirect_matches(registered: &str, presented: &str) -> bool {
    if registered == presented {
        return true;
    }
    match (loopback(registered), loopback(presented)) {
        (Some((rh, rt)), Some((ph, pt))) => rh == ph && rt == pt,
        _ => false,
    }
}

/// Why a request's client credentials are refused; every case answers `invalid_client`
/// (RFC 6749 §5.2) except a malformed request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientAuthError {
    /// More than one method, or a malformed `Authorization` header (RFC 6749 §2.3).
    #[error("malformed client authentication")]
    Malformed,
    /// No such active client.
    #[error("unknown client")]
    Unknown,
    /// The method is not the client's registered one.
    #[error("wrong method")]
    Method,
    /// The secret or assertion did not verify.
    #[error("credentials rejected")]
    Rejected,
}

impl ClientAuthError {
    /// The OAuth error code.
    #[must_use]
    pub const fn error(self) -> &'static str {
        match self {
            Self::Malformed => "invalid_request",
            _ => "invalid_client",
        }
    }
}

/// The JWT bearer client assertion type (RFC 7523 §2.2).
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// What a request presents to authenticate its client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Presented {
    /// Only `client_id`: a public client.
    Id(String),
    /// HTTP Basic (`client_secret_basic`).
    Basic {
        /// The client.
        client_id: String,
        /// The secret, as sent.
        secret: String,
    },
    /// A JWT bearer assertion (`private_key_jwt`).
    Assertion {
        /// The client, from `client_id` when present, else from the assertion's `sub`.
        client_id: Option<String>,
        /// The compact JWT.
        assertion: String,
    },
}

impl Presented {
    /// The `client_id` it names, when it names one outside an assertion.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        match self {
            Self::Id(id) | Self::Basic { client_id: id, .. } => Some(id),
            Self::Assertion { client_id, .. } => client_id.as_deref(),
        }
    }
}

fn b64_std_decode(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let body = s.trim_end_matches('=');
    if !s.len().is_multiple_of(4) || s.len().saturating_sub(body.len()) > 2 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len());
    let mut acc = 0_u32;
    let mut bits = 0_u32;
    for c in body.bytes() {
        let v = ALPHABET.iter().position(|a| *a == c)?;
        acc = (acc.wrapping_shl(6) | u32::try_from(v).ok()?) & 0xffff;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from(acc.wrapping_shr(bits) & 0xff).ok()?);
        }
    }
    let rest = acc & 1_u32.wrapping_shl(bits).wrapping_sub(1);
    (rest == 0).then_some(out)
}

/// `application/x-www-form-urlencoded` decoding of one value.
#[must_use]
pub fn form_decode(value: &str) -> Option<String> {
    let b = value.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = b.get(i.checked_add(1)?..i.checked_add(3)?)?;
                out.push(u8::from_str_radix(core::str::from_utf8(hex).ok()?, 16).ok()?);
                i = i.checked_add(2)?;
            }
            _ => out.push(c),
        }
        i = i.checked_add(1)?;
    }
    String::from_utf8(out).ok()
}

/// The client credentials a token, PAR, revocation or introspection request presents: an
/// `Authorization: Basic` header, a client assertion, or only `client_id`. Using more than one
/// method is refused (RFC 6749 §2.3).
///
/// # Errors
/// [`ClientAuthError::Malformed`].
pub fn presented(
    authorization: Option<&str>,
    client_id: Option<&str>,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
) -> Result<Option<Presented>, ClientAuthError> {
    let basic = authorization
        .map(|h| {
            let (scheme, value) = h.split_once(' ').ok_or(ClientAuthError::Malformed)?;
            if !scheme.eq_ignore_ascii_case("basic") {
                return Err(ClientAuthError::Malformed);
            }
            let raw = b64_std_decode(value.trim()).ok_or(ClientAuthError::Malformed)?;
            let text = String::from_utf8(raw).map_err(|_| ClientAuthError::Malformed)?;
            let (id, secret) = text.split_once(':').ok_or(ClientAuthError::Malformed)?;
            Ok((
                form_decode(id).ok_or(ClientAuthError::Malformed)?,
                form_decode(secret).ok_or(ClientAuthError::Malformed)?,
            ))
        })
        .transpose()?;
    match (basic, assertion_type, assertion) {
        (Some((id, secret)), None, None) => {
            if client_id.is_some_and(|c| c != id) || id.is_empty() {
                return Err(ClientAuthError::Malformed);
            }
            Ok(Some(Presented::Basic {
                client_id: id,
                secret,
            }))
        }
        (None, Some(ASSERTION_TYPE), Some(a)) => Ok(Some(Presented::Assertion {
            client_id: client_id.map(String::from),
            assertion: String::from(a),
        })),
        (None, None, None) => Ok(client_id.map(|c| Presented::Id(String::from(c)))),
        _ => Err(ClientAuthError::Malformed),
    }
}

/// Checks the presented method against the client's registration; an assertion is checked
/// by the caller against the client's keys (OP-146 m.5, RFC 7523).
///
/// # Errors
/// [`ClientAuthError`].
pub fn check_method(client: &Client, presented: &Presented) -> Result<(), ClientAuthError> {
    match (&client.auth, presented) {
        (ClientAuth::None, Presented::Id(_))
        | (ClientAuth::PrivateKeyJwt { .. }, Presented::Assertion { .. }) => Ok(()),
        (ClientAuth::SecretBasic { digest }, Presented::Basic { secret, .. }) => {
            if secret_matches(digest, secret.as_bytes()) {
                Ok(())
            } else {
                Err(ClientAuthError::Rejected)
            }
        }
        _ => Err(ClientAuthError::Method),
    }
}

#[cfg(test)]
mod tests;
