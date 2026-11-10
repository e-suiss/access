//! The ACME resources Access reads (RFC 8555 §7.1): the directory, orders, authorizations and
//! their challenges, and problem documents. Every document is bounded before it is parsed, and
//! every URL in it must stay on the directory's own origin.

use super::AcmeError;

/// Largest ACME JSON document read.
pub const MAX_DOCUMENT: usize = 64 * 1024;

/// Most authorizations or challenges read from one document.
pub const MAX_ITEMS: usize = 16;

/// The media type of ACME requests (§6.2).
pub const JOSE_JSON: &str = "application/jose+json";

/// The media type of a certificate chain (§9.1).
pub const PEM_CHAIN: &str = "application/pem-certificate-chain";

/// The problem type of a stale nonce, retried with a fresh one (§6.5).
pub const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";

/// The `scheme://authority` of an `https` URL.
#[must_use]
pub fn origin(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..end)?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    url.get(..end.checked_add("https://".len())?)
}

/// `url` when it is on `base`'s origin.
///
/// # Errors
/// [`AcmeError::Protocol`].
pub fn on_origin(base: &str, url: &str) -> Result<String, AcmeError> {
    match (origin(base), origin(url)) {
        (Some(a), Some(b)) if a == b => Ok(url.to_owned()),
        _ => Err(AcmeError::Protocol("url off the directory origin")),
    }
}

fn parse(body: &[u8]) -> Result<serde_json::Value, AcmeError> {
    if body.len() > MAX_DOCUMENT {
        return Err(AcmeError::Protocol("document too large"));
    }
    serde_json::from_slice(body).map_err(|_| AcmeError::Protocol("json"))
}

fn text(v: &serde_json::Value, key: &str) -> Result<String, AcmeError> {
    v.get(key)
        .and_then(serde_json::Value::as_str)
        .map(String::from)
        .ok_or(AcmeError::Protocol("missing member"))
}

fn url(base: &str, v: &serde_json::Value, key: &str) -> Result<String, AcmeError> {
    on_origin(base, &text(v, key)?)
}

/// The directory (§7.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Directory {
    /// The directory URL itself.
    pub url: String,
    /// `newNonce`.
    pub new_nonce: String,
    /// `newAccount`.
    pub new_account: String,
    /// `newOrder`.
    pub new_order: String,
}

impl Directory {
    /// Reads the directory at `url`.
    ///
    /// # Errors
    /// [`AcmeError::Protocol`].
    pub fn read(url: &str, body: &[u8]) -> Result<Self, AcmeError> {
        let v = parse(body)?;
        Ok(Self {
            url: url.to_owned(),
            new_nonce: self::url(url, &v, "newNonce")?,
            new_account: self::url(url, &v, "newAccount")?,
            new_order: self::url(url, &v, "newOrder")?,
        })
    }
}

/// The state of an order, authorization or challenge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// `pending`.
    Pending,
    /// `ready` (orders).
    Ready,
    /// `processing`.
    Processing,
    /// `valid`.
    Valid,
    /// `invalid`, `deactivated`, `expired` or `revoked`.
    Invalid,
}

impl State {
    fn read(v: &serde_json::Value) -> Result<Self, AcmeError> {
        Ok(match text(v, "status")?.as_str() {
            "pending" => Self::Pending,
            "ready" => Self::Ready,
            "processing" => Self::Processing,
            "valid" => Self::Valid,
            "invalid" | "deactivated" | "expired" | "revoked" => Self::Invalid,
            _ => return Err(AcmeError::Protocol("status")),
        })
    }
}

/// An order (§7.1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    /// Its state.
    pub state: State,
    /// Its authorizations.
    pub authorizations: Vec<String>,
    /// Its `finalize` URL.
    pub finalize: String,
    /// The certificate URL, once valid.
    pub certificate: Option<String>,
}

impl Order {
    /// Reads an order of the directory `base`.
    ///
    /// # Errors
    /// [`AcmeError::Protocol`].
    pub fn read(base: &str, body: &[u8]) -> Result<Self, AcmeError> {
        let v = parse(body)?;
        let list = v
            .get("authorizations")
            .and_then(serde_json::Value::as_array)
            .ok_or(AcmeError::Protocol("authorizations"))?;
        if list.is_empty() || list.len() > MAX_ITEMS {
            return Err(AcmeError::Protocol("authorizations"));
        }
        let authorizations = list
            .iter()
            .map(|a| {
                a.as_str()
                    .ok_or(AcmeError::Protocol("authorization"))
                    .and_then(|u| on_origin(base, u))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            state: State::read(&v)?,
            authorizations,
            finalize: url(base, &v, "finalize")?,
            certificate: v
                .get("certificate")
                .and_then(serde_json::Value::as_str)
                .map(|u| on_origin(base, u))
                .transpose()?,
        })
    }
}

/// A challenge (§8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// Its type, e.g. `tls-alpn-01`.
    pub kind: String,
    /// Its URL.
    pub url: String,
    /// Its token.
    pub token: String,
    /// Its state.
    pub state: State,
}

/// An authorization (§7.1.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    /// Its state.
    pub state: State,
    /// The `dns` identifier it authorizes.
    pub host: String,
    /// Its challenges.
    pub challenges: Vec<Challenge>,
}

/// The challenge type Access answers (RFC 8737).
pub const TLS_ALPN_01: &str = "tls-alpn-01";

impl Authorization {
    /// Reads an authorization of the directory `base`.
    ///
    /// # Errors
    /// [`AcmeError::Protocol`].
    pub fn read(base: &str, body: &[u8]) -> Result<Self, AcmeError> {
        let v = parse(body)?;
        let identifier = v
            .get("identifier")
            .ok_or(AcmeError::Protocol("identifier"))?;
        if text(identifier, "type")? != "dns" {
            return Err(AcmeError::Protocol("identifier type"));
        }
        let list = v
            .get("challenges")
            .and_then(serde_json::Value::as_array)
            .ok_or(AcmeError::Protocol("challenges"))?;
        if list.len() > MAX_ITEMS {
            return Err(AcmeError::Protocol("challenges"));
        }
        let challenges = list
            .iter()
            .map(|c| {
                Ok(Challenge {
                    kind: text(c, "type")?,
                    url: url(base, c, "url")?,
                    token: c
                        .get("token")
                        .and_then(serde_json::Value::as_str)
                        .map(String::from)
                        .unwrap_or_default(),
                    state: State::read(c)?,
                })
            })
            .collect::<Result<_, AcmeError>>()?;
        Ok(Self {
            state: State::read(&v)?,
            host: text(identifier, "value")?.to_ascii_lowercase(),
            challenges,
        })
    }

    /// Its TLS-ALPN-01 challenge.
    #[must_use]
    pub fn tls_alpn(&self) -> Option<&Challenge> {
        self.challenges.iter().find(|c| c.kind == TLS_ALPN_01)
    }
}

/// The `type` of a problem document (RFC 7807, §6.7), if the body is one.
#[must_use]
pub fn problem_type(body: &[u8]) -> Option<String> {
    let v = parse(body).ok()?;
    v.get("type")
        .and_then(serde_json::Value::as_str)
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8555 §7.1
    #[test]
    fn resources_are_read_and_urls_stay_on_the_directory_origin() {
        let base = "https://acme.example:14000/dir";
        let dir = Directory::read(
            base,
            br#"{"newNonce":"https://acme.example:14000/nonce","newAccount":"https://acme.example:14000/acct","newOrder":"https://acme.example:14000/order"}"#,
        )
        .unwrap();
        assert_eq!(dir.new_order, "https://acme.example:14000/order");
        assert!(
            Directory::read(
                base,
                br#"{"newNonce":"https://evil.example/n","newAccount":"https://acme.example:14000/a","newOrder":"https://acme.example:14000/o"}"#
            )
            .is_err()
        );
        let order = Order::read(
            base,
            br#"{"status":"pending","authorizations":["https://acme.example:14000/authz/1"],"finalize":"https://acme.example:14000/fin/1"}"#,
        )
        .unwrap();
        assert_eq!(order.state, State::Pending);
        assert!(order.certificate.is_none());
        let authz = Authorization::read(
            base,
            br#"{"status":"pending","identifier":{"type":"dns","value":"Login.Acme.Example"},"challenges":[{"type":"http-01","url":"https://acme.example:14000/c/1","token":"a","status":"pending"},{"type":"tls-alpn-01","url":"https://acme.example:14000/c/2","token":"b","status":"pending"}]}"#,
        )
        .unwrap();
        assert_eq!(authz.host, "login.acme.example");
        assert_eq!(authz.tls_alpn().unwrap().token, "b");
        assert_eq!(origin("https://a.example/x?y"), Some("https://a.example"));
        assert_eq!(origin("https://u@a.example/"), None);
        assert_eq!(
            problem_type(br#"{"type":"urn:ietf:params:acme:error:badNonce"}"#).as_deref(),
            Some(BAD_NONCE)
        );
    }
}
