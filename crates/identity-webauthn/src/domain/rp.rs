//! The realm's relying party: RP ID, allowed origins and the Related Origin Requests document
//! (IDP-5, MD-5, TN-17, TN-18).

use core::fmt;

use super::ids::RealmId;

/// Ceiling for distinct registrable-domain labels in `/.well-known/webauthn` (TN-18, PD).
pub const MAX_RELATED_LABELS: usize = 5;

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

fn valid_host(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(valid_label)
        && host
            .rsplit('.')
            .next()
            .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

fn is_localhost(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// A WebAuthn RP ID: a lower-case DNS name, never an IP address. One per realm (MD-5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RpId(String);

impl RpId {
    /// Parses an RP ID.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        valid_host(text).then(|| Self(text.to_owned()))
    }

    /// The RP ID text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn covers(&self, host: &str) -> bool {
        host == self.0
            || host
                .strip_suffix(self.0.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'))
    }
}

/// A web origin: `https://host[:port]`, or `http://` on `localhost` and `*.localhost`, which
/// browsers treat as secure contexts (OP-146 m.4 (a)).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    secure: bool,
    host: String,
    port: Option<u16>,
}

impl Origin {
    /// Parses a serialized origin as browsers put it in `clientDataJSON`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (secure, rest) = if let Some(rest) = text.strip_prefix("https://") {
            (true, rest)
        } else {
            (false, text.strip_prefix("http://")?)
        };
        let (host, port) = match rest.split_once(':') {
            Some((host, port)) => {
                if port.is_empty()
                    || port.starts_with('0')
                    || !port.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                (host, Some(port.parse::<u16>().ok()?))
            }
            None => (rest, None),
        };
        if !valid_host(host) || (!secure && !is_localhost(host)) {
            return None;
        }
        let default_port = if secure { 443 } else { 80 };
        if port == Some(default_port) {
            return None;
        }
        Some(Self {
            secure,
            host: host.to_owned(),
            port,
        })
    }

    /// The host part.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Whether the origin is `https`.
    #[must_use]
    pub const fn is_https(&self) -> bool {
        self.secure
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.secure { "https" } else { "http" };
        match self.port {
            Some(p) => write!(f, "{scheme}://{}:{p}", self.host),
            None => write!(f, "{scheme}://{}", self.host),
        }
    }
}

impl fmt::Debug for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Origin({self})")
    }
}

/// A realm's relying party.
#[derive(Clone)]
pub struct RelyingParty {
    /// The realm.
    pub realm: RealmId,
    /// The RP ID, fixed on day one (TN-17).
    pub rp_id: RpId,
    /// Display name for `rp.name`.
    pub name: String,
    /// Whether the RP ID is pinned; registration waits for it (IDP-5).
    pub pinned: bool,
    /// Related origins outside the RP ID's domain, served at `/.well-known/webauthn` (TN-18).
    pub related: Vec<Origin>,
}

impl RelyingParty {
    /// Whether `origin` may run ceremonies for this RP: the RP ID's host or a subdomain of it,
    /// or a declared related origin.
    #[must_use]
    pub fn allows(&self, origin: &Origin) -> bool {
        self.rp_id.covers(origin.host()) || self.related.contains(origin)
    }
}

/// The registrable domain of a host (eTLD+1); [`super::psl::Psl`] answers it from the embedded
/// Public Suffix List (OP-153 m.25 (f)).
pub trait PublicSuffix {
    /// The registrable domain of `host`, if it has one.
    fn registrable<'h>(&self, host: &'h str) -> Option<&'h str>;
}

/// Why a Related Origin Requests document cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RelatedOriginsError {
    /// More distinct labels than browsers honour (TN-18).
    #[error("more than {MAX_RELATED_LABELS} registrable-domain labels")]
    TooManyLabels,
    /// An origin is not `https` or has no registrable domain.
    #[error("origin not eligible")]
    Origin,
}

/// The `/.well-known/webauthn` body for `rp`: `{"origins":[...]}` with the RP ID's own origin
/// first. Fails rather than publish a list browsers would cut (TN-18).
///
/// # Errors
/// [`RelatedOriginsError`].
pub fn related_origins_document(
    rp: &RelyingParty,
    suffix: &impl PublicSuffix,
) -> Result<String, RelatedOriginsError> {
    let own = format!("https://{}", rp.rp_id.as_str());
    let mut origins: Vec<String> = vec![own];
    let mut labels: Vec<&str> = Vec::new();
    for origin in &rp.related {
        if !origin.is_https() {
            return Err(RelatedOriginsError::Origin);
        }
        let text = origin.to_string();
        if !origins.contains(&text) {
            origins.push(text);
        }
    }
    for host in core::iter::once(rp.rp_id.as_str()).chain(rp.related.iter().map(Origin::host)) {
        let label = suffix
            .registrable(host)
            .and_then(|d| d.split('.').next())
            .ok_or(RelatedOriginsError::Origin)?;
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if labels.len() > MAX_RELATED_LABELS {
        return Err(RelatedOriginsError::TooManyLabels);
    }
    Ok(serde_json::json!({ "origins": origins }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(related: &[&str]) -> RelyingParty {
        RelyingParty {
            realm: RealmId::from_bytes([1; 16]),
            rp_id: RpId::parse("acme.example").unwrap(),
            name: "Acme".into(),
            pinned: true,
            related: related.iter().map(|o| Origin::parse(o).unwrap()).collect(),
        }
    }

    // IDP-5, MD-5
    #[test]
    fn rp_id_and_origin_rules() {
        assert!(RpId::parse("login.acme.example").is_some());
        assert!(RpId::parse("Acme.example").is_none());
        assert!(RpId::parse("10.0.0.1").is_none());
        assert!(RpId::parse("-a.example").is_none());
        assert!(Origin::parse("https://acme.example").is_some());
        assert!(Origin::parse("https://acme.example:8443").is_some());
        assert!(Origin::parse("https://acme.example:443").is_none());
        assert!(Origin::parse("https://acme.example/").is_none());
        assert!(Origin::parse("http://acme.example").is_none());
        assert!(Origin::parse("http://acme.localhost:8080").is_some());
        let rp = rp(&["https://acme-shop.example"]);
        assert!(rp.allows(&Origin::parse("https://acme.example").unwrap()));
        assert!(rp.allows(&Origin::parse("https://login.acme.example").unwrap()));
        assert!(!rp.allows(&Origin::parse("https://evilacme.example").unwrap()));
        assert!(rp.allows(&Origin::parse("https://acme-shop.example").unwrap()));
        assert!(!rp.allows(&Origin::parse("https://other.example").unwrap()));
    }

    // TN-18
    #[test]
    fn related_origins_document_caps_labels() {
        let doc = related_origins_document(
            &rp(&["https://acme-shop.example"]),
            &crate::domain::psl::Psl,
        )
        .unwrap();
        assert_eq!(
            doc,
            r#"{"origins":["https://acme.example","https://acme-shop.example"]}"#
        );
        let five = rp(&[
            "https://a.example",
            "https://b.example",
            "https://c.example",
            "https://www.c.example",
            "https://d.example",
        ]);
        assert!(related_origins_document(&five, &crate::domain::psl::Psl).is_ok());
        let six = rp(&[
            "https://a.example",
            "https://b.example",
            "https://c.example",
            "https://d.example",
            "https://e.example",
        ]);
        assert_eq!(
            related_origins_document(&six, &crate::domain::psl::Psl),
            Err(RelatedOriginsError::TooManyLabels)
        );
        assert_eq!(
            related_origins_document(&rp(&["http://x.localhost"]), &crate::domain::psl::Psl),
            Err(RelatedOriginsError::Origin)
        );
    }
}
