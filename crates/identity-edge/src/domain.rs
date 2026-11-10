//! What a gateway may ask for (§13.2 blast radius, OP-155 m.3 (c)): only its own realm, only
//! its kind's authentication method, and only a recent authentication. Sans-I/O.

use std::collections::BTreeMap;

pub mod directory;

use access_internal_api::edge::{GatewayKind, GatewayUri};
use access_kernel::claim::body::AuthMethod;
use access_store::identity::{RealmId, TenantId};

/// Furthest an edge `auth_time` may lie ahead of the server's clock.
pub const AUTH_TIME_SKEW_MS: u64 = 3 * 60 * 1000;

/// Oldest an edge `auth_time` may be when the gateway reports it.
pub const AUTH_TIME_MAX_AGE_MS: u64 = 5 * 60 * 1000;

/// A live registered gateway.
#[derive(Clone)]
pub struct Gateway {
    /// The tenant of its realm.
    pub tenant: TenantId,
    /// Its realm.
    pub realm: RealmId,
    /// The realm's slug.
    pub slug: String,
    /// Its identity.
    pub uri: GatewayUri,
}

impl core::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gateway")
            .field("slug", &self.slug)
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

/// Why a call is outside the gateway's scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another realm than the gateway's.
    Realm,
    /// Another method than the gateway kind's, or a kind that authenticates nobody.
    Method,
    /// An `auth_time` in the future or too old.
    AuthTime,
    /// No active subject.
    Subject,
    /// An audit event whose type does not fit the audit log.
    Event,
    /// A `session_attest` handle that names no open flow of the realm: forged, used or
    /// expired (IDI-7).
    Attest,
    /// A `session_attest` body outside the contract.
    Malformed,
    /// An LDAP bind handle that is forged, expired, of another gateway or of a dead bind.
    Bind,
    /// An LDAP paging cookie of another search, tampered with or expired.
    Cookie,
}

impl Refusal {
    /// The stable problem code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Realm => "edge-realm",
            Self::Method => "edge-method",
            Self::AuthTime => "edge-auth-time",
            Self::Subject => "edge-subject",
            Self::Event => "edge-event",
            Self::Attest => "edge-attest",
            Self::Malformed => "edge-malformed",
            Self::Bind => "edge-bind",
            Self::Cookie => "edge-cookie",
        }
    }
}

/// IDP-26, §13.2: a gateway asks only in its own realm.
///
/// # Errors
/// [`Refusal::Realm`].
pub fn in_scope(g: &Gateway, realm: &str) -> Result<(), Refusal> {
    if g.slug == realm {
        Ok(())
    } else {
        Err(Refusal::Realm)
    }
}

/// §13.2: the method a gateway reports must be its kind's.
///
/// # Errors
/// [`Refusal::Method`].
pub fn method(kind: GatewayKind, name: &str) -> Result<AuthMethod, Refusal> {
    if kind.method() != Some(name) {
        return Err(Refusal::Method);
    }
    match name {
        "ldap-bind" => Ok(AuthMethod::LdapBind),
        "kerberos" => Ok(AuthMethod::Kerberos),
        "password" => Ok(AuthMethod::Password),
        _ => Err(Refusal::Method),
    }
}

/// The authentication happened recently by the server's clock.
///
/// # Errors
/// [`Refusal::AuthTime`].
pub fn fresh(auth_time: u64, now: u64) -> Result<(), Refusal> {
    let ahead = auth_time > now.saturating_add(AUTH_TIME_SKEW_MS);
    let stale = auth_time < now.saturating_sub(AUTH_TIME_MAX_AGE_MS);
    if ahead || stale {
        Err(Refusal::AuthTime)
    } else {
        Ok(())
    }
}

/// The assurance of an edge authentication (§10.1.6): one knowledge or ticket factor, AAL1,
/// no flag set. A gateway never asserts more.
#[must_use]
pub fn levels() -> BTreeMap<String, u64> {
    [
        "app_controlled_factor",
        "hardware_bound",
        "human_presence",
        "non_custodial",
        "phishing_resistant",
        "synced",
        "uv",
    ]
    .into_iter()
    .map(|k| (String::from(k), 0))
    .chain([(String::from("aal"), 1)])
    .collect()
}

/// The audit event type of a gateway event: `edge.<event>.<outcome>`.
///
/// # Errors
/// [`Refusal::Event`] when it would not fit the audit log's 64 characters.
pub fn event_type(event: &str, outcome: &str) -> Result<String, Refusal> {
    let s = format!("edge.{event}.{outcome}");
    if s.len() <= 64 {
        Ok(s)
    } else {
        Err(Refusal::Event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(kind: GatewayKind) -> Gateway {
        Gateway {
            tenant: TenantId::from_bytes([1; 16]),
            realm: RealmId::from_bytes([2; 16]),
            slug: String::from("corp"),
            uri: GatewayUri {
                kind,
                name: String::from("gw"),
            },
        }
    }

    // IDP-26, §13.2
    #[test]
    fn a_gateway_asks_only_in_its_realm_and_for_its_method() {
        let g = gateway(GatewayKind::Ldap);
        assert!(in_scope(&g, "corp").is_ok());
        assert_eq!(in_scope(&g, "other"), Err(Refusal::Realm));
        assert_eq!(method(g.uri.kind, "ldap-bind"), Ok(AuthMethod::LdapBind));
        assert_eq!(method(g.uri.kind, "kerberos"), Err(Refusal::Method));
        assert_eq!(method(g.uri.kind, "webauthn"), Err(Refusal::Method));
        assert_eq!(method(GatewayKind::Saml, "saml"), Err(Refusal::Method));
        assert_eq!(
            method(GatewayKind::Kerberos, "kerberos"),
            Ok(AuthMethod::Kerberos)
        );
        assert_eq!(
            method(GatewayKind::Radius, "password"),
            Ok(AuthMethod::Password)
        );
    }

    // §13.2
    #[test]
    fn edge_authentications_are_recent_and_single_factor() {
        let now = 10_000_000;
        assert!(fresh(now, now).is_ok());
        assert_eq!(
            fresh(now + AUTH_TIME_SKEW_MS + 1, now),
            Err(Refusal::AuthTime)
        );
        assert_eq!(
            fresh(now - AUTH_TIME_MAX_AGE_MS - 1, now),
            Err(Refusal::AuthTime)
        );
        let l = levels();
        assert_eq!(l.get("aal"), Some(&1));
        assert!(l.iter().filter(|(k, _)| *k != "aal").all(|(_, v)| *v == 0));
        assert_eq!(
            event_type("ldap.bind", "ok").as_deref(),
            Ok("edge.ldap.bind.ok")
        );
    }
}
