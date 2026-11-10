//! `idp.domain.*` changes (OP-156 m.3 (a), (i), §10.2.4, TN-16): registering a custom domain
//! (CT2), retiring it (CT1), and binding the realm's issuer or passkey RP ID to a verified one
//! (reserved CT3, never undone). The host is checked against the deployment's base when the
//! change is checked against the realm. Sans-I/O.

use access_internal_api::idp::IdpAction;
use serde_json::Value as Json;
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// What a custom domain is bound as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// The realm's issuer, before the realm's first activation (TN-16).
    Issuer,
    /// The realm's passkey RP ID: the domain's registrable domain (§12.1.2).
    RpId,
}

impl Binding {
    /// Its name in bodies and in the store.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Issuer => "issuer",
            Self::RpId => "rp_id",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "issuer" => Some(Self::Issuer),
            "rp_id" => Some(Self::RpId),
            _ => None,
        }
    }
}

/// One `idp.domain.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainChange {
    /// `registerDomain`: `idp.domain.register`.
    Register(String),
    /// `retireDomain` of a host: `idp.domain.retire`.
    Retire(String),
    /// `bindDomainIssuer` of a host: `idp.domain.issuer_bind` (reserved).
    IssuerBind(String, Binding),
}

fn obj(body: &Json) -> Result<&serde_json::Map<String, Json>, Invalid> {
    body.as_object().ok_or(Invalid::CustomDomain)
}

fn host_ok(host: &str) -> bool {
    access_identity_domain::domain::host::dns_name(host)
}

impl DomainChange {
    /// `registerDomain`: `{"host"}`.
    ///
    /// # Errors
    /// [`Invalid::CustomDomain`].
    pub fn register(body: &Json) -> Result<Self, Invalid> {
        let m = obj(body)?;
        if m.keys().any(|k| k != "host") {
            return Err(Invalid::CustomDomain);
        }
        let host = m
            .get("host")
            .and_then(Json::as_str)
            .filter(|h| host_ok(h))
            .ok_or(Invalid::CustomDomain)?;
        Ok(Self::Register(String::from(host)))
    }

    /// `retireDomain` of `host`: `{}`.
    ///
    /// # Errors
    /// [`Invalid::CustomDomain`].
    pub fn retire(host: &str, body: &Json) -> Result<Self, Invalid> {
        if !host_ok(host) || !obj(body)?.is_empty() {
            return Err(Invalid::CustomDomain);
        }
        Ok(Self::Retire(String::from(host)))
    }

    /// `bindDomainIssuer` of `host`: `{"bind": "issuer" | "rp_id"}`.
    ///
    /// # Errors
    /// [`Invalid::CustomDomain`].
    pub fn issuer_bind(host: &str, body: &Json) -> Result<Self, Invalid> {
        let m = obj(body)?;
        if !host_ok(host) || m.keys().any(|k| k != "bind") {
            return Err(Invalid::CustomDomain);
        }
        let bind = m
            .get("bind")
            .and_then(Json::as_str)
            .and_then(Binding::parse)
            .ok_or(Invalid::CustomDomain)?;
        Ok(Self::IssuerBind(String::from(host), bind))
    }

    /// The action.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Register(_) => IdpAction::DomainRegister,
            Self::Retire(_) => IdpAction::DomainRetire,
            Self::IssuerBind(..) => IdpAction::DomainIssuerBind,
        }
    }

    /// The host.
    #[must_use]
    pub fn host(&self) -> &str {
        match self {
            Self::Register(h) | Self::Retire(h) | Self::IssuerBind(h, _) => h,
        }
    }

    /// Checks the change on its own.
    ///
    /// # Errors
    /// [`Invalid::CustomDomain`].
    pub fn check(&self) -> Result<(), Invalid> {
        if host_ok(self.host()) {
            Ok(())
        } else {
            Err(Invalid::CustomDomain)
        }
    }

    /// The change body the intent digests.
    #[must_use]
    pub fn body(&self) -> Value {
        let m = |e: Vec<(&str, Value)>| {
            Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
        };
        match self {
            Self::Register(h) => m(vec![("host", Value::text(h))]),
            Self::Retire(h) => m(vec![("retire", Value::text(h))]),
            Self::IssuerBind(h, b) => m(vec![
                ("host", Value::text(h)),
                ("bind", Value::text(b.name())),
            ]),
        }
    }

    /// The resource path below the realm.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        vec![String::from("domain"), String::from(self.host())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (a), (i)
    #[test]
    fn domain_changes_read_their_bodies_strictly() {
        let r =
            DomainChange::register(&serde_json::json!({ "host": "login.acme.example" })).unwrap();
        assert_eq!(r.action(), IdpAction::DomainRegister);
        assert_eq!(r.path(), ["domain", "login.acme.example"]);
        assert!(
            DomainChange::register(&serde_json::json!({ "host": "Login.acme.example" })).is_err()
        );
        assert!(
            DomainChange::register(&serde_json::json!({ "host": "a.example", "x": 1 })).is_err()
        );
        let b = DomainChange::issuer_bind(
            "login.acme.example",
            &serde_json::json!({ "bind": "rp_id" }),
        )
        .unwrap();
        assert_eq!(
            b,
            DomainChange::IssuerBind(String::from("login.acme.example"), Binding::RpId)
        );
        assert!(
            DomainChange::issuer_bind("login.acme.example", &serde_json::json!({ "bind": "x" }))
                .is_err()
        );
        assert!(
            DomainChange::retire("login.acme.example", &serde_json::json!({ "x": 1 })).is_err()
        );
    }
}
