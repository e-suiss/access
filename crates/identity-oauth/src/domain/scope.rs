//! Protocol scopes and resource scopes (§2.2.2 #2, §7.1, L24, S-1, S-2): `openid`, the
//! OpenID Connect claim scopes and `offline_access` are identity plane semantics, released by
//! the user's claim-release consent. Any other scope would ask for access to a resource, and
//! access to a resource is authority: it is asked for as RAR `authorization_details` and is
//! only ever the product of `grant.issue` and `projection.issue`, never of a scope string.

/// The protocol scopes OpenID Connect defines (OIDC Core §3.1.2.1, §5.4, §11).
pub const PROTOCOL_SCOPES: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
];

/// What a requested scope is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeClass {
    /// An identity plane protocol scope.
    Protocol,
    /// Anything else: a request for resource access, which a scope cannot grant.
    Resource,
}

/// The class of `scope`.
#[must_use]
pub fn classify(scope: &str) -> ScopeClass {
    if PROTOCOL_SCOPES.contains(&scope) {
        ScopeClass::Protocol
    } else {
        ScopeClass::Resource
    }
}

/// The description of the `invalid_scope` error for a resource scope.
pub const RESOURCE_SCOPE: &str =
    "resource access is requested with authorization_details, not with a scope";

#[cfg(test)]
mod tests {
    use super::*;

    // §2.2.2, §7.1, L24, S-1, S-2
    #[test]
    fn only_oidc_scopes_are_protocol_scopes() {
        for s in PROTOCOL_SCOPES {
            assert_eq!(classify(s), ScopeClass::Protocol, "{s}");
        }
        for s in [
            "read",
            "orders:write",
            "admin",
            "api://x/.default",
            "OPENID",
        ] {
            assert_eq!(classify(s), ScopeClass::Resource, "{s}");
        }
    }
}
