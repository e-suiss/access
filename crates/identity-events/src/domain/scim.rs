//! The SCIM Security Event Token names (RFC 9967, IDP-23, OP-155 m.3 (g)): the 12 event URIs a
//! SET of the SCIM server or the outbound SCIM client carries, and the `sub_id` format. The
//! claims set is `conformance/cddl/scim-set.cddl`; streams of them are managed through SSF
//! (§9.16.2).

/// Prefix of every SCIM event URI.
pub const URI_PREFIX: &str = "urn:ietf:params:SCIM:event:";

/// The `sub_id` format of a SCIM SET: the resource's URI relative to the SCIM base.
pub const SUBJECT_FORMAT: &str = "scim";

/// One SCIM event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScimEvent {
    /// A resource was created; the changed attributes only.
    CreateNotice,
    /// A resource was created; the resource.
    CreateFull,
    /// A resource was patched; the changed attributes only.
    PatchNotice,
    /// A resource was patched; the `PatchOp` body.
    PatchFull,
    /// A resource was replaced; the changed attributes only.
    PutNotice,
    /// A resource was replaced; the resource.
    PutFull,
    /// A resource was deleted; no attribute is carried.
    Delete,
    /// A resource became active.
    Activate,
    /// A resource became inactive.
    Deactivate,
    /// An authentication method changed.
    AuthMethod,
    /// A password was reset; the password itself is never carried.
    PwdReset,
    /// The answer to an asynchronous request.
    AsyncResponse,
}

impl ScimEvent {
    /// Every event, in RFC order.
    pub const ALL: [Self; 12] = [
        Self::CreateNotice,
        Self::CreateFull,
        Self::PatchNotice,
        Self::PatchFull,
        Self::PutNotice,
        Self::PutFull,
        Self::Delete,
        Self::Activate,
        Self::Deactivate,
        Self::AuthMethod,
        Self::PwdReset,
        Self::AsyncResponse,
    ];

    /// The part of the URI after [`URI_PREFIX`].
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::CreateNotice => "prov:create:notice",
            Self::CreateFull => "prov:create:full",
            Self::PatchNotice => "prov:patch:notice",
            Self::PatchFull => "prov:patch:full",
            Self::PutNotice => "prov:put:notice",
            Self::PutFull => "prov:put:full",
            Self::Delete => "prov:delete",
            Self::Activate => "prov:activate",
            Self::Deactivate => "prov:deactivate",
            Self::AuthMethod => "sig:authMethod",
            Self::PwdReset => "sig:pwdReset",
            Self::AsyncResponse => "misc:asyncResp",
        }
    }

    /// The event URI.
    #[must_use]
    pub fn uri(self) -> String {
        format!("{URI_PREFIX}{}", self.suffix())
    }

    /// The event of a URI.
    #[must_use]
    pub fn of_uri(uri: &str) -> Option<Self> {
        let suffix = uri.strip_prefix(URI_PREFIX)?;
        Self::ALL.into_iter().find(|e| e.suffix() == suffix)
    }

    /// Whether the event carries the resource or its `PatchOp` (`full`) rather than the changed
    /// attribute names.
    #[must_use]
    pub const fn full(self) -> bool {
        matches!(self, Self::CreateFull | Self::PatchFull | Self::PutFull)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // IDP-23, OP-155 m.3 (g)
    #[test]
    fn the_names_are_the_contracts_twelve() {
        let cddl = include_str!("../../../../conformance/cddl/scim-set.cddl");
        let listed: Vec<&str> = cddl
            .split('"')
            .filter(|s| s.starts_with(URI_PREFIX))
            .collect();
        let ours: Vec<String> = ScimEvent::ALL.into_iter().map(ScimEvent::uri).collect();
        assert_eq!(listed, ours);
        for e in ScimEvent::ALL {
            assert_eq!(ScimEvent::of_uri(&e.uri()), Some(e));
        }
        assert_eq!(ScimEvent::of_uri("urn:ietf:params:SCIM:event:prov:merge"), None);
    }
}
