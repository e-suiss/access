//! An organization's enterprise SSO changes (OP-155 m.3 (i), TN-94, TN-134): enforcing SSO with
//! the pending invitations' fate named, lifting it, and issuing a one-use setup link. Sans-I/O.

use suiss_crypto::dcbor::Value;

use super::Invalid;

/// How long a setup link lives: 72 hours (TN-134, OP-155 m.3 (i)).
pub const SETUP_LINK_TTL_S: i64 = 72 * 3_600;

/// What enforcement does with the organization's pending invitations; there is no default
/// (TN-94, C10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteFate {
    /// They are revoked.
    Cancel,
    /// They stay open and are accepted through the organization's SSO only.
    RedirectToSso,
}

impl InviteFate {
    /// The stored word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Cancel => "cancel",
            Self::RedirectToSso => "redirect_to_sso",
        }
    }

    /// The fate of a stored word.
    #[must_use]
    pub fn parse(w: &str) -> Option<Self> {
        [Self::Cancel, Self::RedirectToSso]
            .into_iter()
            .find(|f| f.word() == w)
    }
}

/// `idp.org.sso_enforce` (CT1) with the invitations' fate, or `sso_enforce_lift` (CT2) when
/// `invites` is `None` (TN-94, SI-4: narrowing is CT1, lifting widens).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SsoEnforcement {
    /// The organization's Party.
    pub org: [u8; 16],
    /// The pending invitations' fate; `None` lifts the enforcement.
    pub invites: Option<InviteFate>,
}

impl SsoEnforcement {
    /// The change body the intent digests (EI-25).
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = vec![(Value::text("org"), Value::Bytes(self.org.to_vec()))];
        if let Some(f) = self.invites {
            m.push((Value::text("invites"), Value::text(f.word())));
        }
        Value::Map(m)
    }
}

/// `idp.org.setup_link` (CT2): a one-use setup link of an organization, valid
/// [`SETUP_LINK_TTL_S`], sent by Relay to `email` when named (TN-134).
#[derive(Clone, PartialEq, Eq)]
pub struct SetupLinkOrder {
    /// The organization's Party.
    pub org: [u8; 16],
    /// The folded address the link is sent to, if any.
    pub email: Option<String>,
}

impl core::fmt::Debug for SetupLinkOrder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SetupLinkOrder")
            .field("org", &self.org)
            .field("email", &self.email.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl SetupLinkOrder {
    /// Checks the order on its own.
    ///
    /// # Errors
    /// [`Invalid::SetupLink`]: an address that is not one.
    pub fn check(&self) -> Result<(), Invalid> {
        let Some(email) = &self.email else {
            return Ok(());
        };
        let ok = email.rsplit_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && (1..=253).contains(&domain.len())
                && domain.contains('.')
                && domain
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        }) && email.len() <= 254
            && !email.chars().any(|c| c.is_control() || c.is_whitespace());
        if ok { Ok(()) } else { Err(Invalid::SetupLink) }
    }

    /// The change body the intent digests (EI-25): the address only as its SHA-256.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut m = vec![(Value::text("org"), Value::Bytes(self.org.to_vec()))];
        if let Some(e) = &self.email {
            m.push((
                Value::text("recipient"),
                Value::Bytes(suiss_crypto::digest::sha256(e.as_bytes()).to_vec()),
            ));
        }
        Value::Map(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-94, C10
    #[test]
    fn enforcing_names_the_invitations_fate_and_lifting_names_none() {
        assert_eq!(InviteFate::parse("cancel"), Some(InviteFate::Cancel));
        assert_eq!(
            InviteFate::parse("redirect_to_sso"),
            Some(InviteFate::RedirectToSso)
        );
        assert_eq!(InviteFate::parse(""), None);
        assert_eq!(InviteFate::parse("keep"), None);
        let on = SsoEnforcement {
            org: [1; 16],
            invites: Some(InviteFate::Cancel),
        };
        let off = SsoEnforcement {
            invites: None,
            ..on
        };
        assert_ne!(on.to_value(), off.to_value());
    }

    // TN-134
    #[test]
    fn a_setup_link_address_is_digested_and_checked() {
        let good = SetupLinkOrder {
            org: [2; 16],
            email: Some(String::from("it@contoso.example")),
        };
        assert!(good.check().is_ok());
        assert!(!format!("{good:?}").contains("contoso"));
        let bad = SetupLinkOrder {
            email: Some(String::from("not an address")),
            ..good.clone()
        };
        assert_eq!(bad.check(), Err(Invalid::SetupLink));
        let none = SetupLinkOrder {
            email: None,
            ..good
        };
        assert!(none.check().is_ok());
    }
}
