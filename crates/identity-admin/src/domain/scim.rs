//! `idp.scim.*` changes (OP-155 m.3 (a), (g), IDP-23, IDP-29): inbound SCIM clients and outbound
//! SCIM targets. A target's bearer secret never enters the intent: the change carries its SHA-256
//! and the secret itself is sealed under the realm KEK when the decision is written.

use access_identity_scim::app::clients::{check_register, check_target, valid_name};
use access_internal_api::idp::IdpAction;
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// A target's bearer secret as the write request carries it. It never appears in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct TargetSecret(String);

impl TargetSecret {
    /// The secret of `text`: 16 to 4096 visible ASCII characters.
    ///
    /// # Errors
    /// [`Invalid::ScimClient`].
    pub fn parse(text: &str) -> Result<Self, Invalid> {
        let ok = (16..=4096).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_graphic());
        if ok {
            Ok(Self(String::from(text)))
        } else {
            Err(Invalid::ScimClient)
        }
    }

    /// Its text, to seal.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Its SHA-256, the only form the intent names.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        suiss_crypto::digest::sha256(self.0.as_bytes())
    }
}

impl core::fmt::Debug for TargetSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TargetSecret(<redacted>)")
    }
}

/// One `idp.scim.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScimChange {
    /// `idp.scim.client_register` (CT2): a client and its tolerance profile.
    ClientRegister {
        /// Its name.
        name: String,
        /// Its tolerance profile, `scim.<counterpart>`.
        profile: Option<String>,
    },
    /// `idp.scim.token_rotate` (CT2).
    TokenRotate(String),
    /// `idp.scim.client_retire` (CT1).
    ClientRetire(String),
    /// `idp.scim.outbound_register` (CT2).
    OutboundRegister {
        /// Its name.
        name: String,
        /// Its SCIM base URL.
        base_url: String,
        /// Its bearer secret.
        secret: TargetSecret,
    },
    /// `idp.scim.outbound_retire` (CT1).
    OutboundRetire(String),
}

impl ScimChange {
    /// Its action.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::ClientRegister { .. } => IdpAction::ScimClientRegister,
            Self::TokenRotate(_) => IdpAction::ScimTokenRotate,
            Self::ClientRetire(_) => IdpAction::ScimClientRetire,
            Self::OutboundRegister { .. } => IdpAction::ScimOutboundRegister,
            Self::OutboundRetire(_) => IdpAction::ScimOutboundRetire,
        }
    }

    /// The client or target it names.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::ClientRegister { name, .. } | Self::OutboundRegister { name, .. } => name,
            Self::TokenRotate(n) | Self::ClientRetire(n) | Self::OutboundRetire(n) => n,
        }
    }

    pub(crate) fn check(&self) -> Result<(), Invalid> {
        match self {
            Self::ClientRegister { name, profile } => {
                check_register(name, profile.as_deref()).map_err(|_| Invalid::ScimClient)
            }
            Self::OutboundRegister { name, base_url, .. } => {
                check_target(name, base_url).map_err(|_| Invalid::ScimClient)
            }
            Self::TokenRotate(n) | Self::ClientRetire(n) | Self::OutboundRetire(n) => {
                if valid_name(n) {
                    Ok(())
                } else {
                    Err(Invalid::ScimClient)
                }
            }
        }
    }

    pub(crate) fn body(&self) -> Value {
        let mut fields = vec![(Value::text("name"), Value::text(self.name()))];
        match self {
            Self::ClientRegister {
                profile: Some(p), ..
            } => fields.push((Value::text("profile"), Value::text(p))),
            Self::OutboundRegister {
                base_url, secret, ..
            } => {
                fields.push((Value::text("base_url"), Value::text(base_url)));
                fields.push((
                    Value::text("secret_sha256"),
                    Value::Bytes(secret.digest().to_vec()),
                ));
            }
            _ => {}
        }
        Value::Map(fields)
    }

    /// Its resource path under the realm's slug: `scim-client/<name>` or `scim-target/<name>`.
    #[must_use]
    pub fn path(&self) -> [String; 2] {
        let kind = match self {
            Self::OutboundRegister { .. } | Self::OutboundRetire(_) => "scim-target",
            _ => "scim-client",
        };
        [String::from(kind), String::from(self.name())]
    }
}
