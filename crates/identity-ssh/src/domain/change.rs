//! `idp.ssh.*` changes (catalog 6, OP-156 m.3 (a), (o)): turning the realm's CA on and off,
//! rotating and replacing its key, and registering and retiring server groups. Sans-I/O: the
//! REST body becomes one change, which the intent binds (EI-25).

use access_internal_api::idp::IdpAction;
use serde_json::Value as Json;
use suiss_crypto::dcbor::Value;

use super::schema::group_ok;

/// Longest server group description.
pub const MAX_DESCRIPTION: usize = 256;

/// Why a body is not an `idp.ssh.*` change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChangeError {
    /// Not a CA change body.
    #[error("ssh ca body")]
    Ca,
    /// Not a server group body.
    #[error("ssh host group body")]
    HostGroup,
}

/// An `idp.ssh.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshChange {
    /// `idp.ssh.ca_enable` (CT2): the realm's CA signs.
    CaEnable,
    /// `idp.ssh.ca_disable` (CT1): nothing signs; every CA key enters the KRL.
    CaDisable,
    /// `idp.ssh.ca_rotate` (CT2): a new key is published, then signs.
    CaRotate,
    /// `idp.ssh.ca_emergency` (reserved, CT3): a new key signs at once; the old ones enter the
    /// KRL.
    CaEmergency,
    /// `idp.ssh.host_group_register` (CT2).
    HostGroupRegister {
        /// Its name, never reused.
        name: String,
        /// What it is, for administrators.
        description: String,
    },
    /// `idp.ssh.host_group_retire` (CT1).
    HostGroupRetire(String),
}

fn obj(body: &Json) -> Option<&serde_json::Map<String, Json>> {
    body.as_object()
}

impl SshChange {
    /// `putSshCa`: `{"enabled": true | false}`.
    ///
    /// # Errors
    /// [`ChangeError::Ca`].
    pub fn put_ca(body: &Json) -> Result<Self, ChangeError> {
        let m = obj(body).ok_or(ChangeError::Ca)?;
        if m.keys().any(|k| k != "enabled") {
            return Err(ChangeError::Ca);
        }
        match m.get("enabled").and_then(Json::as_bool) {
            Some(true) => Ok(Self::CaEnable),
            Some(false) => Ok(Self::CaDisable),
            None => Err(ChangeError::Ca),
        }
    }

    /// `rotateSshCa` or `replaceSshCa`: an empty body.
    ///
    /// # Errors
    /// [`ChangeError::Ca`].
    pub fn rotate_ca(body: &Json, emergency: bool) -> Result<Self, ChangeError> {
        if !obj(body).ok_or(ChangeError::Ca)?.is_empty() {
            return Err(ChangeError::Ca);
        }
        Ok(if emergency {
            Self::CaEmergency
        } else {
            Self::CaRotate
        })
    }

    /// `registerSshHostGroup`: `{"name", "description"?}`.
    ///
    /// # Errors
    /// [`ChangeError::HostGroup`].
    pub fn register_group(body: &Json) -> Result<Self, ChangeError> {
        let m = obj(body).ok_or(ChangeError::HostGroup)?;
        if m.keys()
            .any(|k| !matches!(k.as_str(), "name" | "description"))
        {
            return Err(ChangeError::HostGroup);
        }
        let name = m
            .get("name")
            .and_then(Json::as_str)
            .ok_or(ChangeError::HostGroup)?;
        let description = match m.get("description") {
            None => "",
            Some(d) => d.as_str().ok_or(ChangeError::HostGroup)?,
        };
        let c = Self::HostGroupRegister {
            name: String::from(name),
            description: String::from(description),
        };
        c.check()?;
        Ok(c)
    }

    /// `retireSshHostGroup` of `name`: an empty body.
    ///
    /// # Errors
    /// [`ChangeError::HostGroup`].
    pub fn retire_group(name: &str, body: &Json) -> Result<Self, ChangeError> {
        if !obj(body).ok_or(ChangeError::HostGroup)?.is_empty() {
            return Err(ChangeError::HostGroup);
        }
        let c = Self::HostGroupRetire(String::from(name));
        c.check()?;
        Ok(c)
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::CaEnable => IdpAction::SshCaEnable,
            Self::CaDisable => IdpAction::SshCaDisable,
            Self::CaRotate => IdpAction::SshCaRotate,
            Self::CaEmergency => IdpAction::SshCaEmergency,
            Self::HostGroupRegister { .. } => IdpAction::SshHostGroupRegister,
            Self::HostGroupRetire(_) => IdpAction::SshHostGroupRetire,
        }
    }

    /// Whether it is inside the rules: a server group name of lower-case letters, digits and
    /// `-`, and a description of at most 256 characters without control characters.
    ///
    /// # Errors
    /// [`ChangeError::HostGroup`].
    pub fn check(&self) -> Result<(), ChangeError> {
        match self {
            Self::HostGroupRegister { name, description } => {
                if group_ok(name)
                    && description.chars().count() <= MAX_DESCRIPTION
                    && !description.chars().any(char::is_control)
                {
                    Ok(())
                } else {
                    Err(ChangeError::HostGroup)
                }
            }
            Self::HostGroupRetire(name) if group_ok(name) => Ok(()),
            Self::HostGroupRetire(_) => Err(ChangeError::HostGroup),
            Self::CaEnable | Self::CaDisable | Self::CaRotate | Self::CaEmergency => Ok(()),
        }
    }

    /// The name of a CA change as stored (`ssh_ca_changes.change`); `None` for a group change.
    #[must_use]
    pub const fn ca_name(&self) -> Option<&'static str> {
        match self {
            Self::CaEnable => Some("enable"),
            Self::CaDisable => Some("disable"),
            Self::CaRotate => Some("rotate"),
            Self::CaEmergency => Some("emergency"),
            Self::HostGroupRegister { .. } | Self::HostGroupRetire(_) => None,
        }
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        let m = |e: Vec<(&str, Value)>| {
            Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
        };
        match self {
            Self::HostGroupRegister { name, description } => m(vec![
                ("name", Value::text(name)),
                ("description", Value::text(description)),
            ]),
            Self::HostGroupRetire(name) => m(vec![("retire", Value::text(name))]),
            ca => m(vec![("ca", Value::text(ca.ca_name().unwrap_or_default()))]),
        }
    }

    /// Its resource path below the realm's slug.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        match self {
            Self::HostGroupRegister { name, .. } | Self::HostGroupRetire(name) => {
                vec![String::from("ssh-host-group"), name.clone()]
            }
            _ => vec![String::from("ssh-ca")],
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    // OP-156 m.3 (a), (o)
    #[test]
    fn rest_bodies_compile_to_their_catalog_six_action() {
        assert_eq!(
            SshChange::put_ca(&json!({"enabled": true}))
                .unwrap()
                .action(),
            IdpAction::SshCaEnable
        );
        assert_eq!(
            SshChange::put_ca(&json!({"enabled": false}))
                .unwrap()
                .action(),
            IdpAction::SshCaDisable
        );
        assert!(SshChange::put_ca(&json!({"enabled": "yes"})).is_err());
        assert_eq!(
            SshChange::rotate_ca(&json!({}), true).unwrap().action(),
            IdpAction::SshCaEmergency
        );
        assert!(SshChange::rotate_ca(&json!({"x": 1}), false).is_err());
        let g =
            SshChange::register_group(&json!({"name": "prod-web", "description": "Web"})).unwrap();
        assert_eq!(g.action(), IdpAction::SshHostGroupRegister);
        assert_eq!(g.path(), vec!["ssh-host-group", "prod-web"]);
        assert!(SshChange::register_group(&json!({"name": "Prod"})).is_err());
        assert_eq!(
            SshChange::retire_group("prod-web", &json!({}))
                .unwrap()
                .action(),
            IdpAction::SshHostGroupRetire
        );
        assert_ne!(SshChange::CaRotate.body(), SshChange::CaEmergency.body());
    }
}
