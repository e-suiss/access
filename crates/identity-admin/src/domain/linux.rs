//! `idp.linux.*` changes (catalog 6, OP-156 m.3 (a), (p)): registering and retiring a Linux
//! client host, its offline limits and its break-glass switch. Sans-I/O: the REST body becomes
//! one change, which the intent binds (EI-25).

use access_internal_api::idp::IdpAction;
use serde_json::Value as Json;
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// The longest NSS data is served offline (m.3 (p)): 12 hours.
pub const NSS_MAX_S: u64 = 12 * 3600;

/// The longest a console sign-in is reused offline (m.3 (p)): 8 hours.
pub const CONSOLE_MAX_S: u64 = 8 * 3600;

/// The login shell a host's users get unless its registration names another.
pub const DEFAULT_SHELL: &str = "/bin/bash";

/// A host's registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSpec {
    /// Its name, never reused.
    pub name: String,
    /// The server group whose `ssh.login` Grants sign in to it.
    pub host_group: String,
    /// The `x5t#S256` of its client certificate.
    pub certificate: String,
    /// Its users' login shell.
    pub shell: String,
    /// The consequence tier `sudo` asks for: 2 (default) or 3.
    pub sudo_ct: u8,
}

/// An `idp.linux.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinuxChange {
    /// `idp.linux.host_register` (CT2): offline limits at their ceilings, no break-glass.
    Register(HostSpec),
    /// `idp.linux.host_retire` (CT1).
    Retire(String),
    /// `idp.linux.offline_policy` (CT2).
    OfflinePolicy {
        /// The host.
        host: String,
        /// NSS data offline, seconds (≤ 12 h).
        nss_ttl_s: u64,
        /// Console sign-in reuse offline, seconds (≤ 8 h).
        console_ttl_s: u64,
    },
    /// `idp.linux.break_glass_policy` (reserved, CT3).
    BreakGlass {
        /// The host.
        host: String,
        /// Whether local break-glass is allowed.
        enabled: bool,
    },
}

/// Whether `name` may name a host or server group: a lower-case letter, then up to 62
/// lower-case letters, digits and `-`.
#[must_use]
pub fn name_ok(name: &str) -> bool {
    let mut b = name.bytes();
    b.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 63
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn certificate_ok(c: &str) -> bool {
    c.len() == 43
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn shell_ok(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= 255
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}

fn obj<'a>(body: &'a Json, keys: &[&str]) -> Result<&'a serde_json::Map<String, Json>, Invalid> {
    let m = body.as_object().ok_or(Invalid::LinuxHost)?;
    if m.keys().any(|k| !keys.contains(&k.as_str())) {
        return Err(Invalid::LinuxHost);
    }
    Ok(m)
}

fn text<'a>(m: &'a serde_json::Map<String, Json>, k: &str) -> Result<&'a str, Invalid> {
    m.get(k).and_then(Json::as_str).ok_or(Invalid::LinuxHost)
}

impl LinuxChange {
    /// `registerLinuxHost`: `{"name", "host_group", "certificate", "shell"?, "sudo_ct"?}`.
    ///
    /// # Errors
    /// [`Invalid::LinuxHost`].
    pub fn register(body: &Json) -> Result<Self, Invalid> {
        let m = obj(
            body,
            &["name", "host_group", "certificate", "shell", "sudo_ct"],
        )?;
        let shell = match m.get("shell") {
            None => DEFAULT_SHELL,
            Some(s) => s.as_str().ok_or(Invalid::LinuxHost)?,
        };
        let sudo_ct = match m.get("sudo_ct") {
            None => 2,
            Some(v) => v
                .as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or(Invalid::LinuxHost)?,
        };
        let c = Self::Register(HostSpec {
            name: String::from(text(m, "name")?),
            host_group: String::from(text(m, "host_group")?),
            certificate: String::from(text(m, "certificate")?),
            shell: String::from(shell),
            sudo_ct,
        });
        c.check()?;
        Ok(c)
    }

    /// `retireLinuxHost` of `host`: an empty body.
    ///
    /// # Errors
    /// [`Invalid::LinuxHost`].
    pub fn retire(host: &str, body: &Json) -> Result<Self, Invalid> {
        obj(body, &[])?;
        let c = Self::Retire(String::from(host));
        c.check()?;
        Ok(c)
    }

    /// `putLinuxOfflinePolicy` of `host`: `{"nss_ttl_s", "console_ttl_s"}`.
    ///
    /// # Errors
    /// [`Invalid::LinuxHost`].
    pub fn offline_policy(host: &str, body: &Json) -> Result<Self, Invalid> {
        let m = obj(body, &["nss_ttl_s", "console_ttl_s"])?;
        let n = |k: &str| m.get(k).and_then(Json::as_u64).ok_or(Invalid::LinuxHost);
        let c = Self::OfflinePolicy {
            host: String::from(host),
            nss_ttl_s: n("nss_ttl_s")?,
            console_ttl_s: n("console_ttl_s")?,
        };
        c.check()?;
        Ok(c)
    }

    /// `putLinuxBreakGlassPolicy` of `host`: `{"enabled"}`.
    ///
    /// # Errors
    /// [`Invalid::LinuxHost`].
    pub fn break_glass(host: &str, body: &Json) -> Result<Self, Invalid> {
        let m = obj(body, &["enabled"])?;
        let c = Self::BreakGlass {
            host: String::from(host),
            enabled: m
                .get("enabled")
                .and_then(Json::as_bool)
                .ok_or(Invalid::LinuxHost)?,
        };
        c.check()?;
        Ok(c)
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Register(_) => IdpAction::LinuxHostRegister,
            Self::Retire(_) => IdpAction::LinuxHostRetire,
            Self::OfflinePolicy { .. } => IdpAction::LinuxOfflinePolicy,
            Self::BreakGlass { .. } => IdpAction::LinuxBreakGlassPolicy,
        }
    }

    /// The host it changes.
    #[must_use]
    pub fn host(&self) -> &str {
        match self {
            Self::Register(h) => &h.name,
            Self::Retire(h)
            | Self::OfflinePolicy { host: h, .. }
            | Self::BreakGlass { host: h, .. } => h,
        }
    }

    /// Whether it is inside the rules: names of lower-case letters, digits and `-`, a 43
    /// character `x5t#S256`, an absolute shell path, `sudo` at CT2 or CT3, and offline limits
    /// within 12 and 8 hours.
    ///
    /// # Errors
    /// [`Invalid::LinuxHost`].
    pub fn check(&self) -> Result<(), Invalid> {
        let ok = match self {
            Self::Register(h) => {
                name_ok(&h.name)
                    && name_ok(&h.host_group)
                    && certificate_ok(&h.certificate)
                    && shell_ok(&h.shell)
                    && matches!(h.sudo_ct, 2 | 3)
            }
            Self::Retire(h) | Self::BreakGlass { host: h, .. } => name_ok(h),
            Self::OfflinePolicy {
                host,
                nss_ttl_s,
                console_ttl_s,
            } => name_ok(host) && *nss_ttl_s <= NSS_MAX_S && *console_ttl_s <= CONSOLE_MAX_S,
        };
        if ok { Ok(()) } else { Err(Invalid::LinuxHost) }
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        let m = |e: Vec<(&str, Value)>| {
            Value::Map(e.into_iter().map(|(k, v)| (Value::text(k), v)).collect())
        };
        match self {
            Self::Register(h) => m(vec![
                ("name", Value::text(&h.name)),
                ("host_group", Value::text(&h.host_group)),
                ("certificate", Value::text(&h.certificate)),
                ("shell", Value::text(&h.shell)),
                ("sudo_ct", Value::Unsigned(u64::from(h.sudo_ct))),
            ]),
            Self::Retire(h) => m(vec![("retire", Value::text(h))]),
            Self::OfflinePolicy {
                host,
                nss_ttl_s,
                console_ttl_s,
            } => m(vec![
                ("host", Value::text(host)),
                ("nss_ttl_s", Value::Unsigned(*nss_ttl_s)),
                ("console_ttl_s", Value::Unsigned(*console_ttl_s)),
            ]),
            Self::BreakGlass { host, enabled } => m(vec![
                ("host", Value::text(host)),
                ("break_glass", Value::Bool(*enabled)),
            ]),
        }
    }

    /// Its resource path below the realm's slug.
    #[must_use]
    pub fn path(&self) -> Vec<String> {
        vec![String::from("linux-host"), String::from(self.host())]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

    use serde_json::json;

    use super::*;

    const CERT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    // OP-156 m.3 (a), (p)
    #[test]
    fn rest_bodies_compile_to_their_catalog_six_action() {
        let r = LinuxChange::register(
            &json!({"name": "web-1", "host_group": "prod-web", "certificate": CERT}),
        )
        .unwrap();
        assert_eq!(r.action(), IdpAction::LinuxHostRegister);
        assert_eq!(r.path(), vec!["linux-host", "web-1"]);
        let LinuxChange::Register(h) = &r else {
            panic!("{r:?}")
        };
        assert_eq!((h.shell.as_str(), h.sudo_ct), (DEFAULT_SHELL, 2));
        assert!(
            LinuxChange::register(
                &json!({"name": "web-1", "host_group": "prod-web", "certificate": CERT, "sudo_ct": 1})
            )
            .is_err()
        );
        assert!(
            LinuxChange::register(&json!({"name": "Web", "host_group": "g", "certificate": CERT}))
                .is_err()
        );
        assert_eq!(
            LinuxChange::retire("web-1", &json!({})).unwrap().action(),
            IdpAction::LinuxHostRetire
        );
        // OP-156 m.3 (p)
        assert!(
            LinuxChange::offline_policy(
                "web-1",
                &json!({"nss_ttl_s": 43_200, "console_ttl_s": 28_800})
            )
            .is_ok()
        );
        assert!(
            LinuxChange::offline_policy("web-1", &json!({"nss_ttl_s": 43_201, "console_ttl_s": 0}))
                .is_err()
        );
        assert!(
            LinuxChange::offline_policy("web-1", &json!({"nss_ttl_s": 0, "console_ttl_s": 28_801}))
                .is_err()
        );
        assert_eq!(
            LinuxChange::break_glass("web-1", &json!({"enabled": true}))
                .unwrap()
                .action(),
            IdpAction::LinuxBreakGlassPolicy
        );
        assert!(IdpAction::LinuxBreakGlassPolicy.reserved());
    }
}
