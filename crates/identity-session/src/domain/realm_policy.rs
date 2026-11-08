//! The realm's stored sign-in requirements as the flows read them (TN-132, OP-151 m.2 M1): the
//! enabled methods, whether MFA is required and the registration domain lists, from the
//! deterministic CBOR `idp.realm.signin_policy` writes. A row that does not decode is never
//! read as the defaults (MD-8).

use std::collections::BTreeSet;

use suiss_crypto::dcbor::{self, Limits, Value};

use crate::domain::requirement::{AuthPolicy, MfaPolicy};

/// A realm's sign-in requirements as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmSignin {
    /// Enabled methods: `email`, `phone`, `username`, `passkey`, `social:<provider>`.
    pub methods: BTreeSet<String>,
    /// Whether a second factor is required.
    pub mfa_required: bool,
    /// Email domains registration is limited to; empty allows every domain not denied.
    pub domain_allow: BTreeSet<String>,
    /// Email domains registration is refused for.
    pub domain_deny: BTreeSet<String>,
}

impl Default for RealmSignin {
    /// No stored policy: e-mail and passkey, no MFA requirement, open registration (OP-151
    /// m.11 (d)).
    fn default() -> Self {
        Self {
            methods: BTreeSet::from([String::from("email"), String::from("passkey")]),
            mfa_required: false,
            domain_allow: BTreeSet::new(),
            domain_deny: BTreeSet::new(),
        }
    }
}

fn texts(v: Option<&Value>) -> Option<BTreeSet<String>> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| match x {
                Value::Text(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

impl RealmSignin {
    /// The stored policy; `None` when the bytes are not the written form.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let Ok(Value::Map(m)) = dcbor::decode(bytes, Limits::CEILING) else {
            return None;
        };
        let get = |k: &str| {
            m.iter()
                .find(|(key, _)| matches!(key, Value::Text(t) if t == k))
                .map(|(_, v)| v)
        };
        let mfa_required = match get("mfa_required") {
            Some(Value::Bool(b)) => *b,
            _ => return None,
        };
        let methods = texts(get("methods")).filter(|m| !m.is_empty())?;
        Some(Self {
            methods,
            mfa_required,
            domain_allow: texts(get("domain_allow"))?,
            domain_deny: texts(get("domain_deny"))?,
        })
    }

    fn has(&self, method: &str) -> bool {
        self.methods.contains(method)
    }

    /// `base` narrowed by the realm (TN-132): a method the realm did not enable is not offered
    /// and not accepted as a first step, and a required MFA is never skipped. Nothing here
    /// widens `base`.
    #[must_use]
    pub fn apply(&self, base: AuthPolicy) -> AuthPolicy {
        let email = self.has("email");
        AuthPolicy {
            mfa: if self.mfa_required {
                MfaPolicy::Required
            } else {
                base.mfa
            },
            password: base.password && (email || self.has("username")),
            passkey: base.passkey && self.has("passkey"),
            email_otp: base.email_otp && email,
            magic_link: base.magic_link && email,
            ..base
        }
    }

    /// Whether an account may be registered with `email` (TN-132): its domain is not denied
    /// and, when the realm limits registration, allowed. Compared in lower case.
    #[must_use]
    pub fn registration_allowed(&self, email: &str) -> bool {
        let Some((_, domain)) = email.rsplit_once('@') else {
            return false;
        };
        let domain = domain.to_ascii_lowercase();
        !self.domain_deny.contains(&domain)
            && (self.domain_allow.is_empty() || self.domain_allow.contains(&domain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(methods: &[&str], mfa: bool, allow: &[&str], deny: &[&str]) -> Vec<u8> {
        let list = |l: &[&str]| Value::Array(l.iter().map(|s| Value::text(s)).collect());
        dcbor::encode(
            &Value::Map(vec![
                (Value::text("methods"), list(methods)),
                (Value::text("required_fields"), list(&["email"])),
                (Value::text("mfa_required"), Value::Bool(mfa)),
                (Value::text("domain_allow"), list(allow)),
                (Value::text("domain_deny"), list(deny)),
            ]),
            Limits::CEILING,
        )
        .unwrap_or_default()
    }

    // TN-132, OP-151 m.11 (d)
    #[test]
    fn the_default_policy_keeps_the_default_flows() {
        assert_eq!(
            RealmSignin::default().apply(AuthPolicy::DEFAULT),
            AuthPolicy::DEFAULT
        );
    }

    // TN-132
    #[test]
    fn the_stored_policy_narrows_the_flows() {
        let p = RealmSignin::decode(&stored(&["passkey"], true, &[], &[])).unwrap();
        let a = p.apply(AuthPolicy::DEFAULT);
        assert!(!a.password && !a.email_otp && !a.magic_link && a.passkey);
        assert_eq!(a.mfa, MfaPolicy::Required);
        let u = RealmSignin::decode(&stored(&["username"], false, &[], &[])).unwrap();
        let a = u.apply(AuthPolicy::DEFAULT);
        assert!(a.password && !a.passkey && !a.email_otp);
        assert_eq!(a.mfa, MfaPolicy::WhenEnrolled);
    }

    // MD-8
    #[test]
    fn a_malformed_policy_does_not_decode() {
        assert_eq!(RealmSignin::decode(b"\xa0"), None);
        assert_eq!(RealmSignin::decode(&stored(&[], false, &[], &[])), None);
        assert_eq!(RealmSignin::decode(b"not cbor"), None);
    }

    // TN-132
    #[test]
    fn registration_follows_the_domain_lists() {
        let p = RealmSignin::decode(&stored(
            &["email"],
            false,
            &["corp.example"],
            &["spam.example"],
        ))
        .unwrap();
        assert!(p.registration_allowed("a@Corp.Example"));
        assert!(!p.registration_allowed("a@other.example"));
        assert!(!p.registration_allowed("no-at-sign"));
        let open = RealmSignin::decode(&stored(&["email"], false, &[], &["spam.example"])).unwrap();
        assert!(open.registration_allowed("a@other.example"));
        assert!(!open.registration_allowed("a@spam.example"));
    }
}
