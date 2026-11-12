//! The realm's stored sign-in requirements as the flows read them (TN-132, OP-151 m.2 M1): the
//! enabled methods, whether MFA is required and the registration domain lists, from the
//! deterministic CBOR `idp.realm.signin_policy` writes. A row that does not decode is never
//! read as the defaults (MD-8).

use std::collections::BTreeSet;

use access_identity_webauthn::domain::ids::Aaguid;
use access_identity_webauthn::domain::policy::AttestationPolicy;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::domain::assurance::AssuranceProfile;
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
    /// Profile fields required at registration (TN-132).
    pub required_fields: BTreeSet<String>,
    /// Identifier and password on one screen, with no branching (OP-153 m.3 (j)).
    pub strict: bool,
    /// Days a given-up e-mail address stays taken; `None` never frees it (OP-153 m.3 (i)).
    pub email_keep_days: Option<u32>,
    /// Whether a hosted sign-in offers DBSC registration (TN-33, OP-153 m.22 (c), m.25 (b)).
    pub dbsc: bool,
    /// The assurance profile (MD-11, SA-54, OP-156 m.3 (e)).
    pub profile: AssuranceProfile,
    /// The WebAuthn attestation policy (§10.2.4, OP-159 m.3 (ll)).
    pub attestation: AttestationPolicy,
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
            required_fields: BTreeSet::from([String::from("email")]),
            strict: false,
            email_keep_days: None,
            dbsc: true,
            profile: AssuranceProfile::Standard,
            attestation: AttestationPolicy::None,
        }
    }
}

/// `{mode: direct | enterprise, aaguids: [text]}` as `idp.realm.signin_policy` writes it.
fn attestation(v: Option<&Value>) -> Option<AttestationPolicy> {
    let Some(v) = v else {
        return Some(AttestationPolicy::None);
    };
    let Value::Map(m) = v else {
        return None;
    };
    let get = |k: &str| {
        m.iter()
            .find(|(key, _)| matches!(key, Value::Text(t) if t == k))
            .map(|(_, v)| v)
    };
    let enterprise = match get("mode") {
        Some(Value::Text(t)) if t == "direct" => false,
        Some(Value::Text(t)) if t == "enterprise" => true,
        _ => return None,
    };
    let aaguids = texts(get("aaguids"))?
        .iter()
        .map(|a| Aaguid::parse(a))
        .collect::<Option<Vec<_>>>()?;
    Some(AttestationPolicy::Direct {
        aaguids,
        enterprise,
    })
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
        // OP-153 m.3 (i), (j)
        let strict = match get("enumeration") {
            None => false,
            Some(Value::Text(t)) if t == "uniform" => false,
            Some(Value::Text(t)) if t == "strict" => true,
            Some(_) => return None,
        };
        let email_keep_days = match get("email_keep_days") {
            None => None,
            Some(Value::Unsigned(d)) => Some(u32::try_from(*d).ok().filter(|d| *d >= 365)?),
            Some(_) => return None,
        };
        // OP-153 m.25 (b)
        let dbsc = match get("dbsc") {
            None => true,
            Some(Value::Bool(b)) => *b,
            Some(_) => return None,
        };
        // OP-156 m.3 (e)
        let profile = match get("profile") {
            None => AssuranceProfile::Standard,
            Some(Value::Text(t)) => AssuranceProfile::parse(t)?,
            Some(_) => return None,
        };
        let required_fields = match get("required_fields") {
            None => BTreeSet::from([String::from("email")]),
            v => texts(v)?,
        };
        // OP-159 m.3 (ll)
        let attestation = attestation(get("attestation"))?;
        Some(Self {
            attestation,
            methods,
            mfa_required,
            domain_allow: texts(get("domain_allow"))?,
            domain_deny: texts(get("domain_deny"))?,
            required_fields,
            strict,
            email_keep_days,
            dbsc,
            profile,
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
            profile: self.profile,
            ..base
        }
    }

    /// Whether registration asks for the display name (TN-132).
    #[must_use]
    pub fn name_required(&self) -> bool {
        self.required_fields.contains("name")
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

    // TN-33, OP-153 m.22 (c), m.25 (b)
    #[test]
    fn a_policy_offers_dbsc_unless_it_says_no() {
        let on = stored(&["email"], false, &[], &[]);
        assert!(RealmSignin::decode(&on).unwrap().dbsc);
        let Ok(Value::Map(mut m)) = dcbor::decode(&on, Limits::CEILING) else {
            panic!("a policy map");
        };
        m.push((Value::text("dbsc"), Value::Bool(false)));
        let off = dcbor::encode(&Value::Map(m.clone()), Limits::CEILING).unwrap_or_default();
        assert!(!RealmSignin::decode(&off).unwrap().dbsc);
        m.pop();
        m.push((Value::text("dbsc"), Value::text("no")));
        let bad = dcbor::encode(&Value::Map(m), Limits::CEILING).unwrap_or_default();
        assert_eq!(RealmSignin::decode(&bad), None);
    }

    // MD-11, SA-54, OP-156 m.3 (e), MD-8
    #[test]
    fn a_policy_names_its_assurance_profile_or_does_not_decode() {
        let base = stored(&["passkey"], true, &[], &[]);
        assert_eq!(
            RealmSignin::decode(&base).unwrap().profile,
            AssuranceProfile::Standard
        );
        let Ok(Value::Map(mut m)) = dcbor::decode(&base, Limits::CEILING) else {
            panic!("a policy map");
        };
        m.push((Value::text("profile"), Value::text("tr-payment")));
        let tr = dcbor::encode(&Value::Map(m.clone()), Limits::CEILING).unwrap_or_default();
        let p = RealmSignin::decode(&tr).unwrap();
        assert_eq!(p.profile, AssuranceProfile::TrPayment);
        assert_eq!(
            p.apply(AuthPolicy::DEFAULT).profile,
            AssuranceProfile::TrPayment
        );
        m.pop();
        m.push((Value::text("profile"), Value::text("lenient")));
        let bad = dcbor::encode(&Value::Map(m), Limits::CEILING).unwrap_or_default();
        assert_eq!(RealmSignin::decode(&bad), None);
    }

    // §10.2.4, OP-159 m.3 (ll), MD-8
    #[test]
    fn a_policy_names_its_attestation_or_does_not_decode() {
        let base = stored(&["passkey"], false, &[], &[]);
        assert_eq!(
            RealmSignin::decode(&base).unwrap().attestation,
            AttestationPolicy::None
        );
        let Ok(Value::Map(m)) = dcbor::decode(&base, Limits::CEILING) else {
            panic!("a policy map");
        };
        let with = |a: Value| {
            let mut m = m.clone();
            m.push((Value::text("attestation"), a));
            RealmSignin::decode(&dcbor::encode(&Value::Map(m), Limits::CEILING).unwrap_or_default())
        };
        let direct = with(Value::Map(vec![
            (Value::text("mode"), Value::text("enterprise")),
            (
                Value::text("aaguids"),
                Value::Array(vec![Value::text("6b6b6b6b-6b6b-6b6b-6b6b-6b6b6b6b6b6b")]),
            ),
        ]))
        .unwrap();
        assert_eq!(
            direct.attestation,
            AttestationPolicy::Direct {
                aaguids: vec![Aaguid([0x6b; 16])],
                enterprise: true,
            }
        );
        assert_eq!(direct.attestation.conveyance(), "enterprise");
        for bad in [
            Value::text("direct"),
            Value::Map(vec![(Value::text("mode"), Value::text("indirect"))]),
            Value::Map(vec![(Value::text("mode"), Value::text("direct"))]),
            Value::Map(vec![
                (Value::text("mode"), Value::text("direct")),
                (Value::text("aaguids"), Value::Array(vec![Value::text("x")])),
            ]),
        ] {
            assert_eq!(with(bad), None);
        }
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
