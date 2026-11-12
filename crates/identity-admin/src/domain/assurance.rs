//! The catalog 9 realm settings (OP-159 m.3 (a)): the post-quantum signing profile and the
//! hybrid key exchange share policy. Each compiles into its `idp.realm.*` change; until its lane
//! applies it the change is refused as not yet served.

use access_internal_api::idp::IdpAction;
use serde_json::{Map, Value as Json};
use suiss_crypto::dcbor::Value;

use super::Invalid;

fn own(body: &Json) -> Result<&Map<String, Json>, Invalid> {
    body.as_object().ok_or(Invalid::Body)
}

fn only(m: &Map<String, Json>, keys: &[&str]) -> Result<(), Invalid> {
    if m.keys().all(|k| keys.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(Invalid::Body)
    }
}

fn text<'a>(m: &'a Map<String, Json>, key: &str) -> Result<&'a str, Invalid> {
    m.get(key).and_then(Json::as_str).ok_or(Invalid::Body)
}

/// The ML-DSA parameter sets a realm signs with (FIPS 204, CR-41 m.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsa {
    /// ML-DSA-65, the default profile.
    MlDsa65,
    /// ML-DSA-44, for offline PAP projections.
    MlDsa44,
    /// ML-DSA-87.
    MlDsa87,
}

impl MlDsa {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }

    /// The parameter set of `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [Self::MlDsa65, Self::MlDsa44, Self::MlDsa87]
            .into_iter()
            .find(|a| a.name() == name)
    }
}

/// `idp.realm.signing_profile` (CR-41, CR-8, OP-159 m.3 (a), (o)): ML-DSA joins the realm's
/// accept and signing set; the classical algorithms stay (CR-41 m.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningProfile {
    /// The ML-DSA parameter set.
    pub profile: MlDsa,
}

impl SigningProfile {
    /// `putSigningProfile`: `{"profile"}` opens the profile (reserved, CT3), `{}` closes it
    /// (CT1).
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(body: &Json) -> Result<Option<Self>, Invalid> {
        let m = own(body)?;
        only(m, &["profile"])?;
        if m.is_empty() {
            return Ok(None);
        }
        let profile = MlDsa::from_name(text(m, "profile")?).ok_or(Invalid::Body)?;
        Ok(Some(Self { profile }))
    }

    /// The action that authorizes `profile`.
    #[must_use]
    pub const fn action(profile: Option<&Self>) -> IdpAction {
        match profile {
            Some(_) => IdpAction::RealmSigningProfile,
            None => IdpAction::RealmSigningProfileClose,
        }
    }

    /// The change body of `profile`.
    #[must_use]
    pub fn body(profile: Option<&Self>) -> Value {
        Value::Map(
            profile
                .map(|p| vec![(Value::text("profile"), Value::text(p.profile.name()))])
                .unwrap_or_default(),
        )
    }
}

/// The hybrid key exchange share policies (CR-12 m.3); both offer the post-quantum group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KexMode {
    /// The client sends the post-quantum key share first.
    Optimistic,
    /// The client sends X25519 first and announces the post-quantum group.
    AdvertiseOnly,
}

impl KexMode {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Optimistic => "optimistic",
            Self::AdvertiseOnly => "advertise-only",
        }
    }
}

/// `idp.realm.kex_share` (CR-12 m.3, OP-159 m.3 (a), (t)): CT2 in both directions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KexShare {
    /// The share policy.
    pub mode: KexMode,
}

impl KexShare {
    /// `putKexShare`: `{"mode"}`.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["mode"])?;
        let mode = match text(m, "mode")? {
            "optimistic" => KexMode::Optimistic,
            "advertise-only" => KexMode::AdvertiseOnly,
            _ => return Err(Invalid::Body),
        };
        Ok(Self { mode })
    }

    /// The change body.
    #[must_use]
    pub fn body(self) -> Value {
        Value::Map(vec![(Value::text("mode"), Value::text(self.mode.name()))])
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    // OP-159 m.3 (a)
    #[test]
    fn catalog_9_bodies_parse_and_refuse_what_they_must() {
        for name in ["ml-dsa-65", "ml-dsa-44", "ml-dsa-87"] {
            let p = SigningProfile::parse(&json!({ "profile": name }))
                .unwrap()
                .unwrap();
            assert_eq!(p.profile.name(), name);
            assert_eq!(
                SigningProfile::action(Some(&p)),
                IdpAction::RealmSigningProfile
            );
        }
        assert_eq!(SigningProfile::parse(&json!({})), Ok(None));
        assert_eq!(
            SigningProfile::action(None),
            IdpAction::RealmSigningProfileClose
        );
        for bad in [
            json!({ "profile": "ed25519" }),
            json!({ "profile": "ml-dsa-65", "classic": false }),
            json!({ "profile": 65 }),
        ] {
            assert_eq!(SigningProfile::parse(&bad), Err(Invalid::Body), "{bad}");
        }
        for (name, mode) in [
            ("optimistic", KexMode::Optimistic),
            ("advertise-only", KexMode::AdvertiseOnly),
        ] {
            assert_eq!(KexShare::parse(&json!({ "mode": name })).unwrap().mode, mode);
        }
        for bad in [json!({ "mode": "classic-only" }), json!({})] {
            assert_eq!(KexShare::parse(&bad), Err(Invalid::Body), "{bad}");
        }
    }
}
