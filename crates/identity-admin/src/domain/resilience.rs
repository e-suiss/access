//! The catalog 8 realm settings (OP-158 m.3 (a)): rehome, residency, the DR profile, the rate
//! limit, the crypto and hash profiles and the audit tier. Each compiles into its
//! `idp.realm.*` change; until its lane applies it the change is refused as not yet served.

use access_internal_api::idp::IdpAction;
use access_kernel::json::b64url_decode;
use serde_json::{Map, Value as Json};
use suiss_crypto::dcbor::Value;

use super::Invalid;

/// The shortest hot audit window, in days (OP-37, OP-158 m.3 (a)).
pub const MIN_HOT_DAYS: u32 = 30;

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
    m.get(key)
        .and_then(Json::as_str)
        .filter(|t| !t.is_empty() && t.len() <= 255)
        .ok_or(Invalid::Body)
}

fn number(m: &Map<String, Json>, key: &str) -> Result<u64, Invalid> {
    m.get(key).and_then(Json::as_u64).ok_or(Invalid::Body)
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::text(k), v))
            .collect(),
    )
}

/// `idp.realm.rehome` (§12.1.1 2a, E14, OP-158 m.3 (o)): the governing domain the realm moves
/// to. It needs an Exercise in both domains; reserved, CT3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rehome {
    /// The new governing domain's id.
    pub domain: [u8; 32],
}

impl Rehome {
    /// `rehomeRealm`: `{"domain"}`, the domain id in base64url.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["domain"])?;
        let domain = b64url_decode(text(m, "domain")?)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            .ok_or(Invalid::Body)?;
        Ok(Self { domain })
    }

    /// The change body.
    #[must_use]
    pub fn body(&self) -> Value {
        map(vec![("domain", Value::Bytes(self.domain.to_vec()))])
    }
}

/// Residency and DR class (CMP-26, OP-158 m.3 (o)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrClass {
    /// One region.
    Regional,
    /// Synchronous across regions.
    MultiRegionSync,
}

impl DrClass {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Regional => "regional",
            Self::MultiRegionSync => "multi-region-sync",
        }
    }

    fn parse(name: &str) -> Result<Self, Invalid> {
        match name {
            "regional" => Ok(Self::Regional),
            "multi-region-sync" => Ok(Self::MultiRegionSync),
            _ => Err(Invalid::Body),
        }
    }
}

/// `idp.realm.residency` (OP-158 m.3 (o)): the region the realm's cell is in; changing it is a
/// cell move. Reserved, CT3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Residency {
    /// The region identifier.
    pub region: String,
    /// The DR class.
    pub class: DrClass,
}

impl Residency {
    /// `putResidency`: `{"region", "class"}`.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["region", "class"])?;
        Ok(Self {
            region: String::from(text(m, "region")?),
            class: DrClass::parse(text(m, "class")?)?,
        })
    }

    /// The change body.
    #[must_use]
    pub fn body(&self) -> Value {
        map(vec![
            ("region", Value::text(&self.region)),
            ("class", Value::text(self.class.name())),
        ])
    }
}

/// `idp.realm.dr_profile` (OP-158 m.3 (a), (r)): the declared async DR profile and its RPO; a
/// realm without one is never promoted from an async copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrProfile {
    /// The declared recovery point objective, in seconds; above zero.
    pub rpo_s: u64,
}

impl DrProfile {
    /// `putDrProfile`: `{"rpo_s"}` declares the profile (CT3), `{}` closes it (CT1).
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(body: &Json) -> Result<Option<Self>, Invalid> {
        let m = own(body)?;
        only(m, &["rpo_s"])?;
        if m.is_empty() {
            return Ok(None);
        }
        let rpo_s = number(m, "rpo_s")?;
        if rpo_s == 0 {
            return Err(Invalid::Body);
        }
        Ok(Some(Self { rpo_s }))
    }

    /// The action that authorizes `profile`.
    #[must_use]
    pub const fn action(profile: Option<&Self>) -> IdpAction {
        match profile {
            Some(_) => IdpAction::RealmDrProfile,
            None => IdpAction::RealmDrProfileClose,
        }
    }

    /// The change body of `profile`.
    #[must_use]
    pub fn body(profile: Option<&Self>) -> Value {
        map(profile
            .map(|p| vec![("rpo_s", Value::Unsigned(p.rpo_s))])
            .unwrap_or_default())
    }
}

/// The highest `rate_limit_rps` a realm can set (OP-158 m.3 (v)).
pub const MAX_RPS: u32 = 1_000_000;

/// `idp.realm.rate_limit` (OP-35, OP-158 m.3 (a), (v)): the realm's `rate_limit_rps`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    /// Requests per second; 1 to [`MAX_RPS`].
    pub rps: u32,
}

impl RateLimit {
    /// `putRateLimit`: `{"rps"}`.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["rps"])?;
        let rps = u32::try_from(number(m, "rps")?).map_err(|_| Invalid::Body)?;
        if !(1..=MAX_RPS).contains(&rps) {
            return Err(Invalid::Body);
        }
        Ok(Self { rps })
    }

    /// The change body.
    #[must_use]
    pub fn body(self) -> Value {
        map(vec![("rps", Value::Unsigned(u64::from(self.rps)))])
    }
}

/// `idp.realm.crypto_profile` (CR-15, CR-36, OP-158 m.3 (a), (y)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoProfile {
    /// Only FIPS-approved algorithms, and PBKDF2-HMAC-SHA-256 for passwords.
    pub fips: bool,
}

impl CryptoProfile {
    /// `putCryptoProfile`: `{"fips"}`.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["fips"])?;
        let fips = m.get("fips").and_then(Json::as_bool).ok_or(Invalid::Body)?;
        Ok(Self { fips })
    }

    /// The change body.
    #[must_use]
    pub fn body(self) -> Value {
        map(vec![("fips", Value::Bool(self.fips))])
    }
}

/// The hash profiles, in raising order (OP-33, RFC 9106).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HashProfile {
    /// The canonical Argon2id parameters.
    Canonical,
    /// RFC 9106's first recommendation: Argon2id with high memory.
    HighMemory,
}

impl HashProfile {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::HighMemory => "high-memory",
        }
    }
}

/// `idp.realm.hash_profile` (OP-33, OP-158 m.3 (a)): raised, never lowered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashProfileSet {
    /// The profile.
    pub profile: HashProfile,
}

impl HashProfileSet {
    /// `putHashProfile`: `{"profile"}`.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn parse(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        only(m, &["profile"])?;
        let profile = match text(m, "profile")? {
            "canonical" => HashProfile::Canonical,
            "high-memory" => HashProfile::HighMemory,
            _ => return Err(Invalid::Body),
        };
        Ok(Self { profile })
    }

    /// The change body.
    #[must_use]
    pub fn body(self) -> Value {
        map(vec![("profile", Value::text(self.profile.name()))])
    }
}

/// `idp.realm.audit_tier` (OP-37, OP-40, OP-158 m.3 (a), (w)): the cold tier target and the hot
/// window, at least [`MIN_HOT_DAYS`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditTier {
    /// Days the hot PostgreSQL window keeps.
    pub hot_days: u32,
    /// The cold tier's object store target.
    pub target: String,
}

impl AuditTier {
    /// `putAuditTier`: `{"hot_days", "target"}` sets it (CT2), `{}` closes it (CT1).
    ///
    /// # Errors
    /// [`Invalid::Body`], [`Invalid::AuditTierTooShort`].
    pub fn parse(body: &Json) -> Result<Option<Self>, Invalid> {
        let m = own(body)?;
        only(m, &["hot_days", "target"])?;
        if m.is_empty() {
            return Ok(None);
        }
        let hot_days = u32::try_from(number(m, "hot_days")?).map_err(|_| Invalid::Body)?;
        if hot_days < MIN_HOT_DAYS {
            return Err(Invalid::AuditTierTooShort);
        }
        Ok(Some(Self {
            hot_days,
            target: String::from(text(m, "target")?),
        }))
    }

    /// The action that authorizes `tier`.
    #[must_use]
    pub const fn action(tier: Option<&Self>) -> IdpAction {
        match tier {
            Some(_) => IdpAction::RealmAuditTier,
            None => IdpAction::RealmAuditTierClose,
        }
    }

    /// The change body of `tier`.
    #[must_use]
    pub fn body(tier: Option<&Self>) -> Value {
        map(tier
            .map(|t| {
                vec![
                    ("hot_days", Value::Unsigned(u64::from(t.hot_days))),
                    ("target", Value::text(&t.target)),
                ]
            })
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use serde_json::json;

    use super::*;

    // OP-158 m.3 (a)
    #[test]
    fn catalog_8_bodies_parse_and_refuse_what_they_must() {
        let d = access_kernel::json::b64url_encode(&[7; 32]);
        assert_eq!(
            Rehome::parse(&json!({ "domain": d })).unwrap().domain,
            [7; 32]
        );
        assert_eq!(Rehome::parse(&json!({ "domain": "x" })), Err(Invalid::Body));
        assert_eq!(
            Residency::parse(&json!({ "region": "eu-central", "class": "regional" }))
                .unwrap()
                .class,
            DrClass::Regional
        );
        assert_eq!(DrProfile::parse(&json!({})), Ok(None));
        assert_eq!(DrProfile::parse(&json!({ "rpo_s": 0 })), Err(Invalid::Body));
        assert_eq!(RateLimit::parse(&json!({ "rps": 0 })), Err(Invalid::Body));
        assert!(CryptoProfile::parse(&json!({ "fips": true })).unwrap().fips);
        assert_eq!(
            HashProfileSet::parse(&json!({ "profile": "high-memory" }))
                .unwrap()
                .profile,
            HashProfile::HighMemory
        );
        assert_eq!(
            AuditTier::parse(&json!({ "hot_days": 29, "target": "s3://audit" })),
            Err(Invalid::AuditTierTooShort)
        );
        assert_eq!(
            AuditTier::action(AuditTier::parse(&json!({})).unwrap().as_ref()),
            IdpAction::RealmAuditTierClose
        );
    }
}
