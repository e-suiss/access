//! Guardianship, age and parent consent (E53, E47, OP-153 m.3 (q)): a guardian's standing for
//! a ward is the realm issuer's `guardianship` Claim, effective only through an Acceptance, and
//! ends at the ward's majority by the country table; other products get the ward's `age_range`
//! Claim, never the date of birth, which stays in the PII vault's `profile` class. A ward's
//! request that needs a parent waits on a consent that lives 72 hours; silence is not consent.

use access_identity_account::app::vault::{self, Vault};
use access_identity_account::domain::claim_classes::{
    AgeRange, Guardianship, GuardianshipBasis, IdentityClass,
};
use access_identity_account::domain::claims::{ClaimOrder, Content, line};
use access_kernel::combinator::Outcome;
use access_kernel::model::{EqValue, Id};
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};

use crate::AdminError;
use crate::domain::Invalid;

/// How long a parent consent request lives: 72 hours (OP-153 m.3 (q), PD).
pub const CONSENT_TTL_S: i64 = 72 * 3_600;

/// Age of majority in `country` (ISO 3166-1 alpha-2): TR 18, KR 19, otherwise 18
/// (OP-153 m.3 (q), PD; the legal check of the table is outside the stage, m.3 (ii)).
#[must_use]
pub fn majority_years(country: &str) -> u16 {
    match country {
        "KR" => 19,
        _ => 18,
    }
}

/// A calendar date.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    /// Year.
    pub year: u16,
    /// Month, 1 to 12.
    pub month: u8,
    /// Day, 1 to 31.
    pub day: u8,
}

impl Date {
    /// A `YYYY-MM-DD` date.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split('-');
        let year = parts.next()?.parse().ok()?;
        let month: u8 = parts.next()?.parse().ok()?;
        let day: u8 = parts.next()?.parse().ok()?;
        (parts.next().is_none() && (1..=12).contains(&month) && (1..=31).contains(&day))
            .then_some(Self { year, month, day })
    }

    /// Days since 1970-01-01 (proleptic Gregorian).
    #[must_use]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "civil-calendar arithmetic over a u16 year cannot overflow i64"
    )]
    pub fn days(self) -> i64 {
        let y = i64::from(self.year) - i64::from(self.month <= 2);
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let m = i64::from(self.month);
        let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// The date `years` later; 29 February falls to 28 February in a common year.
    #[must_use]
    pub fn plus_years(self, years: u16) -> Self {
        let year = self.year.saturating_add(years);
        let leap =
            (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let day = if self.month == 2 && self.day == 29 && !leap {
            28
        } else {
            self.day
        };
        Self {
            year,
            month: self.month,
            day,
        }
    }

    /// Midnight UTC of the date, Unix ms.
    #[must_use]
    pub fn ms(self) -> i64 {
        self.days().saturating_mul(86_400_000)
    }
}

/// The age band of someone born on `birth` at `today` (OP-153 m.3 (q)).
#[must_use]
pub fn age_range(birth: Date, today: Date) -> AgeRange {
    if today < birth.plus_years(13) {
        AgeRange::Under13
    } else if today < birth.plus_years(16) {
        AgeRange::Age13To15
    } else if today < birth.plus_years(18) {
        AgeRange::Age16To17
    } else {
        AgeRange::Age18Plus
    }
}

/// What a parent consent answers a ward's request with (E53, E47): pending is
/// `REQUIRE_ACTION`, approval `ALLOW`, a decline or an expiry `DENY`.
#[must_use]
pub fn consent_outcome(decision: Option<&str>, expired: bool) -> Outcome {
    match decision {
        Some("approved") => Outcome::Allow,
        Some(_) => Outcome::Deny,
        None if expired => Outcome::Deny,
        None => Outcome::RequireAction,
    }
}

#[expect(
    clippy::arithmetic_side_effects,
    reason = "civil-calendar arithmetic over a u64 millisecond clock divided to days"
)]
/// The UTC date of `now_ms`, Unix ms.
#[must_use]
pub fn today(now_ms: u64) -> Date {
    let days = i64::try_from(now_ms / 86_400_000).unwrap_or(0) + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Date {
        year: u16::try_from(year).unwrap_or(0),
        month: u8::try_from(month).unwrap_or(1),
        day: u8::try_from(day).unwrap_or(1),
    }
}

/// Ends every guardianship whose ward reached majority and retracts its Claim (E53).
///
/// # Errors
/// [`AdminError`].
pub async fn majorities(
    app: &Pool,
    (tenant, realm): (TenantId, RealmId),
) -> Result<u32, AdminError> {
    let mut t = TenantTx::begin(app, tenant, realm).await?;
    let now = t.server_time().await?;
    let ended = t.end_majorities().await?;
    let mut n = 0u32;
    for id in ended {
        let Some(g) = t.guardianship(id).await? else {
            continue;
        };
        let mut order = ClaimOrder::registry(
            g.ward,
            IdentityClass::Guardianship,
            suiss_crypto::dcbor::Value::text("ended"),
            None,
            (now, 0),
            line(&[b"guardianship", &g.guardian]),
        );
        order.retract = true;
        order.content = Content::Scalar(EqValue::Text(String::from("ended")));
        super::domains::queue(&mut t, &order).await?;
        n = n.saturating_add(1);
    }
    t.commit().await?;
    Ok(n)
}

/// The household's use cases over the realm's rows.
pub struct Household<'a> {
    /// The `access_app` pool.
    pub app: &'a Pool,
    /// The realm's vault keys.
    pub vault: &'a Vault,
}

impl Household<'_> {
    async fn birth(&self, t: &mut TenantTx, subject: [u8; 16]) -> Result<Option<Date>, AdminError> {
        let profile = vault::profile(t, self.vault, subject)
            .await
            .map_err(|e| AdminError::Unavailable(e.to_string()))?;
        Ok(profile
            .iter()
            .find(|(k, _)| k == "birthdate")
            .and_then(|(_, v)| Date::parse(v)))
    }

    /// Records `guardian`'s guardianship of `ward` in `country` on `basis`, until the ward's
    /// majority, and queues its `guardianship` Claim and the ward's `age_range` Claim
    /// (E53). The ward's date of birth must be in the vault.
    ///
    /// # Errors
    /// [`AdminError`]; a ward of age is [`Invalid::AccountState`].
    pub async fn guardianship(
        &self,
        (tenant, realm): (TenantId, RealmId),
        (guardian, ward): ([u8; 16], [u8; 16]),
        basis: GuardianshipBasis,
        country: &str,
    ) -> Result<[u8; 16], AdminError> {
        if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(Invalid::Body.into());
        }
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let now = t.server_time().await?;
        let birth = self
            .birth(&mut t, ward)
            .await?
            .ok_or(Invalid::AccountState)?;
        let majority = birth.plus_years(majority_years(country)).ms();
        if majority <= i64::try_from(now).unwrap_or(i64::MAX) {
            return Err(Invalid::AccountState.into());
        }
        let parties = (
            access_store::idp::subject_party(&mut t, &guardian).await?,
            access_store::idp::subject_party(&mut t, &ward).await?,
        );
        let (Some(gp), Some(wp)) = parties else {
            return Err(Invalid::NoAccount.into());
        };
        let id = t
            .insert_guardianship((guardian, ward), basis.name(), country, majority)
            .await
            .map_err(|_| AdminError::Conflict)?;
        let until = u64::try_from(majority).unwrap_or(0);
        let body = Guardianship {
            guardian: Id(gp),
            ward: Id(wp),
            basis,
            until: Some(until),
        }
        .to_value();
        let order = ClaimOrder::registry(
            ward,
            IdentityClass::Guardianship,
            body,
            None,
            (now, until.saturating_sub(now)),
            line(&[b"guardianship", &guardian]),
        );
        super::domains::queue(&mut t, &order).await?;
        let band = age_range(birth, today(now));
        let mut age = ClaimOrder::registry(
            ward,
            IdentityClass::AgeRange,
            suiss_crypto::dcbor::Value::text(band.name()),
            None,
            (now, access_identity_account::domain::claims::BINDING_TTL_MS),
            line(&[b"age_range"]),
        );
        age.content = Content::Scalar(EqValue::Text(String::from(band.name())));
        super::domains::queue(&mut t, &age).await?;
        t.commit().await?;
        Ok(id)
    }

    /// Asks the guardian of `guardianship` to consent to what `purpose` digests (E53, E47).
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn ask(
        &self,
        (tenant, realm): (TenantId, RealmId),
        guardianship: [u8; 16],
        purpose: &[u8; 32],
    ) -> Result<[u8; 16], AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        t.guardianship(guardianship)
            .await?
            .filter(|g| g.ended_by.is_none())
            .ok_or(Invalid::NoAccount)?;
        let id = t
            .insert_consent(guardianship, purpose, CONSENT_TTL_S)
            .await?;
        t.commit().await?;
        Ok(id)
    }

    /// The guardian `by` decides a consent once, before it expires.
    ///
    /// # Errors
    /// [`AdminError`]; anyone but the guardian is refused.
    pub async fn decide(
        &self,
        (tenant, realm): (TenantId, RealmId),
        consent: [u8; 16],
        by: [u8; 16],
        approve: bool,
    ) -> Result<Outcome, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let c = t.consent(consent).await?.ok_or(Invalid::NoAccount)?;
        let g = t
            .guardianship(c.guardianship)
            .await?
            .ok_or(Invalid::NoAccount)?;
        if g.guardian != by || g.ended_by.is_some() {
            return Err(AdminError::Refused(String::from("not-the-guardian")));
        }
        t.decide_consent(consent, approve).await?;
        let c = t.consent(consent).await?.ok_or(Invalid::NoAccount)?;
        t.commit().await?;
        Ok(consent_outcome(c.decision.as_deref(), c.expired))
    }

    /// What the consent answers the ward's request with now.
    ///
    /// # Errors
    /// [`AdminError`].
    pub async fn outcome(
        &self,
        (tenant, realm): (TenantId, RealmId),
        consent: [u8; 16],
    ) -> Result<Outcome, AdminError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let c = t.consent(consent).await?.ok_or(Invalid::NoAccount)?;
        t.commit().await?;
        Ok(consent_outcome(c.decision.as_deref(), c.expired))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn d(s: &str) -> Date {
        Date::parse(s).unwrap()
    }

    // E53, OP-153 m.3 (q), Ek B 3631, 3632
    #[test]
    fn age_bands_and_majority_follow_the_country_table() {
        let birth = d("2010-02-28");
        assert_eq!(age_range(birth, d("2023-02-27")), AgeRange::Under13);
        assert_eq!(age_range(birth, d("2023-02-28")), AgeRange::Age13To15);
        assert_eq!(age_range(birth, d("2026-03-01")), AgeRange::Age16To17);
        assert_eq!(age_range(birth, d("2028-02-28")), AgeRange::Age18Plus);
        assert_eq!(majority_years("TR"), 18);
        assert_eq!(majority_years("KR"), 19);
        assert_eq!(majority_years("DE"), 18);
        assert_eq!(d("2008-02-29").plus_years(18), d("2026-02-28"));
        assert_eq!(d("1970-01-02").ms(), 86_400_000);
        assert_eq!(
            today(d("2026-11-08").ms().try_into().unwrap()),
            d("2026-11-08")
        );
    }

    // E53, E47, Ek B 3633
    #[test]
    fn silence_is_not_consent() {
        assert_eq!(consent_outcome(None, false), Outcome::RequireAction);
        assert_eq!(consent_outcome(None, true), Outcome::Deny);
        assert_eq!(consent_outcome(Some("declined"), false), Outcome::Deny);
        assert_eq!(consent_outcome(Some("approved"), false), Outcome::Allow);
    }
}
