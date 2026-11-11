//! `idp.review.*` changes (catalog 7, OP-157 m.3 (a), (w)): scheduling and ending an access
//! review campaign. A campaign is a view over the reviewer's team's Grants, never a queue; it
//! writes no authority. Sans-I/O: the REST body becomes one change, which the intent binds
//! (EI-25).

use access_internal_api::idp::IdpAction;
use serde_json::{Map, Value as Json};
use suiss_crypto::dcbor::Value;

use super::Invalid;
use super::hr::name_ok;

/// The scopes a campaign may review (IDP-39 (3)): the reviewer's own team.
pub const SCOPES: [&str; 1] = ["manager_team"];

/// Shortest campaign period, in days (PD).
pub const MIN_PERIOD_DAYS: u32 = 7;

/// Longest campaign period, in days (PD).
pub const MAX_PERIOD_DAYS: u32 = 366;

/// One campaign schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewSchedule {
    /// Its name, never reused.
    pub name: String,
    /// How often it runs, in days.
    pub period_days: u32,
    /// What it reviews, one of [`SCOPES`].
    pub scope: String,
}

/// An `idp.review.*` change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReviewChange {
    /// `idp.review.schedule` (CT2).
    Schedule(ReviewSchedule),
    /// `idp.review.schedule_close` (CT1).
    Close(String),
}

fn own(body: &Json) -> Result<&Map<String, Json>, Invalid> {
    body.as_object().ok_or(Invalid::Body)
}

impl ReviewChange {
    /// `scheduleReview`: `{"name", "period_days", "scope"}`.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn schedule(body: &Json) -> Result<Self, Invalid> {
        let m = own(body)?;
        if !m
            .keys()
            .all(|k| ["name", "period_days", "scope"].contains(&k.as_str()))
        {
            return Err(Invalid::Body);
        }
        Ok(Self::Schedule(ReviewSchedule {
            name: String::from(m.get("name").and_then(Json::as_str).ok_or(Invalid::Body)?),
            period_days: m
                .get("period_days")
                .and_then(Json::as_u64)
                .and_then(|d| u32::try_from(d).ok())
                .ok_or(Invalid::Body)?,
            scope: String::from(m.get("scope").and_then(Json::as_str).ok_or(Invalid::Body)?),
        }))
    }

    /// `closeReview` of `name`: an empty body.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn close(name: &str, body: &Json) -> Result<Self, Invalid> {
        if !own(body)?.is_empty() {
            return Err(Invalid::Body);
        }
        Ok(Self::Close(String::from(name)))
    }

    /// The action that authorizes it.
    #[must_use]
    pub const fn action(&self) -> IdpAction {
        match self {
            Self::Schedule(_) => IdpAction::ReviewSchedule,
            Self::Close(_) => IdpAction::ReviewScheduleClose,
        }
    }

    /// Whether it is inside the rules: a name of lower-case letters, digits and `-`, a period
    /// of [`MIN_PERIOD_DAYS`] to [`MAX_PERIOD_DAYS`] days and a known scope.
    ///
    /// # Errors
    /// [`Invalid::Body`].
    pub fn check(&self) -> Result<(), Invalid> {
        let ok = match self {
            Self::Schedule(s) => {
                name_ok(&s.name)
                    && (MIN_PERIOD_DAYS..=MAX_PERIOD_DAYS).contains(&s.period_days)
                    && SCOPES.contains(&s.scope.as_str())
            }
            Self::Close(n) => name_ok(n),
        };
        if ok { Ok(()) } else { Err(Invalid::Body) }
    }

    /// The change's body, which the intent binds (EI-25).
    #[must_use]
    pub fn body(&self) -> Value {
        match self {
            Self::Schedule(s) => Value::Map(vec![
                (Value::text("name"), Value::text(&s.name)),
                (
                    Value::text("period_days"),
                    Value::Unsigned(u64::from(s.period_days)),
                ),
                (Value::text("scope"), Value::text(&s.scope)),
            ]),
            Self::Close(n) => Value::Map(vec![(Value::text("close"), Value::text(n))]),
        }
    }

    /// Its resource path below the realm.
    #[must_use]
    pub fn path(&self) -> [String; 2] {
        let name = match self {
            Self::Schedule(s) => &s.name,
            Self::Close(n) => n,
        };
        [String::from("review"), name.clone()]
    }
}
