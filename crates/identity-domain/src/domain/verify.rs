//! Verification of a custom domain (OP-156 m.3 (i)): both records must hold at once, the TXT
//! challenge at `_access-challenge.<host>` and the host's CNAME to the realm's `<slug>.<base>`.
//! A verification lasts 90 days; a check that finds either record gone lapses it, and a lapsed
//! domain is not served and renews no certificate.

use super::host::CustomHost;

/// How long a verification holds before it is checked again: 90 days (OP-156 m.3 (i)).
pub const REVERIFY_S: i64 = 90 * 86_400;

/// How often a verified domain's records are read again: daily, so a removed record lapses the
/// domain within a day (PD).
pub const RECHECK_S: i64 = 86_400;

/// How often a pending domain's records are read until both are found (PD).
pub const PENDING_CHECK_S: i64 = 300;

/// Longest a registration stays pending before it is retired by the check: 14 days (PD).
pub const PENDING_TTL_S: i64 = 14 * 86_400;

/// The state of a registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Registered, its records not yet found.
    Pending,
    /// Both records found; served while the verification holds.
    Verified,
    /// A check found a record gone, or the verification ran out: not served.
    Lapsed,
    /// A pending registration whose records were never found in time.
    Expired,
    /// Retired by `idp.domain.retire`.
    Retired,
}

impl Status {
    /// Its name in the store.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Lapsed => "lapsed",
            Self::Expired => "expired",
            Self::Retired => "retired",
        }
    }

    /// The status of a stored name.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "verified" => Some(Self::Verified),
            "lapsed" => Some(Self::Lapsed),
            "expired" => Some(Self::Expired),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }
}

/// What the DNS said about a domain's two records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finding {
    /// Both records hold.
    Both,
    /// No TXT record carries the challenge.
    NoChallenge,
    /// The host has no CNAME to the realm hostname.
    NoCname,
}

impl Finding {
    /// Stable code, shown to the administrator.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Both => "verified",
            Self::NoChallenge => "challenge-record-missing",
            Self::NoCname => "cname-record-missing",
        }
    }
}

fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// What the records found mean: `txt` are the TXT strings at the challenge name, `cnames` the
/// CNAME targets of the host, `target` the realm hostname.
#[must_use]
pub fn finding(challenge: &str, txt: &[String], cnames: &[String], target: &str) -> Finding {
    if !txt.iter().any(|t| t.trim() == challenge) {
        return Finding::NoChallenge;
    }
    if !cnames.iter().any(|c| same_name(c, target)) {
        return Finding::NoCname;
    }
    Finding::Both
}

/// A registration as a check reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// The host.
    pub host: CustomHost,
    /// Its state.
    pub status: Status,
    /// When it was registered, Unix seconds.
    pub registered_at: i64,
    /// Until when its verification holds, Unix seconds; none before the first.
    pub reverify_by: Option<i64>,
    /// When its records were last read, Unix seconds.
    pub checked_at: Option<i64>,
}

/// What a check does to a registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Nothing yet.
    Wait,
    /// Read the records now.
    Check,
    /// Retire a pending registration that timed out.
    Expire,
}

/// Whether a check reads the records of `r` at `now_s`.
#[must_use]
pub fn due(r: &Registration, now_s: i64) -> Step {
    let since = |every: i64| {
        r.checked_at
            .is_none_or(|t| now_s >= t.saturating_add(every))
    };
    match r.status {
        Status::Retired | Status::Expired => Step::Wait,
        Status::Pending if now_s >= r.registered_at.saturating_add(PENDING_TTL_S) => Step::Expire,
        Status::Pending | Status::Lapsed => {
            if since(PENDING_CHECK_S) {
                Step::Check
            } else {
                Step::Wait
            }
        }
        Status::Verified => {
            let expired = r.reverify_by.is_none_or(|t| now_s >= t);
            if expired || since(RECHECK_S) {
                Step::Check
            } else {
                Step::Wait
            }
        }
    }
}

/// The state after a check of `r` found `f` at `now_s`, and the new `reverify_by`.
#[must_use]
pub fn after(r: &Registration, f: Finding, now_s: i64) -> (Status, Option<i64>) {
    match (r.status, f) {
        (Status::Retired | Status::Expired, _) => (r.status, r.reverify_by),
        (_, Finding::Both) => (Status::Verified, Some(now_s.saturating_add(REVERIFY_S))),
        (Status::Pending, _) => (Status::Pending, None),
        (Status::Verified | Status::Lapsed, _) => (Status::Lapsed, r.reverify_by),
    }
}

/// Whether `r` is served at `now_s`: verified, and the verification holds (OP-156 m.3 (i)).
#[must_use]
pub fn served(r: &Registration, now_s: i64) -> bool {
    r.status == Status::Verified && r.reverify_by.is_some_and(|t| now_s < t)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(status: Status, reverify_by: Option<i64>, checked_at: Option<i64>) -> Registration {
        Registration {
            host: CustomHost::stored("login.acme.example"),
            status,
            registered_at: 1_000,
            reverify_by,
            checked_at,
        }
    }

    // OP-156 m.3 (i)
    #[test]
    fn both_records_verify_and_either_missing_does_not() {
        let txt = vec![String::from("other"), String::from("tok")];
        let cname = vec![String::from("acme.suiss.id.")];
        assert_eq!(finding("tok", &txt, &cname, "acme.suiss.id"), Finding::Both);
        assert_eq!(
            finding("tok", &[], &cname, "acme.suiss.id"),
            Finding::NoChallenge
        );
        assert_eq!(
            finding(
                "tok",
                &txt,
                &[String::from("evil.suiss.id")],
                "acme.suiss.id"
            ),
            Finding::NoCname
        );
    }

    // OP-156 m.3 (i)
    #[test]
    fn a_verification_holds_ninety_days_and_a_missing_record_lapses_it() {
        let now = 10_000;
        let p = reg(Status::Pending, None, None);
        assert_eq!(due(&p, now), Step::Check);
        assert_eq!(after(&p, Finding::NoCname, now), (Status::Pending, None));
        let (status, by) = after(&p, Finding::Both, now);
        assert_eq!((status, by), (Status::Verified, Some(now + REVERIFY_S)));
        let v = reg(Status::Verified, by, Some(now));
        assert!(served(&v, now + 1));
        assert!(!served(&v, now + REVERIFY_S));
        assert_eq!(due(&v, now + 60), Step::Wait);
        assert_eq!(due(&v, now + RECHECK_S), Step::Check);
        assert_eq!(after(&v, Finding::NoChallenge, now + 1).0, Status::Lapsed);
        let l = reg(Status::Lapsed, by, Some(now));
        assert!(!served(&l, now + 1));
        assert_eq!(after(&l, Finding::Both, now + 600).0, Status::Verified);
        assert_eq!(
            due(&reg(Status::Pending, None, None), 1_000 + PENDING_TTL_S),
            Step::Expire
        );
        assert_eq!(due(&reg(Status::Retired, None, None), now), Step::Wait);
    }
}
