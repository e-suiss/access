//! `cargo xtask psirt deadlines` (SA-16, MD-12, §18.11, OP-159 m.3 (jj)): the CRA Art. 14
//! reporting deadlines of an actively exploited vulnerability or a severe incident, from the
//! periods in the support policy catalog.

use std::fmt::Write as _;
use std::path::Path;

use crate::civil;
use crate::rules::support_policy::{self, Cra};

/// The four deadlines in Unix seconds.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Deadlines {
    pub(crate) early_warning: i64,
    pub(crate) notification: i64,
    pub(crate) final_vulnerability: i64,
    pub(crate) final_incident: i64,
}

/// Deadlines counted from awareness; the final reports from the fix and the notification, or
/// from awareness when those are not given, which is the earliest they can fall.
pub(crate) fn deadlines(
    cra: &Cra,
    aware: i64,
    fixed: Option<i64>,
    notified: Option<i64>,
) -> Deadlines {
    Deadlines {
        early_warning: civil::add_hours(aware, i64::from(cra.early_warning_hours)),
        notification: civil::add_hours(aware, i64::from(cra.notification_hours)),
        final_vulnerability: civil::add_days(
            fixed.unwrap_or(aware),
            i64::from(cra.final_report_vulnerability_days),
        ),
        final_incident: civil::add_months(
            notified.unwrap_or(aware),
            cra.final_report_incident_months,
        ),
    }
}

fn instant(flag: &str, value: Option<&String>) -> Result<i64, String> {
    let value = value.ok_or_else(|| format!("{flag} needs an RFC 3339 date-time"))?;
    civil::parse_rfc3339(value)
        .ok_or_else(|| format!("{flag} {value}: not an RFC 3339 date-time (2026-11-12T09:30:00Z)"))
}

/// The report for `--aware-at <t> [--fixed-at <t>] [--notified-at <t>]`.
pub(crate) fn report(cra: &Cra, args: &[String]) -> Result<String, String> {
    let (mut aware, mut fixed, mut notified) = (None, None, None);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--aware-at" => &mut aware,
            "--fixed-at" => &mut fixed,
            "--notified-at" => &mut notified,
            other => return Err(format!("unknown argument {other}")),
        };
        *slot = Some(instant(flag, it.next())?);
    }
    let aware = aware.ok_or_else(|| String::from("--aware-at is required"))?;
    for (flag, t) in [("--fixed-at", fixed), ("--notified-at", notified)] {
        if t.is_some_and(|t| t < aware) {
            return Err(format!("{flag} precedes --aware-at"));
        }
    }
    let d = deadlines(cra, aware, fixed, notified);
    let fmt = civil::format_rfc3339;
    let from = |t: Option<i64>, what: &str| {
        t.map_or_else(
            || format!("awareness; pass {what} for the actual date"),
            fmt,
        )
    };
    let mut out = String::new();
    let _ = writeln!(out, "CRA Art. 14 deadlines, aware at {}", fmt(aware));
    let _ = writeln!(
        out,
        "early warning                {}  {} h after awareness",
        fmt(d.early_warning),
        cra.early_warning_hours
    );
    let _ = writeln!(
        out,
        "notification                 {}  {} h after awareness",
        fmt(d.notification),
        cra.notification_hours
    );
    let _ = writeln!(
        out,
        "final report, vulnerability  {}  {} days after the fix is available, from {}",
        fmt(d.final_vulnerability),
        cra.final_report_vulnerability_days,
        from(fixed, "--fixed-at")
    );
    let _ = writeln!(
        out,
        "final report, severe incident {} {} month after the notification, from {}",
        fmt(d.final_incident),
        cra.final_report_incident_months,
        from(notified, "--notified-at")
    );
    Ok(out)
}

/// `cargo xtask psirt deadlines ...`.
pub(crate) fn run(root: &Path, args: &[String]) -> Result<String, String> {
    match args.split_first() {
        Some((cmd, rest)) if cmd == "deadlines" => {
            let policy = support_policy::load(root)?;
            report(&policy.cra, rest)
        }
        _ => Err(String::from(
            "usage: cargo xtask psirt deadlines --aware-at <RFC 3339> [--fixed-at <RFC 3339>] [--notified-at <RFC 3339>]",
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assert_is_empty, reason = "test code")]

    use super::*;

    fn cra() -> Cra {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        support_policy::load(root).unwrap().cra
    }

    fn at(s: &str) -> i64 {
        civil::parse_rfc3339(s).unwrap()
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    // SA-16, MD-12
    #[test]
    fn deadlines_follow_article_14() {
        let d = deadlines(
            &cra(),
            at("2026-12-30T22:15:00+01:00"),
            Some(at("2027-01-20T08:00:00Z")),
            Some(at("2027-01-31T12:00:00Z")),
        );
        assert_eq!(
            civil::format_rfc3339(d.early_warning),
            "2026-12-31T21:15:00Z"
        );
        assert_eq!(
            civil::format_rfc3339(d.notification),
            "2027-01-02T21:15:00Z"
        );
        assert_eq!(
            civil::format_rfc3339(d.final_vulnerability),
            "2027-02-03T08:00:00Z"
        );
        assert_eq!(
            civil::format_rfc3339(d.final_incident),
            "2027-02-28T12:00:00Z"
        );
    }

    // SA-16
    #[test]
    fn without_a_fix_or_notification_the_final_reports_count_from_awareness() {
        let text = report(&cra(), &args(&["--aware-at", "2026-11-12T09:30:00Z"])).unwrap();
        assert!(text.contains("early warning                2026-11-13T09:30:00Z"));
        assert!(text.contains("notification                 2026-11-15T09:30:00Z"));
        assert!(text.contains("final report, vulnerability  2026-11-26T09:30:00Z"));
        assert!(text.contains("final report, severe incident 2026-12-12T09:30:00Z"));
        assert!(text.contains("pass --fixed-at"));
    }

    // SA-16
    #[test]
    fn bad_input_is_refused() {
        let c = cra();
        assert!(report(&c, &args(&[])).is_err());
        assert!(report(&c, &args(&["--aware-at", "2026-11-12"])).is_err());
        assert!(report(&c, &args(&["--aware-at"])).is_err());
        assert!(
            report(
                &c,
                &args(&["--aware-at", "2026-11-12T00:00:00Z", "--x", "y"])
            )
            .is_err()
        );
        assert!(
            report(
                &c,
                &args(&[
                    "--aware-at",
                    "2026-11-12T00:00:00Z",
                    "--fixed-at",
                    "2026-11-11T00:00:00Z"
                ])
            )
            .is_err()
        );
    }
}
