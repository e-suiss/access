//! The local deployment's Stage 12 fixtures (OP-157 m.4 (a), OP-69): a support operator Party
//! (lane V1/V2), a break-glass account (lane V3) and a review schedule (lane V10) that the `@live`
//! specs use. Each is made only by Exercises of the realm's own Parties, never by a SQL seed
//! (TN-110, MD-14). Until its lane builds it, a plan that names a section is refused, so a
//! fixture is never silently missing.

use serde::Deserialize;

use super::{BootstrapError, sample_tenant};

/// Longest display name or identifier (it is rendered as text).
const MAX_TEXT: usize = 200;

/// Longest review period, in days.
const MAX_PERIOD_DAYS: u16 = 366;

/// `[support_operator]` as written: a support operator Party in its team's organisation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SupportOperatorFile {
    realm: String,
    display_name: String,
    organisation: String,
}

/// `[breakglass_account]` as written: an organisation member marked `is_breakglass`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BreakglassAccountFile {
    realm: String,
    identifier: String,
}

/// `[review_schedule]` as written: an `idp.review.schedule` over the manager's team.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReviewScheduleFile {
    realm: String,
    period_days: u16,
}

/// The plan's Stage 12 fixture sections.
pub(super) struct Fixtures<'a> {
    pub(super) support_operator: Option<&'a SupportOperatorFile>,
    pub(super) breakglass_account: Option<&'a BreakglassAccountFile>,
    pub(super) review_schedule: Option<&'a ReviewScheduleFile>,
}

fn text(section: &str, field: &str, value: &str) -> Result<(), BootstrapError> {
    if value.trim().is_empty() || value.chars().count() > MAX_TEXT {
        return Err(BootstrapError::Plan(format!(
            "{section}: {field} is 1 to {MAX_TEXT} characters"
        )));
    }
    Ok(())
}

fn not_built(section: &str) -> BootstrapError {
    BootstrapError::Plan(format!(
        "{section}: this fixture is not built yet (OP-157 m.4 (a))"
    ))
}

impl Fixtures<'_> {
    /// Checks each section that is present, then refuses it until its lane builds it.
    pub(super) fn check(&self, tenants: &[String]) -> Result<(), BootstrapError> {
        if let Some(s) = self.support_operator {
            sample_tenant(tenants, "support_operator", &s.realm)?;
            text("support_operator", "display_name", &s.display_name)?;
            text("support_operator", "organisation", &s.organisation)?;
            return Err(not_built("support_operator"));
        }
        if let Some(b) = self.breakglass_account {
            sample_tenant(tenants, "breakglass_account", &b.realm)?;
            text("breakglass_account", "identifier", &b.identifier)?;
            return Err(not_built("breakglass_account"));
        }
        if let Some(r) = self.review_schedule {
            sample_tenant(tenants, "review_schedule", &r.realm)?;
            if r.period_days == 0 || r.period_days > MAX_PERIOD_DAYS {
                return Err(BootstrapError::Plan(format!(
                    "review_schedule: period_days is 1 to {MAX_PERIOD_DAYS}"
                )));
            }
            return Err(not_built("review_schedule"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Plan;

    // OP-157 m.4 (a), TI-9
    #[test]
    fn a_plan_naming_an_unbuilt_fixture_is_refused() {
        let dir = std::env::temp_dir().join(format!("abs-fixtures-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let head = "platform = \"platform\"\ntenants = [\"acme\"]\n";
        for (name, section) in [
            (
                "support",
                "[support_operator]\nrealm = \"acme\"\ndisplay_name = \"Mehmet Y.\"\norganisation = \"Acme Support\"\n",
            ),
            (
                "breakglass",
                "[breakglass_account]\nrealm = \"acme\"\nidentifier = \"oncall@acme.example\"\n",
            ),
            (
                "review",
                "[review_schedule]\nrealm = \"acme\"\nperiod_days = 90\n",
            ),
        ] {
            let path = dir.join(format!("{name}.toml"));
            std::fs::write(&path, format!("{head}{section}")).unwrap();
            let err = Plan::load(&path).unwrap_err().to_string();
            assert!(err.contains("not built yet"), "{name}: {err}");
        }
        let elsewhere = dir.join("elsewhere.toml");
        std::fs::write(
            &elsewhere,
            format!("{head}[review_schedule]\nrealm = \"beta\"\nperiod_days = 90\n"),
        )
        .unwrap();
        let err = Plan::load(&elsewhere).unwrap_err().to_string();
        assert!(err.contains("not one of the plan's tenants"), "{err}");
    }
}
