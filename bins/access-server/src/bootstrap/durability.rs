//! The local deployment's Stage 13 fixtures (OP-158 m.4 (a), OP-157 m.6 (i), OP-69): the witnesses
//! a sample domain declares (lane W2), its replica (lane W3) and a second provider install (lanes
//! W5 and W6) that the `@live` specs and the durability tests use. Each is declared by the
//! domain's own Exercises, never by a SQL seed (TN-110, MD-14). Until its lane builds it, a plan
//! that names a section is refused, so a fixture is never silently missing.

use serde::Deserialize;

use super::{BootstrapError, sample_tenant};

/// Longest endpoint.
const MAX_URL: usize = 2048;

/// The least number of declared witnesses (§13.3, PD).
const MIN_WITNESSES: usize = 2;

/// `[witnesses]` as written: the witness processes the sample domain declares.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WitnessesFile {
    realm: String,
    endpoints: Vec<String>,
}

/// `[replica]` as written: the replica agent that follows the sample domain's mirror.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReplicaFile {
    realm: String,
    endpoint: String,
}

/// `[second_provider]` as written: another `access-server` install that plays the incoming or
/// recovering provider.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecondProviderFile {
    realm: String,
    endpoint: String,
}

/// The plan's Stage 13 fixture sections.
pub(super) struct Fixtures<'a> {
    pub(super) witnesses: Option<&'a WitnessesFile>,
    pub(super) replica: Option<&'a ReplicaFile>,
    pub(super) second_provider: Option<&'a SecondProviderFile>,
}

fn endpoint(section: &str, value: &str) -> Result<(), BootstrapError> {
    let ok = value.len() <= MAX_URL
        && (value.starts_with("https://") || value.starts_with("http://127.0.0.1:"))
        && !value.chars().any(|c| c.is_control() || c.is_whitespace());
    if ok {
        Ok(())
    } else {
        Err(BootstrapError::Plan(format!(
            "{section}: an endpoint is an https URL, or http on 127.0.0.1, of at most {MAX_URL} bytes"
        )))
    }
}

fn not_built(section: &str) -> BootstrapError {
    BootstrapError::Plan(format!(
        "{section}: this fixture is not built yet (OP-158 m.4 (a))"
    ))
}

impl Fixtures<'_> {
    /// Checks each section that is present, then refuses it until its lane builds it.
    pub(super) fn check(&self, tenants: &[String]) -> Result<(), BootstrapError> {
        if let Some(w) = self.witnesses {
            sample_tenant(tenants, "witnesses", &w.realm)?;
            if w.endpoints.len() < MIN_WITNESSES {
                return Err(BootstrapError::Plan(format!(
                    "witnesses: at least {MIN_WITNESSES} endpoints"
                )));
            }
            for e in &w.endpoints {
                endpoint("witnesses", e)?;
            }
            return Err(not_built("witnesses"));
        }
        if let Some(r) = self.replica {
            sample_tenant(tenants, "replica", &r.realm)?;
            endpoint("replica", &r.endpoint)?;
            return Err(not_built("replica"));
        }
        if let Some(p) = self.second_provider {
            sample_tenant(tenants, "second_provider", &p.realm)?;
            endpoint("second_provider", &p.endpoint)?;
            return Err(not_built("second_provider"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Plan;

    // OP-158 m.4 (a), TI-9
    #[test]
    fn a_plan_naming_an_unbuilt_stage_13_fixture_is_refused() {
        let dir = std::env::temp_dir().join(format!("abs-durability-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let head = "platform = \"platform\"\ntenants = [\"acme\"]\n";
        for (name, section) in [
            (
                "witnesses",
                "[witnesses]\nrealm = \"acme\"\nendpoints = [\"http://127.0.0.1:7801\", \"http://127.0.0.1:7802\"]\n",
            ),
            (
                "replica",
                "[replica]\nrealm = \"acme\"\nendpoint = \"http://127.0.0.1:7811\"\n",
            ),
            (
                "second",
                "[second_provider]\nrealm = \"acme\"\nendpoint = \"https://provider-b.example\"\n",
            ),
        ] {
            let path = dir.join(format!("{name}.toml"));
            std::fs::write(&path, format!("{head}{section}")).unwrap();
            let err = Plan::load(&path).unwrap_err().to_string();
            assert!(err.contains("not built yet"), "{name}: {err}");
        }
        let one = dir.join("one.toml");
        std::fs::write(
            &one,
            format!(
                "{head}[witnesses]\nrealm = \"acme\"\nendpoints = [\"http://127.0.0.1:7801\"]\n"
            ),
        )
        .unwrap();
        let err = Plan::load(&one).unwrap_err().to_string();
        assert!(err.contains("at least 2"), "{err}");
    }
}
