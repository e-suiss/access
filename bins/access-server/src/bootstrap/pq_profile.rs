//! The local deployment's Stage 14 fixture (OP-159 m.4 (a), OP-157 m.6 (i), OP-69): a sample realm
//! with the post-quantum signing profile on (lane J3), which the Signing screen's `@live` spec and
//! the post-quantum token tests use. It is opened by the realm's own `idp.realm.signing_profile`
//! and `idp.realm.kex_share` Exercises, never by a SQL seed (TN-110, MD-14). Until its lane builds
//! it, a plan that names the section is refused, so the fixture is never silently missing.

use serde::Deserialize;

use super::{BootstrapError, sample_tenant};

/// `[pq_profile]` as written: the sample realm's ML-DSA parameter set and key exchange share
/// policy.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PqProfileFile {
    realm: String,
    profile: String,
    #[serde(default)]
    kex_share: Option<String>,
}

/// Checks the plan's `[pq_profile]` section when it is present, then refuses it until its lane
/// builds it.
pub(super) fn check(
    pq_profile: Option<&PqProfileFile>,
    tenants: &[String],
) -> Result<(), BootstrapError> {
    let Some(p) = pq_profile else {
        return Ok(());
    };
    sample_tenant(tenants, "pq_profile", &p.realm)?;
    if !["ml-dsa-65", "ml-dsa-44", "ml-dsa-87"].contains(&p.profile.as_str()) {
        return Err(BootstrapError::Plan(String::from(
            "pq_profile: profile is ml-dsa-65, ml-dsa-44 or ml-dsa-87",
        )));
    }
    if p.kex_share
        .as_deref()
        .is_some_and(|k| k != "optimistic" && k != "advertise-only")
    {
        return Err(BootstrapError::Plan(String::from(
            "pq_profile: kex_share is optimistic or advertise-only",
        )));
    }
    Err(BootstrapError::Plan(String::from(
        "pq_profile: this fixture is not built yet (OP-159 m.4 (a))",
    )))
}

#[cfg(test)]
mod tests {
    use super::super::Plan;

    // OP-159 m.4 (a), TI-9
    #[test]
    fn a_plan_naming_the_unbuilt_pq_profile_fixture_is_refused() {
        let dir = std::env::temp_dir().join(format!("abs-assurance-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let head = "platform = \"platform\"\ntenants = [\"acme\"]\n";
        for (name, section, want) in [
            (
                "built",
                "[pq_profile]\nrealm = \"acme\"\nprofile = \"ml-dsa-65\"\nkex_share = \"advertise-only\"\n",
                "not built yet",
            ),
            (
                "classic",
                "[pq_profile]\nrealm = \"acme\"\nprofile = \"ed25519\"\n",
                "ml-dsa-65, ml-dsa-44 or ml-dsa-87",
            ),
            (
                "share",
                "[pq_profile]\nrealm = \"acme\"\nprofile = \"ml-dsa-44\"\nkex_share = \"classic-only\"\n",
                "optimistic or advertise-only",
            ),
        ] {
            let path = dir.join(format!("{name}.toml"));
            std::fs::write(&path, format!("{head}{section}")).unwrap();
            let err = Plan::load(&path).unwrap_err().to_string();
            assert!(err.contains(want), "{name}: {err}");
        }
    }
}
