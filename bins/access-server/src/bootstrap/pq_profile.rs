//! The local deployment's Stage 14 fixture (OP-159 m.4 (a), OP-157 m.6 (i), OP-69): a sample realm
//! with the post-quantum signing profile on, which the Signing screen's `@live` spec and the
//! post-quantum token tests use. It is opened by the realm's own `idp.realm.signing_profile` and
//! `idp.realm.kex_share` Exercises, never by a SQL seed (TN-110, MD-14); a second run changes
//! nothing.

use access_identity_admin::app::Admin;
use access_identity_admin::domain::Change;
use access_identity_admin::domain::assurance::{KexMode, KexShare, MlDsa, SigningProfile};
use access_identity_admin::ports::{Decider, Governance, Instances, RealmKeys};
use access_kernel::digest::Digest;
use access_store::identity::{RealmId, TenantId, TenantTx};
use serde::{Deserialize, Serialize};

use super::{Bootstrap, BootstrapError, HsmSigner, MetaExercises, sample_tenant};

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

/// The fixture as checked.
#[derive(Clone, Debug)]
pub(crate) struct PqProfilePlan {
    /// The sample realm's slug.
    pub(crate) realm: String,
    /// The ML-DSA parameter set.
    pub(crate) profile: MlDsa,
    /// The key exchange share policy, when the plan names one.
    pub(crate) kex_share: Option<KexMode>,
}

/// The fixture in the summary.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct PqProfileOut {
    /// The realm's slug.
    pub(crate) realm: String,
    /// The open ML-DSA parameter set.
    pub(crate) profile: &'static str,
    /// The key exchange share policy.
    pub(crate) kex_share: String,
    /// Whether this run opened the profile.
    pub(crate) created: bool,
}

/// Checks the plan's `[pq_profile]` section when it is present.
pub(super) fn check(
    pq_profile: Option<PqProfileFile>,
    tenants: &[String],
) -> Result<Option<PqProfilePlan>, BootstrapError> {
    let Some(p) = pq_profile else {
        return Ok(None);
    };
    sample_tenant(tenants, "pq_profile", &p.realm)?;
    let profile = [MlDsa::MlDsa65, MlDsa::MlDsa44, MlDsa::MlDsa87]
        .into_iter()
        .find(|m| m.name() == p.profile)
        .ok_or_else(|| {
            BootstrapError::Plan(String::from(
                "pq_profile: profile is ml-dsa-65, ml-dsa-44 or ml-dsa-87",
            ))
        })?;
    let kex_share = match p.kex_share.as_deref() {
        None => None,
        Some(k) => Some(
            [KexMode::Optimistic, KexMode::AdvertiseOnly]
                .into_iter()
                .find(|m| m.name() == k)
                .ok_or_else(|| {
                    BootstrapError::Plan(String::from(
                        "pq_profile: kex_share is optimistic or advertise-only",
                    ))
                })?,
        ),
    };
    Ok(Some(PqProfilePlan {
        realm: p.realm,
        profile,
        kex_share,
    }))
}

impl<P, K> Bootstrap<'_, P, K>
where
    P: Decider + Governance + Instances + MetaExercises,
    K: RealmKeys,
{
    /// Opens `p`'s signing profile and sets its share policy through the realm's own Exercises
    /// (CR-41, OP-159 m.3 (a), (o), (t)), unless the realm already holds them.
    pub(super) async fn pq_profile(
        &self,
        admin: &Admin<'_, P, P, K>,
        (tenant, realm): (TenantId, RealmId),
        (domain, root): (Digest, &HsmSigner),
        p: &PqProfilePlan,
    ) -> Result<PqProfileOut, BootstrapError> {
        let mut t = TenantTx::begin(self.app, tenant, realm).await?;
        let held = t.realm_signing().await?;
        t.commit().await?;
        let created = held.profile.as_deref() != Some(p.profile.name());
        if created {
            self.change(
                admin,
                (tenant, realm),
                domain,
                root,
                Change::SigningProfile(Some(SigningProfile { profile: p.profile })),
            )
            .await?;
        }
        let mut kex_share = held.kex_share;
        if let Some(mode) = p.kex_share.filter(|m| m.name() != kex_share) {
            self.change(
                admin,
                (tenant, realm),
                domain,
                root,
                Change::KexShare(KexShare { mode }),
            )
            .await?;
            kex_share = String::from(mode.name());
        }
        Ok(PqProfileOut {
            realm: p.realm.clone(),
            profile: p.profile.name(),
            kex_share,
            created,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::Plan;
    use super::*;

    // OP-159 m.4 (a), TI-9
    #[test]
    fn a_pq_profile_fixture_names_a_sample_realm_a_parameter_set_and_a_share_policy() {
        let dir = std::env::temp_dir().join(format!("abs-assurance-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let head = "platform = \"platform\"\ntenants = [\"acme\"]\n";
        let path = dir.join("built.toml");
        std::fs::write(
            &path,
            format!("{head}[pq_profile]\nrealm = \"acme\"\nprofile = \"ml-dsa-65\"\nkex_share = \"advertise-only\"\n"),
        )
        .unwrap();
        let plan = Plan::load(&path).unwrap().pq_profile.unwrap();
        assert_eq!(plan.realm, "acme");
        assert_eq!(plan.profile, MlDsa::MlDsa65);
        assert_eq!(plan.kex_share, Some(KexMode::AdvertiseOnly));
        for (name, section, want) in [
            (
                "elsewhere",
                "[pq_profile]\nrealm = \"globex\"\nprofile = \"ml-dsa-65\"\n",
                "pq_profile",
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
