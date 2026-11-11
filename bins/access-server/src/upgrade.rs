//! `access-server upgrade-check` (OP-56, §17.10.2, OP-158 m.3 (q)): whether this deployment can
//! roll to another build, decided from both builds' compatibility manifests before anything
//! changes. The exit codes are OP-56's: 0 a rolling upgrade is possible, 3 it is not (recreate),
//! 4 rolling upgrades are switched off here. The command lives in `access-server`, not
//! `access-cli`, whose 3 and 4 mean configuration and database errors.

use access_kernel::verify::key_scope::SpecVersions;
use serde::{Deserialize, Serialize};

/// The oldest build a rolling upgrade to this one may start from (OP-56, N-1): the previous
/// minor release.
pub(crate) const ROLLING_FROM: &str = "0.5.0";

/// A build's compatibility metadata.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    /// The build's version.
    pub(crate) version: String,
    /// The oldest build it runs beside during a rolling upgrade.
    pub(crate) rolling_from: String,
    /// The core semantic spec version it evaluates.
    pub(crate) core: u64,
    /// The core meta-schema version it evaluates.
    pub(crate) meta_schema: u64,
    /// The newest schema migration it carries.
    pub(crate) migration: i64,
}

impl Manifest {
    /// This build's manifest.
    pub(crate) fn this() -> Self {
        let semantics = access_authority_sequencer::gate::supported();
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            rolling_from: ROLLING_FROM.to_owned(),
            core: semantics.core,
            meta_schema: semantics.meta_schema,
            migration: access_store::MIGRATOR
                .iter()
                .map(|m| m.version)
                .max()
                .unwrap_or(0),
        }
    }

    fn semantics(&self) -> SpecVersions {
        SpecVersions {
            core: self.core,
            meta_schema: self.meta_schema,
            ..SpecVersions::default()
        }
    }
}

/// The decision, as its exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// 0: the two builds run side by side while the cell rolls.
    Rolling = 0,
    /// 3: they cannot; stop every node, then start the new build.
    Recreate = 3,
    /// 4: rolling upgrades are switched off in this deployment.
    Disabled = 4,
}

fn version(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v
        .split('-')
        .next()?
        .split('.')
        .map(|p| p.parse::<u64>().ok());
    let out = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(out)
}

/// Whether `current` can roll to `target` (OP-56, G64): the newer build declares the older one
/// within its rolling window, and the target evaluates every semantic version the current build
/// does, so until an activation record both commit under the same semantics and afterwards only
/// the nodes that evaluate the new one lead. Anything it cannot read is a recreate.
pub(crate) fn verdict(current: &Manifest, target: &Manifest, rolling: bool) -> Verdict {
    if !rolling {
        return Verdict::Disabled;
    }
    let (Some(c), Some(t)) = (version(&current.version), version(&target.version)) else {
        return Verdict::Recreate;
    };
    let (older, newer) = if t >= c { (c, target) } else { (t, current) };
    let Some(window) = version(&newer.rolling_from) else {
        return Verdict::Recreate;
    };
    if older < window {
        return Verdict::Recreate;
    }
    // G64, OP-56
    if access_kernel::version::check_understood(&current.semantics(), &target.semantics()).is_err()
    {
        return Verdict::Recreate;
    }
    Verdict::Rolling
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn m(version: &str, rolling_from: &str, core: u64) -> Manifest {
        Manifest {
            version: version.to_owned(),
            rolling_from: rolling_from.to_owned(),
            core,
            meta_schema: 1,
            migration: 1,
        }
    }

    // OP-56, Ek B 5816
    #[test]
    fn op_56_exit_codes_follow_the_rolling_window_and_the_feature() {
        let now = m("0.6.0", "0.5.0", 1);
        assert_eq!(
            verdict(&now, &m("0.6.1", "0.6.0", 1), true),
            Verdict::Rolling
        );
        assert_eq!(
            verdict(&m("0.5.2", "0.4.0", 1), &now, true),
            Verdict::Rolling
        );
        assert_eq!(
            verdict(&m("0.4.9", "0.4.0", 1), &now, true),
            Verdict::Recreate
        );
        assert_eq!(
            verdict(&now, &m("0.7.0", "0.6.5", 1), true),
            Verdict::Recreate
        );
        assert_eq!(
            verdict(&now, &m("0.6.1", "0.6.0", 1), false),
            Verdict::Disabled
        );
        assert_eq!(
            verdict(&now, &m("not a version", "0.6.0", 1), true),
            Verdict::Recreate
        );
    }

    // G64, OP-56: a build that no longer evaluates the core version in force cannot roll in
    #[test]
    fn g64_a_target_that_drops_the_semantics_in_force_is_a_recreate() {
        let now = m("0.6.0", "0.5.0", 2);
        assert_eq!(
            verdict(&now, &m("0.6.1", "0.6.0", 1), true),
            Verdict::Recreate
        );
        assert_eq!(
            verdict(&now, &m("0.6.1", "0.6.0", 3), true),
            Verdict::Rolling
        );
    }

    #[test]
    fn this_build_declares_itself_within_its_own_window() {
        let me = Manifest::this();
        assert_eq!(verdict(&me, &me, true), Verdict::Rolling);
        assert!(me.migration >= 20_261_119_070_000);
    }
}
