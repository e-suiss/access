//! The management API's pure rules (OP-63 sans-I/O): surfaces, trace context, rate limits,
//! idempotency, conditional requests, pagination, lifecycle headers, JSON Merge Patch and the
//! caller model.

pub mod caller;
pub mod conditional;
pub mod idempotency;
pub mod lifecycle;
pub mod merge_patch;
pub mod page;
pub mod rate;
pub mod trace;

/// A management surface (TN-119, OP-151 m.3 (a)): separate audience, scope namespace and rate
/// budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Surface {
    /// Environment administration, `/admin/v1/envs/{slug}/…`.
    Environment,
    /// Platform administration, `/admin/v1/platform/…`.
    Platform,
}

impl Surface {
    /// The scope a read on this surface needs at least.
    #[must_use]
    pub const fn read_scope(self) -> &'static str {
        match self {
            Self::Environment => "environment.read",
            Self::Platform => "platform.read",
        }
    }

    /// The surface's name in the contract.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Platform => "platform",
        }
    }
}

/// Prefix of an environment-admin audience; the environment's slug follows.
pub const ENVIRONMENT_AUDIENCE_PREFIX: &str = "access-admin:environment:";

/// The platform-admin audience.
pub const PLATFORM_AUDIENCE: &str = "access-admin:platform";

/// One surface instance: an environment's administration, or the platform's.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SurfaceScope {
    /// The environment with this slug.
    Environment(String),
    /// The platform.
    Platform,
}

impl SurfaceScope {
    /// The surface.
    #[must_use]
    pub const fn surface(&self) -> Surface {
        match self {
            Self::Environment(_) => Surface::Environment,
            Self::Platform => Surface::Platform,
        }
    }

    /// The audience a token for this surface carries (OP-151 m.3 (a)).
    #[must_use]
    pub fn audience(&self) -> String {
        match self {
            Self::Environment(slug) => format!("{ENVIRONMENT_AUDIENCE_PREFIX}{slug}"),
            Self::Platform => PLATFORM_AUDIENCE.to_owned(),
        }
    }

    /// A stable key of the scope for rate limits and idempotency; never a metric label (OP-47).
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::Environment(slug) => format!("environment:{slug}"),
            Self::Platform => "platform".to_owned(),
        }
    }
}
