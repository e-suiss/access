//! The endpoint permission manifest (TN-113, §12.5.1): every management route with its method,
//! path, surface, the scope or AIS it needs and what a caller without it sees. The router is
//! built from these rows only ([`Builder`]); a route outside the manifest cannot be served, and
//! the generated tests send each row's request without its permission.
//!
//! There is no credential-setting route (`credential.set`, TN-61) and no route that acts as
//! another user (TN-130, MD-14); `crates/http/tests/admin_conformance.rs` checks both.

use std::collections::BTreeSet;

use axum::Router;
use axum::handler::Handler;
use axum::http::Method;
use axum::routing::{MethodFilter, on};

use super::domain::Surface;
use super::domain::lifecycle::Lifecycle;

/// A route's method.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verb {
    /// `GET`.
    Get,
    /// `POST`: create (`201` with the full representation, TN-112 k.3).
    Post,
    /// `PUT`: create or replace.
    Put,
    /// `PATCH`: JSON Merge Patch (RFC 7396).
    Patch,
    /// `DELETE`: a soft delete (OP-73).
    Delete,
}

impl Verb {
    /// The HTTP method.
    #[must_use]
    pub const fn method(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Post => Method::POST,
            Self::Put => Method::PUT,
            Self::Patch => Method::PATCH,
            Self::Delete => Method::DELETE,
        }
    }

    const fn filter(self) -> MethodFilter {
        match self {
            Self::Get => MethodFilter::GET,
            Self::Post => MethodFilter::POST,
            Self::Put => MethodFilter::PUT,
            Self::Patch => MethodFilter::PATCH,
            Self::Delete => MethodFilter::DELETE,
        }
    }

    /// Whether it changes state: it needs the caller's AIS and an `Idempotency-Key`.
    #[must_use]
    pub const fn mutating(self) -> bool {
        !matches!(self, Self::Get)
    }

    /// The method in lower case, as `OpenAPI` keys it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
            Self::Put => "put",
            Self::Patch => "patch",
            Self::Delete => "delete",
        }
    }
}

/// What a route needs from its caller (OP-151 m.3 (c)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// A holder-bound read token of the surface's audience with this scope (TN-27, TN-130).
    Read {
        /// The scope, in the surface's namespace (`realm.*`, `platform.*`).
        scope: &'static str,
    },
    /// The caller's AIS, compiled into an Exercise (TN-110); never a token.
    Write,
}

/// What a caller whose token lacks the scope sees (TN-113 resource hiding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// `404 not-found`, as for a resource that does not exist: the default.
    Hidden,
    /// `403 insufficient-scope`: only where the route's existence is no secret.
    Forbidden,
}

/// Whether a write's first answer may be kept for replay (TN-126).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Kept 24 hours and replayed for the same key and request.
    Replay,
    /// Carries a secret: never kept at rest; a repeat runs again and the Exercise's AIS nonce
    /// keeps it from changing anything twice.
    Secret,
}

/// One manifest row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// Method.
    pub verb: Verb,
    /// Path template, axum syntax (`{slug}`).
    pub path: &'static str,
    /// Surface.
    pub surface: Surface,
    /// What the caller needs.
    pub access: Access,
    /// What a caller without the permission sees.
    pub visibility: Visibility,
    /// `OpenAPI` operation id; unique.
    pub operation_id: &'static str,
    /// One-line summary.
    pub summary: &'static str,
    /// Query parameters it takes; any other is refused.
    pub query: &'static [&'static str],
    /// Whether its answer is kept for replay.
    pub answer: Answer,
    /// Deprecation and sunset, once announced (OP-65 m.2).
    pub lifecycle: Option<Lifecycle>,
}

/// Route groups for the rate limit's longest-prefix match (TN-127).
pub const GROUPS: &[&str] = &["/admin/v1/platform", "/admin/v1/realms/{slug}"];

/// The platform-admin surface root.
pub const PLATFORM_ROOT: Route = Route {
    verb: Verb::Get,
    path: "/admin/v1/platform",
    surface: Surface::Platform,
    access: Access::Read {
        scope: "platform.read",
    },
    visibility: Visibility::Forbidden,
    operation_id: "getPlatformSurface",
    summary: "The platform-admin surface: its audience, scope namespace and rate policies.",
    query: &[],
    answer: Answer::Replay,
    lifecycle: None,
};

/// The realm-admin surface root.
pub const REALM_ROOT: Route = Route {
    verb: Verb::Get,
    path: "/admin/v1/realms/{slug}",
    surface: Surface::Realm,
    access: Access::Read {
        scope: "realm.read",
    },
    visibility: Visibility::Hidden,
    operation_id: "getRealmSurface",
    summary: "One realm's admin surface: its audience, scope namespace and rate policies.",
    query: &[],
    answer: Answer::Replay,
    lifecycle: None,
};

const ALL_LEN: usize = 2 + super::realm::ROWS.len() + super::platform::ROWS.len();

#[expect(
    clippy::indexing_slicing,
    reason = "evaluated at compile time; an out-of-range index fails the build"
)]
const ALL: [Route; ALL_LEN] = {
    let mut out = [PLATFORM_ROOT; ALL_LEN];
    out[1] = REALM_ROOT;
    let mut i = 0;
    while i < super::realm::ROWS.len() {
        out[i + 2] = super::realm::ROWS[i];
        i += 1;
    }
    let mut j = 0;
    while j < super::platform::ROWS.len() {
        out[i + 2 + j] = super::platform::ROWS[j];
        j += 1;
    }
    out
};

/// Every management route: the surface roots, the realm resources ([`super::realm::ROWS`])
/// and the platform resources ([`super::platform::ROWS`]).
pub const MANIFEST: &[Route] = &ALL;

/// The suffix of the one `POST` that reads: drafting a write's intent changes nothing (TN-110).
pub const DRAFT_SUFFIX: &str = "/intents";

impl Route {
    /// Whether it changes state: every write, and no read; drafting an intent is a read.
    #[must_use]
    pub fn changes_state(&self) -> bool {
        self.access == Access::Write
    }

    /// Whether its verb fits its access: `GET` reads and the other verbs write, except the
    /// intent draft, a `POST` that reads.
    #[must_use]
    pub fn verb_fits(&self) -> bool {
        let draft = self.verb == Verb::Post && self.path.ends_with(DRAFT_SUFFIX);
        draft != (self.verb.mutating() == self.changes_state())
    }
}

/// Why a router cannot be built from a manifest.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// A handler for an operation the manifest does not list.
    #[error("operation {0} is not in the manifest")]
    Unlisted(&'static str),
    /// Two handlers for one operation, or two rows with one operation id or method and path.
    #[error("operation {0} is registered twice")]
    Duplicate(&'static str),
    /// A manifest row without a handler.
    #[error("operation {0} has no handler")]
    Missing(&'static str),
    /// A path outside the surface's prefix, or a read with a scope outside its namespace.
    #[error("operation {0} does not fit its surface")]
    Surface(&'static str),
}

/// Checks the manifest's own consistency: unique operation ids and method-path pairs, each
/// path under its surface's prefix, each read scope in its surface's namespace.
///
/// # Errors
/// [`ManifestError`].
pub fn check(rows: &[Route]) -> Result<(), ManifestError> {
    let mut ids = BTreeSet::new();
    let mut pairs = BTreeSet::new();
    for r in rows {
        if !ids.insert(r.operation_id) || !pairs.insert((r.verb, r.path)) {
            return Err(ManifestError::Duplicate(r.operation_id));
        }
        let (prefix, namespace) = match r.surface {
            Surface::Realm => ("/admin/v1/realms/{slug}", "realm."),
            Surface::Platform => ("/admin/v1/platform", "platform."),
        };
        let under = r
            .path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
        let scoped = match r.access {
            Access::Read { scope } => scope.starts_with(namespace),
            Access::Write => true,
        };
        if !under || !scoped || !r.verb_fits() {
            return Err(ManifestError::Surface(r.operation_id));
        }
    }
    Ok(())
}

/// Builds a router from manifest rows: the only place a management route is added.
pub struct Builder<S> {
    rows: &'static [Route],
    added: BTreeSet<&'static str>,
    router: Router,
    guard: S,
}

/// Wraps one row's handler in the row's guard.
pub trait Guard: Clone + Send + Sync + 'static {
    /// The method router for `row` with its guard layered over `handler`.
    fn wrap<H, T>(&self, row: &'static Route, handler: H) -> axum::routing::MethodRouter
    where
        H: Handler<T, ()>,
        T: 'static;
}

impl<S: Guard> Builder<S> {
    /// A builder for `rows`, guarding each with `guard`.
    ///
    /// # Errors
    /// [`ManifestError`] when the rows are inconsistent.
    pub fn new(rows: &'static [Route], guard: S) -> Result<Self, ManifestError> {
        check(rows)?;
        Ok(Self {
            rows,
            added: BTreeSet::new(),
            router: Router::new(),
            guard,
        })
    }

    /// Serves `operation_id` with `handler` behind its row's guard.
    ///
    /// # Errors
    /// [`ManifestError::Unlisted`] or [`ManifestError::Duplicate`].
    pub fn handle<H, T>(
        mut self,
        operation_id: &'static str,
        handler: H,
    ) -> Result<Self, ManifestError>
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        let row = self
            .rows
            .iter()
            .find(|r| r.operation_id == operation_id)
            .ok_or(ManifestError::Unlisted(operation_id))?;
        if !self.added.insert(row.operation_id) {
            return Err(ManifestError::Duplicate(operation_id));
        }
        let method_router = self.guard.wrap(row, handler);
        self.router = self.router.route(row.path, method_router);
        Ok(self)
    }

    /// The router, once every row has its handler.
    ///
    /// # Errors
    /// [`ManifestError::Missing`].
    pub fn finish(self) -> Result<Router, ManifestError> {
        if let Some(r) = self
            .rows
            .iter()
            .find(|r| !self.added.contains(r.operation_id))
        {
            return Err(ManifestError::Missing(r.operation_id));
        }
        Ok(self.router)
    }
}

/// The method router serving only `row`'s method with `handler`, for [`Guard`] implementations.
pub fn method_router<H, T>(row: &Route, handler: H) -> axum::routing::MethodRouter
where
    H: Handler<T, ()>,
    T: 'static,
{
    on(row.verb.filter(), handler)
}
