//! The scenarios (OP-158 m.3 (z)): what each measures and the route it drives by default.

/// One scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scenario {
    /// Its name on the command line.
    pub(crate) name: &'static str,
    /// What it measures and against which target.
    pub(crate) summary: &'static str,
    /// The route a request without a `path` goes to.
    pub(crate) path: &'static str,
    /// The p99 latency budget in microseconds (CR-17, OP-72); `None` where the target is a
    /// ratio or a rate, not a latency.
    pub(crate) budget_p99_us: Option<u64>,
}

/// Every scenario.
pub(crate) const ALL: &[Scenario] = &[
    Scenario {
        name: "commit",
        summary: "ADP commits (CT1 and CT2 by the bodies given): online commit p99 <= 30 ms, >= 2000 commits/s/domain (OP-32, §17.5.1)",
        path: "/access/v1/evaluation",
        budget_p99_us: Some(30_000),
    },
    Scenario {
        name: "check",
        summary: "advisory checks: hit p99 < 100 us, miss p99 < 5 ms (P46, §9.7A.6)",
        path: "/access/v1/evaluation",
        budget_p99_us: Some(5_000),
    },
    Scenario {
        name: "search",
        summary: "advisory search pages: p99 < 50 ms within the 1 s deadline (P46)",
        path: "/access/v1/search/subject",
        budget_p99_us: Some(50_000),
    },
    Scenario {
        name: "login",
        summary: "hosted sign-in with the realm's Argon2 cost: logins/s and total/Argon2 CPU < 1.10 (MKT-8, OP-32)",
        path: "/login",
        budget_p99_us: None,
    },
    Scenario {
        name: "refresh",
        summary: "token refresh, layer B 50-200 ms, alone and beside login (§12.2.1, TN-38, §4.10)",
        path: "/token",
        budget_p99_us: Some(200_000),
    },
    Scenario {
        name: "introspection",
        summary: "token introspection, layer A p99 < 1 ms (§12.2.1)",
        path: "/introspect",
        budget_p99_us: Some(1_000),
    },
    Scenario {
        name: "revocation",
        summary: "revocation fan-out: commit to status list and SSF delivery (§12.2.1 layer C)",
        path: "/access/v1/evaluation",
        budget_p99_us: Some(30_000),
    },
];

/// The scenario named `name`.
#[must_use]
pub(crate) fn find(name: &str) -> Option<&'static Scenario> {
    ALL.iter().find(|s| s.name == name)
}
