use std::collections::{BTreeMap, BTreeSet};

use access_kernel::digest::Digest;
use access_kernel::intent::ContextRefs;
use access_kernel::json::b64url_encode;
use access_kernel::model::{ActionRef, Window};

use super::*;
use crate::domain::catalog::Catalog;
use crate::domain::resource::{MappedAction, Origin};

const EXECUTOR: &str = "executor-pep-thumbprint";
const PARTY: [u8; 16] = [0x11; 16];
const NOW: u64 = 1_000_000_000;
const HORIZON: u64 = NOW + 900_000;
const FROM: u64 = NOW - 1_000;
const PAST_HORIZON: u64 = HORIZON - NOW + 1;
const PAST_HOUR: u64 = PATH_B_MAX_LIFETIME_MS + 1;
const AHEAD: u64 = NOW + REFRESH_AHEAD_MS;
const BEYOND: u64 = NOW + REFRESH_AHEAD_MS + 1;
const BEFORE: u64 = NOW - 1;

fn action() -> ActionRef {
    ActionRef {
        namespace: String::from("work"),
        name: String::from("send"),
        major: 1,
        schema: Digest([7; 32]),
    }
}

fn intent() -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: action(),
        resources: Vec::new(),
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: FROM,
            until: HORIZON,
        },
    }
}

fn resource(revocable: bool) -> Resource {
    let mut upstream = Catalog::shipped().unwrap().get("google").unwrap().clone();
    if !revocable {
        upstream.revocation_endpoint = None;
    }
    Resource {
        name: String::from("google"),
        origin: Origin::Catalog,
        upstream,
        client_id: String::from("cid"),
        client_secret_ref: String::from("secret://vault/google"),
        scopes: BTreeSet::from([String::from("https://www.googleapis.com/auth/gmail.send")]),
        actions: vec![MappedAction {
            namespace: String::from("work"),
            name: String::from("send"),
            major: 1,
            schema: b64url_encode(&[7; 32]),
            scopes: BTreeSet::new(),
        }],
        executors: BTreeSet::from([String::from(EXECUTOR)]),
    }
}

fn allowed(tier: Option<Tier>) -> Allowed {
    Allowed {
        pep: String::from(EXECUTOR),
        principal: Some(PARTY),
        actor: Some([0x33; 16]),
        tier,
        basis_live: true,
        position: 7,
    }
}

fn token(expires_in: u64, revocable: bool) -> TokenFacts {
    TokenFacts {
        expires_at: NOW.checked_add(expires_in),
        revocable,
    }
}

type Make = fn() -> Case;

/// One release as a path asks it.
struct Case {
    caller: Option<&'static str>,
    allowed: Option<Allowed>,
    status: &'static str,
    open: bool,
    agent: bool,
    token: TokenFacts,
}

impl Case {
    fn executor() -> Self {
        Self {
            caller: Some(EXECUTOR),
            allowed: Some(allowed(Some(Tier::Ct2))),
            status: "active",
            open: false,
            agent: false,
            token: token(600_000, true),
        }
    }

    fn path_b() -> Self {
        Self {
            allowed: Some(allowed(Some(Tier::Ct1))),
            open: true,
            agent: true,
            ..Self::executor()
        }
    }

    fn run(&self, r: &Resource) -> Result<Admitted, Refusal> {
        let held = Held {
            status: self.status,
            party: PARTY,
            resource: Some(r),
        };
        let i = intent();
        admit(
            &Asked {
                caller: self.caller,
                intent: &i,
                agent: self.agent,
            },
            self.allowed.as_ref(),
            &held,
            (self.open, self.token),
            NOW,
        )
    }
}

// U66, G59, EI-26, AGI-2, AG-40 (3), Ek B 4407, 4548
#[test]
fn every_release_path_runs_the_same_check() {
    let r = resource(true);
    let refreshed = || Case {
        token: token(3_000_000, false),
        ..Case::executor()
    };
    let paths: [(&str, Make); 3] = [
        ("executor", Case::executor),
        ("path-b", Case::path_b),
        ("refresh-on-release", refreshed),
    ];
    for (name, path) in paths {
        assert!(path().run(&r).is_ok(), "{name}");
        let refused: [(Case, Refusal); 8] = [
            (
                Case {
                    caller: None,
                    ..path()
                },
                Refusal::Unauthenticated,
            ),
            (
                Case {
                    allowed: None,
                    ..path()
                },
                Refusal::NoExercise,
            ),
            (
                Case {
                    caller: Some("another-pep"),
                    ..path()
                },
                Refusal::ForeignExercise,
            ),
            (
                Case {
                    allowed: path().allowed.map(|a| Allowed {
                        basis_live: false,
                        ..a
                    }),
                    ..path()
                },
                Refusal::BasisEnded,
            ),
            (
                Case {
                    allowed: path().allowed.map(|a| Allowed {
                        principal: Some([0x22; 16]),
                        ..a
                    }),
                    ..path()
                },
                Refusal::NotTheHolder,
            ),
            (
                Case {
                    allowed: path().allowed.map(|a| Allowed {
                        principal: None,
                        ..a
                    }),
                    ..path()
                },
                Refusal::NotTheHolder,
            ),
            (
                Case {
                    status: "needs_reconnect",
                    ..path()
                },
                Refusal::NeedsReconnect,
            ),
            (
                Case {
                    status: "disconnected",
                    ..path()
                },
                Refusal::NotConnected,
            ),
        ];
        for (case, want) in refused {
            assert_eq!(case.run(&r), Err(want), "{name}");
        }
    }
}

// AG-40 (3)
#[test]
fn an_unregistered_executor_gets_nothing() {
    let mut r = resource(true);
    r.executors = BTreeSet::from([String::from("someone-else")]);
    assert_eq!(Case::executor().run(&r), Err(Refusal::NotExecutor));
    let mut r = resource(true);
    r.actions.clear();
    assert_eq!(Case::executor().run(&r), Err(Refusal::ActionNotMapped));
}

// U65, AG-40 (4), (6), MD-8, Ek B 4408, 4409, 4411, 4628
#[test]
fn path_b_needs_every_condition_and_falls_back_to_the_executor() {
    let r = resource(true);
    let b = Case::path_b().run(&r).unwrap();
    assert_eq!(b.path, Path::Agent);
    assert!(b.use_until <= HORIZON);
    let fallbacks = [
        Case {
            open: false,
            ..Case::path_b()
        },
        Case {
            allowed: Some(allowed(Some(Tier::Ct2))),
            ..Case::path_b()
        },
        Case {
            allowed: Some(allowed(None)),
            ..Case::path_b()
        },
        Case {
            token: TokenFacts {
                expires_at: None,
                revocable: true,
            },
            ..Case::path_b()
        },
        Case {
            token: token(PAST_HORIZON, true),
            ..Case::path_b()
        },
        Case {
            token: token(PAST_HOUR, false),
            ..Case::path_b()
        },
        Case {
            agent: false,
            ..Case::path_b()
        },
    ];
    for c in fallbacks {
        let a = c.run(&r).unwrap();
        assert_eq!(a.path, Path::Executor);
        assert!(a.use_until <= HORIZON);
    }
    let unclassified = Case {
        allowed: Some(allowed(None)),
        ..Case::executor()
    };
    assert_eq!(unclassified.run(&r).unwrap().tier, Tier::Ct2);
}

// U65, AG-32
#[test]
fn a_release_never_outlives_the_horizon() {
    let r = resource(false);
    let long = Case {
        token: token(86_400_000, false),
        ..Case::executor()
    };
    assert_eq!(long.run(&r).unwrap().use_until, HORIZON);
    let unknown = Case {
        token: TokenFacts {
            expires_at: None,
            revocable: false,
        },
        ..Case::executor()
    };
    assert_eq!(unknown.run(&r).unwrap().use_until, HORIZON);
    let mut late = intent();
    late.validity.until = NOW;
    let held = Held {
        status: "active",
        party: PARTY,
        resource: Some(&r),
    };
    let a = allowed(Some(Tier::Ct1));
    assert_eq!(
        admit(
            &Asked {
                caller: Some(EXECUTOR),
                intent: &late,
                agent: false,
            },
            Some(&a),
            &held,
            (true, token(60_000, true)),
            NOW
        ),
        Err(Refusal::OutsideValidity)
    );
}

#[test]
fn a_token_close_to_its_expiry_is_refreshed_first() {
    assert!(refresh_first(Some(AHEAD), NOW));
    assert!(refresh_first(Some(BEFORE), NOW));
    assert!(!refresh_first(Some(BEYOND), NOW));
    assert!(!refresh_first(None, NOW));
}
