//! The `access_sdk` adapter (OP-150 m.2 L10, CMP-17): the Rust PEP SDK driven through the
//! adapter protocol, its ports bound to blocking HTTP. Every decision is the SDK's; the
//! adapter only moves bytes and performs the effect on an `Authorized` value.

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Instant;

use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_decode;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::Id;
use access_kernel::verify::cose::Algorithm;
use access_kernel::verify::key_scope::DomainMetadata;
use access_sdk::authorize::{
    Action, Actor, Ask, AskDecision, Class, ExerciseRequest, Intent, Nonce, Pep, Resource,
};
use access_sdk::resource::{
    self, Config, Introspector, KeySource, Keys, NonceSource, Ports, Presented, Profile, Replay,
    ReplayStore, ResourceServer, Revocations, StatusSource,
};
use access_sdk::transport::{Answer, Fault, FixedClock, Response};

use crate::case::Mode;
use crate::fixture::{action, unhex};
use crate::protocol::CaseMessage;
use crate::reference::{Fetch, Fetched, Machine, Step, fetch_blocking};

/// The resource the cases guard.
pub struct Door;

impl Resource for Door {
    const NAMESPACE: &'static str = "door";
}

/// The action the cases enforce.
pub struct Open;

impl Action for Open {
    const NAMESPACE: &'static str = "door";
    const NAME: &'static str = "open";
}

/// Replay state shared by every presentation of this process (TN-30, §9.9.1 `count = 1`).
static SEEN: Mutex<BTreeSet<[u8; 32]>> = Mutex::new(BTreeSet::new());

fn answer(fetched: Fetched) -> Answer {
    match fetched {
        Fetched::Response { status, body } => Answer::Response(Response::new(status, body)),
        Fetched::Failed(why) => {
            Answer::Unanswered(if why.contains("deadline") || why.contains("timed out") {
                Fault::Timeout
            } else {
                Fault::Unreachable
            })
        }
    }
}

/// The SDK's ports over blocking HTTP, bounded by one deadline.
struct Http<'a> {
    msg: &'a CaseMessage,
    until: Instant,
}

impl Http<'_> {
    fn fetch(
        &self,
        method: &'static str,
        url: &str,
        body: Option<(&'static str, String)>,
    ) -> Answer {
        let request = Fetch {
            method,
            url: url.to_owned(),
            body,
        };
        answer(fetch_blocking(&request, self.until))
    }
}

impl AskDecision for Http<'_> {
    fn ask(&self, _request: &ExerciseRequest<'_>) -> Answer {
        self.fetch(
            "POST",
            &self.msg.upstream.adp,
            Some(("application/json", self.msg.request.evaluation.to_string())),
        )
    }
}

impl KeySource for Http<'_> {
    fn metadata(&self) -> Keys {
        Keys::Fetched(self.fetch("GET", &self.msg.upstream.metadata, None))
    }
}

impl StatusSource for Http<'_> {
    fn list(&self, uri: &str) -> Answer {
        self.fetch("GET", uri, None)
    }
}

impl Introspector for Http<'_> {
    fn introspect(&self, token: &str) -> Answer {
        self.fetch(
            "POST",
            &self.msg.upstream.introspection,
            Some((
                "application/x-www-form-urlencoded",
                format!("token={token}&token_type_hint=access_token"),
            )),
        )
    }
}

impl ReplayStore for Http<'_> {
    fn record(&self, key: &[u8; 32], _until: u64) -> Replay {
        match SEEN.lock() {
            Ok(mut seen) => {
                if seen.insert(*key) {
                    Replay::Fresh
                } else {
                    Replay::Seen
                }
            }
            Err(_) => Replay::Unavailable,
        }
    }
}

impl NonceSource for Http<'_> {
    fn accept(&self, _nonce: Option<&str>) -> bool {
        true
    }
}

impl Revocations for Http<'_> {
    fn family_ended(&self, _family: &[u8; 16]) -> bool {
        false
    }
}

/// The SDK as a case machine: one call does the whole verification, with the effect left to
/// the driver.
pub struct Sdk {
    msg: CaseMessage,
    attempt: u32,
    done: bool,
}

impl Sdk {
    /// A machine for one presentation of a case.
    #[must_use]
    pub const fn new(msg: CaseMessage, attempt: u32) -> Self {
        Self {
            msg,
            attempt,
            done: false,
        }
    }

    fn pinned(&self) -> Option<(Digest, DomainMetadata, Digest)> {
        let domain = Digest::from_bytes(&unhex(&self.msg.pep.domain)?).ok()?;
        let metadata = DomainMetadata::from_bytes(&unhex(&self.msg.pep.metadata)?).ok()?;
        let intent = Digest::from_bytes(&unhex(&self.msg.request.intent)?).ok()?;
        Some((domain, metadata, intent))
    }

    fn decision(&self, http: &Http<'_>) -> Step {
        let Some((domain, metadata, intent)) = self.pinned() else {
            return Step::Error(String::from("bad PEP configuration"));
        };
        let nonce = self
            .msg
            .request
            .evaluation
            .get("context")
            .and_then(|c| c.get("nonce"))
            .and_then(|n| n.as_str())
            .and_then(|n| b64url_decode(n).ok())
            .and_then(|n| Nonce::new(n).ok());
        let Some(nonce) = nonce else {
            return Step::Error(String::from("no nonce in the request"));
        };
        let pep = Pep {
            audience: self.msg.pep.audience.clone(),
            domain,
            metadata,
        };
        let intent: Intent<Door, Open> = Intent::approved(intent, Some(action()));
        let basis = ExerciseBasis::Public(Id([7; 16]));
        let ask = Ask {
            intent: &intent,
            nonce: &nonce,
            actor: &Actor::Anonymous,
            basis: &basis,
            capacity: Capacity::Own,
            continued: None,
            content_position: None,
        };
        match pep.authorize(&ask, &FixedClock(self.msg.now), http) {
            Ok(authorized) => match authorized.apply(intent.digest(), |_| ()) {
                Ok(()) => Step::Effect,
                Err(d) => Step::Deny(d.to_string()),
            },
            Err(d) if d.class() == Class::Unknown => Step::Error(d.to_string()),
            Err(d) => Step::Deny(d.to_string()),
        }
    }

    fn token(&self, http: &Http<'_>, profile: Profile) -> Step {
        let Some((domain, metadata, intent)) = self.pinned() else {
            return Step::Error(String::from("bad PEP configuration"));
        };
        let server = ResourceServer::new(Config {
            issuer: self.msg.pep.issuer.clone(),
            audience: self.msg.pep.audience.clone(),
            domain,
            metadata,
            profile,
            algorithms: BTreeSet::from([Algorithm::Ed25519]),
            key_epoch_ms: resource::DEFAULT_KEY_EPOCH_MS,
        });
        let Ok(server) = server else {
            return Step::Error(String::from("bad resource server configuration"));
        };
        let token = self.msg.request.token.clone().unwrap_or_default();
        let proof = usize::try_from(self.attempt)
            .ok()
            .and_then(|i| self.msg.request.proofs.get(i));
        let presented = Presented {
            token: &token,
            method: &self.msg.request.method,
            uri: &self.msg.request.uri,
            proof: proof.map(String::as_str),
            certificate: None,
            content_position: None,
        };
        let intent: Intent<Door, Open> = Intent::approved(intent, Some(action()));
        let ports = Ports {
            keys: http,
            replay: http,
            nonces: http,
            status: http,
            introspection: http,
            revocations: http,
        };
        match server.verify(&presented, &intent, &FixedClock(self.msg.now), &ports) {
            Ok(verified) => match verified.authorized.apply(intent.digest(), |_| ()) {
                Ok(()) => Step::Effect,
                Err(d) => Step::Deny(d.to_string()),
            },
            Err(d) if d.is_decision() => Step::Deny(d.to_string()),
            Err(d) => Step::Error(d.to_string()),
        }
    }
}

impl Machine for Sdk {
    fn step(&mut self, _fetched: Option<Fetched>) -> Step {
        if self.done {
            return Step::Error(String::from("protocol state"));
        }
        self.done = true;
        let budget = std::time::Duration::from_millis(self.msg.deadline_ms);
        let now = Instant::now();
        let http = Http {
            msg: &self.msg,
            until: now.checked_add(budget).unwrap_or(now),
        };
        match self.msg.request.mode {
            Mode::Decision => self.decision(&http),
            Mode::Jwt => self.token(&http, Profile::Fast),
            Mode::Introspection => self.token(&http, Profile::Strict),
        }
    }
}
