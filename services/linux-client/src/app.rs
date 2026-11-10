//! The daemon (OP-156 m.3 (p), IDP-32, MD-8, SI-22): it answers the NSS and PAM modules from
//! Access when Access answers and from its kept state only within the offline limits.
//!
//! - NSS lookups come from the host's snapshot, refreshed from Access; a snapshot past 12 hours
//!   (or the host's shorter limit) or the horizon answers nothing.
//! - A console sign-in is a device authorization the person approves in the browser; Access
//!   decides it against the person's `ssh.login` Grant on the host's server group. Offline, a
//!   sign-in within 8 hours of the last online one is reused only with a local security key
//!   Access listed for the person.
//! - `sudo` is a step-up Access decides every time (CT2 by default: a phishing-resistant
//!   authenticator); it is never answered offline.
//! - A break-glass allowance, verified offline from the reserved break-glass Grant's PAP, signs
//!   in once.
//!
//! Every failure is a refusal (TI-9).

use std::collections::BTreeMap;
use std::path::PathBuf;

use access_linux_module::wire::{Pending, Request, Response};
use tokio::sync::Mutex;

use crate::breakglass;
use crate::domain::fido::{self, Credential};
use crate::domain::snapshot::Snapshot;
use crate::domain::state::State;
use crate::ports::{Access, Clock, DevicePoll, Keep, Random, Reached, SecurityKey};

/// The `TextId` of a sign-in waiting for the browser.
pub const TEXT_PENDING: &str = "linux.signin_pending";
/// The `TextId` of a `sudo` step-up.
pub const TEXT_STEP_UP: &str = "linux.step_up";
/// The `TextId` when Access cannot be reached and nothing cached may answer.
pub const TEXT_UNAVAILABLE: &str = "linux.unavailable";

/// Most attempts waiting at once.
pub const MAX_ATTEMPTS: usize = 64;

#[derive(Clone, Debug)]
enum Kind {
    SignIn { user: String },
    Sudo { user: String, command: [u8; 32] },
}

#[derive(Clone, Debug)]
struct Attempt {
    kind: Kind,
    device_code: String,
    pending: Pending,
    until_ms: u64,
}

/// What the daemon reports about an answer, for its log (OP-67).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// Served from Access.
    Online,
    /// Served from the kept state.
    Offline,
    /// The kept state no longer answers (`linux.cache.expired`).
    Expired,
    /// Access could not be reached (`linux.daemon.unavailable`).
    Unreachable,
}

/// The daemon over its ports.
pub struct Daemon<A, C, R, K, S> {
    access: A,
    clock: C,
    random: R,
    keep: K,
    key: S,
    break_glass: Option<PathBuf>,
    state: Mutex<State>,
    attempts: Mutex<BTreeMap<[u8; 16], Attempt>>,
}

fn unavailable() -> Response {
    Response::Unavailable(String::from(TEXT_UNAVAILABLE))
}

const fn done(allow: bool, offline: bool) -> Response {
    Response::Done {
        allow,
        offline: if offline { Some(true) } else { None },
    }
}

impl<A, C, R, K, S> Daemon<A, C, R, K, S>
where
    A: Access,
    C: Clock,
    R: Random,
    K: Keep,
    S: SecurityKey,
{
    /// The daemon with its kept state loaded; `break_glass` is the directory break-glass
    /// allowances are left in.
    pub fn new(
        access: A,
        clock: C,
        random: R,
        keep: K,
        key: S,
        break_glass: Option<PathBuf>,
    ) -> Self {
        let state = keep.load();
        Self {
            access,
            clock,
            random,
            keep,
            key,
            break_glass,
            state: Mutex::new(state),
            attempts: Mutex::new(BTreeMap::new()),
        }
    }

    /// The kept state, for tests and the status line.
    pub async fn state(&self) -> State {
        self.state.lock().await.clone()
    }

    /// Asks Access for the snapshot and keeps it; `Online` when it did.
    pub async fn refresh(&self) -> Note {
        let Reached::Answer(body) = self.access.snapshot().await else {
            return Note::Unreachable;
        };
        let Ok(s) = Snapshot::parse(&body) else {
            return Note::Unreachable;
        };
        let mut st = self.state.lock().await;
        st.tick(s.now_ms);
        st.snapshot = Some(s);
        st.prune();
        let _ = self.keep.save(&st);
        Note::Online
    }

    /// The answer to one request from a module, with what served it.
    pub async fn handle(&self, request: Request) -> (Response, Note) {
        let Some(now) = self.clock.now_ms() else {
            return (unavailable(), Note::Unreachable);
        };
        match request {
            Request::Authenticate { user, .. } => self.sign_in(user, now).await,
            Request::Sudo { user, command } => self.sudo(user, command, now).await,
            Request::Poll(attempt) => self.poll(attempt, now).await,
            lookup => self.lookup(&lookup, now).await,
        }
    }

    async fn lookup(&self, request: &Request, now: u64) -> (Response, Note) {
        {
            let mut st = self.state.lock().await;
            if let Ok(s) = st.snapshot_at(now)
                && let Some(r) = s.answer(request, now)
            {
                return (r, Note::Offline);
            }
        }
        let note = self.refresh().await;
        let mut st = self.state.lock().await;
        match st.snapshot_at(now) {
            Ok(s) => (s.answer(request, now).unwrap_or(Response::NotFound), note),
            Err(_) if note == Note::Online => (Response::NotFound, note),
            Err(_) => (unavailable(), Note::Expired),
        }
    }

    async fn start(&self, kind: Kind, text: &str, now: u64) -> Option<Response> {
        let Reached::Answer(d) = self.access.device_start().await else {
            return None;
        };
        let attempt = self.random.bytes::<16>()?;
        let pending = Pending {
            attempt,
            text: String::from(text),
            user_code: Some(d.user_code),
            verification_uri: Some(d.verification_uri),
            expires_in: d.expires_in,
        };
        let mut a = self.attempts.lock().await;
        a.retain(|_, v| v.until_ms > now);
        if a.len() >= MAX_ATTEMPTS {
            return Some(done(false, false));
        }
        a.insert(
            attempt,
            Attempt {
                kind,
                device_code: d.device_code,
                pending: pending.clone(),
                until_ms: now.saturating_add(d.expires_in.saturating_mul(1000)),
            },
        );
        Some(Response::Pending(pending))
    }

    async fn sign_in(&self, user: String, now: u64) -> (Response, Note) {
        if self.take_break_glass(&user, now) {
            return (done(true, true), Note::Offline);
        }
        if self.refresh().await == Note::Online {
            let console = {
                let mut st = self.state.lock().await;
                st.snapshot_at(now)
                    .ok()
                    .and_then(|s| s.user(&user, now))
                    .is_some_and(|u| u.console)
            };
            if !console {
                return (done(false, false), Note::Online);
            }
            if let Some(r) = self
                .start(Kind::SignIn { user: user.clone() }, TEXT_PENDING, now)
                .await
            {
                return (r, Note::Online);
            }
        }
        self.offline_sign_in(&user, now).await
    }

    /// An offline console sign-in: a local security key Access listed for the person within
    /// 8 hours of their last online sign-in (m.3 (p)).
    async fn offline_sign_in(&self, user: &str, now: u64) -> (Response, Note) {
        let Ok(credentials) = self.state.lock().await.offline_console(user, now) else {
            return (unavailable(), Note::Expired);
        };
        match self.assert(&credentials).await {
            Some((id, count)) => {
                let mut st = self.state.lock().await;
                st.counted(user, &id, count);
                let _ = self.keep.save(&st);
                (done(true, true), Note::Offline)
            }
            None => (done(false, true), Note::Offline),
        }
    }

    async fn assert(&self, credentials: &[Credential]) -> Option<(Vec<u8>, u32)> {
        let challenge = self.random.bytes::<32>()?;
        let hash = suiss_crypto::digest::sha256(&challenge);
        let first = credentials.first()?;
        let same_rp: Vec<&Credential> = credentials
            .iter()
            .filter(|c| c.rp_id == first.rp_id)
            .collect();
        let ids: Vec<&[u8]> = same_rp.iter().map(|c| c.id.as_slice()).collect();
        let request = fido::get_assertion(&first.rp_id, &hash, &ids).ok()?;
        let answer = self.key.get_assertion(&request).await?;
        let a = fido::parse_assertion(&answer).ok()?;
        let c = same_rp.iter().find(|c| c.id == a.credential)?;
        let count = fido::verify(c, &hash, &a).ok()?;
        Some((a.credential, count))
    }

    async fn sudo(&self, user: String, command: [u8; 32], now: u64) -> (Response, Note) {
        // OP-156 m.3 (p)
        if self.refresh().await != Note::Online {
            return (unavailable(), Note::Unreachable);
        }
        let console = {
            let mut st = self.state.lock().await;
            st.snapshot_at(now)
                .ok()
                .and_then(|s| s.user(&user, now))
                .is_some_and(|u| u.console)
        };
        if !console {
            return (done(false, false), Note::Online);
        }
        match self
            .start(Kind::Sudo { user, command }, TEXT_STEP_UP, now)
            .await
        {
            Some(r) => (r, Note::Online),
            None => (unavailable(), Note::Unreachable),
        }
    }

    async fn poll(&self, attempt: [u8; 16], now: u64) -> (Response, Note) {
        let found = self.attempts.lock().await.get(&attempt).cloned();
        let Some(a) = found.filter(|a| a.until_ms > now) else {
            self.attempts.lock().await.remove(&attempt);
            return (done(false, false), Note::Online);
        };
        let token = match self.access.device_poll(&a.device_code).await {
            Reached::Answer(DevicePoll::Pending) => {
                return (Response::Pending(a.pending), Note::Online);
            }
            Reached::Answer(DevicePoll::Token(t)) => t,
            Reached::Answer(DevicePoll::Ended) => {
                self.attempts.lock().await.remove(&attempt);
                return (done(false, false), Note::Online);
            }
            Reached::Unreachable => return (unavailable(), Note::Unreachable),
        };
        self.attempts.lock().await.remove(&attempt);
        match a.kind {
            Kind::SignIn { user } => match self.access.sign_in(&token, &user).await {
                Reached::Answer(s) if s.allow => {
                    let mut st = self.state.lock().await;
                    st.console.insert(
                        user,
                        crate::domain::state::ConsoleSignIn {
                            at_ms: now,
                            credentials: s.credentials,
                        },
                    );
                    let _ = self.keep.save(&st);
                    (done(true, false), Note::Online)
                }
                Reached::Answer(_) => (done(false, false), Note::Online),
                Reached::Unreachable => (unavailable(), Note::Unreachable),
            },
            Kind::Sudo { user, command } => match self.access.sudo(&token, &user, &command).await {
                Reached::Answer(allow) => (done(allow, false), Note::Online),
                Reached::Unreachable => (unavailable(), Note::Unreachable),
            },
        }
    }

    fn take_break_glass(&self, user: &str, now: u64) -> bool {
        self.break_glass
            .as_deref()
            .is_some_and(|dir| breakglass::take(dir, user, now))
    }
}
