//! The password step's building block (§10.2.1, TN-82, TN-83, CR-36, SA-30, OP-35); the HTTP
//! login flow around it is I5's. Layer A gates the network in process; layer B counts per
//! identifier, identifier + network and network in PostgreSQL. A missing account takes the
//! same path as a wrong password: same counters, same semaphore, same answer, padded to the
//! running mean of successes, without a dummy hash. Every refusal is audited in the
//! transaction that counts it.

use std::net::IpAddr;
use std::sync::Mutex;

use access_store::accounts::{CredentialRow, SealedSecret, SubjectRow};
use access_store::audit::AuditEvent;
use access_store::throttle::ThrottleRow;

use crate::AccountError;
use crate::app::accounts::PASSWORD;
use crate::app::hasher::Hasher;
use crate::app::local::LocalLimiter;
use crate::app::sealing::{open_password, seal_password, subject_key};
use crate::app::{Actor, Realm};
use crate::domain::identifier::normalize;
use crate::domain::login::{PasswordLogin, ceil_seconds, counter_key, network};
use crate::domain::password::{ALGORITHM, Password};
use crate::domain::status::AccountStatus;
use crate::domain::throttle::{DAY_MS, Gate, KeyKind, KeyState, ThrottlePolicy};
use crate::domain::timing::{SAMPLE_CAP_MS, SuccessMean};
use crate::ports::{AccountDb, AccountTx, Clock, Entropy};

/// The audit actor of an unauthenticated attempt.
pub const ANONYMOUS: &str = "anonymous";

/// The audit target when no account holds the identifier.
pub const UNKNOWN: &str = "unknown";

/// Process-wide login state: layer A, the realm policy and the success mean.
pub struct LoginGate {
    local: LocalLimiter,
    policy: ThrottlePolicy,
    mean: Mutex<SuccessMean>,
}

impl LoginGate {
    /// A gate; `seed_mean_ms` comes from calibration (OP-146 m.4 (f)).
    #[must_use]
    pub fn new(local: LocalLimiter, policy: ThrottlePolicy, seed_mean_ms: u64) -> Self {
        Self {
            local,
            policy,
            mean: Mutex::new(SuccessMean::seeded(seed_mean_ms)),
        }
    }

    /// The running mean of successful attempts.
    #[must_use]
    pub fn mean_ms(&self) -> u64 {
        self.mean.lock().map_or(SAMPLE_CAP_MS, |m| m.mean_ms())
    }

    fn pad(&self, elapsed_ms: u64) -> u64 {
        self.mean
            .lock()
            .map_or(SAMPLE_CAP_MS, |m| m.pad(elapsed_ms))
    }

    fn record(&self, duration_ms: u64) {
        if let Ok(mut m) = self.mean.lock() {
            m.record(duration_ms);
        }
    }
}

/// One presented identifier and password.
pub struct Attempt<'a> {
    /// The identifier as typed.
    pub identifier: &'a str,
    /// The password as typed.
    pub password: &'a str,
    /// The client's address, after the trusted-proxy rule (§17.9.6).
    pub ip: IpAddr,
    /// Request correlation id.
    pub correlation: &'a str,
}

/// What the services the step needs.
pub struct LoginServices<'a, C, E> {
    /// Process state.
    pub gate: &'a LoginGate,
    /// Trusted time.
    pub clock: &'a C,
    /// Salts for a rehash.
    pub entropy: &'a E,
    /// The Argon2id service.
    pub hasher: &'a Hasher,
}

fn day(now_ms: u64) -> Result<i32, AccountError> {
    i32::try_from(now_ms / DAY_MS).map_err(|_| AccountError::Corrupt)
}

fn state(r: &ThrottleRow) -> Result<KeyState, AccountError> {
    let u = |v: i64| u64::try_from(v).map_err(|_| AccountError::Corrupt);
    Ok(KeyState {
        tat_ms: u(r.tat_ms)?,
        failures: u32::try_from(r.failures).map_err(|_| AccountError::Corrupt)?,
        last_failure_ms: u(r.last_failure_ms)?,
        blocked_until_ms: u(r.blocked_until_ms)?,
        locked: r.locked,
    })
}

fn row(s: &KeyState) -> ThrottleRow {
    let i = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    ThrottleRow {
        tat_ms: i(s.tat_ms),
        failures: i32::try_from(s.failures).unwrap_or(i32::MAX),
        last_failure_ms: i(s.last_failure_ms),
        blocked_until_ms: i(s.blocked_until_ms),
        locked: s.locked,
    }
}

fn keys(realm: &Realm<'_>, folded: &str, net: &[u8]) -> [(KeyKind, [u8; 32]); 3] {
    let (t, r) = (realm.tenant.as_bytes(), realm.realm.as_bytes());
    [
        (
            KeyKind::Account,
            counter_key(KeyKind::Account, t, r, Some(folded), None),
        ),
        (
            KeyKind::AccountIp,
            counter_key(KeyKind::AccountIp, t, r, Some(folded), Some(net)),
        ),
        (KeyKind::Ip, counter_key(KeyKind::Ip, t, r, None, Some(net))),
    ]
}

struct Candidate {
    subject: SubjectRow,
    password: Option<CredentialRow>,
}

struct Verified {
    subject: [u8; 16],
    epoch: i64,
    credential: [u8; 16],
    reseal: Option<SealedSecret>,
}

/// The counter key of an identifier in a realm, for recovery to clear (I5).
#[must_use]
pub fn account_key(realm: &Realm<'_>, identifier: &str) -> [u8; 32] {
    let folded = normalize(identifier).to_lowercase();
    counter_key(
        KeyKind::Account,
        realm.tenant.as_bytes(),
        realm.realm.as_bytes(),
        Some(&folded),
        None,
    )
}

/// Clears an identifier's failure count and hard lock after the account is recovered.
///
/// # Errors
/// [`AccountError`].
pub async fn clear_account<D: AccountDb, C: Clock>(
    db: &D,
    clock: &C,
    realm: &Realm<'_>,
    identifier: &str,
    horizon_days: u32,
) -> Result<(), AccountError> {
    let key = account_key(realm, identifier);
    let d = day(clock.now_ms())?;
    let horizon = i32::try_from(horizon_days).map_err(|_| AccountError::Corrupt)?;
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let mut s = state(&tx.throttle(&key, d, horizon).await?)?;
    s.failures = 0;
    s.blocked_until_ms = 0;
    s.locked = false;
    tx.put_throttle(&key, d, &row(&s)).await?;
    tx.commit().await
}

/// The first transaction's result: refused at the gate, or admitted with what the
/// identifier names.
enum Admission {
    Throttled(u64),
    Admitted(Option<Box<Candidate>>, u32),
}

async fn admit<D: AccountDb>(
    db: &D,
    realm: &Realm<'_>,
    policy: &ThrottlePolicy,
    keys: &[(KeyKind, [u8; 32]); 3],
    normalized: &str,
    start: u64,
) -> Result<Admission, AccountError> {
    let horizon = i32::try_from(policy.horizon_days).map_err(|_| AccountError::Corrupt)?;
    let today = day(start)?;
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let mut admitted = [KeyState::default(); 3];
    let mut wait = 0_u64;
    let mut locked = false;
    for ((kind, key), slot) in keys.iter().zip(admitted.iter_mut()) {
        let s = state(&tx.throttle(key, today, horizon).await?)?;
        match policy.of(*kind).admit(&s, start) {
            Gate::Open(opened) => *slot = opened,
            Gate::Wait { retry_after_ms } => wait = wait.max(retry_after_ms.max(1)),
            Gate::Locked => locked = true,
        }
    }
    if wait > 0 && !locked {
        tx.commit().await?;
        return Ok(Admission::Throttled(wait));
    }
    let mut candidate = None;
    if !locked {
        for ((_, key), s) in keys.iter().zip(&admitted) {
            tx.put_throttle(key, today, &row(s)).await?;
        }
        if let Some(id) = tx.subject_by_identifier(normalized).await?
            && let Some(subject) = tx.subject(id, false).await?
        {
            let password = tx.credentials(id, PASSWORD).await?.into_iter().next();
            candidate = Some(Box::new(Candidate { subject, password }));
        }
    }
    tx.commit().await?;
    Ok(Admission::Admitted(candidate, admitted[0].failures))
}

/// Counts the attempt on every key and writes its audit rows in one transaction; returns
/// whether a rehash was stored.
async fn record<D: AccountDb>(
    db: &D,
    realm: &Realm<'_>,
    policy: &ThrottlePolicy,
    keys: &[(KeyKind, [u8; 32]); 3],
    outcome: (Option<&Verified>, Option<&Candidate>),
    now: u64,
    correlation: &str,
) -> Result<bool, AccountError> {
    let (verified, candidate) = outcome;
    let horizon = i32::try_from(policy.horizon_days).map_err(|_| AccountError::Corrupt)?;
    let today = day(now)?;
    let mut tx = db.begin(realm.tenant, realm.realm).await?;
    let mut account_locked_now = false;
    for (kind, key) in keys {
        let rules = policy.of(*kind);
        let s = state(&tx.throttle(key, today, horizon).await?)?;
        let counted = if verified.is_some() {
            rules.succeed(&s)
        } else {
            rules.fail(&s, now)
        };
        if *kind == KeyKind::Account && counted.locked && !s.locked {
            account_locked_now = true;
        }
        tx.put_throttle(key, today, &row(&counted)).await?;
    }
    let actor = Actor {
        actor: ANONYMOUS,
        correlation,
    };
    if let Some(v) = verified {
        tx.credential_used(v.credential).await?;
        let rehashed = match &v.reseal {
            Some(sealed) => tx.reseal(v.credential, ALGORITHM, sealed).await?,
            None => false,
        };
        let target = realm.external(v.subject)?;
        audit(&mut tx, "login.password.succeeded", &actor, &target).await?;
        tx.commit().await?;
        return Ok(rehashed);
    }
    let target = match candidate {
        Some(c) => realm.external(c.subject.id)?,
        None => UNKNOWN.to_owned(),
    };
    if account_locked_now && let Some(c) = candidate {
        let id = c.subject.id;
        let live = tx.subject(id, true).await?;
        if live.is_some_and(|r| r.status == AccountStatus::Active.name())
            && tx
                .set_status(id, AccountStatus::Active, AccountStatus::Locked)
                .await?
        {
            crate::app::accounts::status_claim(&mut tx, id, AccountStatus::Locked).await?;
            audit(&mut tx, "account.locked", &actor, &target).await?;
        }
    }
    audit(&mut tx, "login.password.failed", &actor, &target).await?;
    tx.commit().await?;
    Ok(false)
}

/// Runs the password step of a login.
///
/// # Errors
/// [`AccountError::Busy`] and [`AccountError::Store`] (`503 + Retry-After`): the step never
/// turns a failure into an acceptance (MD-8).
pub async fn password_login<D: AccountDb, C: Clock, E: Entropy>(
    db: &D,
    realm: &Realm<'_>,
    services: &LoginServices<'_, C, E>,
    attempt: &Attempt<'_>,
) -> Result<PasswordLogin, AccountError> {
    let gate = services.gate;
    let start = services.clock.now_ms();
    if let Err(wait) = gate.local.check(attempt.ip, start) {
        return Ok(observed(PasswordLogin::Throttled {
            retry_after_s: ceil_seconds(wait),
        }));
    }
    let normalized = normalize(attempt.identifier);
    let keys = keys(realm, &normalized.to_lowercase(), &network(attempt.ip));
    let (candidate, prior_failures) =
        match admit(db, realm, &gate.policy, &keys, &normalized, start).await? {
            Admission::Throttled(wait) => {
                return Ok(observed(PasswordLogin::Throttled {
                    retry_after_s: ceil_seconds(wait),
                }));
            }
            Admission::Admitted(candidate, failures) => (candidate.map(|c| *c), failures),
        };
    let presented = Password::presented(attempt.password);
    let verified = verify(realm, services, candidate.as_ref(), presented.as_ref()).await?;
    let rehashed = record(
        db,
        realm,
        &gate.policy,
        &keys,
        (verified.as_ref(), candidate.as_ref()),
        services.clock.now_ms(),
        attempt.correlation,
    )
    .await?;
    let elapsed = services.clock.now_ms().saturating_sub(start);
    Ok(observed(match verified {
        Some(v) => {
            gate.record(elapsed);
            PasswordLogin::Accepted {
                subject: v.subject,
                session_epoch: v.epoch,
                rehashed,
                prior_failures,
            }
        }
        None => PasswordLogin::Rejected {
            pad_ms: gate.pad(elapsed),
        },
    }))
}

/// Telemetry of a password step (§13.7.4, §13.9, OP-67 m.2): the outcome only, never the
/// identifier or the address. Nothing reads it back (TI-18).
fn observed(step: PasswordLogin) -> PasswordLogin {
    use access_telemetry::signals::REQUESTER_THROTTLED;
    match &step {
        PasswordLogin::Throttled { .. } => {
            REQUESTER_THROTTLED.incr(["login"]);
            tracing::warn!(
                event = "api.throttled",
                outcome = "throttled",
                surface = "login",
                "sign-in attempts throttled (§13.7.4)"
            );
        }
        PasswordLogin::Rejected { .. } => {
            tracing::info!(
                event = "login.failed",
                outcome = "deny",
                reason = "credentials",
                "password step refused"
            );
        }
        PasswordLogin::Accepted { .. } => {
            tracing::info!(
                event = "login.succeeded",
                outcome = "allow",
                factor = "password",
                "password step accepted"
            );
        }
    }
    step
}

async fn audit<T: AccountTx>(
    tx: &mut T,
    event_type: &str,
    who: &Actor<'_>,
    target: &str,
) -> Result<(), AccountError> {
    tx.audit(&AuditEvent {
        event_type,
        actor: who.actor,
        target,
        correlation: who.correlation,
    })
    .await
}

async fn verify<C: Clock, E: Entropy>(
    realm: &Realm<'_>,
    services: &LoginServices<'_, C, E>,
    candidate: Option<&Candidate>,
    presented: Option<&Password>,
) -> Result<Option<Verified>, AccountError> {
    let usable = candidate.and_then(|c| {
        let active =
            AccountStatus::parse(&c.subject.status).is_some_and(AccountStatus::can_authenticate);
        match (&c.password, presented) {
            (Some(cred), Some(pw)) if active => Some((c, cred, pw)),
            _ => None,
        }
    });
    let Some((c, cred, pw)) = usable else {
        services.hasher.admit().await?;
        return Ok(None);
    };
    let subject = c.subject.id;
    let dek = subject_key(realm, &c.subject)?;
    let (phc, unpeppered) = open_password(realm, &dek, &subject, &cred.sealed)?;
    let v = services.hasher.verify(pw, phc).await?;
    if !v.matched {
        return Ok(None);
    }
    // CR-37, OP-150 m.3 (f)
    let reseal = if v.rehash || unpeppered {
        let fresh = services.hasher.hash(pw, services.entropy.salt()?).await?;
        Some(seal_password(
            realm,
            &dek,
            &subject,
            fresh.expose().as_bytes(),
        )?)
    } else {
        None
    };
    Ok(Some(Verified {
        subject,
        epoch: c.subject.session_epoch,
        credential: cred.id,
        reseal,
    }))
}
