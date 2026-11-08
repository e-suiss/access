//! What the domain needs from the outside world (OP-63): time, randomness, the breach
//! corpus and one transaction over the account tables (`UnitOfWork`).

use std::future::Future;

use access_store::accounts::{CredentialRow, NewCredential, Revoke, SealedSecret, SubjectRow};
use access_store::audit::AuditEvent;
use access_store::identity::{RealmId, TenantId};
use access_store::throttle::ThrottleRow;

use crate::AccountError;
use crate::domain::identifier::Identifier;
use crate::domain::status::AccountStatus;

/// Trusted time, Unix milliseconds.
pub trait Clock: Send + Sync {
    /// Now.
    fn now_ms(&self) -> u64;
}

/// Fresh randomness.
pub trait Entropy: Send + Sync {
    /// A 16-byte salt.
    ///
    /// # Errors
    /// [`AccountError::Random`].
    fn salt(&self) -> Result<[u8; 16], AccountError>;
}

/// The breach corpus could not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("breach range unavailable")]
pub struct RangeUnavailable;

/// The k-anonymity range source (IDP-3, OP-146 m.4 (e)).
pub trait BreachRanges: Send + Sync {
    /// The body of range `prefix` (five upper-case hex characters).
    fn range(&self, prefix: &str) -> impl Future<Output = Result<String, RangeUnavailable>> + Send;
}

/// A non-interactive bot signal for a registration or recovery request (OP-153 m.1 (b)).
pub trait BotSignals: Send + Sync {
    /// The signal for the client's `token` from the hosted page, if any, and the request's
    /// address prefix pseudonym; a provider that cannot answer is `Unavailable`, never an error.
    fn assess(
        &self,
        token: Option<&str>,
        context: &[u8],
    ) -> impl Future<Output = crate::domain::bot::BotSignal> + Send;
}

/// The bot signal of a deployment with no provider configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoBotProvider;

impl BotSignals for NoBotProvider {
    fn assess(
        &self,
        _token: Option<&str>,
        _context: &[u8],
    ) -> impl Future<Output = crate::domain::bot::BotSignal> + Send {
        std::future::ready(crate::domain::bot::BotSignal::Unavailable)
    }
}

/// Opens account transactions in one realm.
pub trait AccountDb: Send + Sync {
    /// The transaction.
    type Tx: AccountTx;
    /// Begins a transaction scoped to `tenant` and `realm`.
    fn begin(
        &self,
        tenant: TenantId,
        realm: RealmId,
    ) -> impl Future<Output = Result<Self::Tx, AccountError>> + Send;
}

/// One transaction over the account tables, the login counters and the audit log; nothing
/// is visible until [`AccountTx::commit`].
pub trait AccountTx: Send {
    /// Inserts a subject.
    fn insert_subject(
        &mut self,
        status: AccountStatus,
        kek_id: &str,
        wrapped_dek: &[u8],
    ) -> impl Future<Output = Result<[u8; 16], AccountError>> + Send;
    /// Reads a subject, locking it when `lock` is set.
    fn subject(
        &mut self,
        id: [u8; 16],
        lock: bool,
    ) -> impl Future<Output = Result<Option<SubjectRow>, AccountError>> + Send;
    /// Moves a subject from `from` to `to`; false when it is not in `from`.
    fn set_status(
        &mut self,
        id: [u8; 16],
        from: AccountStatus,
        to: AccountStatus,
    ) -> impl Future<Output = Result<bool, AccountError>> + Send;
    /// Ends the subject's identity sessions and refresh families and returns the new
    /// `session_epoch` (TN-50, MD-7). Every session and refresh family carries the epoch it
    /// was issued under and dies when it is behind.
    fn end_sessions(
        &mut self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<i64>, AccountError>> + Send;
    /// Adds an identifier; false when the realm has it.
    fn add_identifier(
        &mut self,
        subject: [u8; 16],
        identifier: &Identifier,
    ) -> impl Future<Output = Result<bool, AccountError>> + Send;
    /// The subject holding an identifier.
    fn subject_by_identifier(
        &mut self,
        value: &str,
    ) -> impl Future<Output = Result<Option<[u8; 16]>, AccountError>> + Send;
    /// Stores a credential.
    fn insert_credential(
        &mut self,
        credential: &NewCredential<'_>,
    ) -> impl Future<Output = Result<[u8; 16], AccountError>> + Send;
    /// The subject's active credentials of `kind`.
    fn credentials(
        &mut self,
        subject: [u8; 16],
        kind: &str,
    ) -> impl Future<Output = Result<Vec<CredentialRow>, AccountError>> + Send;
    /// Replaces a credential's sealed secret.
    fn reseal(
        &mut self,
        id: [u8; 16],
        algorithm: &str,
        sealed: &SealedSecret,
    ) -> impl Future<Output = Result<bool, AccountError>> + Send;
    /// Revokes a credential unless it is the last method (TN-68).
    fn revoke(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
    ) -> impl Future<Output = Result<Revoke, AccountError>> + Send;
    /// Records a credential's use.
    fn credential_used(
        &mut self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// A counter's state, locked (layer B, OP-35).
    fn throttle(
        &mut self,
        key: &[u8; 32],
        day: i32,
        horizon_days: i32,
    ) -> impl Future<Output = Result<ThrottleRow, AccountError>> + Send;
    /// Writes a counter's state.
    fn put_throttle(
        &mut self,
        key: &[u8; 32],
        day: i32,
        row: &ThrottleRow,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// The database server's clock, Unix milliseconds (OP-129 m.1).
    fn server_time(&mut self) -> impl Future<Output = Result<u64, AccountError>> + Send;
    /// Queues an identity outbox entry in this transaction (OP-10): it exists only if the
    /// transaction commits.
    fn outbox(
        &mut self,
        kind: &str,
        payload: &[u8],
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// Writes the audit row of this transaction (OPI-6).
    fn audit(
        &mut self,
        event: &AuditEvent<'_>,
    ) -> impl Future<Output = Result<(), AccountError>> + Send;
    /// Commits.
    fn commit(self) -> impl Future<Output = Result<(), AccountError>> + Send;
}

/// Whether an address's domain can receive mail (TN-80 step 1, OP-153 m.11 (f)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deliverability {
    /// A usable MX record, or no MX and an A or AAAA record (RFC 5321 §5.1).
    Deliverable,
    /// The domain does not exist, publishes a null MX (RFC 7505) or has neither MX nor address.
    Undeliverable,
    /// The resolver did not answer in time or in its format.
    Unknown,
}

/// The future a [`MailDomains`] lookup returns.
pub type MailFuture<'a> = std::pin::Pin<Box<dyn Future<Output = Deliverability> + Send + 'a>>;

/// The MX/A lookup of the sign-up's first step (OP-153 m.11 (f)). The answer never depends on
/// whether an account holds the address.
pub trait MailDomains: Send + Sync {
    /// Whether `domain` (lower-case ASCII) receives mail.
    fn deliverable<'a>(&'a self, domain: &'a str) -> MailFuture<'a>;
}

/// No resolver configured: every domain is [`Deliverability::Unknown`] and the out-of-band
/// code stays the only proof of the mailbox.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoResolver;

impl MailDomains for NoResolver {
    fn deliverable<'a>(&'a self, _: &'a str) -> MailFuture<'a> {
        Box::pin(async { Deliverability::Unknown })
    }
}
