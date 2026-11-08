//! What the domain needs from the outside world (OP-63): time, randomness and one transaction
//! over the account, flow and session tables; messages go through the Relay seam's
//! [`Notifier`] inside that transaction (E42 m.1).

use std::future::Future;

use access_identity_account::ports::{AccountDb, AccountTx};
use access_identity_risk::ports::RiskTx;
use access_store::sessions::{
    EpochChange, FlowRow, FlowUpdate, MarkerRow, NewFlow, NewSession, SessionRow,
};

pub use access_identity_account::ports::Clock;

use access_identity_account::notify::message::Message;
use access_identity_account::notify::ports::Notifier;

use crate::SessionError;

/// Fresh randomness.
pub trait Random: Send + Sync {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`SessionError::Random`].
    fn fill(&self, out: &mut [u8]) -> Result<(), SessionError>;

    /// A fresh 16-byte salt.
    ///
    /// # Errors
    /// [`SessionError::Random`].
    fn salt(&self) -> Result<[u8; 16], SessionError>;
}

/// The account transaction plus the flow and session tables, and the SL2 risk tables in the
/// same unit of work (TN-46).
pub trait SessionTx: AccountTx + RiskTx {
    /// Stores a flow.
    fn insert_flow(
        &mut self,
        flow: &NewFlow<'_>,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
    /// A flow by handle digest, locked.
    fn flow(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<FlowRow>, SessionError>> + Send;
    /// A flow by resume digest, locked.
    fn flow_by_resume(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<FlowRow>, SessionError>> + Send;
    /// Compare-and-set of a flow.
    fn update_flow(
        &mut self,
        update: &FlowUpdate<'_>,
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// Stores a session.
    fn insert_session(
        &mut self,
        session: &NewSession<'_>,
    ) -> impl Future<Output = Result<[u8; 16], SessionError>> + Send;
    /// A session by cookie digest with its subject's current state, locked.
    fn session_by_cookie(
        &mut self,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<SessionRow>, SessionError>> + Send;
    /// The subject's live sessions.
    fn live_sessions(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Vec<SessionRow>, SessionError>> + Send;
    /// Records a use.
    fn touch_session(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
    /// Ends a session.
    fn end_session(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
        reason: &str,
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// Carries a live session from epoch `from` to `to` with a new authentication; a
    /// `step_up` records its time.
    fn restamp_session(
        &mut self,
        id: [u8; 16],
        from: i64,
        to: i64,
        auth_time_ms: i64,
        assurance: &[u8],
        step_up: bool,
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// Stores a device marker.
    fn insert_marker(
        &mut self,
        hash: &[u8; 32],
        subject: [u8; 16],
        session_epoch: i64,
        created_ms: i64,
        expires_ms: i64,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
    /// A device marker.
    fn marker(
        &mut self,
        hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<MarkerRow>, SessionError>> + Send;
    /// Marks a TOTP step used.
    fn use_otp_step(
        &mut self,
        credential: [u8; 16],
        step: i64,
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// Records a new set of recovery codes waiting for its "I saved them" (TN-59).
    fn insert_code_set(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
    /// Acknowledges the newest set; false when none waits.
    fn acknowledge_code_set(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// Whether the newest set still waits for its acknowledgement.
    fn code_set_pending(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// The subject's WebAuthn `user.id`.
    fn user_handle(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Option<[u8; 64]>, SessionError>> + Send;
    /// Gives the subject a `user.id`.
    fn insert_user_handle(
        &mut self,
        subject: [u8; 16],
        handle: &[u8; 64],
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// The subject of a `user.id`.
    fn subject_by_user_handle(
        &mut self,
        handle: &[u8],
    ) -> impl Future<Output = Result<Option<[u8; 16]>, SessionError>> + Send;
    /// The sibling credential of a passkey.
    fn passkey_credential(
        &mut self,
        raw_id: &[u8],
    ) -> impl Future<Output = Result<Option<[u8; 16]>, SessionError>> + Send;
    /// Where the subject's sign-in messages go: `(kind, value)`.
    fn contact(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Option<(String, String)>, SessionError>> + Send;
    /// Queues `message` through `notifier` in this transaction.
    fn notify<N: Notifier + Sync>(
        &mut self,
        notifier: &N,
        message: &Message,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
    /// Subjects whose epoch moved after `since_ms`.
    fn epochs_since(
        &mut self,
        since_ms: i64,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<EpochChange>, SessionError>> + Send;
    /// N1: since when the subject has owned the mailbox its messages go to, Unix ms (TN-66,
    /// OP-153 m.3 (i)).
    fn mailbox_since(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Option<u64>, SessionError>> + Send;
    /// Denies the subject's running recoveries: its own sign-in cancels them (TN-54); how many.
    fn cancel_recoveries(
        &mut self,
        subject: [u8; 16],
        at_ms: u64,
    ) -> impl Future<Output = Result<u64, SessionError>> + Send;
}

/// Opens session transactions in one realm.
pub trait SessionDb: AccountDb<Tx: SessionTx> {}

impl<T: AccountDb<Tx: SessionTx>> SessionDb for T {}

pub use access_store::recovery::{
    AccountPolicyRow, AttemptRow, EvidenceRow, MethodRow, NewAttempt, NewToken, NewTransition,
    TokenRow, TransitionRow,
};

/// A notice address as the recovery service reads it.
#[derive(Clone, PartialEq, Eq)]
pub struct NoticeAddress {
    /// Its id, `[0; 16]` before it is stored.
    pub id: [u8; 16],
    /// Where.
    pub to: access_identity_account::notify::message::Address,
    /// Recovery codes go to it.
    pub recovery_target: bool,
    /// A recovery contact's.
    pub recovery_contact: bool,
    /// Since when its owner has proved it, Unix ms (RFC 7293); 0 before it is stored.
    pub since_ms: u64,
}

impl core::fmt::Debug for NoticeAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NoticeAddress")
            .field("to", &self.to)
            .field("recovery_target", &self.recovery_target)
            .field("recovery_contact", &self.recovery_contact)
            .finish_non_exhaustive()
    }
}

/// The recovery tables in the same unit of work (§12.3.2; OP-153 m.4: an addition beside
/// [`SessionTx`]).
pub trait RecoveryTx: SessionTx {
    /// Serialises the work on one attempt or one subject's recovery (TN-54).
    fn recovery_lock(
        &mut self,
        key: &[u8; 16],
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
    /// The subject's live notice addresses, opened; one whose key is shredded is left out.
    fn notice_addresses(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Vec<NoticeAddress>, SessionError>> + Send;
    /// Seals and stores a notice address.
    fn add_notice_address(
        &mut self,
        subject: [u8; 16],
        address: &NoticeAddress,
    ) -> impl Future<Output = Result<[u8; 16], SessionError>> + Send;
    /// Retires a notice address.
    fn retire_notice_address(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// The subject's live recovery methods.
    fn recovery_methods(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Vec<MethodRow>, SessionError>> + Send;
    /// Adds a recovery method.
    fn add_recovery_method(
        &mut self,
        subject: [u8; 16],
        class: &str,
        assurance: &str,
        address: Option<[u8; 16]>,
    ) -> impl Future<Output = Result<[u8; 16], SessionError>> + Send;
    /// Retires a recovery method.
    fn retire_recovery_method(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// The account's recovery settings.
    fn account_recovery_policy(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Option<AccountPolicyRow>, SessionError>> + Send;
    /// Records the account's recovery settings.
    fn set_account_recovery_policy(
        &mut self,
        subject: [u8; 16],
        policy: &AccountPolicyRow,
    ) -> impl Future<Output = Result<(), SessionError>> + Send;
    /// The realm's recovery policy, encoded.
    fn recovery_realm_policy(
        &mut self,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, SessionError>> + Send;
    /// Opens an attempt.
    fn insert_attempt(
        &mut self,
        attempt: &NewAttempt<'_>,
    ) -> impl Future<Output = Result<[u8; 16], SessionError>> + Send;
    /// The attempt of a handle digest.
    fn attempt(
        &mut self,
        handle_hash: &[u8; 32],
    ) -> impl Future<Output = Result<Option<AttemptRow>, SessionError>> + Send;
    /// The subject's attempts since `since_ms`, newest first.
    fn attempts_since(
        &mut self,
        subject: [u8; 16],
        since_ms: i64,
    ) -> impl Future<Output = Result<Vec<AttemptRow>, SessionError>> + Send;
    /// The attempt's transitions, in order.
    fn transitions(
        &mut self,
        attempt: [u8; 16],
    ) -> impl Future<Output = Result<Vec<TransitionRow>, SessionError>> + Send;
    /// Appends a transition; `false` when another transaction took its place (TN-54).
    fn transition(
        &mut self,
        attempt: [u8; 16],
        t: &NewTransition<'_>,
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// Stores a sent code.
    fn insert_evidence(
        &mut self,
        attempt: [u8; 16],
        class: &str,
        code_hash: &[u8; 32],
        address: Option<[u8; 16]>,
        expires_ms: i64,
    ) -> impl Future<Output = Result<[u8; 16], SessionError>> + Send;
    /// The attempt's unspent codes.
    fn evidence(
        &mut self,
        attempt: [u8; 16],
    ) -> impl Future<Output = Result<Vec<EvidenceRow>, SessionError>> + Send;
    /// Spends a code once.
    fn consume_evidence(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// Counts a wrong try.
    fn spend_try(&mut self, id: [u8; 16]) -> impl Future<Output = Result<(), SessionError>> + Send;
    /// Extends the attempt's live recovery contact codes once by 24 hours; how many.
    fn extend_contact_codes(
        &mut self,
        attempt: [u8; 16],
    ) -> impl Future<Output = Result<u64, SessionError>> + Send;
    /// Stores a single-use token; `None` for a second live pass of the user (TN-62).
    fn insert_token(
        &mut self,
        token: &NewToken<'_>,
    ) -> impl Future<Output = Result<Option<[u8; 16]>, SessionError>> + Send;
    /// The live token of a digest.
    fn token(
        &mut self,
        token_hash: &[u8; 32],
        kinds: &[String],
        at_ms: i64,
    ) -> impl Future<Output = Result<Option<TokenRow>, SessionError>> + Send;
    /// Uses a token once.
    fn use_token(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
    ) -> impl Future<Output = Result<bool, SessionError>> + Send;
    /// Revokes the subject's live tokens of `kinds`.
    fn revoke_tokens(
        &mut self,
        subject: [u8; 16],
        kinds: &[String],
    ) -> impl Future<Output = Result<u64, SessionError>> + Send;
    /// The subject's live federated links (TN-64).
    fn federated_links(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<u64, SessionError>> + Send;
    /// Cuts the subject's federated links (TN-64).
    fn cut_federated_links(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<u64, SessionError>> + Send;
    /// The Party the subject is bound to in the realm's governing domain, if any (OP-153 m.3
    /// (c)).
    fn subject_party(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Option<[u8; 16]>, SessionError>> + Send;
    /// When the realm's RP ID last changed, Unix ms (RR-45).
    fn last_rp_id_change(
        &mut self,
    ) -> impl Future<Output = Result<Option<u64>, SessionError>> + Send;
    /// The Instance of the subject's first active device key, if any.
    fn subject_instance(
        &mut self,
        subject: [u8; 16],
    ) -> impl Future<Output = Result<Option<[u8; 16]>, SessionError>> + Send;
    /// The newest Claim the realm issuer issued in `line` about the subject in `domain` and
    /// that Claim Ingest did not reject.
    fn issued_in_line(
        &mut self,
        subject: [u8; 16],
        domain: [u8; 32],
        line: [u8; 32],
    ) -> impl Future<Output = Result<Option<[u8; 16]>, SessionError>> + Send;
}
