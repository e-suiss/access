//! What the domain needs from the outside world (OP-63): time, randomness and one transaction
//! over the account, flow and session tables; messages go through the Relay seam's
//! [`Notifier`] inside that transaction (E42 m.1).

use std::future::Future;

use access_identity_account::ports::{AccountDb, AccountTx};
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
}

/// The account transaction plus the flow and session tables.
pub trait SessionTx: AccountTx {
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
    /// Carries a live session from epoch `from` to `to` with a new authentication.
    fn restamp_session(
        &mut self,
        id: [u8; 16],
        from: i64,
        to: i64,
        auth_time_ms: i64,
        assurance: &[u8],
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
    fn notify<N: Notifier>(
        &mut self,
        notifier: &N,
        message: &Message,
    ) -> impl Future<Output = Result<(), SessionError>>;
    /// Subjects whose epoch moved after `since_ms`.
    fn epochs_since(
        &mut self,
        since_ms: i64,
        limit: i64,
    ) -> impl Future<Output = Result<Vec<EpochChange>, SessionError>> + Send;
}

/// Opens session transactions in one realm.
pub trait SessionDb: AccountDb<Tx: SessionTx> {}

impl<T: AccountDb<Tx: SessionTx>> SessionDb for T {}
