//! PostgreSQL adapter of [`SessionTx`]: the account transaction of `identity-account`, with
//! the flow and session tables in the same unit of work (OP-63, OP-66).

use access_identity_account::adapters::pg::PgTx;
use access_identity_account::notify::message::Message;
use access_identity_account::notify::ports::Notifier;
use access_store::sessions::{
    EpochChange, FlowRow, FlowUpdate, MarkerRow, NewFlow, NewSession, SessionRow,
};

use crate::SessionError;
use crate::ports::SessionTx;

impl SessionTx for PgTx {
    async fn insert_flow(&mut self, flow: &NewFlow<'_>) -> Result<(), SessionError> {
        Ok(self.0.insert_flow(flow).await?)
    }

    async fn flow(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> Result<Option<FlowRow>, SessionError> {
        Ok(self.0.flow(from_day, hash).await?)
    }

    async fn flow_by_resume(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> Result<Option<FlowRow>, SessionError> {
        Ok(self.0.flow_by_resume(from_day, hash).await?)
    }

    async fn update_flow(&mut self, update: &FlowUpdate<'_>) -> Result<bool, SessionError> {
        Ok(self.0.update_flow(update).await?)
    }

    async fn insert_session(&mut self, session: &NewSession<'_>) -> Result<[u8; 16], SessionError> {
        Ok(self.0.insert_session(session).await?)
    }

    async fn session_by_cookie(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<SessionRow>, SessionError> {
        Ok(self.0.session_by_cookie(hash).await?)
    }

    async fn live_sessions(&mut self, subject: [u8; 16]) -> Result<Vec<SessionRow>, SessionError> {
        Ok(self.0.live_sessions(subject).await?)
    }

    async fn touch_session(&mut self, id: [u8; 16], at_ms: i64) -> Result<(), SessionError> {
        Ok(self.0.touch_session(id, at_ms).await?)
    }

    async fn end_session(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
        reason: &str,
    ) -> Result<bool, SessionError> {
        Ok(self.0.end_session(id, at_ms, reason).await?)
    }

    async fn restamp_session(
        &mut self,
        id: [u8; 16],
        from: i64,
        to: i64,
        auth_time_ms: i64,
        assurance: &[u8],
        step_up: bool,
    ) -> Result<bool, SessionError> {
        Ok(self
            .0
            .restamp_session(id, from, to, auth_time_ms, assurance, step_up)
            .await?)
    }

    async fn insert_marker(
        &mut self,
        hash: &[u8; 32],
        subject: [u8; 16],
        session_epoch: i64,
        created_ms: i64,
        expires_ms: i64,
    ) -> Result<(), SessionError> {
        Ok(self
            .0
            .insert_marker(hash, subject, session_epoch, created_ms, expires_ms)
            .await?)
    }

    async fn marker(&mut self, hash: &[u8; 32]) -> Result<Option<MarkerRow>, SessionError> {
        Ok(self.0.marker(hash).await?)
    }

    async fn use_otp_step(
        &mut self,
        credential: [u8; 16],
        step: i64,
    ) -> Result<bool, SessionError> {
        Ok(self.0.use_otp_step(credential, step).await?)
    }

    async fn user_handle(&mut self, subject: [u8; 16]) -> Result<Option<[u8; 64]>, SessionError> {
        Ok(self.0.user_handle(subject).await?)
    }

    async fn insert_user_handle(
        &mut self,
        subject: [u8; 16],
        handle: &[u8; 64],
    ) -> Result<bool, SessionError> {
        Ok(self.0.insert_user_handle(subject, handle).await?)
    }

    async fn subject_by_user_handle(
        &mut self,
        handle: &[u8],
    ) -> Result<Option<[u8; 16]>, SessionError> {
        Ok(self.0.subject_by_user_handle(handle).await?)
    }

    async fn passkey_credential(
        &mut self,
        raw_id: &[u8],
    ) -> Result<Option<[u8; 16]>, SessionError> {
        Ok(self.0.passkey(raw_id).await?.map(|p| p.credential))
    }

    async fn contact(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<(String, String)>, SessionError> {
        let Some((kind, stored)) = self.0.contact(subject).await? else {
            return Ok(None);
        };
        Ok(self.reveal(subject, &stored).await?.map(|v| (kind, v)))
    }

    async fn notify<N: Notifier + Sync>(
        &mut self,
        notifier: &N,
        message: &Message,
    ) -> Result<(), SessionError> {
        notifier.notify(&mut self.0, message).await?;
        Ok(())
    }

    async fn epochs_since(
        &mut self,
        since_ms: i64,
        limit: i64,
    ) -> Result<Vec<EpochChange>, SessionError> {
        Ok(self.0.epochs_since(since_ms, limit).await?)
    }

    async fn mailbox_since(&mut self, subject: [u8; 16]) -> Result<Option<u64>, SessionError> {
        Ok(self
            .0
            .mailbox_since(subject)
            .await?
            .and_then(|v| u64::try_from(v).ok()))
    }

    async fn cancel_recoveries(
        &mut self,
        subject: [u8; 16],
        at_ms: u64,
    ) -> Result<u64, SessionError> {
        crate::app::recovery::cancel(self, subject, at_ms).await
    }
}
