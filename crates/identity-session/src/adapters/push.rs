//! PostgreSQL adapter of [`PushTx`] (OP-156 m.3 (d), OP-66).

use access_identity_account::adapters::pg::PgTx;
use access_store::push::{DeviceKeyRow, NewPushChallenge, PushChallengeRow, PushHistoryRow};

use crate::SessionError;
use crate::ports::PushTx;

impl PushTx for PgTx {
    async fn approvers(&mut self, subject: [u8; 16]) -> Result<Vec<DeviceKeyRow>, SessionError> {
        Ok(self.0.device_keys(subject).await?)
    }

    async fn approver_by_thumbprint(
        &mut self,
        thumbprint: &[u8; 32],
    ) -> Result<Option<DeviceKeyRow>, SessionError> {
        Ok(self.0.device_key_by_thumbprint(thumbprint).await?)
    }

    async fn approver_seen(&mut self, id: [u8; 16]) -> Result<(), SessionError> {
        Ok(self.0.device_key_seen(id).await?)
    }

    async fn insert_push_challenge(
        &mut self,
        c: &NewPushChallenge<'_>,
    ) -> Result<(), SessionError> {
        Ok(self.0.insert_push_challenge(c).await?)
    }

    async fn push_challenge(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<PushChallengeRow>, SessionError> {
        Ok(self.0.push_challenge(hash).await?)
    }

    async fn decide_push_challenge(
        &mut self,
        id: [u8; 16],
        decision: &str,
        at_ms: u64,
        device: [u8; 16],
    ) -> Result<bool, SessionError> {
        Ok(self
            .0
            .decide_push_challenge(id, decision, at_ms, device)
            .await?)
    }

    async fn use_push_challenge(&mut self, id: [u8; 16], at_ms: u64) -> Result<bool, SessionError> {
        Ok(self.0.use_push_challenge(id, at_ms).await?)
    }

    async fn push_history(
        &mut self,
        subject: [u8; 16],
        since_ms: u64,
    ) -> Result<Vec<PushHistoryRow>, SessionError> {
        Ok(self.0.push_history(subject, since_ms).await?)
    }
}
