//! PostgreSQL adapter of [`PaymentTx`] (OP-156 m.3 (e), (f), OP-66).

use access_identity_account::adapters::pg::PgTx;
use access_store::payment::{AppFactorKey, NewSmsCode, SmsCodeRow};

use crate::SessionError;
use crate::ports::PaymentTx;

impl PaymentTx for PgTx {
    async fn sms_line(&mut self, subject: [u8; 16]) -> Result<Option<String>, SessionError> {
        let Some(stored) = self.0.sms_line(subject).await? else {
            return Ok(None);
        };
        Ok(self.reveal(subject, &stored).await?)
    }

    async fn sim_signals(&mut self, subject: [u8; 16]) -> Result<Option<(u64, u64)>, SessionError> {
        Ok(self.0.sim_signals(subject).await?)
    }

    async fn insert_sms_code(&mut self, c: &NewSmsCode<'_>) -> Result<(), SessionError> {
        Ok(self.0.insert_sms_code(c).await?)
    }

    async fn sms_code(
        &mut self,
        binding: &[u8; 32],
        purpose: &str,
    ) -> Result<Option<SmsCodeRow>, SessionError> {
        Ok(self.0.sms_code(binding, purpose).await?)
    }

    async fn try_sms_code(
        &mut self,
        id: [u8; 16],
        used_ms: Option<u64>,
    ) -> Result<bool, SessionError> {
        Ok(self.0.try_sms_code(id, used_ms).await?)
    }

    async fn sms_codes_since(
        &mut self,
        subject: [u8; 16],
        since_ms: u64,
    ) -> Result<u64, SessionError> {
        Ok(self.0.sms_codes_since(subject, since_ms).await?)
    }

    async fn app_factor_key(
        &mut self,
        device: [u8; 16],
    ) -> Result<Option<AppFactorKey>, SessionError> {
        Ok(self.0.app_factor_key(device).await?)
    }

    async fn record_app_factor_answer(
        &mut self,
        challenge: [u8; 16],
        device: [u8; 16],
        pin_verified: bool,
    ) -> Result<(), SessionError> {
        Ok(self
            .0
            .record_app_factor_answer(challenge, device, pin_verified)
            .await?)
    }

    async fn app_factor_answer(&mut self, challenge: [u8; 16]) -> Result<bool, SessionError> {
        Ok(self.0.app_factor_answer(challenge).await?)
    }
}
