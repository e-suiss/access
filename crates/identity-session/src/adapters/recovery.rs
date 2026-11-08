//! PostgreSQL adapter of [`RecoveryTx`] (OP-63, OP-66): the recovery tables of `access-store` in
//! the account transaction, notice addresses sealed under the subject's `contact` key (OP-153
//! m.3 (aa)).

use access_identity_account::adapters::pg::PgTx;
use access_identity_account::app::vault::{self, PiiClass};
use access_identity_account::notify::message::Address;
use access_store::StoreError;
use access_store::recovery::NewAddress;
use suiss_crypto::envelope::Sealed;

use crate::SessionError;
use crate::ports::{
    AccountPolicyRow, AttemptRow, EvidenceRow, MethodRow, NewAttempt, NewToken, NewTransition,
    NoticeAddress, RecoveryTx, TokenRow, TransitionRow,
};

/// The field every notice address is sealed under.
const FIELD: &str = "notification_address";

fn text(a: &Address) -> (&'static str, &str) {
    match a {
        Address::Email(v) => ("email", v),
        Address::Phone(v) => ("phone", v),
    }
}

impl RecoveryTx for PgTx {
    async fn recovery_lock(&mut self, key: &[u8; 16]) -> Result<(), SessionError> {
        Ok(self.0.recovery_lock(key).await?)
    }

    async fn notice_addresses(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<NoticeAddress>, SessionError> {
        let rows = self.0.notification_addresses(subject).await?;
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let v = self.vault()?.clone();
        let Some(dek) =
            vault::class_key(&mut self.0, &v, subject, PiiClass::Contact, false).await?
        else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for r in rows {
            let Some((nonce, ciphertext)) = r.sealed else {
                continue;
            };
            let sealed = Sealed { nonce, ciphertext };
            let value = vault::open(&self.0, &dek, subject, PiiClass::Contact, FIELD, &sealed)?;
            let to = match r.kind.as_str() {
                "email" => Address::Email(value),
                "phone" => Address::Phone(value),
                _ => return Err(SessionError::Corrupt),
            };
            out.push(NoticeAddress {
                id: r.id,
                to,
                recovery_target: r.recovery_target,
                recovery_contact: r.recovery_contact,
                since_ms: u64::try_from(r.since_ms).map_err(|_| SessionError::Corrupt)?,
            });
        }
        Ok(out)
    }

    async fn add_notice_address(
        &mut self,
        subject: [u8; 16],
        address: &NoticeAddress,
    ) -> Result<[u8; 16], SessionError> {
        let v = self.vault()?.clone();
        let dek = vault::class_key(&mut self.0, &v, subject, PiiClass::Contact, true)
            .await?
            .ok_or(SessionError::Corrupt)?;
        let (kind, value) = text(&address.to);
        let sealed = vault::seal(
            &self.0,
            &dek,
            subject,
            PiiClass::Contact,
            FIELD,
            value.as_bytes(),
        )?;
        Ok(self
            .0
            .insert_notification_address(&NewAddress {
                subject,
                kind,
                identifier: None,
                sealed: Some((&sealed.nonce, &sealed.ciphertext)),
                recovery_target: address.recovery_target,
                recovery_contact: address.recovery_contact,
            })
            .await?)
    }

    async fn retire_notice_address(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
    ) -> Result<bool, SessionError> {
        Ok(self.0.retire_notification_address(subject, id).await?)
    }

    async fn recovery_methods(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<MethodRow>, SessionError> {
        Ok(self.0.recovery_methods(subject).await?)
    }

    async fn add_recovery_method(
        &mut self,
        subject: [u8; 16],
        class: &str,
        assurance: &str,
        address: Option<[u8; 16]>,
    ) -> Result<[u8; 16], SessionError> {
        Ok(self
            .0
            .insert_recovery_method(subject, class, assurance, address)
            .await?)
    }

    async fn retire_recovery_method(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
    ) -> Result<bool, SessionError> {
        Ok(self.0.retire_recovery_method(subject, id).await?)
    }

    async fn account_recovery_policy(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<AccountPolicyRow>, SessionError> {
        Ok(self.0.account_recovery_policy(subject).await?)
    }

    async fn set_account_recovery_policy(
        &mut self,
        subject: [u8; 16],
        policy: &AccountPolicyRow,
    ) -> Result<(), SessionError> {
        Ok(self
            .0
            .insert_account_recovery_policy(subject, policy)
            .await?)
    }

    async fn recovery_realm_policy(&mut self) -> Result<Option<Vec<u8>>, SessionError> {
        Ok(self.0.recovery_realm_policy().await?)
    }

    async fn insert_attempt(&mut self, attempt: &NewAttempt<'_>) -> Result<[u8; 16], SessionError> {
        Ok(self.0.insert_recovery_attempt(attempt).await?)
    }

    async fn attempt(
        &mut self,
        handle_hash: &[u8; 32],
    ) -> Result<Option<AttemptRow>, SessionError> {
        Ok(self.0.recovery_attempt(handle_hash).await?)
    }

    async fn attempts_since(
        &mut self,
        subject: [u8; 16],
        since_ms: i64,
    ) -> Result<Vec<AttemptRow>, SessionError> {
        Ok(self.0.recovery_attempts_since(subject, since_ms).await?)
    }

    async fn transitions(&mut self, attempt: [u8; 16]) -> Result<Vec<TransitionRow>, SessionError> {
        Ok(self.0.recovery_transitions(attempt).await?)
    }

    async fn transition(
        &mut self,
        attempt: [u8; 16],
        t: &NewTransition<'_>,
    ) -> Result<bool, SessionError> {
        match self.0.insert_recovery_transition(attempt, t).await {
            Ok(()) => Ok(true),
            Err(StoreError::Consumed) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn insert_evidence(
        &mut self,
        attempt: [u8; 16],
        class: &str,
        code_hash: &[u8; 32],
        address: Option<[u8; 16]>,
        expires_ms: i64,
    ) -> Result<[u8; 16], SessionError> {
        Ok(self
            .0
            .insert_recovery_evidence(
                attempt,
                class,
                code_hash,
                address,
                crate::domain::recovery::SENT_CODE_TRIES,
                expires_ms,
            )
            .await?)
    }

    async fn evidence(&mut self, attempt: [u8; 16]) -> Result<Vec<EvidenceRow>, SessionError> {
        Ok(self.0.recovery_evidence(attempt).await?)
    }

    async fn consume_evidence(&mut self, id: [u8; 16], at_ms: i64) -> Result<bool, SessionError> {
        Ok(self.0.consume_recovery_evidence(id, at_ms).await?)
    }

    async fn spend_try(&mut self, id: [u8; 16]) -> Result<(), SessionError> {
        Ok(self.0.spend_recovery_try(id).await?)
    }

    async fn insert_token(
        &mut self,
        token: &NewToken<'_>,
    ) -> Result<Option<[u8; 16]>, SessionError> {
        match self.0.insert_recovery_token(token).await {
            Ok(id) => Ok(Some(id)),
            Err(StoreError::Consumed) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn token(
        &mut self,
        token_hash: &[u8; 32],
        kinds: &[String],
        at_ms: i64,
    ) -> Result<Option<TokenRow>, SessionError> {
        Ok(self.0.recovery_token(token_hash, kinds, at_ms).await?)
    }

    async fn use_token(&mut self, id: [u8; 16], at_ms: i64) -> Result<bool, SessionError> {
        Ok(self.0.use_recovery_token(id, at_ms).await?)
    }

    async fn revoke_tokens(
        &mut self,
        subject: [u8; 16],
        kinds: &[String],
    ) -> Result<u64, SessionError> {
        Ok(self.0.revoke_recovery_tokens(subject, kinds).await?)
    }

    async fn federated_links(&mut self, subject: [u8; 16]) -> Result<u64, SessionError> {
        Ok(self.0.federated_links(subject).await?)
    }

    async fn cut_federated_links(&mut self, subject: [u8; 16]) -> Result<u64, SessionError> {
        Ok(self.0.release_federated_links(subject).await?)
    }

    async fn subject_party(&mut self, subject: [u8; 16]) -> Result<Option<[u8; 16]>, SessionError> {
        Ok(access_store::idp::subject_party(&mut self.0, &subject).await?)
    }

    async fn subject_instance(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<[u8; 16]>, SessionError> {
        Ok(access_store::issuer::subject_instance(&mut self.0, &subject).await?)
    }

    async fn issued_in_line(
        &mut self,
        subject: [u8; 16],
        domain: [u8; 32],
        line: [u8; 32],
    ) -> Result<Option<[u8; 16]>, SessionError> {
        let domain = access_store::scope::DomainId::from_bytes(domain);
        Ok(access_store::issuer::last_in_line(&mut self.0, &subject, &domain, &line).await?)
    }
}
