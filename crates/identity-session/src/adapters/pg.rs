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

    async fn insert_code_set(&mut self, subject: [u8; 16]) -> Result<(), SessionError> {
        Ok(self.0.insert_code_set(subject).await?)
    }

    async fn acknowledge_code_set(&mut self, subject: [u8; 16]) -> Result<bool, SessionError> {
        Ok(self.0.acknowledge_code_set(subject).await?)
    }

    async fn code_set_pending(&mut self, subject: [u8; 16]) -> Result<bool, SessionError> {
        Ok(self.0.code_set_pending(subject).await?)
    }

    async fn second_factor_ever(&mut self, subject: [u8; 16]) -> Result<bool, SessionError> {
        Ok(self
            .0
            .ever_held(
                subject,
                &[crate::app::TOTP, crate::adapters::passkeys::WEBAUTHN],
            )
            .await?)
    }

    async fn revoke_totp_by_recovery(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<[u8; 16]>, SessionError> {
        Ok(self.0.revoke_by_recovery(subject, crate::app::TOTP).await?)
    }

    async fn second_factor_lost_to_recovery(
        &mut self,
        subject: [u8; 16],
        now_ms: i64,
    ) -> Result<bool, SessionError> {
        Ok(self
            .0
            .last_removed_by_recovery(
                subject,
                &[crate::app::TOTP, crate::adapters::passkeys::WEBAUTHN],
            )
            .await?
            && self
                .0
                .recovery_grace_until(subject, now_ms)
                .await?
                .is_none())
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

    async fn has_name(&mut self, subject: [u8; 16]) -> Result<bool, SessionError> {
        let v = self.vault()?.clone();
        Ok(
            access_identity_account::app::vault::profile(&mut self.0, &v, subject)
                .await?
                .iter()
                .any(|(k, n)| k == "name" && !n.trim().is_empty()),
        )
    }

    async fn set_name(&mut self, subject: [u8; 16], name: &str) -> Result<(), SessionError> {
        let v = self.vault()?.clone();
        access_identity_account::app::vault::set_profile(&mut self.0, &v, subject, "name", name)
            .await?;
        Ok(())
    }

    async fn secret_facts(&mut self, subject: [u8; 16]) -> Result<Vec<String>, SessionError> {
        let v = self.vault()?.clone();
        let mut out = Vec::new();
        for row in self.0.identifiers(subject).await? {
            if row.live
                && row.kind == "phone"
                && let Some(p) = self.reveal(subject, &row.stored).await?
            {
                out.push(p);
            }
        }
        for (k, value) in
            access_identity_account::app::vault::profile(&mut self.0, &v, subject).await?
        {
            if k == "birthdate" || k == "national_id" {
                out.push(value);
            }
        }
        Ok(out)
    }

    async fn has_national_id(&mut self, subject: [u8; 16]) -> Result<bool, SessionError> {
        Ok(self.0.has_national_id(subject).await?)
    }

    async fn label_passkey(
        &mut self,
        credential: [u8; 16],
        label: &str,
        now_ms: u64,
    ) -> Result<(), SessionError> {
        Ok(self.0.label_passkey(credential, label, now_ms).await?)
    }

    async fn pending_documents(
        &mut self,
        subject: [u8; 16],
        digests: &[[u8; 32]],
    ) -> Result<Vec<[u8; 32]>, SessionError> {
        let accepted = self.0.acceptances(subject).await?;
        Ok(digests
            .iter()
            .filter(|d| {
                !accepted
                    .iter()
                    .any(|a| a.document_digest.as_slice() == d.as_slice())
            })
            .copied()
            .collect())
    }

    async fn accept_documents(
        &mut self,
        environment: &access_identity_account::app::Environment<'_>,
        subject: [u8; 16],
        documents: &[access_identity_account::domain::document::Document],
        (locale, correlation): (&str, &str),
    ) -> Result<(), SessionError> {
        let actor = environment.external(subject)?;
        let who = access_identity_account::app::Actor {
            actor: &actor,
            correlation,
        };
        for d in documents {
            access_identity_account::app::privacy::record_acceptance(
                self,
                environment,
                subject,
                &access_identity_account::app::privacy::Acceptance {
                    document_type: &d.kind,
                    version: &d.version,
                    document_digest: d.digest,
                    locale,
                    method: "checkbox",
                    client: None,
                },
                &who,
            )
            .await?;
        }
        Ok(())
    }

    async fn national_id_holder(
        &mut self,
        scheme: &str,
        number: &str,
    ) -> Result<Option<[u8; 16]>, SessionError> {
        let v = self.vault()?.clone();
        Ok(access_identity_account::app::national_id::holder(self, &v, scheme, number).await?)
    }

    async fn keep_national_id(
        &mut self,
        subject: [u8; 16],
        scheme: &str,
        number: &str,
    ) -> Result<bool, SessionError> {
        let v = self.vault()?.clone();
        Ok(
            access_identity_account::app::national_id::keep(self, &v, subject, (scheme, number))
                .await?,
        )
    }

    async fn has_birthdate(&mut self, subject: [u8; 16]) -> Result<bool, SessionError> {
        let v = self.vault()?.clone();
        Ok(
            access_identity_account::app::vault::profile(&mut self.0, &v, subject)
                .await?
                .iter()
                .any(|(k, d)| k == "birthdate" && !d.is_empty()),
        )
    }

    async fn set_birthdate(&mut self, subject: [u8; 16], date: &str) -> Result<(), SessionError> {
        let v = self.vault()?.clone();
        access_identity_account::app::vault::set_profile(
            &mut self.0,
            &v,
            subject,
            "birthdate",
            date,
        )
        .await?;
        Ok(())
    }

    async fn has_phone(&mut self, subject: [u8; 16]) -> Result<bool, SessionError> {
        Ok(self
            .0
            .identifiers(subject)
            .await?
            .iter()
            .any(|i| i.live && i.kind == "phone"))
    }

    async fn has_email(&mut self, subject: [u8; 16]) -> Result<bool, SessionError> {
        Ok(self
            .0
            .identifiers(subject)
            .await?
            .iter()
            .any(|i| i.live && i.kind == "email"))
    }

    async fn provider_email(&mut self, subject: [u8; 16]) -> Result<Option<String>, SessionError> {
        let Some((nonce, ciphertext)) = self.0.unvouched_provider_address(subject).await? else {
            return Ok(None);
        };
        let stored = access_store::accounts::StoredValue::Sealed {
            class: String::from(access_identity_account::app::vault::PiiClass::Contact.name()),
            nonce,
            ciphertext,
        };
        Ok(self.reveal(subject, &stored).await?)
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

    async fn sso_connections(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<Vec<String>>, SessionError> {
        let orgs = self.0.sso_enforced_orgs_of(subject).await?;
        if orgs.is_empty() {
            return Ok(None);
        }
        let mut parties = Vec::with_capacity(orgs.len());
        for o in orgs {
            if let Some(row) = self.0.org(o).await? {
                parties.push(access_kernel::json::b64url_encode(&row.party));
            }
        }
        Ok(Some(self.0.organization_connections(&parties).await?))
    }

    async fn breakglass_account(&mut self, subject: [u8; 16]) -> Result<bool, SessionError> {
        Ok(self.0.is_breakglass_account(&subject).await?)
    }

    async fn breakglass_on_call(&mut self) -> Result<Vec<[u8; 16]>, SessionError> {
        Ok(self.0.breakglass_on_call().await?)
    }

    async fn sign_in_methods(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<access_store::accounts::MethodRow>, SessionError> {
        Ok(self.0.sign_in_methods(subject).await?)
    }

    async fn session_by_id(&mut self, id: [u8; 16]) -> Result<Option<SessionRow>, SessionError> {
        Ok(self.0.session_by_id(id).await?)
    }

    async fn dbsc_challenge(
        &mut self,
        id: [u8; 16],
        challenge: &[u8; 32],
        expires_ms: i64,
    ) -> Result<bool, SessionError> {
        Ok(self.0.dbsc_challenge(id, challenge, expires_ms).await?)
    }

    async fn dbsc_bind(
        &mut self,
        id: [u8; 16],
        key: &[u8; 65],
        now_ms: i64,
        cookie_hash: &[u8; 32],
        cookie_expires_ms: i64,
    ) -> Result<bool, SessionError> {
        Ok(self
            .0
            .dbsc_bind(id, key, now_ms, cookie_hash, cookie_expires_ms)
            .await?)
    }

    async fn dbsc_refresh(
        &mut self,
        id: [u8; 16],
        cookie_hash: &[u8; 32],
        cookie_expires_ms: i64,
    ) -> Result<bool, SessionError> {
        Ok(self
            .0
            .dbsc_refresh(id, cookie_hash, cookie_expires_ms)
            .await?)
    }

    async fn session_instance(
        &mut self,
        session: [u8; 16],
    ) -> Result<Option<[u8; 16]>, SessionError> {
        Ok(self.0.session_instance(session).await?)
    }

    async fn record_upstream_session(
        &mut self,
        session: [u8; 16],
        connection: &str,
        now_ms: u64,
    ) -> Result<(), SessionError> {
        Ok(self
            .0
            .record_upstream_session(session, connection, now_ms)
            .await?)
    }

    async fn upstream_live_sessions(
        &mut self,
        connection: &str,
    ) -> Result<Vec<([u8; 16], [u8; 16])>, SessionError> {
        Ok(self.0.upstream_live_sessions(connection).await?)
    }
}
