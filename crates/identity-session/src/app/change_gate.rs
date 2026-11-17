//! What a person's own sign-in method change needs before it starts (TN-147, OP-159 m.52): a
//! re-authentication within five minutes, AAL2 while the account holds a strong method, and a
//! code at the account's address when a first strong method is added.

use access_crypto::Secret;
use access_identity_account::notify::message::{Address, Body, Message, OtpPurpose};
use access_identity_account::ports::AccountTx;
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::sessions::SessionRow;

use super::sessions::{SessionStatus, view};
use super::signin::address;
use super::{
    Auth, CODE_NOT_ACCEPTED, FLOW_GONE, FlowRef, Notifier, Problem, Resume, STEP_NOT_ALLOWED, Step,
    TOTP, audit, gone, load, refuse, save,
};
use crate::SessionError;
use crate::adapters::passkeys::WEBAUTHN;
use crate::domain::assurance::{Aal, MethodClass};
use crate::domain::codes::email_code;
use crate::domain::device::STEP_UP_WINDOW_MS;
use crate::domain::flow::{
    EMAIL_CODE_ATTEMPTS, FlowRejection, Pending, Purpose, SUSPENSION_TTL_MS, code_digest,
};
use crate::ports::{Clock, Random, SessionDb, SessionTx};

/// The change waits for the code sent to the account's address (TN-147).
pub const PROOF_REQUIRED: Problem = Problem {
    status: 403,
    code: "proof-required",
    title: "Enter the code we sent to your address first",
    retry_after_s: None,
};

/// Why a sign-in method change is refused before it starts (TN-147); a decision, not an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    /// The session is not live.
    Ended(SessionStatus),
    /// The session must re-authenticate first: it is older than five minutes, or below AAL2
    /// while the change needs it.
    StepUp,
    /// The change needs a code at the account's address and the account has none.
    NoAddress,
    /// The account's mail cap is spent.
    Throttled,
}

/// What a change that passed the gate still needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Passed {
    /// Nothing more.
    Open,
    /// A code at the account's address: the account holds no strong method yet.
    Proof,
}

/// Whether a session authenticated at `aal` at `auth_time_ms` may change sign-in methods at
/// `now_ms` (TN-147): within five minutes, and at AAL2 when `strong` (the account holds a
/// passkey or TOTP) or when the change always needs it.
#[must_use]
pub const fn gate(aal: Aal, auth_time_ms: u64, now_ms: u64, strong: bool, always: bool) -> bool {
    if now_ms.saturating_sub(auth_time_ms) > STEP_UP_WINDOW_MS {
        return false;
    }
    !((strong || always) && (aal as u8) < (Aal::Aal2 as u8))
}

impl<D, C, R, N, P, S> Auth<'_, D, C, R, N, P, S>
where
    D: SessionDb,
    C: Clock,
    R: Random,
    N: Notifier + Sync,
    P: CredentialRegistry + Sync,
    S: SignalSink + Sync,
{
    /// Whether the subject holds a strong method: a passkey or TOTP (TN-147).
    pub(crate) async fn strong(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
    ) -> Result<bool, SessionError> {
        Ok(!tx.credentials(subject, WEBAUTHN).await?.is_empty()
            || !tx.credentials(subject, TOTP).await?.is_empty())
    }

    /// The gate of a change from `row` (TN-147); `always` asks AAL2 whatever the account holds.
    pub(crate) async fn change_gate(
        &self,
        tx: &mut D::Tx,
        row: &SessionRow,
        now: u64,
        always: bool,
    ) -> Result<Result<Passed, Gate>, SessionError> {
        let v = view(row)?;
        let strong = self.strong(tx, row.subject).await?;
        if !gate(v.assurance.aal, v.auth_time_ms, now, strong, always) {
            return Ok(Err(Gate::StepUp));
        }
        Ok(Ok(if strong { Passed::Open } else { Passed::Proof }))
    }

    /// The live session of `cookie` when it passes the gate, with the code its change waits
    /// for (TN-147).
    pub(crate) async fn gated(
        &self,
        tx: &mut D::Tx,
        cookie: &str,
        now: u64,
        always: bool,
    ) -> Result<Result<(SessionRow, Option<(String, Address)>), Gate>, SessionError> {
        let row = match self.live_session(tx, cookie, now).await? {
            Ok(r) => r,
            Err(status) => return Ok(Err(Gate::Ended(status))),
        };
        match self.change_gate(tx, &row, now, always).await? {
            Ok(Passed::Open) => Ok(Ok((row, None))),
            Ok(Passed::Proof) => match self.proof_code(tx, row.subject, now).await? {
                Ok(p) => Ok(Ok((row, Some(p)))),
                Err(g) => Ok(Err(g)),
            },
            Err(g) => Ok(Err(g)),
        }
    }

    /// The session's subject when `cookie` may change sign-in methods without a code (TN-147):
    /// removing a method and changing the password.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn change_subject(
        &self,
        cookie: &str,
    ) -> Result<Result<[u8; 16], Gate>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let row = match self.live_session(&mut tx, cookie, now).await? {
            Ok(r) => r,
            Err(status) => {
                tx.commit().await?;
                return Ok(Err(Gate::Ended(status)));
            }
        };
        let out = self
            .change_gate(&mut tx, &row, now, false)
            .await?
            .map(|_| row.subject);
        tx.commit().await?;
        Ok(out)
    }

    /// A fresh code for a first strong method, when the account has an address it may be sent
    /// to (TN-147); the code is not sent yet.
    pub(crate) async fn proof_code(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        now: u64,
    ) -> Result<Result<(String, Address), Gate>, SessionError> {
        let Some(to) = address(tx.contact(subject).await?) else {
            return Ok(Err(Gate::NoAddress));
        };
        // TN-83 (6), IDP-3
        if !access_identity_account::app::registration::account_mail_allowed(
            tx,
            self.environment.tenant.as_bytes(),
            self.environment.environment.as_bytes(),
            subject,
            now,
        )
        .await?
        {
            return Ok(Err(Gate::Throttled));
        }
        let mut raw = [0; 8];
        self.random.fill(&mut raw)?;
        Ok(Ok((email_code(&raw), to)))
    }

    /// The pending code a flow whose handle digests to `flow_hash` waits for (TN-147).
    pub(crate) fn proof_pending(flow_hash: &[u8; 32], code: &str, now: u64) -> Pending {
        Pending::EmailCode {
            digest: Some(code_digest(flow_hash, code)),
            expires_ms: now.saturating_add(SUSPENSION_TTL_MS),
            attempts_left: EMAIL_CODE_ATTEMPTS,
        }
    }

    /// Sends `code` to `to` (TN-147, OP-153 m.3 (i)).
    pub(crate) async fn send_proof(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        (code, to): (String, Address),
        now: u64,
    ) -> Result<(), SessionError> {
        let valid_since_ms = match to {
            Address::Email(_) => Some(tx.mailbox_since(subject).await?.unwrap_or(1)),
            Address::Phone(_) | Address::Device(_) => None,
        };
        tx.notify(
            self.notifier,
            &Message {
                subject,
                to,
                locale: None,
                valid_since_ms,
                body: Body::Otp {
                    code: Secret::new(code),
                    purpose: OtpPurpose::VerifyAddress,
                    expires_at_ms: now.saturating_add(SUSPENSION_TTL_MS),
                },
            },
        )
        .await?;
        Ok(())
    }

    /// Takes the code from the account's address for a passkey registration or a TOTP
    /// enrolment of this session (TN-147); wrong codes are counted and the code dies after five.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn prove_change(
        &self,
        cookie: &str,
        handle: &str,
        code: &str,
        correlation: &str,
    ) -> Result<Result<(), Step>, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let Ok(session) = self.live_session(&mut tx, cookie, now).await? else {
            tx.commit().await?;
            return Ok(Err(refuse(FLOW_GONE)));
        };
        let flow = FlowRef {
            handle,
            device: cookie,
        };
        let mut l = match load(&mut tx, &flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(Err(gone(e))),
        };
        let ours = matches!(
            l.state.purpose,
            Purpose::EnrollTotp { session: s } | Purpose::RegisterPasskey { session: s }
                if s == session.id
        );
        if !ours {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        }
        let pending = match l.state.take_pending(MethodClass::EmailOtp, now) {
            Ok(p) => p,
            Err(FlowRejection::Expired) => {
                save(&mut tx, &l, "open", Resume::Keep).await?;
                tx.commit().await?;
                return Ok(Err(refuse(FLOW_GONE)));
            }
            Err(_) => return Ok(Err(refuse(STEP_NOT_ALLOWED))),
        };
        let Pending::EmailCode {
            digest,
            expires_ms,
            attempts_left,
        } = pending
        else {
            return Ok(Err(refuse(STEP_NOT_ALLOWED)));
        };
        let presented = code_digest(&l.row.flow_hash, code.trim());
        if !digest.is_some_and(|d| Secret::new(d).ct_eq_bytes(&presented)) {
            if attempts_left > 1 {
                l.state.pending = Some(Pending::EmailCode {
                    digest,
                    expires_ms,
                    attempts_left: attempts_left.saturating_sub(1),
                });
            }
            save(&mut tx, &l, "open", Resume::Keep).await?;
            tx.commit().await?;
            return Ok(Err(refuse(CODE_NOT_ACCEPTED)));
        }
        save(&mut tx, &l, "open", Resume::Keep).await?;
        let target = self.external(session.subject)?;
        audit(
            &mut tx,
            "credential.change.proved",
            &target,
            &target,
            correlation,
        )
        .await?;
        tx.commit().await?;
        Ok(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-147
    #[test]
    fn a_change_needs_a_fresh_sign_in_and_aal2_once_a_strong_method_exists() {
        let now = 10_000_000;
        let fresh = now - 60_000;
        let stale = now - STEP_UP_WINDOW_MS - 1;
        assert!(gate(Aal::Aal1, fresh, now, false, false));
        assert!(!gate(Aal::Aal1, stale, now, false, false));
        assert!(!gate(Aal::Aal1, fresh, now, true, false));
        assert!(gate(Aal::Aal2, fresh, now, true, false));
        assert!(!gate(Aal::Aal2, stale, now, true, false));
        assert!(!gate(Aal::Aal1, fresh, now, false, true));
        assert!(gate(Aal::Aal3, fresh, now, false, true));
    }
}
