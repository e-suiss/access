//! The restricted SMS one-time code (OP-156 m.3 (f), §10.2.2, IDP-4, IDP-9): off unless the realm
//! decided `idp.realm.sms_otp`; a second step only, AAL2 at best and never a Consequence Tier.
//! The code is 6 digits, lives 5 minutes, takes 3 tries and is used once; Relay carries it to the
//! account's phone number only (`Address::Phone`). A line whose SIM changed in the last 90 days
//! takes no code; under the TR payment profile a line without a SIM signal checked in the last
//! 24 hours takes none, and a code is never a sign-in step, only an activation one.

use access_crypto::Secret;
use access_identity_account::notify::message::{Address, Body, Message, OtpPurpose};
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::payment::NewSmsCode;
use suiss_crypto::digest::sha256;

use super::signin::ANONYMOUS;
use super::{
    Auth, CODE_NOT_ACCEPTED, FlowRef, Notifier, STEP_NOT_ALLOWED, Step, audit, gone, load, neutral,
    refuse,
};
use crate::SessionError;
use crate::domain::assurance::Factor;
use crate::domain::payment::{
    CODE_TTL_MS, MAX_SENDS, SEND_WINDOW_MS, SimRefusal, SimSignals, SmsPurpose, code_digest,
    code_of, sim_rule, well_formed,
};
use crate::ports::{Clock, PaymentTx as _, Random, SessionDb, SessionTx as _};
use access_identity_account::ports::AccountTx as _;

const ACTIVATION_CONTEXT: &[u8] = b"access/sms-activation/v1\0";

/// The binding of an activation code: the digest of the session it was sent for.
#[must_use]
pub fn activation_binding(session: &[u8; 16]) -> [u8; 32] {
    let mut m = ACTIVATION_CONTEXT.to_vec();
    m.extend_from_slice(session);
    sha256(&m)
}

/// The outcome of sending a code. A decision, not an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SmsStart {
    /// Sent to the number ending in these digits.
    Sent {
        /// The last two digits of the number.
        last_digits: String,
        /// Unix ms.
        expires_ms: u64,
    },
    /// The line takes no code now.
    Refused(SimRefusal),
    /// Too many codes in the last hour.
    Held {
        /// Whole seconds.
        retry_after_s: u64,
    },
    /// Refused or gone.
    Step(Step),
}

/// The outcome of an activation code. A decision, not an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activation {
    /// The code matched and is used.
    Proven,
    /// The code did not match, ran out of tries or expired.
    NotAccepted,
    /// The line takes no code now.
    Refused(SimRefusal),
}

fn last_digits(phone: &str) -> String {
    let digits: Vec<char> = phone.chars().filter(char::is_ascii_digit).collect();
    digits
        .get(digits.len().saturating_sub(2)..)
        .unwrap_or_default()
        .iter()
        .collect()
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
    fn sms_code_now(&self) -> Result<String, SessionError> {
        loop {
            let mut b = [0_u8; 4];
            self.random.fill(&mut b)?;
            if let Some(c) = code_of(b) {
                return Ok(c);
            }
        }
    }

    /// IDP-9, OP-156 m.3 (f): the SIM rule for `subject` now.
    async fn sim_ok(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        now: u64,
    ) -> Result<Result<(), SimRefusal>, SessionError> {
        let signals = tx
            .sim_signals(subject)
            .await?
            .map(|(last_change_ms, checked_ms)| SimSignals {
                last_change_ms,
                checked_ms,
            });
        Ok(sim_rule(signals, self.policy.profile, now))
    }

    /// Sends a code to `subject`'s phone, bound to `binding`, after the profile, SIM and
    /// sending limits; the caller commits.
    async fn send_code(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        purpose: SmsPurpose,
        binding: &[u8; 32],
        correlation: &str,
    ) -> Result<SmsStart, SessionError> {
        let now = self.now();
        let target = self.external(subject)?;
        // OP-156 m.3 (f)
        if !self.policy.sms || !purpose.allowed_in(self.policy.profile) {
            return Ok(SmsStart::Step(refuse(STEP_NOT_ALLOWED)));
        }
        let Some(phone) = tx.sms_line(subject).await? else {
            return Ok(SmsStart::Step(refuse(STEP_NOT_ALLOWED)));
        };
        // IDP-9, Ek B 5124
        if let Err(why) = self.sim_ok(tx, subject, now).await? {
            audit(tx, "sms.refused", ANONYMOUS, &target, correlation).await?;
            return Ok(SmsStart::Refused(why));
        }
        if tx
            .sms_codes_since(subject, now.saturating_sub(SEND_WINDOW_MS))
            .await?
            >= MAX_SENDS
        {
            return Ok(SmsStart::Held {
                retry_after_s: SEND_WINDOW_MS / 1000,
            });
        }
        let code = self.sms_code_now()?;
        let expires_ms = now.saturating_add(CODE_TTL_MS);
        tx.insert_sms_code(&NewSmsCode {
            subject,
            purpose: purpose.name(),
            binding,
            code_hash: &code_digest(binding, &code),
            created_ms: now,
            expires_ms,
        })
        .await?;
        tx.notify(
            self.notifier,
            &Message {
                subject,
                to: Address::Phone(phone.clone()),
                locale: None,
                valid_since_ms: None,
                body: Body::SmsOtp {
                    code: Secret::new(code),
                    purpose: match purpose {
                        SmsPurpose::SignIn => OtpPurpose::SignIn,
                        SmsPurpose::Activation => OtpPurpose::VerifyAddress,
                    },
                    expires_at_ms: expires_ms,
                },
            },
        )
        .await?;
        audit(tx, "sms.code_sent", ANONYMOUS, &target, correlation).await?;
        Ok(SmsStart::Sent {
            last_digits: last_digits(&phone),
            expires_ms,
        })
    }

    /// Checks `typed` against the newest code bound to `binding`: one try counted, used once on a
    /// match, refused after three tries, after five minutes or for a line the SIM rule refuses.
    async fn check_code(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        purpose: SmsPurpose,
        binding: &[u8; 32],
        typed: &str,
    ) -> Result<Activation, SessionError> {
        let now = self.now();
        if let Err(why) = self.sim_ok(tx, subject, now).await? {
            return Ok(Activation::Refused(why));
        }
        let Some(row) = tx.sms_code(binding, purpose.name()).await? else {
            return Ok(Activation::NotAccepted);
        };
        if row.subject != subject || row.used_ms.is_some() || now >= row.expires_ms {
            return Ok(Activation::NotAccepted);
        }
        let typed = typed.trim();
        let matched = well_formed(typed) && code_digest(binding, typed) == row.code_hash;
        if !tx.try_sms_code(row.id, matched.then_some(now)).await? || !matched {
            return Ok(Activation::NotAccepted);
        }
        Ok(Activation::Proven)
    }

    /// Sends a code for the flow's second step (OP-156 m.3 (f)): only in a realm that offers SMS
    /// at sign-in, after the first step, to an account with a phone number.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn send_sms(
        &self,
        flow: &FlowRef<'_>,
        correlation: &str,
    ) -> Result<SmsStart, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(SmsStart::Step(gone(e))),
        };
        let Some(subject) = l.state.subject.filter(|_| l.state.first_done()) else {
            return Ok(SmsStart::Step(refuse(STEP_NOT_ALLOWED)));
        };
        let out = self
            .send_code(
                &mut tx,
                subject,
                SmsPurpose::SignIn,
                &l.row.flow_hash,
                correlation,
            )
            .await?;
        tx.commit().await?;
        Ok(out)
    }

    /// The SMS step: the code sent for this flow completes its second step once.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn sms(
        &self,
        flow: &FlowRef<'_>,
        typed: &str,
        correlation: &str,
    ) -> Result<Step, SessionError> {
        let now = self.now();
        let mut tx = self.begin().await?;
        let mut l = match load(&mut tx, flow, now).await? {
            Ok(l) => l,
            Err(e) => return Ok(gone(e)),
        };
        let Some(subject) = l.state.subject.filter(|_| l.state.first_done()) else {
            return Ok(neutral(0));
        };
        if !self.policy.sms || !SmsPurpose::SignIn.allowed_in(self.policy.profile) {
            return Ok(refuse(STEP_NOT_ALLOWED));
        }
        let key = self.factor_key(subject, "sms");
        let gate = match self.factor_gate(&mut tx, &key, now).await? {
            Ok(s) => s,
            Err(step) => {
                tx.commit().await?;
                return Ok(step);
            }
        };
        let binding = l.row.flow_hash;
        let checked = self
            .check_code(&mut tx, subject, SmsPurpose::SignIn, &binding, typed)
            .await?;
        self.factor_counted(&mut tx, &key, &gate, checked == Activation::Proven, now)
            .await?;
        let target = self.external(subject)?;
        match checked {
            Activation::Proven => {}
            Activation::Refused(_) => {
                audit(&mut tx, "sms.refused", ANONYMOUS, &target, correlation).await?;
                tx.commit().await?;
                return Ok(refuse(STEP_NOT_ALLOWED));
            }
            Activation::NotAccepted => {
                audit(&mut tx, "login.sms.failed", ANONYMOUS, &target, correlation).await?;
                tx.commit().await?;
                return Ok(refuse(CODE_NOT_ACCEPTED));
            }
        }
        audit(
            &mut tx,
            "login.sms.succeeded",
            ANONYMOUS,
            &target,
            correlation,
        )
        .await?;
        if l.state.record(subject, Factor::sms(now)).is_err() {
            tx.commit().await?;
            return Ok(refuse(STEP_NOT_ALLOWED));
        }
        self.advance(tx, l, now, correlation).await
    }

    /// Sends an activation code to the signed-in `subject` for `session` (OP-156 m.3 (f)): the
    /// only SMS use the TR payment profile allows.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn send_activation_sms(
        &self,
        subject: [u8; 16],
        session: &[u8; 16],
        correlation: &str,
    ) -> Result<SmsStart, SessionError> {
        let mut tx = self.begin().await?;
        let out = self
            .send_code(
                &mut tx,
                subject,
                SmsPurpose::Activation,
                &activation_binding(session),
                correlation,
            )
            .await?;
        tx.commit().await?;
        Ok(out)
    }

    /// Checks and uses an activation code of `subject` for `session`.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn activation_sms(
        &self,
        subject: [u8; 16],
        session: &[u8; 16],
        typed: &str,
        correlation: &str,
    ) -> Result<Activation, SessionError> {
        let mut tx = self.begin().await?;
        let out = if self.policy.sms {
            self.check_code(
                &mut tx,
                subject,
                SmsPurpose::Activation,
                &activation_binding(session),
                typed,
            )
            .await?
        } else {
            Activation::NotAccepted
        };
        if let Activation::Refused(_) = out {
            let target = self.external(subject)?;
            audit(&mut tx, "sms.refused", ANONYMOUS, &target, correlation).await?;
        }
        tx.commit().await?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-156 m.3 (f)
    #[test]
    fn the_page_names_only_the_last_two_digits() {
        assert_eq!(last_digits("+90 532 123 45 67"), "67");
        assert_eq!(last_digits("7"), "7");
        assert_eq!(activation_binding(&[1; 16]), activation_binding(&[1; 16]));
        assert_ne!(activation_binding(&[1; 16]), activation_binding(&[2; 16]));
    }
}
