//! The sign-in a proven registration opens (TN-80 step 8, OP-153 m.3 (g)): the returned code is
//! the e-mail factor of a login flow for the new account, which then completes like any other.
//! A realm that requires a second step leaves the flow at that step, with nothing enrolled yet.

use access_identity_account::notify::message::{Address, Body, Message, Notice};
use access_identity_webauthn::ports::{CredentialRegistry, SignalSink};
use access_store::sessions::NewFlow;

use super::{Auth, Loaded, Notifier, Step, decode32, encode, from_day, i64_of, partition};
use crate::SessionError;
use crate::domain::assurance::{Factor, MethodClass};
use crate::domain::flow::{FlowState, Purpose, device_digest, handle_digest};
use crate::domain::session::{FLOW_COOKIE, set_cookie};
use crate::ports::{Clock, Random, SessionDb, SessionTx};

/// A login flow opened by a proven registration.
#[derive(Debug)]
pub struct Opened {
    /// The flow handle.
    pub handle: String,
    /// The flow cookie's value.
    pub device: String,
    /// The flow cookie's `Set-Cookie` when the browser had none.
    pub set_cookie: Option<String>,
    /// Where the flow stands.
    pub step: Step,
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
    /// Opens the login flow of `subject`, whose address was just proven by a code at
    /// `proven_ms`, in the browser that proved it (TN-102 rule 2).
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn registered(
        &self,
        subject: [u8; 16],
        proven_ms: u64,
        device: Option<&str>,
        correlation: &str,
    ) -> Result<Opened, SessionError> {
        self.open_with(
            subject,
            Factor::email(MethodClass::EmailOtp, proven_ms),
            device,
            correlation,
        )
        .await
    }

    /// Opens the login flow of `subject` whose social or upstream provider's assertion was
    /// checked at `proven_ms` (IDP-31, OP-153 m.3 (l)); it completes like any other first step.
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn federated(
        &self,
        subject: [u8; 16],
        proven_ms: u64,
        device: Option<&str>,
        correlation: &str,
    ) -> Result<Opened, SessionError> {
        self.open_with(subject, Factor::federated(proven_ms), device, correlation)
            .await
    }

    /// Opens the login flow of `subject` who presented a client certificate on the mTLS
    /// listener, checked by the caller: path, CA Acceptance, revocation and mapping (OP-155
    /// m.3 (m)); `factor` is [`Factor::certificate`].
    ///
    /// # Errors
    /// [`SessionError`].
    pub async fn certificate(
        &self,
        subject: [u8; 16],
        factor: Factor,
        device: Option<&str>,
        correlation: &str,
    ) -> Result<Opened, SessionError> {
        if factor.certificate.is_none() {
            return Err(SessionError::Corrupt);
        }
        self.open_with(subject, factor, device, correlation).await
    }

    async fn open_with(
        &self,
        subject: [u8; 16],
        factor: Factor,
        device: Option<&str>,
        correlation: &str,
    ) -> Result<Opened, SessionError> {
        let now = self.now();
        let mut state = FlowState::new(Purpose::Login, now);
        if state.record(subject, factor).is_err() {
            return Err(SessionError::Corrupt);
        }
        let handle = self.random32()?;
        let (device, fresh) = match device.and_then(decode32) {
            Some(d) => (d, false),
            None => (self.random32()?, true),
        };
        let encoded = state.encode().map_err(|_| SessionError::Corrupt)?;
        let mut tx = self.begin().await?;
        tx.insert_flow(&NewFlow {
            day: partition(now)?,
            flow_hash: &handle_digest(&handle),
            device_hash: &device_digest(&device),
            resume_hash: None,
            expires_ms: i64_of(state.expires_ms)?,
            state: &encoded,
        })
        .await?;
        let row = tx
            .flow(from_day(now), &handle_digest(&handle))
            .await?
            .ok_or(SessionError::Corrupt)?;
        let step = self
            .advance(tx, Loaded { row, state }, now, correlation)
            .await?;
        let device = encode(&device);
        Ok(Opened {
            handle: encode(&handle),
            set_cookie: fresh.then(|| set_cookie(FLOW_COOKIE, &device, None)),
            device,
            step,
        })
    }

    /// Queues `notice` to the account's own address, with its mailbox proof time (E42, §8.15.2,
    /// OP-153 m.3 (i)); an account with no address gets nothing.
    ///
    /// # Errors
    /// [`SessionError`].
    pub(crate) async fn account_notice(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        notice: Notice,
        at_ms: u64,
    ) -> Result<(), SessionError> {
        self.account_message(
            tx,
            subject,
            Body::Notice {
                notice,
                at_ms,
                until_ms: None,
            },
        )
        .await
    }

    /// Queues `body` to the account's own address, as [`Self::account_notice`] does.
    ///
    /// # Errors
    /// [`SessionError`].
    pub(crate) async fn account_message(
        &self,
        tx: &mut D::Tx,
        subject: [u8; 16],
        body: Body,
    ) -> Result<(), SessionError> {
        let to = match tx.contact(subject).await? {
            Some((kind, value)) if kind == "email" => Address::Email(value),
            Some((kind, value)) if kind == "phone" => Address::Phone(value),
            _ => return Ok(()),
        };
        let valid_since_ms = match to {
            Address::Email(_) => Some(tx.mailbox_since(subject).await?.unwrap_or(1)),
            Address::Phone(_) => None,
        };
        tx.notify(
            self.notifier,
            &Message {
                subject,
                to,
                locale: None,
                valid_since_ms,
                body,
            },
        )
        .await
    }
}
