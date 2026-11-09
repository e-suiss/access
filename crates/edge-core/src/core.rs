//! The edge core over the channel: realm, subject, Claim and audit layers.

use access_internal_api::edge::{
    Audit, Audited, Call, GatewayUri, Hello, IssueClaim, Issued, Subject, SubjectLookup,
    hello_request,
};

use crate::channel::{Channel, ChannelError};
use crate::health::{Health, Outcome};

/// Why an edge request was not made or not answered.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EdgeError {
    /// The request names another realm than the gateway's (IDP-26).
    #[error("realm outside the gateway's scope")]
    Realm,
    /// The channel refused or failed.
    #[error(transparent)]
    Channel(#[from] ChannelError),
    /// access-server answered outside the contract.
    #[error("malformed answer")]
    Malformed,
}

/// A connected gateway's edge core.
#[derive(Debug)]
pub struct EdgeCore {
    channel: Channel,
    gateway: GatewayUri,
    realm: String,
    health: Health,
}

impl EdgeCore {
    /// Asks access-server who this gateway is (`hello`): its identity and its realm.
    ///
    /// # Errors
    /// [`EdgeError`].
    pub async fn connect(channel: Channel) -> Result<Self, EdgeError> {
        let health = Health::default();
        let answer = channel.call(Call::Hello, &hello_request()).await;
        let hello = Self::decoded(&health, Call::Hello, answer, Hello::decode)?;
        Ok(Self {
            channel,
            gateway: hello.gateway,
            realm: hello.realm,
            health,
        })
    }

    fn decoded<T, E>(
        health: &Health,
        call: Call,
        answer: Result<Vec<u8>, ChannelError>,
        decode: impl FnOnce(&[u8]) -> Result<T, E>,
    ) -> Result<T, EdgeError> {
        let outcome = match &answer {
            Ok(_) => Outcome::Ok,
            Err(ChannelError::Refused { .. }) => Outcome::Refused,
            Err(_) => Outcome::Failed,
        };
        health.call(call, outcome);
        decode(&answer?).map_err(|_| EdgeError::Malformed)
    }

    /// The gateway's identity.
    #[must_use]
    pub const fn gateway(&self) -> &GatewayUri {
        &self.gateway
    }

    /// The realm layer: the gateway's realm, or [`EdgeError::Realm`] when the protocol named
    /// another (IDP-26, §13.2).
    ///
    /// # Errors
    /// [`EdgeError::Realm`].
    pub fn realm(&self, asked: Option<&str>) -> Result<&str, EdgeError> {
        match asked {
            Some(r) if r != self.realm => Err(EdgeError::Realm),
            _ => Ok(&self.realm),
        }
    }

    /// The counters.
    #[must_use]
    pub const fn health(&self) -> &Health {
        &self.health
    }

    /// The subject layer: the active subject holding `identifier`, or `None`.
    ///
    /// # Errors
    /// [`EdgeError`].
    pub async fn subject(&self, identifier: &str) -> Result<Option<[u8; 16]>, EdgeError> {
        let body = SubjectLookup {
            realm: self.realm.clone(),
            identifier: String::from(identifier),
        }
        .encode();
        let answer = self.channel.call(Call::SubjectLookup, &body).await;
        Self::decoded(&self.health, Call::SubjectLookup, answer, Subject::decode).map(|s| s.subject)
    }

    /// The Claim layer: reports that `subject` authenticated with `method` at `auth_time`; the
    /// realm issuer makes the Claim. `realm` is the realm the protocol named, if any.
    ///
    /// # Errors
    /// [`EdgeError`]; [`EdgeError::Realm`] before anything is sent.
    pub async fn issue(
        &self,
        realm: Option<&str>,
        subject: [u8; 16],
        method: &str,
        auth_time: u64,
        evidence: Option<[u8; 32]>,
    ) -> Result<Issued, EdgeError> {
        let realm = String::from(self.realm(realm)?);
        let body = IssueClaim {
            realm,
            subject,
            method: String::from(method),
            auth_time,
            evidence,
        }
        .encode();
        let answer = self.channel.call(Call::IssueClaim, &body).await;
        Self::decoded(&self.health, Call::IssueClaim, answer, Issued::decode)
    }

    /// The audit layer: one event, codes only (OP-47).
    ///
    /// # Errors
    /// [`EdgeError`].
    pub async fn audit(
        &self,
        event: &str,
        outcome: &str,
        subject: Option<[u8; 16]>,
    ) -> Result<Audited, EdgeError> {
        let body = Audit {
            realm: self.realm.clone(),
            event: String::from(event),
            outcome: String::from(outcome),
            subject,
        }
        .encode();
        let answer = self.channel.call(Call::Audit, &body).await;
        Self::decoded(&self.health, Call::Audit, answer, Audited::decode)
    }

    /// A raw call, for the protocol lanes' calls (`authenticate`, `session_attest`,
    /// `directory_read`) until their bodies land; the answer is CBOR.
    ///
    /// # Errors
    /// [`EdgeError`].
    pub async fn raw(&self, call: Call, body: &[u8]) -> Result<Vec<u8>, EdgeError> {
        let answer = self.channel.call(call, body).await;
        Self::decoded(&self.health, call, answer, |b: &[u8]| {
            Ok::<_, ()>(b.to_vec())
        })
    }
}
