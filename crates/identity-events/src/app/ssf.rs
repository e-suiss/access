//! The SSF transmitter's HTTP surface without HTTP (SSF 1.0 §7, §8; RFC 8936): the realm the
//! request reached, the transmitter metadata, a stream read, update or disable by its bearer
//! credential, and poll.

use access_identity_oauth::app::resolve;
use access_identity_oauth::domain::metadata::JWKS_PATH;
use access_identity_oauth::ports::{Directory, RealmEntry};
use serde_json::Value;

use crate::app::streams::{StreamError, Streams};
use crate::domain::stream::ssf_configuration;
use crate::ports::{Clock, Random, Sealer, TokenSigner};

/// What the HTTP layer answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SsfReply {
    /// `200` with a JSON body.
    Json(Value),
    /// `204`.
    NoContent,
    /// An RFC 9457 problem: status and stable code.
    Problem(u16, &'static str),
}

impl From<StreamError> for SsfReply {
    fn from(e: StreamError) -> Self {
        let (status, code) = e.problem();
        Self::Problem(status, code)
    }
}

/// How a stream is managed by its own credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamCall<'a> {
    /// `GET`.
    Read,
    /// `PATCH` with the new `events_requested`, `status` and `description`.
    Update(&'a [u8]),
    /// `DELETE`: disables it.
    Disable,
}

/// The transmitter of every realm.
pub struct Transmitter<D, K, R, S, C> {
    directory: D,
    streams: Streams<K, R>,
    signer: S,
    clock: C,
}

const NOT_FOUND: SsfReply = SsfReply::Problem(404, "not-found");
const UNAVAILABLE: SsfReply = SsfReply::Problem(503, "temporarily-unavailable");
const UNAUTHORIZED: SsfReply = SsfReply::Problem(401, "invalid-token");

impl<D, K, R, S, C> Transmitter<D, K, R, S, C>
where
    D: Directory,
    K: Sealer,
    R: Random,
    S: TokenSigner,
    C: Clock,
{
    /// A transmitter over its services.
    pub const fn new(directory: D, streams: Streams<K, R>, signer: S, clock: C) -> Self {
        Self {
            directory,
            streams,
            signer,
            clock,
        }
    }

    async fn realm(&self, authority: &str, slug: Option<&str>) -> Result<RealmEntry, SsfReply> {
        match resolve(&self.directory, authority, slug).await {
            Ok(Some(r)) => Ok(r),
            Ok(None) => Err(NOT_FOUND),
            Err(_) => Err(UNAVAILABLE),
        }
    }

    /// `/.well-known/ssf-configuration` of the realm the request reached.
    pub async fn configuration(&self, authority: &str, slug: Option<&str>) -> SsfReply {
        match self.realm(authority, slug).await {
            Ok(r) => SsfReply::Json(ssf_configuration(
                r.issuer.as_str(),
                &r.issuer.endpoint(JWKS_PATH),
            )),
            Err(e) => e,
        }
    }

    /// `/ssf/streams` by the stream's bearer credential (RFC 6750).
    pub async fn stream(
        &self,
        authority: &str,
        slug: Option<&str>,
        bearer: Option<&str>,
        call: StreamCall<'_>,
    ) -> SsfReply {
        let r = match self.realm(authority, slug).await {
            Ok(r) => r,
            Err(e) => return e,
        };
        let Some(token) = bearer else {
            return UNAUTHORIZED;
        };
        let s = match self.streams.by_token(r.tenant, r.realm, token).await {
            Ok(s) => s,
            Err(StreamError::NotFound) => return UNAUTHORIZED,
            Err(e) => return e.into(),
        };
        let done = match call {
            StreamCall::Read => self.streams.get(r.tenant, r.realm, s.id).await,
            StreamCall::Update(body) => self.streams.update(r.tenant, r.realm, s.id, body).await,
            StreamCall::Disable => {
                return match self.streams.disable(r.tenant, r.realm, s.id).await {
                    Ok(()) => SsfReply::NoContent,
                    Err(e) => e.into(),
                };
            }
        };
        done.map_or_else(SsfReply::from, SsfReply::Json)
    }

    /// `/ssf/poll` (RFC 8936).
    pub async fn poll(
        &self,
        authority: &str,
        slug: Option<&str>,
        bearer: Option<&str>,
        body: &[u8],
    ) -> SsfReply {
        let r = match self.realm(authority, slug).await {
            Ok(r) => r,
            Err(e) => return e,
        };
        let Some(token) = bearer else {
            return UNAUTHORIZED;
        };
        match self
            .streams
            .poll(&self.signer, &self.clock, r.tenant, r.realm, token, body)
            .await
        {
            Ok(v) => SsfReply::Json(v),
            Err(StreamError::NotFound) => UNAUTHORIZED,
            Err(e) => e.into(),
        }
    }
}
