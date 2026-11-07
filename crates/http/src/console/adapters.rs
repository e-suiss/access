//! The fail-closed adapters a process serves until the real ones are wired: no sign-in
//! completes, no session is found, no read token is issued, no device registers, nothing is
//! passed upstream, and no `GeoResolver` source answers.

use std::future::{Future, ready};
use std::net::IpAddr;

use access_identity_session::domain::console::BindingPolicy;
use axum::body::Bytes;

use super::ports::{
    ConsoleSession, ConsoleSessions, DeviceAnswer, Devices, Forward, Forwarded, IssuedRead,
    Network, NewConsoleSession, Profiles, ReadGrants, SessionInstance, SessionSummary, SignIn,
    SignedIn, Unavailable, Upstream,
};

/// No sign-in hand-off: every start is unavailable.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSignIn;

impl SignIn for NoSignIn {
    fn start(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send {
        ready(Err(Unavailable))
    }

    fn finish(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> impl Future<Output = Result<Option<SignedIn>, Unavailable>> + Send {
        ready(Err(Unavailable))
    }
}

/// No session store: no cookie finds a session, and none opens.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSessions;

impl ConsoleSessions for NoSessions {
    fn open(
        &self,
        _: NewConsoleSession,
    ) -> impl Future<Output = Result<[u8; 16], Unavailable>> + Send {
        ready(Err(Unavailable))
    }

    fn find(
        &self,
        _: [u8; 32],
    ) -> impl Future<Output = Result<Option<ConsoleSession>, Unavailable>> + Send {
        ready(Ok(None))
    }

    fn touch(&self, _: [u8; 16], _: u64) -> impl Future<Output = Result<(), Unavailable>> + Send {
        ready(Err(Unavailable))
    }

    fn end(&self, _: [u8; 16], _: u64) -> impl Future<Output = Result<(), Unavailable>> + Send {
        ready(Err(Unavailable))
    }

    fn attach(
        &self,
        _: [u8; 16],
        _: SessionInstance,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send {
        ready(Err(Unavailable))
    }

    fn list(
        &self,
        _: &ConsoleSession,
    ) -> impl Future<Output = Result<Vec<SessionSummary>, Unavailable>> + Send {
        ready(Err(Unavailable))
    }

    fn revoke(
        &self,
        _: &ConsoleSession,
        _: [u8; 16],
        _: u64,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send {
        ready(Err(Unavailable))
    }
}

/// No `GeoResolver` source (OP-151 m.1 (b)): sessions bind to the client's prefix; realms set
/// no full address binding.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrefixOnly;

impl Network for PrefixOnly {
    fn asn(&self, _: IpAddr) -> Option<u32> {
        None
    }

    fn policy(&self, _: &str) -> impl Future<Output = Result<BindingPolicy, Unavailable>> + Send {
        ready(Ok(BindingPolicy::default()))
    }
}

/// No profile source.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoProfiles;

impl Profiles for NoProfiles {
    fn profile(
        &self,
        _: &ConsoleSession,
    ) -> impl Future<Output = Result<Option<serde_json::Value>, Unavailable>> + Send {
        ready(Err(Unavailable))
    }
}

/// No device registration.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDevices;

impl Devices for NoDevices {
    fn challenge(
        &self,
        _: &ConsoleSession,
        _: Bytes,
    ) -> impl Future<Output = Result<DeviceAnswer, Unavailable>> + Send {
        ready(Err(Unavailable))
    }

    fn register(
        &self,
        _: &ConsoleSession,
        _: Bytes,
    ) -> impl Future<Output = Result<DeviceAnswer, Unavailable>> + Send {
        ready(Err(Unavailable))
    }
}

/// No read token is issued.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoReadGrants;

impl ReadGrants for NoReadGrants {
    fn issue(
        &self,
        _: &ConsoleSession,
        _: &SessionInstance,
        _: [u8; 32],
    ) -> impl Future<Output = Result<Option<IssuedRead>, Unavailable>> + Send {
        ready(Ok(None))
    }
}

/// Nothing upstream.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoUpstream;

impl Upstream for NoUpstream {
    fn admin(&self, _: Forward) -> impl Future<Output = Result<Forwarded, Unavailable>> + Send {
        ready(Err(Unavailable))
    }

    fn adp(&self, _: Forward) -> impl Future<Output = Result<Forwarded, Unavailable>> + Send {
        ready(Err(Unavailable))
    }
}
