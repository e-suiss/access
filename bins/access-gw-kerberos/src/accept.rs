//! Accepting a Kerberos ticket with libgssapi (RFC 4121; §10.6.4, IDP-17, OP-155 m.3 (o)). The
//! parser worker has already read the token and the gateway has checked its SPN, enctype and key
//! version; libgssapi then decrypts the ticket with the in-memory keytab and names the client.
//! With a backend configured, the acceptor credential may also initiate, so that an accepted
//! forwardable ticket yields a proxy credential for `S4U2Proxy`.

use libgssapi::context::{CtxFlags, SecurityContext as _, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL, OidSet};

/// Why a ticket was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AcceptError {
    /// The acceptor credential could not be acquired; the gateway does not start.
    #[error("acceptor credential unavailable")]
    Credential,
    /// libgssapi refused the token (bad ticket, wrong key, replay, clock skew).
    #[error("ticket refused")]
    Refused,
    /// The exchange needs another leg, which HTTP Negotiate with Kerberos never does.
    #[error("context incomplete")]
    Incomplete,
}

/// One accepted ticket.
pub struct Accepted {
    /// The client principal, `user@REALM`.
    pub principal: String,
    /// libgssapi's AP-REP, when mutual authentication was asked for.
    pub ap_rep: Option<Vec<u8>>,
    /// The proxy credential for `S4U2Proxy`, when the ticket allows it.
    pub delegated: Option<Cred>,
}

impl core::fmt::Debug for Accepted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Accepted")
            .field("principal", &self.principal)
            .field("delegated", &self.delegated.is_some())
            .finish_non_exhaustive()
    }
}

/// The acceptor for the one configured SPN.
#[derive(Clone)]
pub struct Acceptor {
    cred: Cred,
}

impl core::fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Acceptor").finish_non_exhaustive()
    }
}

impl Acceptor {
    /// The acceptor credential of `spn` from the installed in-memory keytab; `initiate` when
    /// `S4U2Proxy` is configured.
    ///
    /// # Errors
    /// [`AcceptError::Credential`].
    pub fn new(spn: &str, initiate: bool) -> Result<Self, AcceptError> {
        let name = Name::new(spn.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))
            .and_then(|n| n.canonicalize(Some(GSS_MECH_KRB5)))
            .map_err(|_| AcceptError::Credential)?;
        let mechs = OidSet::singleton(GSS_MECH_KRB5).map_err(|_| AcceptError::Credential)?;
        let usage = if initiate {
            CredUsage::Both
        } else {
            CredUsage::Accept
        };
        let cred = Cred::acquire(Some(&name), None, usage, Some(&mechs))
            .map_err(|_| AcceptError::Credential)?;
        Ok(Self { cred })
    }

    /// Accepts the Kerberos initial context token `token`. Blocking: call it off the runtime.
    ///
    /// # Errors
    /// [`AcceptError`].
    pub fn accept(&self, token: &[u8]) -> Result<Accepted, AcceptError> {
        let mut ctx = ServerCtx::new(Some(self.cred.clone()));
        let out = ctx.step(token, None).map_err(|_| AcceptError::Refused)?;
        if !ctx.is_complete() {
            return Err(AcceptError::Incomplete);
        }
        let principal = ctx
            .source_name()
            .map_err(|_| AcceptError::Refused)?
            .to_string();
        let delegated = if ctx
            .flags()
            .is_ok_and(|f| f.contains(CtxFlags::GSS_C_DELEG_FLAG))
        {
            ctx.take_delegated_cred()
        } else {
            None
        };
        Ok(Accepted {
            principal,
            ap_rep: out.map(|b| b.to_vec()),
            delegated,
        })
    }
}
