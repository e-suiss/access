//! Fail-closed stub for targets without the SA-22 lockdown. Every entry point returns
//! [`Error::Unsupported`]; nothing pretends to be sandboxed.

use core::num::NonZeroUsize;

use crate::{Error, Lockdown, Locked};

/// Placeholder: no phase 2 exists without a phase 1.
#[derive(Debug)]
pub(crate) struct Phase2;

pub(crate) fn apply(lockdown: &Lockdown) -> Result<Locked, Error> {
    let _ = (
        lockdown.landlock_abi,
        &lockdown.read_only,
        &lockdown.read_write,
        &lockdown.tcp_connect,
        &lockdown.tcp_bind,
        lockdown.run_as,
    );
    Err(Error::Unsupported)
}

pub(crate) fn narrow(_phase2: &Phase2) -> Result<(), Error> {
    Err(Error::Unsupported)
}

/// Placeholder: cannot be constructed off Linux.
pub(crate) struct SecretMemory(core::convert::Infallible);

impl SecretMemory {
    pub(crate) fn new(_len: NonZeroUsize) -> Result<Self, Error> {
        Err(Error::Unsupported)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        match self.0 {}
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        match self.0 {}
    }
}
