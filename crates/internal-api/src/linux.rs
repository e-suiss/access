//! The authority read of the Linux client (OP-156 m.3 (p), IDP-32): who holds a live Grant that
//! covers `ssh.login` on a server group, by name, which decides who the group's hosts resolve
//! through NSS. Derived; it records nothing.

use std::future::Future;

use access_kernel::digest::Digest;
use access_kernel::model::{ActionRef, CanonicalAuthority, Id, ResourceRef};

use crate::idp::Unavailable;

/// One live Grant held by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The Party that holds it.
    pub party: Id,
    /// The Grant's canonical authority.
    pub authority: CanonicalAuthority,
}

/// The Linux client's read (CMP-7).
pub trait LinuxGrants: Send + Sync {
    /// The live Grants in `domain` held by a named Party whose actions cover `action` on
    /// `resource`, at most `limit`. Rule-shaped and public holders are not listed.
    fn members(
        &self,
        domain: Digest,
        action: ActionRef,
        resource: ResourceRef,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Member>, Unavailable>> + Send;
}
