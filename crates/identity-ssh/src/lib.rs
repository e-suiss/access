//! The realm's SSH user certificate authority (IDP-32, OP-156 m.3 (o)), free of I/O except
//! through [`ports`] (OP-63).
//!
//! - [`domain::cert`]: our own encoder of `ssh-ed25519-cert-v01@openssh.com` user certificates.
//! - [`domain::krl`]: the OpenSSH key revocation list the realm publishes.
//! - [`domain::key`]: Ed25519 keys in OpenSSH form, the CA's `authorized_keys` line.
//! - [`domain::schema`]: the `ssh.login` action, its catalog and the server group resources.
//! - [`domain::projection`]: a certificate as a projection of an `ssh.login` Grant, its
//!   lifetimes, and the `ssh-cert.cddl` record.
//! - [`app`]: a certificate for an allowed projection, signed by the realm's CA key.

pub mod app;
pub mod domain;
pub mod ports;

/// Why a certificate or a list is refused; a decision, not an infrastructure error (OP-64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SshError {
    /// Not well-formed SSH wire data or `ssh-cert.cddl` record.
    #[error("malformed")]
    Malformed,
    /// A field is larger than allowed.
    #[error("too large")]
    TooLarge,
    /// The certificate fields are outside the encoder's limits.
    #[error("certificate fields")]
    Fields,
    /// A principal the Grant does not name, or a Grant that names none.
    #[error("principal not granted")]
    NoPrincipal,
    /// A `force-command` or `source-address` that is not the Grant's.
    #[error("constraint not the grant's")]
    Constraint,
    /// An extension the Grant does not permit.
    #[error("extension not granted")]
    Extension,
    /// A lifetime past the holder's ceiling, the Grant or the horizon.
    #[error("lifetime")]
    Lifetime,
    /// Not an `ssh.login` on one server group the Grant covers.
    #[error("not granted")]
    NotGranted,
}

impl SshError {
    /// The stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Malformed => "ssh-malformed",
            Self::TooLarge => "ssh-too-large",
            Self::Fields => "ssh-fields",
            Self::NoPrincipal => "ssh-principal-not-granted",
            Self::Constraint => "ssh-constraint-not-granted",
            Self::Extension => "ssh-extension-not-granted",
            Self::Lifetime => "ssh-lifetime",
            Self::NotGranted => "ssh-not-granted",
        }
    }
}
