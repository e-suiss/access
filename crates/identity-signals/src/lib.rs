//! Signal sources of the identity plane (OP-156 m.3 (r), E38, CI-2, IDP-34, IDP-39, TN-46,
//! TN-135): external KYC, MDM, risk and DLP issuers.
//!
//! - [`domain::source`]: `idp.signal.source_register` and `source_retire`.
//! - [`domain::vendor`]: Intune, Jamf, Onfido and Persona answers as signal bodies.
//! - [`domain::mapping`]: the mapping the SSF receiver, Claim Ingest and the call point share.
//! - [`domain::effect`]: the closed, narrowing set of what a risk level may do.
//! - [`domain::statement`]: "Compliant per *provider* (statement)".
//! - [`domain::boundary`]: the proofing Access never does itself.
//! - [`app`]: a vendor answer relayed as the source's own Claim through the [`ports::Issuer`].
//!
//! The bodies themselves are [`access_internal_api::signals`], which the authority plane reads.

pub mod app;
pub mod domain;
pub mod ports;
