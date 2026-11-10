//! `pam_access.so` (OP-156 m.3 (p), R-2): the PAM module of the Access Linux client. A sign-in
//! or `sudo` step-up is asked of `access-linuxd` and polled until it is decided; the person reads
//! the device code through the PAM conversation. When the daemon does not answer the module
//! answers `PAM_AUTHINFO_UNAVAIL`, never a success (fail-closed). Linux only; elsewhere the
//! library is empty.

#[cfg(target_os = "linux")]
pub mod linux;
