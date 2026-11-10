//! `libnss_access.so.2` (OP-156 m.3 (p), R-2): the NSS module of the Access Linux client. Each
//! lookup is one request to `access-linuxd`; when the daemon does not answer the module says
//! `NSS_STATUS_UNAVAIL`, so no user resolves through it (fail-closed). Linux only; elsewhere the
//! library is empty.

#[cfg(target_os = "linux")]
pub mod linux;
