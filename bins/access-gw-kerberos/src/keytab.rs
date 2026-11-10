//! The keytab (§10.6.4, OP-155 m.3 (o)): read once from the operator's secret store straight into
//! `memfd_secret` memory, before the lockdown, and handed to libkrb5 as an in-memory keytab
//! (`MEMORY:`) that the acceptor uses. It is never written to a file: there is no `FILE:` keytab
//! and no temporary copy.

use std::io::Read as _;
use std::num::NonZeroUsize;
use std::path::Path;

use access_edge_core::keytab::{self, Entry, MAX_KEYTAB};
use suiss_sandbox::SecretMemory;

/// The in-memory keytab's name in libkrb5.
pub const MEMORY_KEYTAB: &str = "MEMORY:access-gw-kerberos";

/// Why the keytab could not be installed; the gateway does not start.
#[derive(Debug, thiserror::Error)]
pub enum KeytabError {
    /// The file could not be read, or is larger than allowed.
    #[error("keytab: {0}")]
    Read(String),
    /// `memfd_secret` memory is not available; there is no fallback to ordinary memory.
    #[error("keytab: secret memory unavailable: {0}")]
    Secret(suiss_sandbox::Error),
    /// The keytab is malformed or holds no AES256 key of the SPN.
    #[error("keytab: {0}")]
    Format(#[from] keytab::KeytabError),
    /// libkrb5 refused the in-memory keytab.
    #[error("keytab: libkrb5 error {0}")]
    Krb5(i32),
}

/// The installed keytab: its secret memory, the key versions it holds, and libkrb5's handle,
/// which stays open for the life of the process (closing the last handle destroys a `MEMORY:`
/// keytab).
pub struct Installed {
    memory: SecretMemory,
    /// The key versions of the SPN's AES256 keys.
    pub kvnos: Vec<u32>,
    _handle: krb5::Handle,
}

impl core::fmt::Debug for Installed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Installed")
            .field("kvnos", &self.kvnos)
            .finish_non_exhaustive()
    }
}

impl Installed {
    /// Whether the keytab's bytes live in `memfd_secret` memory (always, once installed).
    #[must_use]
    pub fn in_secret_memory(&self) -> bool {
        !self.memory.is_empty()
    }
}

/// Reads the keytab at `path` into secret memory, keeps the AES256 keys of `spn`, and installs
/// them as libkrb5's acceptor keytab.
///
/// # Errors
/// [`KeytabError`].
pub fn install(path: &Path, spn: &str) -> Result<Installed, KeytabError> {
    let mut file = std::fs::File::open(path).map_err(|e| KeytabError::Read(e.to_string()))?;
    let len = file
        .metadata()
        .map_err(|e| KeytabError::Read(e.to_string()))?
        .len();
    let len = usize::try_from(len)
        .ok()
        .filter(|n| *n <= MAX_KEYTAB)
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| KeytabError::Read(String::from("size out of range")))?;
    let mut memory = SecretMemory::new(len).map_err(KeytabError::Secret)?;
    file.read_exact(memory.as_mut_slice())
        .map_err(|e| KeytabError::Read(e.to_string()))?;
    let entries = keytab::read(memory.as_slice(), spn)?;
    let handle = krb5::install(memory.as_slice(), &entries)?;
    let mut kvnos: Vec<u32> = entries.iter().map(|e| e.kvno).collect();
    kvnos.sort_unstable();
    kvnos.dedup();
    Ok(Installed {
        memory,
        kvnos,
        _handle: handle,
    })
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "the libkrb5 C FFI, which links into this process only (§14.5)"
)]
mod krb5 {
    //! The four libkrb5 calls a `MEMORY:` keytab needs (MIT krb5 public ABI).

    use core::ffi::{c_char, c_void};
    use std::ffi::CString;

    use super::{Entry, KeytabError, MEMORY_KEYTAB};

    #[repr(C)]
    struct Keyblock {
        magic: i32,
        enctype: i32,
        length: u32,
        contents: *mut u8,
    }

    #[repr(C)]
    struct KeytabEntry {
        magic: i32,
        principal: *mut c_void,
        timestamp: i32,
        vno: u32,
        key: Keyblock,
    }

    // SAFETY: MIT krb5's public declarations (krb5.h); every call site upholds their contracts.
    #[link(name = "krb5")]
    unsafe extern "C" {
        fn krb5_init_context(context: *mut *mut c_void) -> i32;
        fn krb5_parse_name(context: *mut c_void, name: *const c_char, out: *mut *mut c_void)
        -> i32;
        fn krb5_free_principal(context: *mut c_void, principal: *mut c_void);
        fn krb5_kt_resolve(context: *mut c_void, name: *const c_char, out: *mut *mut c_void)
        -> i32;
        fn krb5_kt_add_entry(
            context: *mut c_void,
            keytab: *mut c_void,
            entry: *mut KeytabEntry,
        ) -> i32;
    }

    // SAFETY: MIT krb5's public declaration (gssapi_krb5.h).
    #[link(name = "gssapi_krb5")]
    unsafe extern "C" {
        fn krb5_gss_register_acceptor_identity(name: *const c_char) -> u32;
    }

    /// libkrb5's context and the open `MEMORY:` keytab; never closed.
    pub(super) struct Handle {
        _context: *mut c_void,
        _keytab: *mut c_void,
    }

    pub(super) fn install(buf: &[u8], entries: &[Entry]) -> Result<Handle, KeytabError> {
        let name = CString::new(MEMORY_KEYTAB).map_err(|_| KeytabError::Krb5(-1))?;
        let mut context: *mut c_void = core::ptr::null_mut();
        // SAFETY: `krb5_init_context` writes a new context to the valid out-pointer.
        let rc = unsafe { krb5_init_context(&raw mut context) };
        if rc != 0 {
            return Err(KeytabError::Krb5(rc));
        }
        let mut keytab: *mut c_void = core::ptr::null_mut();
        // SAFETY: `context` is live; `name` is a NUL-terminated string that outlives the call.
        let rc = unsafe { krb5_kt_resolve(context, name.as_ptr(), &raw mut keytab) };
        if rc != 0 {
            return Err(KeytabError::Krb5(rc));
        }
        for e in entries {
            let principal = CString::new(e.principal()).map_err(|_| KeytabError::Krb5(-1))?;
            let key = buf.get(e.key.clone()).ok_or(KeytabError::Krb5(-1))?;
            let mut parsed: *mut c_void = core::ptr::null_mut();
            // SAFETY: `context` is live; `principal` is NUL-terminated and outlives the call.
            let rc = unsafe { krb5_parse_name(context, principal.as_ptr(), &raw mut parsed) };
            if rc != 0 {
                return Err(KeytabError::Krb5(rc));
            }
            let mut entry = KeytabEntry {
                magic: 0,
                principal: parsed,
                timestamp: 0,
                vno: e.kvno,
                key: Keyblock {
                    magic: 0,
                    enctype: e.enctype,
                    length: u32::try_from(key.len()).map_err(|_| KeytabError::Krb5(-1))?,
                    contents: key.as_ptr().cast_mut(),
                },
            };
            // SAFETY: `context` and `keytab` are live; `entry` points at a principal libkrb5
            // parsed and at key bytes in secret memory that outlive the call. libkrb5 copies
            // both and never writes through `contents`.
            let rc = unsafe { krb5_kt_add_entry(context, keytab, &raw mut entry) };
            // SAFETY: `parsed` came from `krb5_parse_name` with this context and is freed once.
            unsafe { krb5_free_principal(context, parsed) };
            if rc != 0 {
                return Err(KeytabError::Krb5(rc));
            }
        }
        // SAFETY: `name` is NUL-terminated; libgssapi copies the keytab name.
        let major = unsafe { krb5_gss_register_acceptor_identity(name.as_ptr()) };
        if major != 0 {
            return Err(KeytabError::Krb5(-2));
        }
        Ok(Handle {
            _context: context,
            _keytab: keytab,
        })
    }
}

#[cfg(not(target_os = "linux"))]
mod krb5 {
    //! The gateway runs on Linux only (OP-155 m.3 (o)).

    use super::{Entry, KeytabError};

    pub(super) struct Handle;

    pub(super) fn install(_: &[u8], _: &[Entry]) -> Result<Handle, KeytabError> {
        Err(KeytabError::Krb5(-3))
    }
}
