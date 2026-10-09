//! `memfd_secret(2)` memory for signer key material (§14.5, OP-2).

use core::num::NonZeroUsize;
use std::os::fd::{FromRawFd, OwnedFd};

use rustix::mm::{MapFlags, ProtFlags};
use zeroize::Zeroize;

use crate::Error;

pub(crate) struct SecretMemory {
    /// The mapping. `'static` only inside this type: every accessor reborrows it for `&self`
    /// / `&mut self`, and `Drop` unmaps it.
    bytes: &'static mut [u8],
    /// Kept open for the lifetime of the mapping.
    _fd: OwnedFd,
}

impl SecretMemory {
    pub(crate) fn new(len: NonZeroUsize) -> Result<Self, Error> {
        let fd = memfd_secret()?;
        let size =
            u64::try_from(len.get()).map_err(|e| Error::SecretMemory(std::io::Error::other(e)))?;
        rustix::fs::ftruncate(&fd, size).map_err(|e| Error::SecretMemory(e.into()))?;

        #[allow(unsafe_code)]
        // SAFETY: a fresh shared mapping of `len` bytes of a descriptor we own and just sized
        // to `len`, at an address the kernel chooses, so it aliases no existing Rust object.
        // On success the kernel returns a page-aligned pointer to `len` readable and writable
        // bytes (zero-filled by memfd_secret), valid until `munmap` in `Drop`; `Self` owns it
        // exclusively, so building one `&mut [u8]` over it is sound.
        let bytes = unsafe {
            let ptr = rustix::mm::mmap(
                core::ptr::null_mut(),
                len.get(),
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                &fd,
                0,
            )
            .map_err(|e| Error::SecretMemory(e.into()))?;
            core::slice::from_raw_parts_mut(ptr.cast::<u8>(), len.get())
        };
        Ok(Self { bytes, _fd: fd })
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.bytes
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        self.bytes
    }
}

impl Drop for SecretMemory {
    fn drop(&mut self) {
        self.bytes.zeroize();
        let ptr = self.bytes.as_mut_ptr().cast::<core::ffi::c_void>();
        let len = self.bytes.len();
        #[allow(unsafe_code)]
        // SAFETY: `ptr`/`len` are exactly the mapping created in `new`; it is unmapped once,
        // here, and `self.bytes` is never used again.
        let result = unsafe { rustix::mm::munmap(ptr, len) };
        let _ = result;
    }
}

fn memfd_secret() -> Result<OwnedFd, Error> {
    let flags = libc::c_uint::from(libc::O_CLOEXEC.unsigned_abs());
    #[allow(unsafe_code)]
    // SAFETY: `memfd_secret(unsigned int flags)` takes no pointers. A non-negative return is a
    // new descriptor that nothing else owns, so `OwnedFd` may take ownership of it.
    let fd = unsafe {
        let raw = libc::syscall(libc::SYS_memfd_secret, flags);
        if raw < 0 {
            None
        } else {
            i32::try_from(raw).ok().map(|raw| OwnedFd::from_raw_fd(raw))
        }
    };
    fd.ok_or_else(|| {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOSYS) => Error::SecretMemoryUnavailable(err),
            _ => Error::SecretMemory(err),
        }
    })
}
