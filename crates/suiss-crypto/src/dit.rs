//! ARM64 Data Independent Timing (CR-39 m.6): comparison and crypto code runs with
//! `PSTATE.DIT` set on CPUs that have `FEAT_DIT`. Elsewhere the guard does nothing.

use core::marker::PhantomData;

/// Sets `PSTATE.DIT` for its lifetime and restores the previous value on drop.
/// `PSTATE` is per thread, so the guard is neither `Send` nor `Sync`.
#[must_use = "DIT is cleared again when the guard is dropped"]
pub struct DitGuard {
    restore: bool,
    _thread: PhantomData<*const ()>,
}

impl DitGuard {
    /// Turns DIT on if the CPU supports it and it is off.
    pub fn new() -> Self {
        let restore = imp::supported() && !imp::get() && {
            imp::set(true);
            true
        };
        Self {
            restore,
            _thread: PhantomData,
        }
    }

    /// Whether DIT is on for the current thread; always `false` without `FEAT_DIT`.
    #[must_use]
    pub fn active() -> bool {
        imp::supported() && imp::get()
    }
}

impl Default for DitGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DitGuard {
    fn drop(&mut self) {
        if self.restore {
            imp::set(false);
        }
    }
}

/// Whether this host is Apple Silicon. Its data memory-dependent prefetcher (GoFetch) breaks
/// constant-time code, so a production signer refuses to start on it (CR-39 m.6). An aarch64
/// Linux host whose CPU cannot be read counts as Apple Silicon.
#[must_use]
pub fn apple_silicon() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        true
    }
    #[cfg(all(target_arch = "aarch64", not(target_os = "macos")))]
    {
        std::fs::read_to_string("/proc/cpuinfo").map_or(true, |c| apple_implementer(&c))
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// Whether a `/proc/cpuinfo` text names Apple (implementer `0x61`) as a CPU's implementer.
#[must_use]
pub fn apple_implementer(cpuinfo: &str) -> bool {
    cpuinfo.lines().any(|l| {
        l.split_once(':').is_some_and(|(k, v)| {
            k.trim() == "CPU implementer" && v.trim().eq_ignore_ascii_case("0x61")
        })
    })
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use core::arch::asm;

    /// `PSTATE.DIT` in the DIT system register (`S3_3_C4_C2_5`, bit 24).
    const DIT: u64 = 1 << 24;

    pub(super) fn supported() -> bool {
        std::arch::is_aarch64_feature_detected!("dit")
    }

    pub(super) fn get() -> bool {
        let value: u64;
        // SAFETY: only called after `supported()`; reading DIT is allowed at EL0 with
        // FEAT_DIT.
        #[allow(unsafe_code)]
        unsafe {
            asm!("mrs {v}, S3_3_C4_C2_5", v = out(reg) value, options(nostack, preserves_flags));
        }
        value & DIT != 0
    }

    pub(super) fn set(on: bool) {
        let value: u64 = if on { DIT } else { 0 };
        // SAFETY: only called after `supported()`; writing DIT is allowed at EL0 with
        // FEAT_DIT and changes only instruction timing. It is not `nomem`, so the
        // compiler does not move the comparison's loads across it.
        #[allow(unsafe_code)]
        unsafe {
            asm!("msr S3_3_C4_C2_5, {v}", v = in(reg) value, options(nostack, preserves_flags));
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
mod imp {
    pub(super) fn supported() -> bool {
        false
    }

    pub(super) fn get() -> bool {
        false
    }

    pub(super) fn set(_on: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-39 m.6
    #[test]
    fn guard_sets_dit_and_restores_it() {
        let before = DitGuard::active();
        {
            let _outer = DitGuard::new();
            assert_eq!(DitGuard::active(), imp::supported());
            {
                let _inner = DitGuard::new();
                assert_eq!(DitGuard::active(), imp::supported());
            }
            assert_eq!(DitGuard::active(), imp::supported());
        }
        assert_eq!(DitGuard::active(), before);
    }

    // CR-39 m.6, OP-159 m.3 (s)
    #[test]
    fn dit_is_active_where_the_cpu_has_it() {
        if std::env::var_os("ACCESS_REQUIRE_DIT").is_some() {
            assert!(
                imp::supported(),
                "the CPU reports FEAT_DIT but the guard sees none"
            );
        }
        let _guard = DitGuard::new();
        assert_eq!(DitGuard::active(), imp::supported());
    }

    // CR-39 m.6
    #[test]
    fn an_apple_implementer_is_recognised() {
        let apple =
            "processor\t: 0\nBogoMIPS\t: 48.00\nCPU implementer\t: 0x61\nCPU part\t: 0x022\n";
        let neoverse = "processor\t: 0\nCPU implementer\t: 0x41\nCPU part\t: 0xd4f\n";
        assert!(apple_implementer(apple));
        assert!(!apple_implementer(neoverse));
        assert!(!apple_implementer(""));
        #[cfg(not(target_arch = "aarch64"))]
        assert!(!apple_silicon());
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        assert!(apple_silicon());
    }
}
