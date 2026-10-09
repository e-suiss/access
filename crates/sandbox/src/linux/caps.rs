//! SA-22 step 4 and the tail of step 5: capability bounding, ambient and process sets.

use rustix::thread::{CapabilitySet, CapabilitySets};

use super::os;
use crate::{Error, Step};

/// Highest capability number the running kernel knows (`/proc/sys/kernel/cap_last_cap`).
fn last_cap() -> Result<u32, Error> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap").map_err(|e| Error::Os {
        step: Step::Capabilities,
        source: e,
    })?;
    raw.trim().parse::<u32>().map_err(|e| Error::Os {
        step: Step::Capabilities,
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })
}

/// Empties the bounding set and the ambient set. Fails closed when a capability stays in the
/// bounding set (for example a non-root process without `CAP_SETPCAP` whose container runtime did
/// not drop it): SA-22 requires an empty set, not a best effort.
pub(super) fn drop_bounding_and_ambient() -> Result<(), Error> {
    rustix::thread::clear_ambient_capability_set().map_err(|e| os(Step::Capabilities, e))?;

    let last = last_cap()?.min(63);
    for capability in 0..=last {
        let set = CapabilitySet::from_bits_retain(1_u64 << capability);
        let present = rustix::thread::capability_is_in_bounding_set(set)
            .map_err(|e| os(Step::Capabilities, e))?;
        if !present {
            continue;
        }
        let _ = rustix::thread::remove_capability_from_bounding_set(set);
        let still_present = rustix::thread::capability_is_in_bounding_set(set)
            .map_err(|e| os(Step::Capabilities, e))?;
        if still_present {
            return Err(Error::CapabilityNotDropped { capability });
        }
    }
    Ok(())
}

/// Empties the effective, permitted and inheritable sets and checks that they are empty.
pub(super) fn clear_process_sets() -> Result<(), Error> {
    let empty = CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    };
    rustix::thread::set_capabilities(None, empty).map_err(|e| os(Step::Capabilities, e))?;
    let now = rustix::thread::capabilities(None).map_err(|e| os(Step::Capabilities, e))?;
    if now == empty {
        Ok(())
    } else {
        Err(Error::Os {
            step: Step::Capabilities,
            source: std::io::Error::other("capability sets are not empty after capset"),
        })
    }
}
