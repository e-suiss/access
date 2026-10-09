//! SA-22 step 6: Landlock filesystem and (ABI ≥ V4) TCP restriction with a hard ABI
//! requirement (OP-92).

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, LandlockStatus, NetPort,
    PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, make_bitflags,
};

use crate::{Error, LandlockAbi, Lockdown};

const fn to_abi(abi: LandlockAbi) -> ABI {
    match abi {
        LandlockAbi::V1 => ABI::V1,
        LandlockAbi::V2 => ABI::V2,
        LandlockAbi::V3 => ABI::V3,
        LandlockAbi::V4 => ABI::V4,
        LandlockAbi::V5 => ABI::V5,
        LandlockAbi::V6 => ABI::V6,
    }
}

fn landlock_error(e: impl core::error::Error + Send + Sync + 'static) -> Error {
    Error::Landlock(Box::new(e))
}

/// Restricts the process to the declared paths and returns the kernel's Landlock ABI.
pub(super) fn restrict(lockdown: &Lockdown) -> Result<u32, Error> {
    let abi = to_abi(lockdown.landlock_abi);
    let handled = AccessFs::from_all(abi);
    let read_only: BitFlags<AccessFs> = make_bitflags!(AccessFs::{ReadFile | ReadDir});
    let read_write = handled
        & (read_only
            | make_bitflags!(AccessFs::{
                WriteFile | RemoveFile | RemoveDir | MakeReg | MakeDir | Refer | Truncate
            }));

    let ruleset = Ruleset::default()
        // SA-22
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(landlock_error)?;
    // OP-92
    let handled_net = AccessNet::from_all(abi);
    let mut ruleset = if handled_net.is_empty() {
        ruleset
    } else {
        ruleset.handle_access(handled_net).map_err(landlock_error)?
    }
    .create()
    .map_err(landlock_error)?;

    let rules = lockdown
        .read_only
        .iter()
        .map(|p| (p, read_only))
        .chain(lockdown.read_write.iter().map(|p| (p, read_write)));
    for (path, access) in rules {
        let is_dir = std::fs::metadata(path)
            .map_err(|e| Error::Landlock(Box::new(e)))?
            .is_dir();
        let access = if is_dir {
            access
        } else {
            access & AccessFs::from_file(abi)
        };
        let fd = PathFd::new(path).map_err(landlock_error)?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, access))
            .map_err(landlock_error)?;
    }

    if !handled_net.is_empty() {
        let ports = lockdown
            .tcp_connect
            .iter()
            .map(|&p| (p, AccessNet::ConnectTcp))
            .chain(lockdown.tcp_bind.iter().map(|&p| (p, AccessNet::BindTcp)));
        for (port, access) in ports {
            ruleset = ruleset
                .add_rule(NetPort::new(port, access))
                .map_err(landlock_error)?;
        }
    }

    let status = ruleset.restrict_self().map_err(landlock_error)?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(Error::Landlock(
            format!("ruleset not fully enforced: {:?}", status.ruleset).into(),
        ));
    }
    match status.landlock {
        LandlockStatus::Available {
            effective_abi,
            kernel_abi,
        } => Ok(kernel_abi
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or_else(|| abi_number(effective_abi))),
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => {
            Err(Error::Landlock("landlock is not available".into()))
        }
    }
}

fn abi_number(abi: ABI) -> u32 {
    abi.to_string().parse().unwrap_or(0)
}
