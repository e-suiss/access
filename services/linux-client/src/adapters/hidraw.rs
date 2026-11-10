//! A local security key over Linux `hidraw` (OP-156 m.3 (p), (z)): the first device whose HID
//! report descriptor declares the FIDO usage page (`0xF1D0`), spoken to with our own CTAPHID
//! framing. Every read is bounded; no key, a busy key or a broken answer is `None`.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::domain::fido::{
    BROADCAST, CMD_CBOR, CMD_INIT, REPORT, Reassembly, init_channel, packets,
};
use crate::ports::SecurityKey;

/// How long the person has to touch the key.
pub const TOUCH: Duration = Duration::from_secs(30);

/// The FIDO usage page as a HID report descriptor item.
const FIDO_PAGE: [u8; 3] = [0x06, 0xd0, 0xf1];

/// Security keys on `/dev/hidraw*`.
pub struct Hidraw {
    /// Where `hidraw` devices are listed.
    pub sysfs: PathBuf,
    /// Where their nodes are.
    pub dev: PathBuf,
}

impl Default for Hidraw {
    fn default() -> Self {
        Self {
            sysfs: PathBuf::from("/sys/class/hidraw"),
            dev: PathBuf::from("/dev"),
        }
    }
}

fn fido_nodes(sysfs: &Path, dev: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(sysfs) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in entries.flatten() {
        let desc = e.path().join("device/report_descriptor");
        let fido =
            std::fs::read(desc).is_ok_and(|d| d.windows(FIDO_PAGE.len()).any(|w| w == FIDO_PAGE));
        if fido {
            out.push(dev.join(e.file_name()));
        }
    }
    out.sort();
    out
}

fn transact(node: &Path, cid: [u8; 4], cmd: u8, payload: &[u8], until: Instant) -> Option<Vec<u8>> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(node)
        .ok()?;
    for p in packets(cid, cmd, payload).ok()? {
        let mut report = [0u8; REPORT + 1];
        report.get_mut(1..)?.copy_from_slice(&p);
        f.write_all(&report).ok()?;
    }
    let mut r = Reassembly::new(cid);
    loop {
        if Instant::now() >= until {
            return None;
        }
        let left = until.saturating_duration_since(Instant::now());
        let wait = rustix::event::Timespec {
            tv_sec: i64::try_from(left.as_secs()).ok()?,
            tv_nsec: i64::from(left.subsec_nanos()),
        };
        let mut fds = [rustix::event::PollFd::new(&f, rustix::event::PollFlags::IN)];
        if rustix::event::poll(&mut fds, Some(&wait)).ok()? == 0 {
            return None;
        }
        let mut buf = [0u8; REPORT];
        let n = f.read(&mut buf).ok()?;
        if n != REPORT {
            return None;
        }
        if let Some((got, body)) = r.feed(&buf).ok()? {
            return (got == cmd).then_some(body);
        }
    }
}

fn assert_on(node: &Path, request: &[u8]) -> Option<Vec<u8>> {
    let until = Instant::now().checked_add(TOUCH)?;
    let mut nonce = <[u8; 8]>::default();
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut nonce)
        .ok()?;
    let init = transact(node, BROADCAST, CMD_INIT, &nonce, until)?;
    let cid = init_channel(&init, &nonce)?;
    transact(node, cid, CMD_CBOR, request, until)
}

impl SecurityKey for Hidraw {
    async fn get_assertion(&self, request: &[u8]) -> Option<Vec<u8>> {
        let nodes = fido_nodes(&self.sysfs, &self.dev);
        let node = nodes.into_iter().next()?;
        let request = request.to_vec();
        tokio::task::spawn_blocking(move || assert_on(&node, &request))
            .await
            .ok()?
    }
}
