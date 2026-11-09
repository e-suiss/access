//! The parser worker pool (OP-155 m.3 (c), MD-18, U43): pre-forked worker processes, one request
//! in flight each, talking over a Unix socket pair. A worker is replaced after
//! [`PoolConfig::max_requests`] requests or after any answer but a clean `ok`; one that crashes,
//! overruns the wall clock or answers outside the protocol is killed and its caller gets
//! [`Reply::WorkerFailed`]. Nothing a worker does reaches the process that runs the pool.
//!
//! On Linux every byte read from a worker must carry the worker's own process id in its
//! `SCM_CREDENTIALS` (`SO_PASSCRED`), so no other process can answer in its place.

use std::ffi::OsString;
use std::io::Write as _;
use std::num::NonZeroUsize;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::ipc::{FrameError, MAX_HEADER, MAX_SEGMENT, Reply, length};

/// Requests one worker serves before it is replaced.
pub const MAX_REQUESTS: u32 = 1000;

/// Wall-clock limit of one request.
pub const WALL: Duration = Duration::from_secs(5);

/// How the pool starts its workers.
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// The worker program.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// Workers kept running.
    pub size: NonZeroUsize,
    /// Requests per worker before it is replaced.
    pub max_requests: u32,
    /// Wall-clock limit of one request.
    pub wall: Duration,
}

impl PoolConfig {
    /// Four workers of `program work`, [`MAX_REQUESTS`] each, [`WALL`] per request.
    #[must_use]
    pub fn new(program: PathBuf) -> Self {
        Self {
            program,
            args: vec![OsString::from("work")],
            size: NonZeroUsize::MIN.saturating_add(3),
            max_requests: MAX_REQUESTS,
            wall: WALL,
        }
    }
}

struct Worker {
    child: Child,
    socket: UnixStream,
    served: u32,
}

impl Worker {
    fn spawn(config: &PoolConfig) -> std::io::Result<Self> {
        let (ours, theirs) = UnixStream::pair()?;
        // U43
        #[cfg(target_os = "linux")]
        rustix::net::sockopt::set_socket_passcred(&ours, true)?;
        let input = OwnedFd::from(theirs.try_clone()?);
        let output = OwnedFd::from(theirs);
        let child = Command::new(&config.program)
            .args(&config.args)
            .env_clear()
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self {
            child,
            socket: ours,
            served: 0,
        })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn end(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn retire(mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
        drop(self.socket);
        let _ = self.child.wait();
    }
}

#[derive(Debug)]
enum Failure {
    Io,
    Frame,
}

impl From<std::io::Error> for Failure {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

impl From<FrameError> for Failure {
    fn from(_: FrameError) -> Self {
        Self::Frame
    }
}

#[cfg(target_os = "linux")]
fn read_some(socket: &UnixStream, buf: &mut [u8], pid: u32) -> Result<usize, Failure> {
    use std::mem::MaybeUninit;

    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let got = recvmsg(
        socket,
        &mut [std::io::IoSliceMut::new(buf)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| Failure::Io)?;
    if got.bytes == 0 {
        return Ok(0);
    }
    let mut from_worker = false;
    for message in control.drain() {
        if let RecvAncillaryMessage::ScmCredentials(c) = message {
            from_worker = u32::try_from(c.pid.as_raw_pid()).is_ok_and(|p| p == pid);
        }
    }
    if from_worker {
        Ok(got.bytes)
    } else {
        Err(Failure::Io)
    }
}

#[cfg(not(target_os = "linux"))]
fn read_some(socket: &UnixStream, buf: &mut [u8], _pid: u32) -> Result<usize, Failure> {
    use std::io::Read as _;
    let mut s = socket;
    Ok(s.read(buf)?)
}

fn read_exact(
    socket: &UnixStream,
    buf: &mut [u8],
    pid: u32,
    deadline: Instant,
) -> Result<(), Failure> {
    let mut at = 0;
    while at < buf.len() {
        let left = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(Failure::Io)?;
        socket.set_read_timeout(Some(left))?;
        let rest = buf.get_mut(at..).ok_or(Failure::Frame)?;
        let n = read_some(socket, rest, pid)?;
        if n == 0 {
            return Err(Failure::Io);
        }
        at = at.checked_add(n).ok_or(Failure::Frame)?;
    }
    Ok(())
}

fn exchange(w: &mut Worker, frame: &[u8], wall: Duration) -> Result<Reply, Failure> {
    let deadline = Instant::now().checked_add(wall).ok_or(Failure::Io)?;
    let pid = w.pid();
    w.socket.set_write_timeout(Some(wall))?;
    w.socket.write_all(frame)?;
    let mut prefix = [0_u8; 4];
    read_exact(&w.socket, &mut prefix, pid, deadline)?;
    let header_len = length(prefix, MAX_HEADER)?;
    let mut whole = Vec::new();
    whole.extend_from_slice(&prefix);
    let mut header = vec![0_u8; header_len];
    read_exact(&w.socket, &mut header, pid, deadline)?;
    whole.extend_from_slice(&header);
    read_exact(&w.socket, &mut prefix, pid, deadline)?;
    let segment_len = length(prefix, MAX_SEGMENT)?;
    whole.extend_from_slice(&prefix);
    let mut segment = vec![0_u8; segment_len];
    read_exact(&w.socket, &mut segment, pid, deadline)?;
    whole.extend_from_slice(&segment);
    Ok(Reply::decode(&whole)?)
}

/// Reads one whole frame (request or reply) from `r`, checking each length before it allocates;
/// `None` at a clean end of input.
///
/// # Errors
/// The read failed, the input ended inside the frame, or a length is above its ceiling.
pub fn read_frame<R: std::io::Read>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut whole = Vec::new();
    for (i, max) in [MAX_HEADER, MAX_SEGMENT].into_iter().enumerate() {
        let mut prefix = [0_u8; 4];
        if i == 0 {
            let n = r.read(&mut prefix)?;
            if n == 0 {
                return Ok(None);
            }
            r.read_exact(prefix.get_mut(n..).unwrap_or_default())?;
        } else {
            r.read_exact(&mut prefix)?;
        }
        let n = length(prefix, max).map_err(|_| std::io::ErrorKind::InvalidData)?;
        whole.extend_from_slice(&prefix);
        let mut part = vec![0_u8; n];
        r.read_exact(&mut part)?;
        whole.extend_from_slice(&part);
    }
    Ok(Some(whole))
}

struct Slots {
    idle: Vec<Worker>,
    free: usize,
}

/// The pool.
pub struct Pool {
    config: PoolConfig,
    slots: Mutex<Slots>,
    ready: Condvar,
}

impl core::fmt::Debug for Pool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pool")
            .field("size", &self.config.size)
            .finish_non_exhaustive()
    }
}

impl Pool {
    /// Starts [`PoolConfig::size`] workers.
    ///
    /// # Errors
    /// The first worker that cannot be started.
    pub fn start(config: PoolConfig) -> std::io::Result<Self> {
        let mut idle = Vec::new();
        for _ in 0..config.size.get() {
            idle.push(Worker::spawn(&config)?);
        }
        Ok(Self {
            slots: Mutex::new(Slots {
                free: config.size.get(),
                idle,
            }),
            ready: Condvar::new(),
            config,
        })
    }

    fn take(&self) -> Option<Worker> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        while slots.free == 0 {
            slots = self
                .ready
                .wait(slots)
                .unwrap_or_else(PoisonError::into_inner);
        }
        slots.free = slots.free.saturating_sub(1);
        slots.idle.pop()
    }

    fn give(&self, worker: Option<Worker>) {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(w) = worker {
            slots.idle.push(w);
        }
        slots.free = slots.free.saturating_add(1);
        drop(slots);
        self.ready.notify_one();
    }

    /// Sends one request frame to a worker and returns its reply. Blocks while every worker is
    /// busy.
    #[must_use]
    pub fn call(&self, frame: &[u8]) -> Reply {
        let worker = match self.take() {
            Some(w) => Some(w),
            None => Worker::spawn(&self.config).ok(),
        };
        let Some(mut worker) = worker else {
            self.give(None);
            return Reply::WorkerFailed;
        };
        let reply = exchange(&mut worker, frame, self.config.wall);
        let next = match reply {
            Ok(Reply::Ok { .. }) => {
                worker.served = worker.served.saturating_add(1);
                if worker.served >= self.config.max_requests {
                    worker.retire();
                    Worker::spawn(&self.config).ok()
                } else {
                    Some(worker)
                }
            }
            Ok(_) => {
                worker.retire();
                Worker::spawn(&self.config).ok()
            }
            Err(_) => {
                worker.end();
                Worker::spawn(&self.config).ok()
            }
        };
        self.give(next);
        reply.unwrap_or(Reply::WorkerFailed)
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        let slots = self.slots.get_mut().unwrap_or_else(PoisonError::into_inner);
        for w in slots.idle.drain(..) {
            w.end();
        }
    }
}
