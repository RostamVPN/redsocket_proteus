// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! io_uring relay backend (opt-in via `[relay] io_backend = "iouring"`).

use std::collections::HashMap;
use std::io;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::{fence, AtomicUsize, Ordering};
use std::sync::mpsc;

use io_uring::types::{BufRingEntry, Fd};
use io_uring::{opcode, IoUring};

/// Buffers in the shared pool (== ring entries). Power of two.
const P: u16 = 512;
/// Size of each pooled buffer. 32 KiB absorbs a typical recv burst; a larger
/// message simply spans multiple recv completions (handled incrementally).
const SIZE: u32 = 32768;
/// Buffer group id the multishot recvs select from.
const BGID: u16 = 1;
/// io_uring SQ/CQ depth.
const RING_ENTRIES: u32 = 8192;
/// Max reactor threads regardless of core count.
const MAX_REACTORS: usize = 32;

const IORING_CQE_BUFFER_SHIFT: u32 = 16;
const IORING_CQE_F_BUFFER: u32 = 1 << 0;
const IORING_CQE_F_MORE: u32 = 1 << 1;
const ENOBUFS: i32 = 105;

const OP_RECV: u64 = 0 << 62;
const OP_SEND: u64 = 1 << 62;
const DIR_AB: u64 = 0 << 61;
const DIR_BA: u64 = 1 << 61;
const CONN_MASK: u64 = (1 << 61) - 1;

/// Wakeup eventfd completion tag. conn id 0 is never assigned to a real relay
/// (next_conn starts at 1), so this value can't collide with any
/// ud(op,dir,conn).
const WAKE_USER_DATA: u64 = 0;

#[inline]
fn ud(op: u64, dir: u64, conn: u64) -> u64 {
    op | dir | (conn & CONN_MASK)
}
#[inline]
fn ud_op(u: u64) -> u64 {
    u & (3 << 62)
}
#[inline]
fn ud_dir(u: u64) -> u64 {
    u & (1 << 61)
}
#[inline]
fn ud_conn(u: u64) -> u64 {
    u & CONN_MASK
}

struct Mmap {
    ptr: *mut u8,
}
impl Mmap {
    fn new(len: usize) -> io::Result<Mmap> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        let len = (len + page - 1) & !(page - 1);
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Mmap { ptr: ptr as *mut u8 })
    }
}

unsafe impl Send for Mmap {}

struct BufRing {
    pool: Mmap,
    ring: Mmap,
    tail: u16,
    mask: u16,
}
impl BufRing {
    fn new() -> io::Result<BufRing> {
        let pool = Mmap::new(P as usize * SIZE as usize)?;
        let ring = Mmap::new(P as usize * std::mem::size_of::<BufRingEntry>())?;
        Ok(BufRing {
            pool,
            ring,
            tail: 0,
            mask: P - 1,
        })
    }
    fn ring_base(&self) -> *mut BufRingEntry {
        self.ring.ptr as *mut BufRingEntry
    }
    fn buf_addr(&self, bid: u16) -> u64 {
        unsafe { self.pool.ptr.add(bid as usize * SIZE as usize) as u64 }
    }
    /// Bytes of buffer `bid` (read the recv payload before recycling).
    unsafe fn buf_slice(&self, bid: u16, len: usize) -> &[u8] {
        std::slice::from_raw_parts(self.pool.ptr.add(bid as usize * SIZE as usize), len)
    }
    fn push(&mut self, bid: u16) {
        let idx = (self.tail & self.mask) as usize;
        let base = self.ring_base();
        unsafe {
            let e = &mut *base.add(idx);
            e.set_addr(self.buf_addr(bid));
            e.set_len(SIZE);
            e.set_bid(bid);
        }
        self.tail = self.tail.wrapping_add(1);
    }
    fn commit(&self) {
        let tail_ptr =
            unsafe { BufRingEntry::tail(self.ring_base() as *const BufRingEntry) as *mut u16 };
        fence(Ordering::Release);
        unsafe { ptr::write_volatile(tail_ptr, self.tail) };
    }
    fn fill(&mut self) {
        for bid in 0..P {
            self.push(bid);
        }
        self.commit();
    }
    fn recycle(&mut self, bid: u16) {
        self.push(bid);
        self.commit();
    }
}

struct RelayConn {
    fd_a: RawFd,
    fd_b: RawFd,
    ws: Option<crate::ws_codec::WsDecoder>,
    noise: crate::noise_framer::NoiseFramer,

    pend_ab: std::collections::VecDeque<u8>,
    pend_ba: std::collections::VecDeque<u8>,
    send_ab_inflight: bool,
    send_ba_inflight: bool,
    send_ab_buf: Vec<u8>,
    send_ba_buf: Vec<u8>,
    closing: bool,
}

impl RelayConn {
    fn new(job: RelayJob) -> Self {
        let RelayJob {
            fd_a,
            fd_b,
            session,
            ws_prefix,
            websocket,
        } = job;

        let mut noise = crate::noise_framer::NoiseFramer::new(session);
        let ws = if websocket {
            Some(crate::ws_codec::WsDecoder::with_prefix(ws_prefix))
        } else {
            if !ws_prefix.is_empty() {
                let _ = noise.feed_inbound(&ws_prefix);
            }
            None
        };
        RelayConn {
            fd_a,
            fd_b,
            ws,
            noise,
            pend_ab: Default::default(),
            pend_ba: Default::default(),
            send_ab_inflight: false,
            send_ba_inflight: false,
            send_ab_buf: Vec::new(),
            send_ba_buf: Vec::new(),
            closing: false,
        }
    }
}

/// A relay job handed from tokio to a reactor after setup completes: - fd_a:
/// the client TcpStream fd, taken from tokio - fd_b: the connected target
/// TcpStream fd (plaintext) - session.
pub struct RelayJob {
    pub fd_a: RawFd,
    pub fd_b: RawFd,
    pub session: snow::TransportState,
    pub ws_prefix: Vec<u8>,
    pub websocket: bool,
}

struct Reactor {
    ring: IoUring,
    bufs: BufRing,
    conns: HashMap<u64, RelayConn>,
    next_conn: u64,
    jobs: mpsc::Receiver<RelayJob>,
    load: std::sync::Arc<AtomicUsize>,
    wake_fd: RawFd,
}

impl Reactor {
    fn new(
        jobs: mpsc::Receiver<RelayJob>,
        load: std::sync::Arc<AtomicUsize>,
        wake_fd: RawFd,
    ) -> io::Result<Reactor> {
        let ring = IoUring::new(RING_ENTRIES)?;
        let mut bufs = BufRing::new()?;
        unsafe {
            ring.submitter()
                .register_buf_ring(bufs.ring_base() as u64, P, BGID)?;
        }
        bufs.fill();
        Ok(Reactor {
            ring,
            bufs,
            conns: HashMap::new(),
            next_conn: 1,
            jobs,
            load,
            wake_fd,
        })
    }

    /// Arm a single-shot poll on the wake eventfd.
    fn arm_wake(&mut self) {
        let e = opcode::PollAdd::new(Fd(self.wake_fd), libc::POLLIN as u32)
            .build()
            .user_data(WAKE_USER_DATA);
        self.push_sqe(&e);
    }

    /// Drain the eventfd counter so the level-triggered poll can re-arm cleanly.
    fn drain_wake(&self) {
        let mut buf = [0u8; 8];
        unsafe {
            let _ = libc::read(self.wake_fd, buf.as_mut_ptr() as *mut libc::c_void, 8);
        }
    }

    fn push_sqe(&mut self, entry: &io_uring::squeue::Entry) {
        loop {
            unsafe {
                if self.ring.submission().push(entry).is_ok() {
                    return;
                }
            }
            let _ = self.ring.submit();
        }
    }

    /// Arm a bufferless multishot recv on `fd` for `dir`.
    fn arm_recv(&mut self, conn: u64, dir: u64, fd: RawFd) {
        let e = opcode::RecvMulti::new(Fd(fd), BGID)
            .build()
            .user_data(ud(OP_RECV, dir, conn));
        self.push_sqe(&e);
    }

    /// Kick a send of queued bytes for `dir` if none is in flight.
    fn kick_send(&mut self, conn: u64, dir: u64) {
        let (fd, buf) = {
            let c = match self.conns.get_mut(&conn) {
                Some(c) => c,
                None => return,
            };
            if dir == DIR_AB {
                if c.send_ab_inflight || c.pend_ab.is_empty() {
                    return;
                }
                c.send_ab_inflight = true;
                c.send_ab_buf = c.pend_ab.drain(..).collect();
                (c.fd_b, c.send_ab_buf.as_ptr())
            } else {
                if c.send_ba_inflight || c.pend_ba.is_empty() {
                    return;
                }
                c.send_ba_inflight = true;
                c.send_ba_buf = c.pend_ba.drain(..).collect();
                (c.fd_a, c.send_ba_buf.as_ptr())
            }
        };
        let len = if dir == DIR_AB {
            self.conns[&conn].send_ab_buf.len()
        } else {
            self.conns[&conn].send_ba_buf.len()
        };
        let e = opcode::Send::new(Fd(fd), buf, len as u32)
            .build()
            .user_data(ud(OP_SEND, dir, conn));
        self.push_sqe(&e);
    }

    fn accept_jobs(&mut self) {
        while let Ok(job) = self.jobs.try_recv() {
            let conn = self.next_conn;
            self.next_conn += 1;
            let fd_a = job.fd_a;
            let fd_b = job.fd_b;
            self.conns.insert(conn, RelayConn::new(job));
            self.load.fetch_add(1, Ordering::Relaxed);
            log::debug!("[iou] accepted conn={} fd_a={} fd_b={}", conn, fd_a, fd_b);

            self.arm_recv(conn, DIR_AB, fd_a);
            self.arm_recv(conn, DIR_BA, fd_b);
        }
    }

    fn close_conn(&mut self, conn: u64) {
        if let Some(c) = self.conns.remove(&conn) {
            unsafe {
                libc::close(c.fd_a);
                libc::close(c.fd_b);
            }
            self.load.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn run(mut self) {
        self.arm_wake();
        self.accept_jobs();
        loop {
            match self.ring.submit_and_wait(1) {
                Ok(_) => {}
                Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(_) => break,
            }
            let mut events: Vec<(u64, i32, u32)> = Vec::new();
            {
                let cq = self.ring.completion();
                for cqe in cq {
                    events.push((cqe.user_data(), cqe.result(), cqe.flags()));
                }
            }
            let mut woke = false;
            for (u, res, flags) in events {
                if u == WAKE_USER_DATA {
                    self.drain_wake();
                    self.arm_wake();
                    woke = true;
                    continue;
                }
                let conn = ud_conn(u);
                match ud_op(u) {
                    OP_RECV => self.on_recv(conn, ud_dir(u), res, flags),
                    OP_SEND => self.on_send(conn, ud_dir(u), res),
                    _ => {}
                }
            }
            if woke {
                self.accept_jobs();
            }

            let done: Vec<u64> = self
                .conns
                .iter()
                .filter(|(_, c)| c.closing && !c.send_ab_inflight && !c.send_ba_inflight)
                .map(|(k, _)| *k)
                .collect();
            for conn in done {
                self.close_conn(conn);
            }
        }
    }

    /// c2t: raw client bytes (WS-framed, Noise ciphertext) -> deframe -> decrypt ->
    /// queue plaintext to the target (fd_b). Ping frames are answered with a pong
    /// queued back to the client (fd_a); Close begins teardown.
    fn process_c2t(&mut self, conn: u64, bytes: &[u8]) -> bool {
        let mut to_target: Vec<u8> = Vec::new();
        let mut to_client: Vec<u8> = Vec::new();
        let mut close = false;
        {
            let c = match self.conns.get_mut(&conn) {
                Some(c) => c,
                None => return true,
            };
            match c.ws.as_mut() {
                Some(ws) => {
                    let events = match ws.stats(bytes) {
                        Ok(ev) => ev,
                        Err(_) => return false,
                    };
                    for ev in events {
                        match ev {
                            crate::ws_codec::WsEvent::Binary(ct) => {
                                match c.noise.feed_inbound(&ct) {
                                    Ok(pt) => to_target.extend_from_slice(&pt),
                                    Err(_) => return false,
                                }
                            }
                            crate::ws_codec::WsEvent::Ping(p) => {
                                to_client.extend_from_slice(&crate::ws_codec::encode_pong(&p));
                            }
                            crate::ws_codec::WsEvent::Pong(_) => {}
                            crate::ws_codec::WsEvent::Close => {
                                to_client.extend_from_slice(&crate::ws_codec::encode_close());
                                close = true;
                            }
                        }
                    }
                }

                None => match c.noise.feed_inbound(bytes) {
                    Ok(pt) => to_target.extend_from_slice(&pt),
                    Err(_) => return false,
                },
            }
            c.pend_ab.extend(to_target);
            c.pend_ba.extend(to_client);
            if close {
                c.closing = true;
            }
        }
        true
    }

    /// t2c: raw target bytes (plaintext) -> Noise-encrypt -> (WS binary frame on
    /// the WS path) -> queue to the client (fd_a). Returns false on encrypt fail.
    fn process_t2c(&mut self, conn: u64, bytes: &[u8]) -> bool {
        let c = match self.conns.get_mut(&conn) {
            Some(c) => c,
            None => return true,
        };
        let framed = match c.noise.frame_outbound(bytes) {
            Ok(ct) => ct,
            Err(_) => return false,
        };
        if c.ws.is_some() {
            c.pend_ba.extend(crate::ws_codec::encode_binary(&framed));
        } else {
            c.pend_ba.extend(framed);
        }
        true
    }

    fn on_recv(&mut self, conn: u64, dir: u64, res: i32, flags: u32) {
        if flags & IORING_CQE_F_BUFFER != 0 && res > 0 {
            let bid = (flags >> IORING_CQE_BUFFER_SHIFT) as u16;
            let bytes = unsafe { self.bufs.buf_slice(bid, res as usize).to_vec() };
            self.bufs.recycle(bid);
            let codec_ok = if dir == DIR_AB {
                self.process_c2t(conn, &bytes)
            } else {
                self.process_t2c(conn, &bytes)
            };
            if !codec_ok {
                if let Some(c) = self.conns.get_mut(&conn) {
                    c.closing = true;
                }
            }

            self.kick_send(conn, DIR_AB);
            self.kick_send(conn, DIR_BA);
        }

        if res == 0 {
            if let Some(c) = self.conns.get_mut(&conn) {
                c.closing = true;
            }
        } else if res < 0 {
            let err = -res;
            if err == ENOBUFS {
                if flags & IORING_CQE_F_MORE == 0 {
                    let fd = self
                        .conns
                        .get(&conn)
                        .map(|c| if dir == DIR_AB { c.fd_a } else { c.fd_b });
                    if let Some(fd) = fd {
                        self.arm_recv(conn, dir, fd);
                    }
                }
            } else if let Some(c) = self.conns.get_mut(&conn) {
                c.closing = true;
            }
        } else {
            if flags & IORING_CQE_F_MORE == 0 {
                let fd = self
                    .conns
                    .get(&conn)
                    .map(|c| if dir == DIR_AB { c.fd_a } else { c.fd_b });
                if let Some(fd) = fd {
                    self.arm_recv(conn, dir, fd);
                }
            }
        }
    }

    fn on_send(&mut self, conn: u64, dir: u64, res: i32) {
        let more = {
            let c = match self.conns.get_mut(&conn) {
                Some(c) => c,
                None => return,
            };
            if dir == DIR_AB {
                c.send_ab_inflight = false;
                !c.pend_ab.is_empty()
            } else {
                c.send_ba_inflight = false;
                !c.pend_ba.is_empty()
            }
        };
        if res < 0 {
            if let Some(c) = self.conns.get_mut(&conn) {
                c.closing = true;
            }
            return;
        }
        if more {
            self.kick_send(conn, dir);
        }
    }
}

pub struct Engine {
    txs: Vec<mpsc::Sender<RelayJob>>,
    loads: Vec<std::sync::Arc<AtomicUsize>>,
    wake_fds: Vec<RawFd>,
}

impl Engine {
    /// Spawn `n` reactor threads (defaults to num_cpus, capped at MAX_REACTORS).
    pub fn start(n: usize) -> io::Result<Engine> {
        let n = n.clamp(1, MAX_REACTORS);
        let mut txs = Vec::with_capacity(n);
        let mut loads = Vec::with_capacity(n);
        let mut wake_fds = Vec::with_capacity(n);
        for i in 0..n {
            let (tx, rx) = mpsc::channel();
            let load = std::sync::Arc::new(AtomicUsize::new(0));
            let load_c = load.clone();

            let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK) };
            if wake_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let reactor = Reactor::new(rx, load_c, wake_fd)?;
            std::thread::Builder::new()
                .name(format!("iou-relay-{i}"))
                .spawn(move || reactor.run())?;
            txs.push(tx);
            loads.push(load);
            wake_fds.push(wake_fd);
        }
        log::info!("[iouring] relay engine started with {n} reactor(s)");
        Ok(Engine {
            txs,
            loads,
            wake_fds,
        })
    }

    /// Hand a fully-set-up relay job to the least-loaded reactor. Ownership of both
    /// fds (and the Noise session) transfers to the reactor.
    pub fn submit(&self, job: RelayJob) {
        let mut best = 0;
        let mut best_load = usize::MAX;
        for (i, l) in self.loads.iter().enumerate() {
            let v = l.load(Ordering::Relaxed);
            if v < best_load {
                best_load = v;
                best = i;
            }
        }

        let _ = self.txs[best].send(job);
        let one: u64 = 1;
        unsafe {
            libc::write(
                self.wake_fds[best],
                &one as *const u64 as *const libc::c_void,
                8,
            );
        }
    }
}

static ENGINE: std::sync::OnceLock<Engine> = std::sync::OnceLock::new();

/// Start the io_uring relay engine (one reactor per core). Idempotent; a second
/// call is ignored. Called from main() only when the config selects "iouring".
pub fn init(reactors: usize) {
    if ENGINE.get().is_some() {
        return;
    }
    match Engine::start(reactors) {
        Ok(e) => {
            let _ = ENGINE.set(e);
        }
        Err(e) => log::error!("[iouring] engine failed to start, staying on epoll: {e}"),
    }
}

/// True once the engine is running (i.e. the io_uring backend is active).
pub fn enabled() -> bool {
    ENGINE.get().is_some()
}

/// Hand a fully-set-up relay job to the engine. Returns the job back in `Err`
/// if the engine isn't running (caller must fall back to the epoll relay).
#[allow(clippy::result_large_err)]
pub fn submit(job: RelayJob) -> Result<(), RelayJob> {
    match ENGINE.get() {
        Some(e) => {
            e.submit(job);
            Ok(())
        }
        None => Err(job),
    }
}

#[cfg(test)]
mod ud_tests {
    use super::*;

    /// The completion token packs op, direction and connection id into one u64.
    #[test]
    fn every_field_survives_a_round_trip() {
        for &op in &[OP_RECV, OP_SEND] {
            for &dir in &[DIR_AB, DIR_BA] {
                for conn in [1u64, 2, 255, 256, 65535, 1 << 20, CONN_MASK - 1, CONN_MASK] {
                    let u = ud(op, dir, conn);
                    assert_eq!(ud_op(u), op, "op lost (conn={conn})");
                    assert_eq!(ud_dir(u), dir, "dir lost (conn={conn})");
                    assert_eq!(ud_conn(u), conn, "conn lost (conn={conn})");
                }
            }
        }
    }

    /// Fields must be independent: changing the direction must not perturb the
    /// connection id, and vice versa.
    #[test]
    fn fields_do_not_bleed_into_each_other() {
        let conn = 0x1234_5678u64;
        let recv_ab = ud(OP_RECV, DIR_AB, conn);
        let send_ba = ud(OP_SEND, DIR_BA, conn);
        assert_eq!(ud_conn(recv_ab), ud_conn(send_ba), "conn moved with op/dir");
        assert_ne!(recv_ab, send_ba, "distinct op/dir collapsed to one token");
        assert_ne!(ud_op(recv_ab), ud_op(send_ba));
        assert_ne!(ud_dir(recv_ab), ud_dir(send_ba));
    }

    /// The wake eventfd uses token 0. `next_conn` starts at 1 precisely so no real
    /// relay can ever produce it; if that invariant breaks, wakeups and a live
    /// connection's recv completions become indistinguishable.
    #[test]
    fn the_wake_token_cannot_collide_with_a_real_connection() {
        assert_eq!(WAKE_USER_DATA, 0);
        for conn in 1u64..4096 {
            for &op in &[OP_RECV, OP_SEND] {
                for &dir in &[DIR_AB, DIR_BA] {
                    assert_ne!(ud(op, dir, conn), WAKE_USER_DATA, "conn {conn} collided");
                }
            }
        }

        assert_eq!(ud(OP_RECV, DIR_AB, 0), WAKE_USER_DATA);
    }

    /// Connection ids are 61 bits. Past that they wrap silently, so the ceiling is
    /// recorded here rather than discovered in production.
    #[test]
    fn connection_ids_are_capped_at_61_bits() {
        assert_eq!(CONN_MASK, (1u64 << 61) - 1);
        assert_eq!(
            ud_conn(ud(OP_RECV, DIR_AB, CONN_MASK + 1)),
            0,
            "no wrap at the cap"
        );

        let u = ud(OP_SEND, DIR_BA, CONN_MASK + 1);
        assert_eq!(ud_op(u), OP_SEND);
        assert_eq!(ud_dir(u), DIR_BA);
    }
}
