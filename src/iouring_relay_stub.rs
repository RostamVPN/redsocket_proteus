// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Non-Linux stand-in for [`crate::iouring_relay`].
use std::os::unix::io::RawFd;

pub struct RelayJob {
    pub fd_a: RawFd,
    pub fd_b: RawFd,
    pub session: snow::TransportState,
    pub ws_prefix: Vec<u8>,
    pub websocket: bool,
}

/// No reactor to start. Logged rather than silent: a config asking for the
/// io_uring backend on a platform that cannot provide it should say so.
pub fn init(_reactors: usize) {
    log::info!("[relay] io_uring backend unavailable on this platform; using the tokio relay");
}

pub fn enabled() -> bool {
    false
}

/// Always refuses, handing the job back. The caller treats `Err` as "the
/// reactor did not take it", which is exactly the truth here.
#[allow(clippy::result_large_err)]
pub fn submit(job: RelayJob) -> Result<(), RelayJob> {
    Err(job)
}
