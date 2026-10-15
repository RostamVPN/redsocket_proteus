// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Metrics — process-global counters only.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant as StdInstant;

static ACTIVE_RELAYS: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES_UP: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES_DOWN: AtomicU64 = AtomicU64::new(0);
static TOTAL_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static EGRESS_V4: AtomicU64 = AtomicU64::new(0);
/// Destinations refused before any connect attempt because no resolved address
/// is routable from an exit (RFC1918, CGNAT, loopback, ...).
static EGRESS_REFUSED_UNROUTABLE: AtomicU64 = AtomicU64::new(0);
static EGRESS_V6: AtomicU64 = AtomicU64::new(0);
static EGRESS_BYTES_V4_UP: AtomicU64 = AtomicU64::new(0);
static EGRESS_BYTES_V4_DOWN: AtomicU64 = AtomicU64::new(0);
static EGRESS_BYTES_V6_UP: AtomicU64 = AtomicU64::new(0);
static EGRESS_BYTES_V6_DOWN: AtomicU64 = AtomicU64::new(0);
static HANDSHAKE_SUCCESSES: AtomicU64 = AtomicU64::new(0);
static HANDSHAKE_FAILURES: AtomicU64 = AtomicU64::new(0);

pub fn active_relays() -> u64 {
    ACTIVE_RELAYS.load(Ordering::Relaxed)
}
pub fn total_bytes_up() -> u64 {
    TOTAL_BYTES_UP.load(Ordering::Relaxed)
}
pub fn total_bytes_down() -> u64 {
    TOTAL_BYTES_DOWN.load(Ordering::Relaxed)
}
/// Bytes moved on each family, in each direction, on the destination side of
/// the node — the side `prefer_ipv6` moves. Same up/down sense as the global
/// counters: up is toward the destination.
pub fn egress_bytes() -> (u64, u64, u64, u64) {
    (
        EGRESS_BYTES_V4_UP.load(Ordering::Relaxed),
        EGRESS_BYTES_V4_DOWN.load(Ordering::Relaxed),
        EGRESS_BYTES_V6_UP.load(Ordering::Relaxed),
        EGRESS_BYTES_V6_DOWN.load(Ordering::Relaxed),
    )
}

pub fn egress_v4() -> u64 {
    EGRESS_V4.load(Ordering::Relaxed)
}

pub fn egress_v6() -> u64 {
    EGRESS_V6.load(Ordering::Relaxed)
}

pub fn total_connections() -> u64 {
    TOTAL_CONNECTIONS.load(Ordering::Relaxed)
}
pub fn handshake_successes() -> u64 {
    HANDSHAKE_SUCCESSES.load(Ordering::Relaxed)
}
pub fn handshake_failures() -> u64 {
    HANDSHAKE_FAILURES.load(Ordering::Relaxed)
}

pub fn inc_relay() {
    ACTIVE_RELAYS.fetch_add(1, Ordering::Relaxed);
}
pub fn dec_relay() {
    ACTIVE_RELAYS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        })
        .ok();
}
pub fn add_bytes_up(n: u64, v6: bool) {
    TOTAL_BYTES_UP.fetch_add(n, Ordering::Relaxed);
    if v6 {
        EGRESS_BYTES_V6_UP.fetch_add(n, Ordering::Relaxed);
    } else {
        EGRESS_BYTES_V4_UP.fetch_add(n, Ordering::Relaxed);
    }
}
pub fn add_bytes_down(n: u64, v6: bool) {
    TOTAL_BYTES_DOWN.fetch_add(n, Ordering::Relaxed);
    if v6 {
        EGRESS_BYTES_V6_DOWN.fetch_add(n, Ordering::Relaxed);
    } else {
        EGRESS_BYTES_V4_DOWN.fetch_add(n, Ordering::Relaxed);
    }
}
/// Count an egress connection by address family. Connection counts, not bytes.
static EGRESS_POOL: OnceLock<Vec<(String, AtomicU64, AtomicU64)>> = OnceLock::new();

pub fn init_egress_pool(ips: &[String]) {
    let _ = EGRESS_POOL.set(
        ips.iter()
            .map(|ip| (ip.clone(), AtomicU64::new(0), AtomicU64::new(0)))
            .collect(),
    );
}

pub fn inc_egress_ip(ip: &str, ok: bool) {
    let Some(pool) = EGRESS_POOL.get() else {
        return;
    };
    let Some((_, o, f)) = pool.iter().find(|(p, _, _)| p == ip) else {
        return;
    };
    if ok {
        o.fetch_add(1, Ordering::Relaxed);
    } else {
        f.fetch_add(1, Ordering::Relaxed);
    }
}

/// (ip, connects, failures) per configured exit address.
pub fn egress_pool_counts() -> Vec<(String, u64, u64)> {
    EGRESS_POOL
        .get()
        .map(|p| {
            p.iter()
                .map(|(ip, o, f)| {
                    (
                        ip.clone(),
                        o.load(Ordering::Relaxed),
                        f.load(Ordering::Relaxed),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn inc_egress(v6: bool) {
    if v6 {
        EGRESS_V6.fetch_add(1, Ordering::Relaxed);
    } else {
        EGRESS_V4.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn inc_egress_refused_unroutable() {
    EGRESS_REFUSED_UNROUTABLE.fetch_add(1, Ordering::Relaxed);
}

pub fn egress_refused_unroutable() -> u64 {
    EGRESS_REFUSED_UNROUTABLE.load(Ordering::Relaxed)
}

pub fn inc_connection() {
    TOTAL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_hs_ok() {
    HANDSHAKE_SUCCESSES.fetch_add(1, Ordering::Relaxed);
}
pub fn inc_hs_fail() {
    HANDSHAKE_FAILURES.fetch_add(1, Ordering::Relaxed);
}

/// RAII guard for active relay count.
pub struct RelayGuard;
impl Default for RelayGuard {
    fn default() -> Self {
        Self::new()
    }
}
impl RelayGuard {
    pub fn new() -> Self {
        inc_relay();
        RelayGuard
    }
}
impl Drop for RelayGuard {
    fn drop(&mut self) {
        dec_relay();
    }
}

static NEXT_TUNNEL_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_TUNNELS: AtomicU64 = AtomicU64::new(0);
static TOTAL_TUNNELS: AtomicU64 = AtomicU64::new(0);

/// Live byte counters, shared with the two relay tasks so the usage record is
/// accurate even when the tunnel is cancelled rather than closed cleanly.
#[derive(Clone, Default)]
pub struct TunnelBytes {
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
}

impl TunnelBytes {
    #[inline]
    pub fn add(&self, n: u64, is_up: bool) {
        let c = if is_up { &self.up } else { &self.down };
        c.fetch_add(n, Ordering::Relaxed);
    }
    pub fn get(&self) -> (u64, u64) {
        (
            self.up.load(Ordering::Relaxed),
            self.down.load(Ordering::Relaxed),
        )
    }
}

/// Per-tunnel state, held by the relay task for exactly as long as the tunnel
/// lives. Only what the close record needs is kept — dest/tz/ua are logged at
/// the call site where they are already in scope, so they cost nothing here.
pub struct TunnelGuard {
    pub id: u64,
    pub bytes: TunnelBytes,
    cid: String,
    started: StdInstant,
    started_unix: u64,
}

impl TunnelGuard {
    pub fn open(cid: &str) -> Self {
        ACTIVE_TUNNELS.fetch_add(1, Ordering::Relaxed);
        TOTAL_TUNNELS.fetch_add(1, Ordering::Relaxed);
        TunnelGuard {
            id: NEXT_TUNNEL_ID.fetch_add(1, Ordering::Relaxed),
            bytes: TunnelBytes::default(),
            cid: cid.to_string(),
            started: StdInstant::now(),
            started_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn age(&self) -> std::time::Duration {
        self.started.elapsed()
    }
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        ACTIVE_TUNNELS.fetch_sub(1, Ordering::Relaxed);

        if !self.cid.is_empty() {
            let (up, down) = self.bytes.get();
            crate::stats::record_tunnel_closed(
                &self.cid,
                self.started_unix,
                self.started.elapsed().as_secs(),
                up,
                down,
            );
        }
    }
}

pub fn active_tunnels() -> u64 {
    ACTIVE_TUNNELS.load(Ordering::Relaxed)
}

pub fn total_tunnels() -> u64 {
    TOTAL_TUNNELS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_balances_on_normal_and_cancelled_exit() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let base = active_tunnels();

        rt.block_on(async {
            let g = TunnelGuard::open("cid-normal");
            assert_eq!(active_tunnels(), base + 1);
            g.bytes.add(100, true);
            g.bytes.add(200, false);
            assert_eq!(g.bytes.get(), (100, 200));
        });
        assert_eq!(active_tunnels(), base, "normal exit leaked a tunnel");

        rt.block_on(async {
            let fut = async {
                let _g = TunnelGuard::open("cid-cancelled");
                assert_eq!(active_tunnels(), base + 1);

                futures::future::pending::<()>().await;
            };
            let r = tokio::time::timeout(std::time::Duration::from_millis(20), fut).await;
            assert!(r.is_err(), "expected the timeout to fire");
        });
        assert_eq!(active_tunnels(), base, "cancelled exit leaked a tunnel");
    }

    #[test]
    fn aborting_one_direction_does_not_zero_its_bytes() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let bytes = TunnelBytes::default();

            let up_bytes = bytes.clone();
            let c2t = tokio::spawn(async move {
                up_bytes.add(4096, true);
                futures::future::pending::<u64>().await
            });

            let down_bytes = bytes.clone();
            let t2c = tokio::spawn(async move {
                down_bytes.add(8192, false);
                7u64
            });

            tokio::pin!(c2t, t2c);
            let (sel_up, sel_down) = tokio::select! {
                up = &mut c2t => { t2c.abort(); let _ = t2c.await; (up.unwrap_or(0), 0) }
                down = &mut t2c => { c2t.abort(); let _ = c2t.await; (0, down.unwrap_or(0)) }
            };

            assert!(
                sel_up == 0 || sel_down == 0,
                "select! is expected to zero one side; it returned ({sel_up}, {sel_down})"
            );

            assert_eq!(
                bytes.get(),
                (4096, 8192),
                "aborting a direction erased its bytes — the usage stats is wrong again"
            );
        });
    }

    #[test]
    fn bytes_are_visible_across_clones() {
        let bytes = TunnelBytes::default();
        let a = bytes.clone();
        let b = bytes.clone();
        a.add(1024, true);
        b.add(2048, false);
        a.add(1, true);
        assert_eq!(bytes.get(), (1025, 2048));
    }
}
