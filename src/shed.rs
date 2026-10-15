// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Refuse new tunnels when memory is nearly gone, instead of dying with them.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Set while the node is refusing new tunnels.
static SHEDDING: AtomicBool = AtomicBool::new(false);
/// Last sampled usage, in percent of the limit. Exported for metrics.
static USAGE_PCT: AtomicU64 = AtomicU64::new(0);
/// New tunnels refused since start.
static REFUSED: AtomicU64 = AtomicU64::new(0);

/// Start refusing at this percentage of the memory limit.
pub const DEFAULT_HIGH_PCT: u64 = 88;
/// Resume accepting below this one. The 8-point gap is the anti-flap margin.
pub const DEFAULT_LOW_PCT: u64 = 80;

/// Whether to refuse a new tunnel right now.
#[inline]
pub fn is_shedding() -> bool {
    SHEDDING.load(Ordering::Relaxed)
}

/// `(shedding, usage_pct, refused_total)` for the metrics endpoint.
pub fn stats() -> (bool, u64, u64) {
    (
        SHEDDING.load(Ordering::Relaxed),
        USAGE_PCT.load(Ordering::Relaxed),
        REFUSED.load(Ordering::Relaxed),
    )
}

/// Count one refused tunnel.
#[inline]
pub fn note_refused() {
    REFUSED.fetch_add(1, Ordering::Relaxed);
}

/// The response a shedding node sends instead of `101 Switching Protocols`.
pub const SHED_RESPONSE: &str = "HTTP/1.1 404 Not Found\r\n\
                                 Content-Type: text/plain\r\n\
                                 Content-Length: 10\r\n\
                                 \r\n\
                                 Not Found\n";

/// Read `(used, limit)` in bytes, preferring the cgroup because that is what
/// the OOM killer enforces. `None` means we could not tell, which is treated as
/// healthy.
fn read_usage() -> Option<(u64, u64)> {
    let rd = |p: &str| std::fs::read_to_string(p).ok()?.trim().parse::<u64>().ok();

    if let Ok(self_cg) = std::fs::read_to_string("/proc/self/cgroup") {
        if let Some(rel) = self_cg
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(|p| p.trim().trim_start_matches('/').to_string())
        {
            let mut parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
            loop {
                let dir = if parts.is_empty() {
                    "/sys/fs/cgroup".to_string()
                } else {
                    format!("/sys/fs/cgroup/{}", parts.join("/"))
                };
                let cur = rd(&format!("{dir}/memory.current"));
                let max = std::fs::read_to_string(format!("{dir}/memory.max"))
                    .ok()
                    .map(|v| v.trim().to_string());
                if let (Some(u), Some(m)) = (cur, max) {
                    if m != "max" {
                        if let Ok(l) = m.parse::<u64>() {
                            if l > 0 && l < (1u64 << 62) {
                                return Some((u, l));
                            }
                        }
                    }
                }
                if parts.pop().is_none() {
                    break;
                }
            }
        }
    }

    if let (Some(u), Some(l)) = (
        rd("/sys/fs/cgroup/memory/memory.usage_in_bytes"),
        rd("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    ) {
        if l > 0 && l < (1u64 << 62) {
            return Some((u, l));
        }
    }

    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let rss_kb: u64 = status.lines().find_map(|l| {
        l.strip_prefix("VmRSS:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })?;
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    let total_kb: u64 = meminfo.lines().find_map(|l| {
        l.strip_prefix("MemTotal:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })?;
    (total_kb > 0).then(|| (rss_kb * 1024, total_kb * 1024))
}

/// Sample memory forever and drive [`is_shedding`].
pub fn spawn(high_pct: u64, low_pct: u64, interval: Duration) {
    let (high_pct, low_pct) =
        if high_pct <= low_pct {
            log::warn!(
            "[SHED] high_pct {} <= low_pct {} leaves no anti-flap margin — using defaults {}/{}",
            high_pct, low_pct, DEFAULT_HIGH_PCT, DEFAULT_LOW_PCT
        );
            (DEFAULT_HIGH_PCT, DEFAULT_LOW_PCT)
        } else {
            (high_pct, low_pct)
        };

    tokio::spawn(async move {
        let mut warned_blind = false;
        loop {
            match read_usage() {
                Some((used, limit)) => {
                    let pct = used.saturating_mul(100) / limit.max(1);
                    USAGE_PCT.store(pct, Ordering::Relaxed);
                    let was = SHEDDING.load(Ordering::Relaxed);
                    if !was && pct >= high_pct {
                        SHEDDING.store(true, Ordering::Relaxed);
                        log::warn!(
                            "[SHED] memory {}% of limit ({:.1} of {:.1} GB) — refusing NEW tunnels \
                             with 503 so clients fail over; established tunnels are untouched",
                            pct,
                            used as f64 / 1e9,
                            limit as f64 / 1e9
                        );
                    } else if was && pct <= low_pct {
                        SHEDDING.store(false, Ordering::Relaxed);
                        log::warn!(
                            "[SHED] memory back to {}% — accepting new tunnels again ({} refused)",
                            pct,
                            REFUSED.load(Ordering::Relaxed)
                        );
                    }
                }
                None => {
                    if !warned_blind {
                        log::warn!(
                            "[SHED] cannot read cgroup or /proc memory — load shedding is DISABLED \
                             and this node will accept until it dies"
                        );
                        warned_blind = true;
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shed response must be byte-identical to the decoy 404 in http.rs. If
    /// they ever diverge, a prober can tell a shedding node from a healthy one,
    /// which is the whole thing this is trying to avoid.
    #[test]
    fn the_shed_response_is_indistinguishable_from_the_decoy() {
        let decoy = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\nNot Found\n";
        assert_eq!(
            SHED_RESPONSE, decoy,
            "shed response drifted from the http.rs fall-through — it is now externally distinguishable"
        );
    }

    /// It must not leak that the box is under pressure.
    #[test]
    fn the_shed_response_announces_nothing_about_load() {
        let low = SHED_RESPONSE.to_ascii_lowercase();
        for leak in [
            "retry-after",
            "server:",
            "503",
            "unavailable",
            "memory",
            "overload",
        ] {
            assert!(!low.contains(leak), "shed response leaks {leak:?}");
        }
    }

    /// The exact check the deployed client performs (redsocket-http-
    /// core/src/tunnel.rs): anything not starting "HTTP/1.1 101" becomes
    /// ConnectionRefused and it moves to the next endpoint.
    #[test]
    fn the_deployed_client_would_reject_and_fail_over() {
        assert!(!SHED_RESPONSE.starts_with("HTTP/1.1 101"));
        assert!(SHED_RESPONSE.contains("\r\n\r\n"), "headers must terminate");
    }

    /// Defaults must leave a gap, or the node flaps between states.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn the_default_marks_have_an_antiflap_gap() {
        assert!(
            DEFAULT_HIGH_PCT > DEFAULT_LOW_PCT,
            "high {} must exceed low {}",
            DEFAULT_HIGH_PCT,
            DEFAULT_LOW_PCT
        );
        assert!(
            DEFAULT_HIGH_PCT - DEFAULT_LOW_PCT >= 5,
            "gap is too narrow to damp"
        );
        assert!(
            DEFAULT_HIGH_PCT < 100,
            "shedding at 100% is shedding too late"
        );
    }

    /// Reading the live host must not panic and must produce a sane percentage.
    #[test]
    fn reading_usage_is_sane_or_absent() {
        if let Some((used, limit)) = read_usage() {
            assert!(limit > 0);
            assert!(
                used <= limit.saturating_mul(2),
                "used {used} vs limit {limit}"
            );
        }
    }
}
