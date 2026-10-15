// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! SOCKS5 connect parser + egress connect.

use std::sync::OnceLock;
use std::time::Duration;
use tokio::net::TcpStream;

use hickory_resolver::config::{LookupIpStrategy, ResolverOpts};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};

/// Floor on cached TTLs. Some CDNs answer with TTL 0 or 1, which would put a
/// DNS round-trip in front of every single connection setup.
const POSITIVE_MIN_TTL: Duration = Duration::from_secs(5);
/// Ceiling, so a stale answer can never be pinned for a day.
const POSITIVE_MAX_TTL: Duration = Duration::from_secs(3600);
/// Failures are cached briefly so a dead name cannot become a query amplifier.
const NEGATIVE_MIN_TTL: Duration = Duration::from_secs(5);
/// In-flight query ceiling. Hickory's default of 32 is a connection-setup
/// bottleneck on a busy node; DNS must never be the thing that queues traffic.
const MAX_ACTIVE_REQUESTS: usize = 4096;
/// Answer cache entries. Hickory's default is 8192; names outnumber that on a
/// busy exit, and each entry is small.
const CACHE_SIZE: u64 = 65_536;

static RESOLVER: OnceLock<Option<TokioResolver>> = OnceLock::new();

/// Process-wide resolver, built once from /etc/resolv.conf.
fn resolver() -> Option<&'static TokioResolver> {
    RESOLVER
        .get_or_init(|| {
            let mut builder = match Resolver::builder_tokio() {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("[DNS] system resolver config unreadable ({e}) — using getaddrinfo");
                    return None;
                }
            };
            let opts: &mut ResolverOpts = builder.options_mut();
            opts.cache_size = CACHE_SIZE;
            opts.max_active_requests = MAX_ACTIVE_REQUESTS;
            opts.positive_min_ttl = Some(POSITIVE_MIN_TTL);
            opts.positive_max_ttl = Some(POSITIVE_MAX_TTL);
            opts.negative_min_ttl = Some(NEGATIVE_MIN_TTL);

            opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

            opts.preserve_intermediates = true;
            match builder.build() {
                Ok(r) => Some(r),
                Err(e) => {
                    log::warn!("[DNS] resolver build failed ({e}) — using getaddrinfo");
                    None
                }
            }
        })
        .as_ref()
}

/// Warm the resolver at startup so the first tunnel does not pay for building
/// it, and so a broken /etc/resolv.conf is logged before traffic arrives.
pub fn init_resolver() {
    let _ = resolver();
}

/// Longest a single connect attempt may take: SYNs at t=0,1,3,7. A destination
/// that is merely slow or lossy still gets through; the ~130 s the kernel would
/// otherwise spend does not.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(8);
/// Ceiling on the whole connect, every candidate and the retry included. This
/// is what bounds the worst case, so no single attempt has to be hair-trigger
/// to keep the total sane.
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);
/// Addresses tried per family. A partially blocked CDN with eight A records is
/// this product's normal case: 3.1.3 walked all of them and found the live one,
/// and a cap of 2 gave up before reaching it.
const CANDIDATES_PER_FAMILY: usize = 8;

static PREFER_V6: OnceLock<bool> = OnceLock::new();

/// Decide once, at startup, whether egress prefers IPv6.
pub async fn init_egress(want: bool) {
    let capable = if want { has_ipv6_route().await } else { false };
    if want && !capable {
        log::warn!("[EGRESS] prefer_ipv6 is on but this node has no IPv6 route — staying on IPv4");
    }
    if capable {
        log::info!("[EGRESS] preferring IPv6 to dual-stack destinations, IPv4 as fallback");
    }
    let _ = PREFER_V6.set(capable);
}

async fn has_ipv6_route() -> bool {
    let Ok(s) = tokio::net::UdpSocket::bind("[::]:0").await else {
        return false;
    };
    s.connect("[2001:4860:4860::8888]:53").await.is_ok()
}

/// Whether egress should try IPv6 first. False until `init_egress` runs, so a
/// caller that forgets it gets today's IPv4-first behaviour.
pub fn prefer_ipv6() -> bool {
    *PREFER_V6.get().unwrap_or(&false)
}

/// Budget for the next attempt, or `None` once the overall deadline is spent.
fn remaining_budget(started: std::time::Instant) -> Option<Duration> {
    CONNECT_DEADLINE
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
        .map(|left| left.min(ATTEMPT_TIMEOUT))
}

/// Order `addrs` by the preferred family, capped per family so one family
/// cannot consume every attempt.
fn order_candidates(addrs: &[std::net::SocketAddr]) -> Vec<std::net::SocketAddr> {
    order_by_family(addrs, prefer_ipv6())
}

/// True for an address an exit node can never reach on behalf of a client:
/// RFC1918, CGNAT, loopback, link-local, ULA, multicast, benchmarking,
/// documentation and reserved space, plus the IPv4-mapped forms of those.
pub const DEFAULT_DENY_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "100::/64",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// A parsed CIDR. Masking integers beats string prefixes: "151.243.11.70" is
/// not inside 151.243.111.0/24, and a `starts_with` would say it is.
#[derive(Debug, Clone, Copy)]
pub struct Cidr {
    net: std::net::IpAddr,
    len: u32,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let (net, len) = s.split_once('/')?;
        let net: std::net::IpAddr = net.trim().parse().ok()?;
        let len: u32 = len.trim().parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        (len <= max).then_some(Self { net, len })
    }

    pub fn contains(&self, ip: &std::net::IpAddr) -> bool {
        use std::net::IpAddr;
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.len)
                };
                u32::from(*a) & mask == u32::from(n) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.len)
                };
                u128::from(*a) & mask == u128::from(n) & mask
            }
            _ => false,
        }
    }
}

#[derive(Debug, Default)]
struct DestinationPolicy {
    deny: Vec<Cidr>,
    allow: Vec<Cidr>,
}

static POLICY: OnceLock<DestinationPolicy> = OnceLock::new();

/// Install the destination policy. `deny = None` keeps [`DEFAULT_DENY_CIDRS`];
/// `Some(&[])` refuses nothing at all.
pub fn init_destination_policy(deny: Option<&[String]>, allow: &[String]) {
    let parse = |list: &[String], what: &str| -> Vec<Cidr> {
        list.iter()
            .filter_map(|s| match Cidr::parse(s) {
                Some(c) => Some(c),
                None => {
                    log::warn!("[EGRESS] {what} entry {s:?} is not a CIDR — ignored");
                    None
                }
            })
            .collect()
    };
    let deny = match deny {
        Some(list) => parse(list, "deny_cidrs"),
        None => DEFAULT_DENY_CIDRS
            .iter()
            .filter_map(|s| Cidr::parse(s))
            .collect(),
    };
    let allow = parse(allow, "allow_cidrs");
    if deny.is_empty() {
        log::warn!("[EGRESS] destination filtering is OFF: no deny_cidrs configured");
    } else {
        log::info!(
            "[EGRESS] destination policy: {} denied range(s), {} allowed carve-out(s)",
            deny.len(),
            allow.len()
        );
    }
    let _ = POLICY.set(DestinationPolicy { deny, allow });
}

/// Is this address refused as a destination?
pub fn is_unroutable(ip: &std::net::IpAddr) -> bool {
    if let std::net::IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return is_unroutable(&std::net::IpAddr::V4(v4));
        }
    }
    let policy = POLICY.get_or_init(|| DestinationPolicy {
        deny: DEFAULT_DENY_CIDRS
            .iter()
            .filter_map(|s| Cidr::parse(s))
            .collect(),
        allow: Vec::new(),
    });
    judge(ip, &policy.deny, &policy.allow)
}

/// Is this address inside an `allow_cidrs` carve-out? The protection judge
/// treats those ranges as our own infrastructure and never looks them up.
pub fn is_carved_out(ip: &std::net::IpAddr) -> bool {
    POLICY
        .get()
        .map(|p| p.allow.iter().any(|c| c.contains(ip)))
        .unwrap_or(false)
}

/// The decision itself, with no global state, so the rules are testable
/// independently of whichever policy a process happens to have installed.
fn judge(ip: &std::net::IpAddr, deny: &[Cidr], allow: &[Cidr]) -> bool {
    if allow.iter().any(|c| c.contains(ip)) {
        return false;
    }
    deny.iter().any(|c| c.contains(ip))
}

fn order_by_family(addrs: &[std::net::SocketAddr], prefer_v6: bool) -> Vec<std::net::SocketAddr> {
    let (first, second): (Vec<_>, Vec<_>) = addrs.iter().partition(|a| a.is_ipv6() == prefer_v6);
    first
        .into_iter()
        .take(CANDIDATES_PER_FAMILY)
        .chain(second.into_iter().take(CANDIDATES_PER_FAMILY))
        .copied()
        .collect()
}

/// A resolved name plus the metadata a lookup returns. `ttl` and `cnames`
/// are empty on the getaddrinfo fallback path.
pub struct Resolved {
    pub addrs: Vec<std::net::SocketAddr>,
    /// Minimum TTL across the answer, in seconds. 0 when unknown.
    pub ttl: u32,
    /// CNAME chain in answer order, e.g. ["www.github.com.", "github.com."].
    pub cnames: Vec<String>,
}

/// OS-resolver path (`getaddrinfo`). Used when the hickory resolver is absent
/// or fails a lookup. Carries no TTL or CNAME.
async fn getaddrinfo(host: &str, port: u16) -> std::io::Result<Resolved> {
    let addrs: Vec<_> = tokio::net::lookup_host((host, port)).await?.collect();
    Ok(Resolved {
        addrs,
        ttl: 0,
        cnames: Vec::new(),
    })
}

/// Warn at most once per 60 s that lookups are falling back. At exit-node query
/// rates an unthrottled line would bury the journal.
fn warn_dns_fallback(host: &str, e: impl std::fmt::Display) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let prev = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(prev) >= 60
        && LAST
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        log::warn!("[DNS] hickory lookup failed ({host}: {e}) — falling back to getaddrinfo; pdns stats loses TTL/CNAME until the resolver recovers");
    }
}

/// Resolve `host` to socket addresses. Answers are cached by the resolver
/// itself, honouring real record TTLs.
pub async fn resolve(host: &str, port: u16) -> std::io::Result<Resolved> {
    let Some(r) = resolver() else {
        return getaddrinfo(host, port).await;
    };

    let lookup = match r.lookup_ip(host).await {
        Ok(l) => l,
        Err(e) => {
            warn_dns_fallback(host, &e);
            return getaddrinfo(host, port).await;
        }
    };

    let mut ttl = u32::MAX;
    let mut cnames = Vec::new();
    for rec in lookup.as_lookup().answers() {
        ttl = ttl.min(rec.ttl);
        if let RData::CNAME(target) = &rec.data {
            cnames.push(target.to_string());
        }
    }

    Ok(Resolved {
        addrs: lookup
            .iter()
            .map(|ip| std::net::SocketAddr::new(ip, port))
            .collect(),
        ttl: if ttl == u32::MAX { 0 } else { ttl },
        cnames,
    })
}

/// UDP ASSOCIATE request. Sent in place of the trimmed CONNECT on a MUX2
/// stream; that stream then carries length-prefixed SOCKS5 UDP datagrams (RFC
/// 1928 §7) in both directions instead of a TCP byte stream.
pub const UDP_ASSOCIATE: [u8; 2] = [0x05, 0xFD];

/// Parse `[1: atyp][variable: addr][2: port BE]`, returning the bytes consumed.
/// Shared by the CONNECT request and the UDP datagram header, which differ only
/// in what precedes the ATYP byte.
pub fn parse_addr(d: &[u8]) -> anyhow::Result<(String, u16, usize)> {
    let atyp = *d.first().ok_or_else(|| anyhow::anyhow!("addr truncated"))?;
    let (host, port_at, used) = match atyp {
        1 => {
            if d.len() < 7 {
                anyhow::bail!("IPv4 addr too short");
            }
            let o = [d[1], d[2], d[3], d[4]];
            (std::net::Ipv4Addr::from(o).to_string(), 5, 7)
        }
        3 => {
            let dlen = *d.get(1).ok_or_else(|| anyhow::anyhow!("no domain len"))? as usize;
            if d.len() < 2 + dlen + 2 {
                anyhow::bail!("domain addr too short");
            }
            (
                std::str::from_utf8(&d[2..2 + dlen])?.to_string(),
                2 + dlen,
                4 + dlen,
            )
        }
        4 => {
            if d.len() < 19 {
                anyhow::bail!("IPv6 addr too short");
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&d[1..17]);
            (std::net::Ipv6Addr::from(o).to_string(), 17, 19)
        }
        other => anyhow::bail!("unsupported addr type: {}", other),
    };
    Ok((host, u16::from_be_bytes([d[port_at], d[port_at + 1]]), used))
}

/// SOCKS5 connect request parser. Format: `[1: version=0x05][1:
/// dest_type][variable: addr][2: port BE]`.
pub fn parse_connect_request(data: &[u8]) -> anyhow::Result<(String, u16)> {
    if data.len() < 4 {
        anyhow::bail!("connect request too short");
    }
    if data[0] != 0x05 {
        anyhow::bail!("unsupported socks version: {}", data[0]);
    }
    let (host, port, _) = parse_addr(&data[1..])?;
    Ok((host, port))
}

/// Parse a SOCKS5 UDP request header (RFC 1928 §7): `[2: RSV=0][1: FRAG][1:
/// ATYP][addr][2: port BE][payload]`. Returns the target and the offset at
/// which the payload starts.
pub fn parse_udp_header(d: &[u8]) -> anyhow::Result<(String, u16, usize)> {
    if d.len() < 4 {
        anyhow::bail!("udp header too short");
    }
    if d[2] != 0 {
        anyhow::bail!("fragmented udp datagram");
    }
    let (host, port, used) = parse_addr(&d[3..])?;
    Ok((host, port, 3 + used))
}

/// Build the SOCKS5 UDP header naming `from` as the datagram's origin.
pub fn udp_header(from: &std::net::SocketAddr) -> Vec<u8> {
    let mut h = Vec::with_capacity(22);
    h.extend_from_slice(&[0, 0, 0]);
    match from.ip() {
        std::net::IpAddr::V4(v4) => {
            h.push(1);
            h.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            h.push(4);
            h.extend_from_slice(&v6.octets());
        }
    }
    h.extend_from_slice(&from.port().to_be_bytes());
    h
}

/// Connect to `host:port` from one of this node's egress IPs.
pub async fn connect_via(
    host: &str,
    port: u16,
    egress_ips: &[String],
    sticky_key: &str,
    _real_ip: &str,
    _cid: &str,
) -> anyhow::Result<TcpStream> {
    let resolved = resolve(host, port)
        .await
        .map_err(|e| anyhow::anyhow!("DNS lookup failed for {}:{}: {}", host, port, e))?;
    connect_resolved(host, port, &resolved.addrs, egress_ips, sticky_key).await
}

/// The dial half of [`connect_via`], for a caller that has already resolved the
/// name — the protection judge needs the addresses before the first SYN, and
/// resolving twice would double the resolver load for nothing.
pub async fn connect_resolved(
    host: &str,
    port: u16,
    addrs: &[std::net::SocketAddr],
    egress_ips: &[String],
    sticky_key: &str,
) -> anyhow::Result<TcpStream> {
    if addrs.is_empty() {
        anyhow::bail!("no addresses for {}:{}", host, port);
    }

    let routable: Vec<_> = addrs
        .iter()
        .copied()
        .filter(|a| !is_unroutable(&a.ip()))
        .collect();
    if routable.is_empty() {
        crate::metrics::inc_egress_refused_unroutable();
        anyhow::bail!(
            "refused unroutable destination {}:{} ({} address(es), none routable from an exit)",
            host,
            port,
            addrs.len()
        );
    }
    let candidates = order_candidates(&routable);
    let started = std::time::Instant::now();

    for addr in candidates.iter() {
        let Some(budget) = remaining_budget(started) else {
            break;
        };
        if let Some(s) = try_addr(*addr, egress_ips, sticky_key, 0, budget).await {
            return Ok(s);
        }
    }
    if let Some(addr) = candidates.first() {
        if let Some(budget) = remaining_budget(started) {
            if let Some(s) = try_addr(*addr, egress_ips, sticky_key, 1, budget).await {
                log::debug!(
                    "[EGRESS] {}:{} reached on the second exit address for key {}",
                    host,
                    port,
                    sticky_key
                );
                return Ok(s);
            }
        }
    }
    anyhow::bail!("all connect attempts failed for {}:{}", host, port)
}

/// One attempt at `addr` using this client's `rank`-th exit address, reporting
/// the outcome per exit IP. `None` means it did not connect.
async fn try_addr(
    addr: std::net::SocketAddr,
    egress_ips: &[String],
    sticky_key: &str,
    rank: usize,
    budget: Duration,
) -> Option<TcpStream> {
    let bind = pick_egress_ranked(egress_ips, sticky_key, addr.is_ipv6(), rank);
    let bind_ip = bind.and_then(|s| s.parse::<std::net::IpAddr>().ok());
    if rank > 0 && bind.is_none() {
        return None;
    }
    match tokio::time::timeout(budget, dial(addr, bind_ip)).await {
        Ok(Ok(stream)) => {
            crate::metrics::inc_egress(addr.is_ipv6());
            if let Some(ip) = bind {
                crate::metrics::inc_egress_ip(ip, true);
            }
            Some(stream)
        }
        outcome => {
            match outcome {
                Ok(Err(e)) => log::debug!("[EGRESS] connect to {} failed: {}", addr, e),
                _ => log::debug!("[EGRESS] connect to {} timed out after {:?}", addr, budget),
            }
            if let Some(ip) = bind {
                crate::metrics::inc_egress_ip(ip, false);
            }
            None
        }
    }
}

/// One attempt, bound to `bind_ip`.
async fn dial(
    addr: std::net::SocketAddr,
    bind_ip: Option<std::net::IpAddr>,
) -> std::io::Result<TcpStream> {
    let stream = match bind_ip {
        Some(ip) => {
            let sock = if addr.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };
            set_bind_address_no_port(&sock);
            sock.bind(std::net::SocketAddr::new(ip, 0))
                .map_err(|e| std::io::Error::new(e.kind(), format!("bind {ip} failed: {e}")))?;
            sock.connect(addr).await?
        }
        None => TcpStream::connect(addr).await?,
    };
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Defer ephemeral-port selection from `bind()` to `connect()`.
fn set_bind_address_no_port(sock: &tokio::net::TcpSocket) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let one: libc::c_int = 1;

        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_BIND_ADDRESS_NO_PORT,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = sock;
}

/// Deterministically pick an egress IP for a client key (cid or real_ip).
/// FNV-1a — fast, stable across restarts, good enough distribution. Reserved
/// control-channel prefix.
pub fn is_control_channel(host: &str) -> bool {
    host.starts_with("_rs.")
}

/// FNV-1a over a byte string. The primitive both egress selectors are built
/// from, and the one the VPP plugin ports to C.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Final avalanche step (splitmix64's).
fn mix64(mut z: u64) -> u64 {
    z ^= z >> 30;
    z = z.wrapping_mul(0xbf58476d1ce4e5b9);
    z ^= z >> 27;
    z = z.wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// Pick the `rank`-th choice of egress IP for `key`, among the pool entries of
/// the requested family. `rank` 0 is the client's normal exit; higher ranks are
/// what a failed connection falls back to.
pub fn pick_egress_ranked<'a>(
    egress_ips: &'a [String],
    key: &str,
    want_v6: bool,
    rank: usize,
) -> Option<&'a str> {
    let mut scored: Vec<(u64, &'a str)> = egress_ips
        .iter()
        .filter(|s| {
            s.parse::<std::net::IpAddr>()
                .map(|ip| ip.is_ipv6() == want_v6)
                .unwrap_or(false)
        })
        .map(|s| {
            let mut buf = Vec::with_capacity(key.len() + 1 + s.len());
            buf.extend_from_slice(key.as_bytes());
            buf.push(0);
            buf.extend_from_slice(s.as_bytes());
            (mix64(fnv1a(&buf)), s.as_str())
        })
        .collect();
    scored.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    scored.get(rank).map(|(_, ip)| *ip)
}

/// The client's normal exit of the requested family.
pub fn pick_egress_family<'a>(
    egress_ips: &'a [String],
    key: &str,
    want_v6: bool,
) -> Option<&'a str> {
    pick_egress_ranked(egress_ips, key, want_v6, 0)
}

#[cfg(test)]
mod tests {
    use super::{
        getaddrinfo, is_unroutable, order_by_family, parse_connect_request, parse_udp_header,
        pick_egress_family, pick_egress_ranked, udp_header,
    };

    /// Boundary-heavy table for the exit refusal set. The NAT64-embedded GUA is
    /// here on purpose: it must stay *routable* — we refuse address space, never
    /// guess at what a global address "really" is.
    fn cidrs(list: &[&str]) -> Vec<super::Cidr> {
        list.iter().filter_map(|s| super::Cidr::parse(s)).collect()
    }

    #[test]
    fn the_blocked_set_is_data_an_operator_can_change() {
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        let default = cidrs(super::DEFAULT_DENY_CIDRS);

        assert!(super::judge(&ip("10.1.2.3"), &default, &[]));
        assert!(super::judge(&ip("127.0.0.1"), &default, &[]));
        assert!(!super::judge(&ip("8.8.8.8"), &default, &[]));

        let only_rfc1918 = cidrs(&["10.0.0.0/8"]);
        assert!(super::judge(&ip("10.1.2.3"), &only_rfc1918, &[]));
        assert!(!super::judge(&ip("127.0.0.1"), &only_rfc1918, &[]));

        assert!(!super::judge(&ip("127.0.0.1"), &[], &[]));

        let allow = cidrs(&["10.9.0.0/16"]);
        assert!(!super::judge(&ip("10.9.0.5"), &default, &allow));
        assert!(super::judge(&ip("10.10.0.5"), &default, &allow));

        assert!(cidrs(&["not-a-cidr", "10.0.0.0/33", "10.0.0.0/x"]).is_empty());

        let mapped = ip("::ffff:10.1.2.3");
        assert!(super::judge(&ip("10.1.2.3"), &only_rfc1918, &[]));
        assert!(
            !super::judge(&mapped, &only_rfc1918, &[]),
            "judge sees it as v6..."
        );
        assert!(
            super::is_unroutable(&mapped),
            "...but is_unroutable unwraps it first"
        );
    }

    #[test]
    fn unroutable_classification() {
        let refused = [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.1.1",
            "10.10.34.36",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.255",
            "198.18.0.2",
            "198.19.255.255",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "ff02::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "2001:db8::1",
            "100::1",
            "::ffff:10.1.1.1",
            "::ffff:127.0.0.1",
            "::ffff:100.64.9.9",
        ];
        let allowed = [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.36.170",
            "100.63.255.255",
            "100.128.0.0",
            "198.17.255.255",
            "198.20.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "9.255.255.255",
            "11.0.0.1",
            "223.255.255.255",
            "2001:4188:2:600:10:10:34:36",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2a03:2880:f227:2e6:face:b00c:0:6e2e",
            "::ffff:1.1.1.1",
            "2001:db7::1",
            "2001:db9::1",
            "fb00::1",
            "fe00::1",
            "fec0::1",
        ];
        for s in refused {
            let ip: std::net::IpAddr = s.parse().unwrap();
            assert!(is_unroutable(&ip), "{s} must be refused");
        }
        for s in allowed {
            let ip: std::net::IpAddr = s.parse().unwrap();
            assert!(!is_unroutable(&ip), "{s} must stay routable");
        }
    }

    /// The flag is only meaningful on Linux and only if it actually takes: read it
    /// back through getsockopt on both families. Runs on the target (cargo test
    /// --target aarch64-unknown-linux-musl), not on the Mac host.
    #[cfg(target_os = "linux")]
    #[test]
    fn bind_address_no_port_is_set_on_both_families() {
        use std::os::unix::io::AsRawFd;
        for sock in [
            tokio::net::TcpSocket::new_v4().unwrap(),
            tokio::net::TcpSocket::new_v6().unwrap(),
        ] {
            super::set_bind_address_no_port(&sock);
            let mut val: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    sock.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_BIND_ADDRESS_NO_PORT,
                    &mut val as *mut libc::c_int as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(rc, 0, "getsockopt failed");
            assert_eq!(val, 1, "IP_BIND_ADDRESS_NO_PORT did not take");
        }
    }

    #[tokio::test]
    async fn getaddrinfo_fallback_resolves_ip_literal() {
        let r = getaddrinfo("127.0.0.1", 443)
            .await
            .expect("ip literal resolves");
        assert!(r
            .addrs
            .iter()
            .any(|a| a.ip().is_loopback() && a.port() == 443));
        assert_eq!(r.ttl, 0);
        assert!(r.cnames.is_empty());
    }

    fn sa(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn preferred_family_goes_first_and_the_other_stays_as_fallback() {
        let dual = [
            sa("1.2.3.4:443"),
            sa("[2606:4700::1]:443"),
            sa("5.6.7.8:443"),
            sa("[2606:4700::2]:443"),
        ];
        let v6first = order_by_family(&dual, true);
        assert!(v6first[0].is_ipv6() && v6first[1].is_ipv6(), "{v6first:?}");
        assert!(v6first[2].is_ipv4(), "IPv4 must remain the fallback");

        assert!(order_by_family(&dual, false)[0].is_ipv4());

        let many: Vec<_> = (1..=6).map(|i| sa(&format!("10.0.0.{i}:80"))).collect();
        let mut mixed = many.clone();
        mixed.push(sa("[2606:4700::9]:80"));
        let ordered = order_by_family(&mixed, true);
        assert_eq!(ordered.len(), 7, "1 v6 + all 6 v4: {ordered:?}");
        assert!(ordered[0].is_ipv6());

        let huge: Vec<_> = (1..=20).map(|i| sa(&format!("10.0.1.{i}:80"))).collect();
        assert_eq!(
            order_by_family(&huge, false).len(),
            super::CANDIDATES_PER_FAMILY
        );

        assert_eq!(order_by_family(&many, true).len(), 6);
        assert!(order_by_family(&[sa("[2606:4700::1]:80")], false)[0].is_ipv6());
        assert!(order_by_family(&[], true).is_empty());
    }

    fn pool(n: usize, v6: bool) -> Vec<String> {
        (0..n)
            .map(|i| {
                if v6 {
                    format!("2001:db8::{:x}", 0x120 + i)
                } else {
                    format!("172.32.36.{}", 178 + i)
                }
            })
            .collect()
    }

    #[test]
    fn every_address_of_a_multi_record_destination_is_reachable() {
        let eight: Vec<std::net::SocketAddr> = (1..=8)
            .map(|i| sa(&format!("93.184.216.{i}:443")))
            .collect();
        assert_eq!(
            order_by_family(&eight, false).len(),
            8,
            "all A records must be tried"
        );

        let mut dual = eight.clone();
        dual.push(sa("[2606:2800:220:1::1]:443"));
        let ordered = order_by_family(&dual, false);
        assert_eq!(ordered.len(), 9);
        assert!(ordered[..8].iter().all(|a| a.is_ipv4()));
        assert!(ordered[8].is_ipv6());

        let fresh = std::time::Instant::now();
        assert_eq!(super::remaining_budget(fresh), Some(super::ATTEMPT_TIMEOUT));
        assert!(super::ATTEMPT_TIMEOUT < super::CONNECT_DEADLINE);
    }

    #[test]
    fn assignment_is_balanced_and_survives_losing_one_address() {
        let mut all = pool(11, false);
        all.extend(pool(11, true));
        let cids: Vec<String> = (0..20_000).map(|i| format!("cid-{i:08x}")).collect();

        let assign = |p: &[String]| -> Vec<String> {
            cids.iter()
                .map(|c| pick_egress_family(p, c, false).unwrap().to_string())
                .collect()
        };
        let before = assign(&all);

        let mut count = std::collections::HashMap::new();
        for ip in &before {
            *count.entry(ip.clone()).or_insert(0usize) += 1;
        }
        assert_eq!(count.len(), 11, "every v4 address must be used: {count:?}");
        let fair = cids.len() / 11;
        for (ip, n) in &count {
            assert!(
                *n > fair * 4 / 5 && *n < fair * 6 / 5,
                "{ip} carries {n}, fair share is {fair}"
            );
        }

        let drained: Vec<String> = all
            .iter()
            .filter(|s| *s != "172.32.36.178")
            .cloned()
            .collect();
        let after = assign(&drained);
        let moved = before.iter().zip(&after).filter(|(a, b)| a != b).count();
        let was_on_it = before.iter().filter(|ip| *ip == "172.32.36.178").count();
        assert_eq!(
            moved, was_on_it,
            "only the drained address's clients may move"
        );
        assert!(moved < cids.len() / 5, "{moved} of {} moved", cids.len());
    }

    #[test]
    fn a_client_always_gets_an_address_of_the_destination_family() {
        let mut all = pool(11, false);
        all.extend(pool(11, true));
        for i in 0..2000 {
            let cid = format!("cid-{i}");
            let v4 = pick_egress_family(&all, &cid, false).expect("a v4 exit");
            let v6 = pick_egress_family(&all, &cid, true).expect("a v6 exit");
            assert!(v4.parse::<std::net::Ipv4Addr>().is_ok(), "{v4}");
            assert!(v6.parse::<std::net::Ipv6Addr>().is_ok(), "{v6}");

            let alt = pick_egress_ranked(&all, &cid, false, 1).expect("a second v4 exit");
            assert_ne!(alt, v4);
        }

        assert!(pick_egress_family(&pool(3, false), "any", true).is_none());
        assert!(pick_egress_ranked(&pool(1, false), "any", false, 1).is_none());
    }

    #[test]
    fn egress_pick_is_per_family_and_stable_as_the_other_family_grows() {
        let v4only: Vec<String> = vec!["172.33.21.20".into(), "172.33.21.21".into()];
        let mut mixed = v4only.clone();
        mixed.push("2a01:4f8::1".into());
        mixed.insert(0, "2a01:4f8::2".into());

        for cid in ["cid-alpha-0001", "user_8f2c9a71", "0042:android:us"] {
            assert_eq!(
                pick_egress_family(&v4only, cid, false),
                pick_egress_family(&mixed, cid, false),
                "IPv4 mapping moved for {cid}"
            );

            let v6 = pick_egress_family(&mixed, cid, true).expect("a v6 exit");
            assert!(v6.parse::<std::net::Ipv6Addr>().is_ok(), "{v6}");
        }

        assert!(pick_egress_family(&v4only, "any", true).is_none());
        assert!(pick_egress_family(&[], "any", false).is_none());
    }

    #[test]
    fn udp_header_roundtrip_and_bounds() {
        let from: std::net::SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut dgram = udp_header(&from);
        dgram.extend_from_slice(b"quic");
        let (host, port, off) = parse_udp_header(&dgram).unwrap();
        assert_eq!((host.as_str(), port), ("1.2.3.4", 443));
        assert_eq!(&dgram[off..], b"quic");

        let from6: std::net::SocketAddr = "[2606:4700::1111]:53".parse().unwrap();
        let mut d6 = udp_header(&from6);
        d6.extend_from_slice(b"x");
        let (h6, p6, off6) = parse_udp_header(&d6).unwrap();
        assert_eq!((h6.as_str(), p6), ("2606:4700::1111", 53));
        assert_eq!(&d6[off6..], b"x");

        let dom = [
            &[0u8, 0, 0, 3, 3][..],
            b"a.b",
            &[0x01, 0xbb][..],
            b"payload",
        ]
        .concat();
        let (hd, pd, offd) = parse_udp_header(&dom).unwrap();
        assert_eq!((hd.as_str(), pd), ("a.b", 443));
        assert_eq!(&dom[offd..], b"payload");

        for n in 0..dom.len() - b"payload".len() {
            assert!(parse_udp_header(&dom[..n]).is_err(), "len {n} parsed");
        }
        assert!(parse_udp_header(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 80]).is_err());

        assert_eq!(
            parse_connect_request(&[5, 1, 8, 8, 8, 8, 0, 53]).unwrap(),
            ("8.8.8.8".to_string(), 53)
        );
    }
}
