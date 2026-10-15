// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Exit-side malware protection — the Team Cymru-derived bundle, enforced where
//! the destination is dialled, signalled back to capable clients.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use sha2::Digest;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    pub blk1: bool,
    pub msg1: bool,
}

impl Caps {
    pub fn merge(self, other: Caps) -> Caps {
        Caps {
            blk1: self.blk1 || other.blk1,
            msg1: self.msg1 || other.msg1,
        }
    }
    pub fn any(self) -> bool {
        self.blk1 || self.msg1
    }
}

/// Parse a comma-separated capability list. Whitespace is tolerated, unknown
/// names are ignored.
pub fn parse_caps(field: &str) -> Caps {
    let mut caps = Caps::default();
    for c in field.split(',') {
        match c.trim() {
            "blk1" => caps.blk1 = true,
            "msg1" => caps.msg1 = true,
            _ => {}
        }
    }
    caps
}

/// Caps from field 6 of a `|`-separated META/MUX2 header. Fewer than seven
/// fields = none; anything past the seventh is ignored.
pub fn header_caps(header: &str) -> Caps {
    header.split('|').nth(6).map(parse_caps).unwrap_or_default()
}

/// True once either protection or messaging is on — the one static read a
/// header parse pays before deciding whether to look at field 6 at all.
static CAPS_WANTED: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn caps_wanted() -> bool {
    CAPS_WANTED.load(Ordering::Relaxed)
}

pub fn set_caps_wanted(on: bool) {
    CAPS_WANTED.store(on, Ordering::Relaxed);
}

pub const VERDICT_CLEAR: u8 = 0x00;
pub const VERDICT_NOTIFY: u8 = 0x01;
pub const VERDICT_BLOCK: u8 = 0x02;
/// Largest verdict frame: tag + bits + len + 255 reason bytes.
pub const VERDICT_MAX: usize = 1 + 2 + 1 + 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clear,
    Notify { bits: u16, reason: String },
    Block { bits: u16, reason: String },
}

impl Verdict {
    pub fn tag(&self) -> u8 {
        match self {
            Verdict::Clear => VERDICT_CLEAR,
            Verdict::Notify { .. } => VERDICT_NOTIFY,
            Verdict::Block { .. } => VERDICT_BLOCK,
        }
    }
    pub fn is_block(&self) -> bool {
        matches!(self, Verdict::Block { .. })
    }
    /// Wire form into a stack buffer; returns the length. `Clear` is one byte.
    pub fn encode_into(&self, out: &mut [u8; VERDICT_MAX]) -> usize {
        out[0] = self.tag();
        let (bits, reason) = match self {
            Verdict::Clear => return 1,
            Verdict::Notify { bits, reason } | Verdict::Block { bits, reason } => (*bits, reason),
        };
        out[1..3].copy_from_slice(&bits.to_le_bytes());
        let n = reason_len(reason);
        out[3] = n as u8;
        out[4..4 + n].copy_from_slice(&reason.as_bytes()[..n]);
        4 + n
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = [0u8; VERDICT_MAX];
        let n = self.encode_into(&mut buf);
        buf[..n].to_vec()
    }
}

/// Reason bytes that fit the u8 length, cut on a UTF-8 boundary.
fn reason_len(reason: &str) -> usize {
    let mut n = reason.len().min(255);
    while n > 0 && !reason.is_char_boundary(n) {
        n -= 1;
    }
    n
}

/// Decode a verdict frame from the head of `d` (client-side view, used by the
/// tests and the test clients). Returns the verdict and the bytes consumed.
pub fn decode_verdict(d: &[u8]) -> anyhow::Result<(Verdict, usize)> {
    let tag = *d.first().ok_or_else(|| anyhow::anyhow!("empty verdict"))?;
    if tag == VERDICT_CLEAR {
        return Ok((Verdict::Clear, 1));
    }
    if d.len() < 4 {
        anyhow::bail!("verdict header truncated");
    }
    let bits = u16::from_le_bytes([d[1], d[2]]);
    let n = d[3] as usize;
    if d.len() < 4 + n {
        anyhow::bail!("verdict reason truncated");
    }
    let reason = String::from_utf8_lossy(&d[4..4 + n]).into_owned();
    let v = match tag {
        VERDICT_NOTIFY => Verdict::Notify { bits, reason },
        VERDICT_BLOCK => Verdict::Block { bits, reason },
        other => anyhow::bail!("unknown verdict tag {:#x}", other),
    };
    Ok((v, 4 + n))
}

/// Flags byte bit 0: the user allowed this destination on the device.
pub const FLAG_USER_ALLOWED: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRequest {
    pub host: String,
    pub port: u16,
    /// Flags bit 0: the user allowed this destination on the device.
    pub user_allowed: bool,
}

/// Parse the per-stream request of a `blk1` tunnel:
/// `[05][atyp][addr][port][flags]` — the trimmed CONNECT every client sends,
/// plus ONE trailing flags byte that only `blk1` tunnels append.
pub fn parse_stream_request(d: &[u8]) -> anyhow::Result<StreamRequest> {
    if d.len() < 4 {
        anyhow::bail!("connect request too short");
    }
    if d[0] != 0x05 {
        anyhow::bail!("unsupported socks version: {}", d[0]);
    }
    let (host, port, used) = crate::proxy::parse_addr(&d[1..])?;
    let flags = match d.len() - (1 + used) {
        0 => 0,
        1 => d[1 + used],
        n => anyhow::bail!(
            "{} bytes after the stream header, want at most one flags byte",
            n
        ),
    };
    if flags & !FLAG_USER_ALLOWED != 0 {
        anyhow::bail!("unsupported stream flags {:#04x}", flags);
    }
    Ok(StreamRequest {
        host,
        port,
        user_allowed: flags & FLAG_USER_ALLOWED != 0,
    })
}

#[derive(Debug, Clone, Copy)]
struct V4 {
    start: u32,
    end: u32,
    bits: u16,
}

#[derive(Debug, Clone, Copy)]
struct V6 {
    start: u128,
    end: u128,
    bits: u16,
}

/// Config overrides on the bundle's bit table: names in `block` block, names in
/// `notify` notify, every other reason bit follows its own `kind`. Both empty —
/// the default — means the bundle decides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TierNames {
    pub block: Vec<String>,
    pub notify: Vec<String>,
}

#[derive(Debug, Clone)]
struct Tiers {
    block_mask: u16,
    notify_mask: u16,
    /// The tier bit named BLOCK in the bundle, used for domain hits.
    block_tier_bit: u16,
    /// Block bits no user may switch off: `controller` and `malware`, by name. A
    /// `categories_off` that names them is stored for sync but never enforced.
    floor_mask: u16,
    names: [Option<Box<str>>; 16],
}

/// Bit names that `categories_off` can never clear.
pub const CATEGORIES_FLOOR: &[&str] = &["controller", "malware"];

impl Tiers {
    fn names_for(&self, bits: u16, mask: u16) -> String {
        let mut out = String::new();
        for (i, name) in self.names.iter().enumerate() {
            if bits & mask & (1 << i) != 0 {
                if let Some(n) = name {
                    if !out.is_empty() {
                        out.push(',');
                    }
                    out.push_str(n);
                }
            }
        }
        out
    }
    /// `off` is the cid's `categories_off`: block bits the user switched off, less
    /// the floor nobody may switch off.
    fn verdict(&self, bits: u16, off: u16) -> Verdict {
        let block_mask = self.block_mask & !(off & !self.floor_mask);
        if bits & block_mask != 0 {
            Verdict::Block {
                bits,
                reason: self.names_for(bits, block_mask),
            }
        } else if bits & self.notify_mask != 0 {
            Verdict::Notify {
                bits,
                reason: self.names_for(bits, self.notify_mask),
            }
        } else {
            Verdict::Clear
        }
    }
}

#[derive(Debug)]
pub struct Bundle {
    /// sha256 of the exact `meta.json` bytes, hex: the identity of a build. The
    /// publisher writes the same value as `protection:bundle version`, so a same-
    /// day rebuild is a new version and a replayed old one is not.
    pub version: String,
    pub feed_date: String,
    /// `generated_at` from `meta.json`, as epoch seconds. A bundle older than the
    /// installed one is refused: rollback and replay are not updates.
    pub generated_at: u64,
    v4: Vec<V4>,
    v6: Vec<V6>,
    domains: HashSet<Box<str>>,
    tiers: Tiers,
    pub loaded_at: std::time::Instant,
}

impl Bundle {
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.v4.len(), self.v6.len(), self.domains.len())
    }

    /// Bits of the range covering `ip`, or 0. One binary search.
    pub fn lookup_ip(&self, ip: &IpAddr) -> u16 {
        match ip {
            IpAddr::V4(a) => {
                let ip = u32::from(*a);
                let i = self.v4.partition_point(|r| r.start <= ip);
                match i.checked_sub(1).map(|i| &self.v4[i]) {
                    Some(r) if ip <= r.end => r.bits,
                    _ => 0,
                }
            }
            IpAddr::V6(a) => {
                if let Some(v4) = a.to_ipv4_mapped() {
                    return self.lookup_ip(&IpAddr::V4(v4));
                }
                let ip = u128::from(*a);
                let i = self.v6.partition_point(|r| r.start <= ip);
                match i.checked_sub(1).map(|i| &self.v6[i]) {
                    Some(r) if ip <= r.end => r.bits,
                    _ => 0,
                }
            }
        }
    }

    /// Exact name or any parent label in the domain set. `host` must already be
    /// lowercase without a trailing dot (see [`normalize_host`]).
    pub fn domain_hit(&self, host: &str) -> bool {
        let mut s = host;
        loop {
            if self.domains.contains(s) {
                return true;
            }
            match s.find('.') {
                Some(i) => s = &s[i + 1..],
                None => return false,
            }
        }
    }

    pub fn verdict_for_bits(&self, bits: u16) -> Verdict {
        self.tiers.verdict(bits, 0)
    }

    /// Same, ignoring the block-reason bits in `categories_off`.
    pub fn verdict_for_bits_masked(&self, bits: u16, categories_off: u16) -> Verdict {
        self.tiers.verdict(bits, categories_off)
    }

    fn domain_verdict(&self) -> Verdict {
        Verdict::Block {
            bits: self.tiers.block_tier_bit,
            reason: "domain".to_string(),
        }
    }
}

/// The form the domain set is in: lowercase ASCII, IDNA/punycode for any non-
/// ASCII label (as `build.py` writes it), no trailing dots. Borrows when
/// already normal — the common case — so a clear stream allocates nothing here.
pub fn normalize_host(host: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = host.trim_end_matches('.');
    if !trimmed.is_ascii() {
        return match idna::domain_to_ascii(trimmed) {
            Ok(a) => std::borrow::Cow::Owned(a),
            Err(_) => std::borrow::Cow::Owned(trimmed.to_lowercase()),
        };
    }
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    }
}

/// The five files of a bundle, as bytes.
#[derive(Debug, Clone, Default)]
pub struct RawBundle {
    pub meta: Vec<u8>,
    pub sig: Vec<u8>,
    pub v4: Vec<u8>,
    pub v6: Vec<u8>,
    pub domains_gz: Vec<u8>,
}

impl RawBundle {
    pub fn read_dir(dir: &std::path::Path) -> anyhow::Result<RawBundle> {
        let rd = |name: &str| {
            std::fs::read(dir.join(name)).map_err(|e| anyhow::anyhow!("{}: {}", name, e))
        };
        Ok(RawBundle {
            meta: rd("meta.json")?,
            sig: rd("meta.sig")?,
            v4: rd("v4.bin")?,
            v6: rd("v6.bin")?,
            domains_gz: rd("domains.txt.gz")?,
        })
    }
}

/// `feed_date` from a `meta.json` without loading anything else — what the
/// reloader polls.
pub fn meta_version(meta: &[u8]) -> anyhow::Result<String> {
    let v: serde_json::Value = serde_json::from_slice(meta)?;
    Ok(v.get("feed_date")
        .and_then(|d| d.as_str())
        .unwrap_or("")
        .to_string())
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(data))
}

/// Verify and parse a bundle. Order: signature over the meta bytes, then every
/// file's sha256 and size, then the tables. Any failure leaves the caller with
/// its previous bundle.
pub fn parse_bundle(
    raw: &RawBundle,
    pubkey: &[u8; 32],
    tiers: &TierNames,
) -> anyhow::Result<Bundle> {
    if raw.sig.len() != 64 {
        anyhow::bail!("meta.sig is {} bytes, want 64", raw.sig.len());
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey)
        .verify(&raw.meta, &raw.sig)
        .map_err(|_| anyhow::anyhow!("meta.sig does not verify against the configured pubkey"))?;

    let meta: serde_json::Value = serde_json::from_slice(&raw.meta)?;
    match meta.get("format_version").and_then(|v| v.as_u64()) {
        Some(1) => {}
        other => anyhow::bail!("unsupported format_version {:?}", other),
    }
    let feed_date = meta
        .get("feed_date")
        .and_then(|d| d.as_str())
        .filter(|d| !d.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("meta.json has no feed_date"))?
        .to_string();
    let generated_at = meta
        .get("generated_at")
        .and_then(|g| g.as_str())
        .and_then(parse_generated_at)
        .ok_or_else(|| anyhow::anyhow!("meta.json has no parseable generated_at"))?;
    let files = meta
        .get("files")
        .ok_or_else(|| anyhow::anyhow!("meta.json has no files table"))?;
    for (name, data) in [
        ("v4.bin", &raw.v4),
        ("v6.bin", &raw.v6),
        ("domains.txt.gz", &raw.domains_gz),
    ] {
        let want = files
            .get(name)
            .and_then(|f| f.get("sha256"))
            .and_then(|s| s.as_str())
            .ok_or_else(|| anyhow::anyhow!("meta.json has no sha256 for {}", name))?;
        let got = sha256_hex(data);
        if !got.eq_ignore_ascii_case(want) {
            anyhow::bail!("{}: sha256 {} does not match meta.json {}", name, got, want);
        }
        if let Some(bytes) = files
            .get(name)
            .and_then(|f| f.get("bytes"))
            .and_then(|b| b.as_u64())
        {
            if bytes as usize != data.len() {
                anyhow::bail!("{}: {} bytes, meta.json says {}", name, data.len(), bytes);
            }
        }
    }

    let mut names: [Option<Box<str>>; 16] = Default::default();
    let mut block_mask = 0u16;
    let mut notify_mask = 0u16;
    let mut block_tier_bit = 0x0001u16;
    let mut floor_mask = 0u16;
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(bits) = meta.get("bits").and_then(|b| b.as_object()) {
        for (name, def) in bits {
            let Some(bit) = def.get("bit").and_then(|b| b.as_u64()) else {
                continue;
            };
            if bit >= 16 {
                anyhow::bail!("bit {} for {} out of u16 range", bit, name);
            }
            let kind = def.get("kind").and_then(|k| k.as_str()).unwrap_or("");
            names[bit as usize] = Some(name.as_str().into());
            seen.insert(name.clone());
            if CATEGORIES_FLOOR.contains(&name.as_str()) {
                floor_mask |= 1 << bit;
            }
            if kind == "tier" {
                if name == "BLOCK" {
                    block_tier_bit = 1 << bit;
                }
                continue;
            }

            if tiers.block.iter().any(|n| n == name) {
                block_mask |= 1 << bit;
            } else if tiers.notify.iter().any(|n| n == name) {
                notify_mask |= 1 << bit;
            } else if kind == "block_reason" {
                block_mask |= 1 << bit;
            } else {
                notify_mask |= 1 << bit;
            }
        }
    }
    for n in tiers.block.iter().chain(tiers.notify.iter()) {
        if !seen.contains(n) {
            log::warn!(
                "[protection] configured bit name {:?} is not in this bundle's bit table — ignored",
                n
            );
        }
    }
    if block_mask == 0 {
        anyhow::bail!(
            "this bundle's bit table has no block bit (none of kind block_reason, none configured)"
        );
    }

    if !raw.v4.len().is_multiple_of(10) {
        anyhow::bail!("v4.bin length {} is not a multiple of 10", raw.v4.len());
    }
    let mut v4 = Vec::with_capacity(raw.v4.len() / 10);
    for (i, rec) in raw.v4.chunks_exact(10).enumerate() {
        let r = V4 {
            start: u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]),
            end: u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]),
            bits: u16::from_le_bytes([rec[8], rec[9]]),
        };
        if r.start > r.end {
            anyhow::bail!("v4.bin entry {} has start > end", i);
        }
        if let Some(prev) = v4.last() {
            let prev: &V4 = prev;
            if r.start <= prev.end {
                anyhow::bail!("v4.bin entry {} overlaps or is out of order", i);
            }
        }
        v4.push(r);
    }
    if !raw.v6.len().is_multiple_of(34) {
        anyhow::bail!("v6.bin length {} is not a multiple of 34", raw.v6.len());
    }
    let mut v6 = Vec::with_capacity(raw.v6.len() / 34);
    for (i, rec) in raw.v6.chunks_exact(34).enumerate() {
        let mut s = [0u8; 16];
        let mut e = [0u8; 16];
        s.copy_from_slice(&rec[0..16]);
        e.copy_from_slice(&rec[16..32]);
        let r = V6 {
            start: u128::from_le_bytes(s),
            end: u128::from_le_bytes(e),
            bits: u16::from_le_bytes([rec[32], rec[33]]),
        };
        if r.start > r.end {
            anyhow::bail!("v6.bin entry {} has start > end", i);
        }
        if let Some(prev) = v6.last() {
            let prev: &V6 = prev;
            if r.start <= prev.end {
                anyhow::bail!("v6.bin entry {} overlaps or is out of order", i);
            }
        }
        v6.push(r);
    }
    let mut text = String::new();
    {
        use std::io::Read;
        flate2::read::GzDecoder::new(raw.domains_gz.as_slice())
            .read_to_string(&mut text)
            .map_err(|e| anyhow::anyhow!("domains.txt.gz: {}", e))?;
    }
    let mut domains: HashSet<Box<str>> = HashSet::with_capacity(text.len() / 16);
    for line in text.lines() {
        let d = line.trim();
        if !d.is_empty() {
            domains.insert(normalize_host(d).into_owned().into_boxed_str());
        }
    }

    Ok(Bundle {
        version: sha256_hex(&raw.meta),
        feed_date,
        generated_at,
        v4,
        v6,
        domains,
        tiers: Tiers {
            block_mask,
            notify_mask,
            block_tier_bit,
            floor_mask,
            names,
        },
        loaded_at: std::time::Instant::now(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowHost {
    Exact(String),
    /// `*.suffix`: the suffix itself or any name under it.
    Suffix(String),
}

impl AllowHost {
    fn parse(s: &str) -> Option<AllowHost> {
        let s = normalize_host(s.trim()).into_owned();
        if s.is_empty() {
            return None;
        }
        Some(match s.strip_prefix("*.") {
            Some(suf) if !suf.is_empty() => AllowHost::Suffix(suf.to_string()),
            _ => AllowHost::Exact(s),
        })
    }
    fn matches(&self, host: &str) -> bool {
        match self {
            AllowHost::Exact(e) => host == e,
            AllowHost::Suffix(suf) => {
                host == suf
                    || (host.len() > suf.len()
                        && host.ends_with(suf.as_str())
                        && host.as_bytes()[host.len() - suf.len() - 1] == b'.')
            }
        }
    }
}

/// Most entries a user list may carry; the rest are ignored.
pub const MAX_RULE_ENTRIES: usize = 200;
/// Longest entry (a hostname's limit).
pub const MAX_RULE_ENTRY_LEN: usize = 253;

/// Is `e` a single destination — one hostname, one IP literal, or a CIDR of
/// full length (`/32`, `/128`)? Anything wider is not a user rule.
pub fn valid_rule_entry(e: &str) -> bool {
    let e = e.trim();
    if e.is_empty() || e.len() > MAX_RULE_ENTRY_LEN {
        return false;
    }
    if let Some((ip, len)) = e.split_once('/') {
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return false;
        };
        let full = if ip.is_ipv4() { "32" } else { "128" };
        return len == full;
    }
    if e.parse::<IpAddr>().is_ok() {
        return true;
    }

    e.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// A user's own allow list (`rules:<cid>` → `allow`): hostnames, matched like
/// the domain set (exact or parent label), and single addresses.
#[derive(Debug, Clone, Default)]
pub struct UserRules {
    hosts: Vec<String>,
    cidrs: Vec<crate::proxy::Cidr>,
    /// Block-reason bits the user switched off (`rules:<cid>` → `categories_off`).
    /// A hit whose only block bits are in here is not blocked for this cid; notify
    /// bits are unaffected.
    pub categories_off: u16,
}

impl UserRules {
    pub fn from_allow(entries: &[String]) -> UserRules {
        Self::new(entries, 0)
    }

    pub fn new(entries: &[String], categories_off: u16) -> UserRules {
        let mut r = UserRules {
            categories_off,
            ..UserRules::default()
        };
        for e in entries.iter().take(MAX_RULE_ENTRIES) {
            let e = e.trim();
            if !valid_rule_entry(e) {
                continue;
            }
            if let Some(c) = crate::proxy::Cidr::parse(e) {
                r.cidrs.push(c);
            } else if let Ok(ip) = e.parse::<IpAddr>() {
                let len = if ip.is_ipv4() { 32 } else { 128 };
                if let Some(c) = crate::proxy::Cidr::parse(&format!("{ip}/{len}")) {
                    r.cidrs.push(c);
                }
            } else {
                r.hosts.push(normalize_host(e).into_owned());
            }
        }
        r
    }
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.cidrs.is_empty() && self.categories_off == 0
    }
    pub fn allows_host(&self, host: &str) -> bool {
        self.hosts.iter().any(|h| {
            host == h
                || (host.len() > h.len()
                    && host.ends_with(h.as_str())
                    && host.as_bytes()[host.len() - h.len() - 1] == b'.')
        })
    }
    pub fn allows_ip(&self, ip: &IpAddr) -> bool {
        self.cidrs.iter().any(|c| c.contains(ip))
    }
}

struct Brand {
    name: String,
    /// clear, notify, block.
    verdicts: [AtomicU64; 3],
}

struct State {
    pubkey: [u8; 32],
    tiers: TierNames,
    brands: Vec<Brand>,
    allow_hosts: Vec<AllowHost>,
    egress: Vec<IpAddr>,
    debug_log_destinations: bool,
    bundle: RwLock<Option<Arc<Bundle>>>,
    reload: tokio::sync::Notify,
    reload_secs: u64,
    user_allowed: AtomicU64,
    rules_allowed: AtomicU64,
    udp_dropped: AtomicU64,
    unchecked: AtomicU64,
    reload_ok: AtomicU64,
    reload_failed: AtomicU64,
    /// Refused because older than the installed bundle.
    reload_stale: AtomicU64,
    /// Refused because the HASH `version` is not the sha256 of its `meta`.
    reload_mismatch: AtomicU64,
}

static STATE: OnceLock<State> = OnceLock::new();
static ENABLED: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Install the configuration. Nothing is loaded yet; see [`install`] and
/// [`spawn_reloader`]. A bad public key is a startup error: an operator who
/// turned this on must not get a node that silently checks nothing.
pub fn init(cfg: &crate::config::ProtectionConfig, egress_ips: &[String]) -> anyhow::Result<()> {
    let key = hex::decode(cfg.pubkey.trim())
        .map_err(|e| anyhow::anyhow!("[protection] pubkey is not hex: {}", e))?;
    let pubkey: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("[protection] pubkey must be 32 bytes (64 hex chars)"))?;
    let brands: Vec<Brand> = cfg
        .brands
        .iter()
        .map(|b| b.trim().to_ascii_lowercase())
        .filter(|b| !b.is_empty())
        .map(|name| Brand {
            name,
            verdicts: Default::default(),
        })
        .collect();
    if brands.is_empty() {
        anyhow::bail!("[protection] enabled with an empty brand list — nothing would be checked");
    }
    let allow_hosts = cfg
        .allow_hosts
        .iter()
        .filter_map(|s| AllowHost::parse(s))
        .collect();
    let egress = egress_ips.iter().filter_map(|s| s.parse().ok()).collect();
    let state = State {
        pubkey,
        tiers: TierNames {
            block: cfg.block_bits.clone(),
            notify: cfg.notify_bits.clone(),
        },
        brands,
        allow_hosts,
        egress,
        debug_log_destinations: cfg.debug_log_destinations,
        bundle: RwLock::new(None),
        reload: tokio::sync::Notify::new(),
        reload_secs: cfg.reload_secs.max(5),
        user_allowed: AtomicU64::new(0),
        rules_allowed: AtomicU64::new(0),
        udp_dropped: AtomicU64::new(0),
        unchecked: AtomicU64::new(0),
        reload_ok: AtomicU64::new(0),
        reload_failed: AtomicU64::new(0),
        reload_stale: AtomicU64::new(0),
        reload_mismatch: AtomicU64::new(0),
    };
    if STATE.set(state).is_err() {
        anyhow::bail!("[protection] initialised twice");
    }
    ENABLED.store(true, Ordering::Relaxed);
    CAPS_WANTED.store(true, Ordering::Relaxed);
    log::info!(
        "[protection] on for brands {:?}; {} allow_hosts; bundle not loaded yet",
        cfg.brands,
        cfg.allow_hosts.len()
    );
    Ok(())
}

/// Parse and install a raw bundle (tests and the reloader). A bundle whose
/// `generated_at` is older than the installed one is refused as stale and
/// counted under `outcome="stale"`.
pub fn install_raw(raw: &RawBundle) -> anyhow::Result<()> {
    let st = STATE
        .get()
        .ok_or_else(|| anyhow::anyhow!("protection not initialised"))?;
    let bundle = parse_bundle(raw, &st.pubkey, &st.tiers)?;
    if let Some(cur) = current() {
        if bundle.generated_at < cur.generated_at {
            st.reload_stale.fetch_add(1, Ordering::Relaxed);
            anyhow::bail!(
                "stale bundle: generated_at {} is older than the installed {} (feed_date {} vs {})",
                bundle.generated_at,
                cur.generated_at,
                bundle.feed_date,
                cur.feed_date
            );
        }
    }
    install(bundle);
    Ok(())
}

/// `2026-10-12T03:31:07Z` → epoch seconds. The pipeline writes exactly this
/// shape; a fractional-second or offset form is accepted too.
pub fn parse_generated_at(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        return u64::try_from(t.timestamp()).ok();
    }
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
        .ok()
        .and_then(|t| u64::try_from(t.and_utc().timestamp()).ok())
}

/// Is `version` the sha256 of these meta bytes?
pub fn version_matches(version: &str, meta: &[u8]) -> bool {
    version.trim().eq_ignore_ascii_case(&sha256_hex(meta))
}

pub fn install(bundle: Bundle) {
    let Some(st) = STATE.get() else {
        return;
    };
    let (v4, v6, d) = bundle.counts();
    let version = bundle.version.clone();
    let feed_date = bundle.feed_date.clone();
    if let Ok(mut slot) = st.bundle.write() {
        *slot = Some(Arc::new(bundle));
    }
    st.reload_ok.fetch_add(1, Ordering::Relaxed);
    log::warn!(
        "[protection] bundle {} loaded: {} v4 ranges, {} v6 ranges, {} domains",
        version,
        v4,
        v6,
        d
    );
    crate::messaging::protection_switched(&version, &feed_date);
}

/// What a control stream tells the device about this exit's protection.
pub fn status() -> (bool, Option<String>, Option<String>) {
    match current() {
        Some(b) if enabled() => (true, Some(b.version.clone()), Some(b.feed_date.clone())),
        _ => (false, None, None),
    }
}

pub fn current() -> Option<Arc<Bundle>> {
    STATE.get()?.bundle.read().ok()?.clone()
}

pub fn current_version() -> Option<String> {
    current().map(|b| b.version.clone())
}

/// Ask the reloader to look for a new bundle now (SIGHUP, or a `protection`
/// mailbox message).
pub fn request_reload() {
    if let Some(st) = STATE.get() {
        st.reload.notify_one();
    }
}

/// What a checked tunnel carries: its brand slot for the counters and the
/// user's synced allow rules.
pub struct TunnelCtx {
    brand: usize,
    pub rules: RwLock<UserRules>,
}

/// The context for a `blk1` tunnel of brand `app`, or `None` when protection is
/// off or the brand is not enrolled — then the tunnel still gets its verdict
/// bytes (all `0x00`) but nothing is looked up.
pub fn tunnel_ctx(app: &str) -> Option<Arc<TunnelCtx>> {
    let st = STATE.get()?;
    if !enabled() {
        return None;
    }
    let brand = st
        .brands
        .iter()
        .position(|b| b.name.eq_ignore_ascii_case(app.trim()))?;
    Some(Arc::new(TunnelCtx {
        brand,
        rules: RwLock::new(UserRules::default()),
    }))
}

pub enum HostVerdict {
    /// Allow-listed (ours or the user's): clear, no resolution needed.
    Allowed,
    /// In the domain set.
    Blocked(Verdict),
    /// Not known by name; judge the resolved addresses.
    Unknown,
}

/// First half of the judge: the name alone. Runs before any DNS, so a domain-
/// set hit never resolves and an allow-listed name is never looked up.
pub fn judge_host(ctx: &TunnelCtx, host: &str) -> HostVerdict {
    let Some(st) = STATE.get() else {
        return HostVerdict::Allowed;
    };
    let Some(bundle) = current() else {
        st.unchecked.fetch_add(1, Ordering::Relaxed);
        return HostVerdict::Allowed;
    };
    let name = normalize_host(host);
    if st.allow_hosts.iter().any(|a| a.matches(&name)) {
        return HostVerdict::Allowed;
    }
    if let Ok(rules) = ctx.rules.read() {
        if rules.allows_host(&name) {
            st.rules_allowed.fetch_add(1, Ordering::Relaxed);
            return HostVerdict::Allowed;
        }
    }
    if host.parse::<IpAddr>().is_err() && bundle.domain_hit(&name) {
        return HostVerdict::Blocked(bundle.domain_verdict());
    }
    HostVerdict::Unknown
}

/// Second half: every resolved address the dialer would try. Addresses in
/// `allow_cidrs`, the node's own egress IPs, the user's allowed CIDRs, or the
/// unroutable set (which the dialer skips anyway) are not judged.
pub fn judge_addrs(ctx: &TunnelCtx, addrs: &[SocketAddr]) -> Verdict {
    let Some(st) = STATE.get() else {
        return Verdict::Clear;
    };
    let Some(bundle) = current() else {
        return Verdict::Clear;
    };
    let mut bits = 0u16;
    let mut rules_hit = false;
    let off = ctx.rules.read().map(|r| r.categories_off).unwrap_or(0);
    for a in addrs {
        let ip = a.ip();
        if crate::proxy::is_unroutable(&ip) || crate::proxy::is_carved_out(&ip) {
            continue;
        }
        if st.egress.contains(&ip) {
            continue;
        }
        if let Ok(rules) = ctx.rules.read() {
            if rules.allows_ip(&ip) {
                rules_hit = true;
                continue;
            }
        }
        bits |= bundle.lookup_ip(&ip);
    }
    if rules_hit {
        st.rules_allowed.fetch_add(1, Ordering::Relaxed);
    }
    bundle.verdict_for_bits_masked(bits, off)
}

/// Judge one address with no tunnel context — for the UDP path, where there is
/// no per-stream verdict and the only action is to drop.
pub fn judge_one(ctx: &TunnelCtx, host: &str, ip: &IpAddr) -> Verdict {
    match judge_host(ctx, host) {
        HostVerdict::Allowed => Verdict::Clear,
        HostVerdict::Blocked(v) => v,
        HostVerdict::Unknown => judge_addrs(ctx, &[SocketAddr::new(*ip, 0)]),
    }
}

/// Count a stream's verdict against its brand. `user_allowed` streams were not
/// judged and count separately.
pub fn record(ctx: &TunnelCtx, verdict: &Verdict, user_allowed: bool) {
    let Some(st) = STATE.get() else {
        return;
    };
    if user_allowed {
        st.user_allowed.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if let Some(b) = st.brands.get(ctx.brand) {
        b.verdicts[verdict.tag() as usize].fetch_add(1, Ordering::Relaxed);
    }
}

pub fn brand_name(ctx: &TunnelCtx) -> &'static str {
    STATE
        .get()
        .and_then(|st| st.brands.get(ctx.brand))
        .map(|b| b.name.as_str())
        .unwrap_or("")
}

pub fn inc_udp_dropped() {
    if let Some(st) = STATE.get() {
        st.udp_dropped.fetch_add(1, Ordering::Relaxed);
    }
}

/// Is destination-level debug logging on? Also gates the raw upstream control
/// frames in `messaging`, which carry the user's own rules.
pub fn debug_destinations() -> bool {
    STATE.get().is_some_and(|st| st.debug_log_destinations)
}

/// One line per block, at debug, only with `debug_log_destinations = true`: a
/// production node at debug level must not record where anyone went. Never the
/// cid either way.
pub fn log_block(ctx: &TunnelCtx, host: &str, port: u16, verdict: &Verdict, real_ip: &str) {
    if !STATE.get().is_some_and(|st| st.debug_log_destinations) {
        return;
    }
    if let Verdict::Block { bits, reason } = verdict {
        log::debug!(
            "metric=protection.block brand=\"{}\" host=\"{}\" port={} bits={:#06x} reason=\"{}\" ip=\"{}\"",
            brand_name(ctx),
            host,
            port,
            bits,
            reason,
            real_ip
        );
    }
}

/// Where bundles come from.
#[derive(Debug, Clone)]
pub enum Source {
    Dir(std::path::PathBuf),
    /// `HGETALL protection:bundle`: `version`, `meta`, `sig` (base64),
    /// `v4`/`v6`/`domains` (base64 of the files).
    Valkey(crate::valkey::Config),
}

pub const BUNDLE_KEY: &[u8] = b"protection:bundle";
/// Read deadline per bundle field. The largest (`v4`) is ~7 MB base64 on the
/// real stats; a POP on a slow path to valkey-main must still get it.
pub const BUNDLE_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Load now, then again every `reload_secs`, on SIGHUP, and on
/// [`request_reload`]. A bundle whose version matches the loaded one is not re-
/// read; a bundle that fails to verify is logged and the previous one kept.
pub fn spawn_reloader(source: Source) {
    let Some(st) = STATE.get() else {
        return;
    };
    let every = std::time::Duration::from_secs(st.reload_secs);
    tokio::spawn(async move {
        let mut sighup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
        let mut conn: Option<crate::valkey::Conn> = None;
        loop {
            match reload_once(&source, &mut conn).await {
                Ok(true) => {}
                Ok(false) => log::debug!("[protection] bundle unchanged"),
                Err(e) => {
                    conn = None;

                    let msg = e.to_string();
                    if !msg.starts_with("stale bundle") && !msg.starts_with("version mismatch") {
                        st.reload_failed.fetch_add(1, Ordering::Relaxed);
                    }
                    log::warn!(
                        "[protection] bundle reload failed: {} — keeping {}",
                        e,
                        current_version().unwrap_or_else(|| "nothing (no bundle loaded)".into())
                    );
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(every) => {}
                _ = st.reload.notified() => {}
                _ = async {
                    match sighup.as_mut() {
                        Some(s) => { s.recv().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => log::info!("[protection] SIGHUP — reloading bundle"),
            }
        }
    });
}

async fn reload_once(
    source: &Source,
    conn: &mut Option<crate::valkey::Conn>,
) -> anyhow::Result<bool> {
    let loaded = current_version();
    match source {
        Source::Dir(dir) => {
            let meta = std::fs::read(dir.join("meta.json"))?;
            let version = sha256_hex(&meta);
            if loaded.as_deref() == Some(version.as_str()) {
                return Ok(false);
            }
            let raw = RawBundle::read_dir(dir)?;
            install_raw(&raw)?;
            Ok(true)
        }
        Source::Valkey(cfg) => {
            if conn.is_none() {
                *conn = Some(crate::valkey::Conn::connect(cfg).await?);
            }
            let c = conn.as_mut().expect("just connected");
            let version = c
                .cmd(&[b"HGET", BUNDLE_KEY, b"version"])
                .await?
                .into_err()?
                .as_string()
                .ok_or_else(|| anyhow::anyhow!("protection:bundle has no version field"))?;
            if loaded.as_deref() == Some(version.as_str()) {
                return Ok(false);
            }

            let mut fields = Vec::with_capacity(5);
            for name in [&b"meta"[..], b"sig", b"v4", b"v6", b"domains"] {
                let r = c
                    .cmd_for(&[b"HGET", BUNDLE_KEY, name], BUNDLE_FETCH_TIMEOUT)
                    .await?
                    .into_err()?;
                fields.push(r);
            }
            let raw = raw_from_hmget(&crate::valkey::Resp::Arr(fields))?;
            if !version_matches(&version, &raw.meta) {
                if let Some(st) = STATE.get() {
                    st.reload_mismatch.fetch_add(1, Ordering::Relaxed);
                }
                anyhow::bail!(
                    "version mismatch: protection:bundle version {:?} is not the sha256 of its meta ({}); \
                     the publisher must write version = sha256(meta.json)",
                    version,
                    sha256_hex(&raw.meta)
                );
            }
            install_raw(&raw)?;
            Ok(true)
        }
    }
}

/// Decode an `HMGET protection:bundle meta sig v4 v6 domains` reply.
pub fn raw_from_hmget(r: &crate::valkey::Resp) -> anyhow::Result<RawBundle> {
    use base64::Engine;
    let crate::valkey::Resp::Arr(items) = r else {
        anyhow::bail!("HMGET: unexpected reply shape");
    };
    if items.len() != 5 {
        anyhow::bail!("HMGET: {} fields, want 5", items.len());
    }
    let field = |i: usize, name: &str| -> anyhow::Result<Vec<u8>> {
        items[i]
            .as_bytes()
            .map(|b| b.to_vec())
            .ok_or_else(|| anyhow::anyhow!("protection:bundle has no {} field", name))
    };
    let b64 = |data: Vec<u8>, name: &str| -> anyhow::Result<Vec<u8>> {
        let trimmed: Vec<u8> = data
            .into_iter()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(&trimmed)
            .map_err(|e| anyhow::anyhow!("{}: not base64: {}", name, e))
    };
    Ok(RawBundle {
        meta: field(0, "meta")?,
        sig: b64(field(1, "sig")?, "sig")?,
        v4: b64(field(2, "v4")?, "v4")?,
        v6: b64(field(3, "v6")?, "v6")?,
        domains_gz: b64(field(4, "domains")?, "domains")?,
    })
}

pub fn prometheus(out: &mut String) {
    use std::fmt::Write;
    let Some(st) = STATE.get() else {
        return;
    };
    let bundle = current();
    out.push_str(
        "# HELP redsocket_protection_bundle_loaded 1 when a verified bundle is installed\n",
    );
    out.push_str("# TYPE redsocket_protection_bundle_loaded gauge\n");
    let _ = writeln!(
        out,
        "redsocket_protection_bundle_loaded {}",
        u8::from(bundle.is_some())
    );
    if let Some(b) = &bundle {
        let (v4, v6, d) = b.counts();
        out.push_str(
            "# HELP redsocket_protection_bundle_entries entries per table of the loaded bundle\n",
        );
        out.push_str("# TYPE redsocket_protection_bundle_entries gauge\n");
        let _ = writeln!(
            out,
            "redsocket_protection_bundle_entries{{table=\"v4\"}} {}",
            v4
        );
        let _ = writeln!(
            out,
            "redsocket_protection_bundle_entries{{table=\"v6\"}} {}",
            v6
        );
        let _ = writeln!(
            out,
            "redsocket_protection_bundle_entries{{table=\"domains\"}} {}",
            d
        );
        out.push_str("# HELP redsocket_protection_bundle_age_seconds seconds since the bundle was installed\n");
        out.push_str("# TYPE redsocket_protection_bundle_age_seconds gauge\n");
        let _ = writeln!(
            out,
            "redsocket_protection_bundle_age_seconds {}",
            b.loaded_at.elapsed().as_secs()
        );
        out.push_str("# HELP redsocket_protection_bundle_info the loaded stats date\n");
        let _ = writeln!(
            out,
            "redsocket_protection_bundle_info{{feed_date=\"{}\"}} 1",
            b.feed_date
        );
    }
    out.push_str("# HELP redsocket_protection_verdicts_total stream verdicts per brand\n");
    out.push_str("# TYPE redsocket_protection_verdicts_total counter\n");
    for b in &st.brands {
        for (i, name) in ["clear", "notify", "block"].iter().enumerate() {
            let _ = writeln!(
                out,
                "redsocket_protection_verdicts_total{{brand=\"{}\",verdict=\"{}\"}} {}",
                b.name,
                name,
                b.verdicts[i].load(Ordering::Relaxed)
            );
        }
    }
    out.push_str("# HELP redsocket_protection_user_allowed_total streams skipped on the flags-byte user-allow bit\n");
    out.push_str("# TYPE redsocket_protection_user_allowed_total counter\n");
    let _ = writeln!(
        out,
        "redsocket_protection_user_allowed_total {}",
        st.user_allowed.load(Ordering::Relaxed)
    );
    out.push_str("# HELP redsocket_protection_rules_allowed_total streams cleared by the user's synced allow rules\n");
    out.push_str("# TYPE redsocket_protection_rules_allowed_total counter\n");
    let _ = writeln!(
        out,
        "redsocket_protection_rules_allowed_total {}",
        st.rules_allowed.load(Ordering::Relaxed)
    );
    out.push_str("# HELP redsocket_protection_unchecked_total streams of checked tunnels given 0x00 because no bundle was installed\n");
    out.push_str("# TYPE redsocket_protection_unchecked_total counter\n");
    let _ = writeln!(
        out,
        "redsocket_protection_unchecked_total {}",
        st.unchecked.load(Ordering::Relaxed)
    );
    out.push_str("# HELP redsocket_protection_udp_dropped_total UDP datagrams to BLOCK-tier targets dropped\n");
    out.push_str("# TYPE redsocket_protection_udp_dropped_total counter\n");
    let _ = writeln!(
        out,
        "redsocket_protection_udp_dropped_total {}",
        st.udp_dropped.load(Ordering::Relaxed)
    );
    out.push_str("# HELP redsocket_protection_reloads_total bundle loads by outcome\n");
    out.push_str("# TYPE redsocket_protection_reloads_total counter\n");
    let _ = writeln!(
        out,
        "redsocket_protection_reloads_total{{outcome=\"ok\"}} {}",
        st.reload_ok.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "redsocket_protection_reloads_total{{outcome=\"failed\"}} {}",
        st.reload_failed.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "redsocket_protection_reloads_total{{outcome=\"stale\"}} {}",
        st.reload_stale.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "redsocket_protection_reloads_total{{outcome=\"mismatch\"}} {}",
        st.reload_mismatch.load(Ordering::Relaxed)
    );
}

/// Build a signed bundle in memory with a fresh Ed25519 key. Public so the
/// integration tests under `tests/` can use it; it is not reachable from any
/// runtime path.
pub mod fixture {
    use super::RawBundle;
    use std::io::Write;

    /// Standard bit table, as `rules.json` defines it.
    pub const BITS: &[(&str, u8, &str)] = &[
        ("BLOCK", 0, "tier"),
        ("NOTIFY", 1, "tier"),
        ("BOGON", 2, "tier"),
        ("controller", 4, "block_reason"),
        ("malware", 5, "block_reason"),
        ("phishing", 6, "block_reason"),
        ("orb", 7, "block_reason"),
        ("rating_malicious", 8, "block_reason"),
        ("scanner", 9, "notify_reason"),
        ("ost", 10, "notify_reason"),
        ("risknet", 11, "notify_reason"),
        ("sinkhole", 12, "notify_reason"),
        ("honeypot", 13, "notify_reason"),
        ("proxy", 14, "notify_reason"),
    ];

    pub struct Signer {
        key: ring::signature::Ed25519KeyPair,
        pub pubkey: [u8; 32],
    }

    impl Signer {
        pub fn new() -> Signer {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
            let key = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key");
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(ring::signature::KeyPair::public_key(&key).as_ref());
            Signer { key, pubkey }
        }
        pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
            self.key.sign(msg).as_ref().to_vec()
        }
        pub fn pubkey_hex(&self) -> String {
            hex::encode(self.pubkey)
        }
    }

    impl Default for Signer {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Sorted by start, as the pipeline writes it. Pass raw bytes to [`assemble`]
    /// to build a deliberately malformed table.
    pub fn v4_bin(ranges: &[(u32, u32, u16)]) -> Vec<u8> {
        let mut sorted = ranges.to_vec();
        sorted.sort_by_key(|r| r.0);
        let mut out = Vec::with_capacity(ranges.len() * 10);
        for (s, e, b) in &sorted {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
        out
    }

    pub fn v6_bin(ranges: &[(u128, u128, u16)]) -> Vec<u8> {
        let mut sorted = ranges.to_vec();
        sorted.sort_by_key(|r| r.0);
        let mut out = Vec::with_capacity(ranges.len() * 34);
        for (s, e, b) in &sorted {
            out.extend_from_slice(&s.to_le_bytes());
            out.extend_from_slice(&e.to_le_bytes());
            out.extend_from_slice(&b.to_le_bytes());
        }
        out
    }

    pub fn domains_gz(domains: &[&str]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        for d in domains {
            gz.write_all(d.as_bytes()).unwrap();
            gz.write_all(b"\n").unwrap();
        }
        gz.finish().unwrap()
    }

    /// Assemble `meta.json` + `meta.sig` around the three files.
    pub fn assemble(
        signer: &Signer,
        feed_date: &str,
        v4: Vec<u8>,
        v6: Vec<u8>,
        domains_gz: Vec<u8>,
    ) -> RawBundle {
        assemble_at(signer, feed_date, GENERATED_AT, v4, v6, domains_gz)
    }

    /// The `generated_at` every fixture carries unless told otherwise.
    pub const GENERATED_AT: &str = "2026-10-12T00:00:00Z";

    /// Same, with an explicit `generated_at` (RFC 3339).
    pub fn assemble_at(
        signer: &Signer,
        feed_date: &str,
        generated_at: &str,
        v4: Vec<u8>,
        v6: Vec<u8>,
        domains_gz: Vec<u8>,
    ) -> RawBundle {
        use sha2::Digest;
        let sha = |d: &[u8]| hex::encode(sha2::Sha256::digest(d));
        let mut bits = serde_json::Map::new();
        for (name, bit, kind) in BITS {
            bits.insert(
                name.to_string(),
                serde_json::json!({"bit": bit, "kind": kind, "mask": format!("0x{:04x}", 1u16 << bit)}),
            );
        }
        let meta = serde_json::json!({
            "format_version": 1,
            "feed_date": feed_date,
            "generated_at": generated_at,
            "bits": bits,
            "entries": {"v4": v4.len() / 10, "v6": v6.len() / 34},
            "files": {
                "v4.bin": {"bytes": v4.len(), "sha256": sha(&v4)},
                "v6.bin": {"bytes": v6.len(), "sha256": sha(&v6)},
                "domains.txt.gz": {"bytes": domains_gz.len(), "sha256": sha(&domains_gz)},
            },
        });
        let meta = (serde_json::to_string_pretty(&meta).unwrap() + "\n").into_bytes();
        let sig = signer.sign(&meta);
        RawBundle {
            meta,
            sig,
            v4,
            v6,
            domains_gz,
        }
    }

    pub fn build(
        signer: &Signer,
        feed_date: &str,
        v4: &[(u32, u32, u16)],
        v6: &[(u128, u128, u16)],
        domains: &[&str],
    ) -> RawBundle {
        assemble(
            signer,
            feed_date,
            v4_bin(v4),
            v6_bin(v6),
            domains_gz(domains),
        )
    }

    pub fn write_dir(raw: &RawBundle, dir: &std::path::Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("meta.json"), &raw.meta).unwrap();
        std::fs::write(dir.join("meta.sig"), &raw.sig).unwrap();
        std::fs::write(dir.join("v4.bin"), &raw.v4).unwrap();
        std::fs::write(dir.join("v6.bin"), &raw.v6).unwrap();
        std::fs::write(dir.join("domains.txt.gz"), &raw.domains_gz).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    const BLOCK: u16 = 0x0001;
    const NOTIFY: u16 = 0x0002;
    const CONTROLLER: u16 = 0x0010;
    const PHISHING: u16 = 0x0040;
    const RATING: u16 = 0x0100;
    const SCANNER: u16 = 0x0200;
    const PROXY: u16 = 0x4000;

    fn ip4(s: &str) -> u32 {
        u32::from(s.parse::<std::net::Ipv4Addr>().unwrap())
    }
    fn ip6(s: &str) -> u128 {
        u128::from(s.parse::<std::net::Ipv6Addr>().unwrap())
    }
    fn tiers() -> TierNames {
        TierNames {
            block: [
                "controller",
                "malware",
                "phishing",
                "orb",
                "rating_malicious",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            notify: Vec::new(),
        }
    }
    fn sample(signer: &fixture::Signer) -> RawBundle {
        fixture::build(
            signer,
            "2026-10-11",
            &[
                (
                    ip4("1.12.74.49"),
                    ip4("1.12.74.49"),
                    BLOCK | CONTROLLER | RATING,
                ),
                (ip4("1.0.0.2"), ip4("1.0.0.255"), NOTIFY | SCANNER),
                (ip4("2.26.225.0"), ip4("2.26.225.255"), BLOCK | PHISHING),
                (ip4("203.0.113.0"), ip4("203.0.113.255"), BLOCK | RATING),
            ],
            &[
                (ip6("2001:db8::"), ip6("2001:db8::ffff"), NOTIFY | PROXY),
                (ip6("2a06:1::1"), ip6("2a06:1::1"), BLOCK | CONTROLLER),
            ],
            &["evil.example", "xn--bad-example.test", "c2.bad.example"],
        )
    }

    /// The exact hello the client core emits (`ctl::mux_hello`): one MUX2 line, no
    /// separate META frame, brand in `app`, caps at index 6.
    #[test]
    fn the_client_cores_hello_line_parses_as_sent() {
        let hello = "MUX2|Asia/Dubai|rostam||4f2a9c1e8b7d3a60||blk1,msg1";
        let parts: Vec<&str> = hello.splitn(7, '|').collect();
        assert_eq!(parts[0], "MUX2");
        assert_eq!(parts[2], "rostam", "brand rides in app");
        assert_eq!(parts[4], "4f2a9c1e8b7d3a60");
        assert_eq!(parts[5], "", "no sni");
        assert_eq!(
            header_caps(hello),
            Caps {
                blk1: true,
                msg1: true
            }
        );
        assert_eq!(
            header_caps("MUX2|UTC|rostam||c||blk1"),
            Caps {
                blk1: true,
                msg1: false
            }
        );
        assert_eq!(
            header_caps("MUX2|UTC|rostam||c||msg1"),
            Caps {
                blk1: false,
                msg1: true
            }
        );

        assert_eq!(header_caps("MUX2|Asia/Tehran|||abc|"), Caps::default());
    }

    #[test]
    fn caps_are_field_six_and_tolerant() {
        assert_eq!(
            header_caps("META|Asia/Dubai|rostam||cid||blk1,msg1"),
            Caps {
                blk1: true,
                msg1: true
            }
        );
        assert_eq!(
            header_caps("MUX2|tz|rostam||cid||blk1"),
            Caps {
                blk1: true,
                msg1: false
            }
        );
        assert_eq!(
            header_caps("MUX2|tz|rostam||cid|| msg1 ,blk1|future=1"),
            Caps {
                blk1: true,
                msg1: true
            }
        );

        assert_eq!(header_caps("META|Asia/Tehran|||cid"), Caps::default());
        assert_eq!(header_caps("MUX2|Asia/Tehran|||cid|"), Caps::default());
        assert_eq!(header_caps("META|tz|app|os|cid|sni|"), Caps::default());

        assert_eq!(header_caps("META||||||zzz9"), Caps::default());
        assert!(!Caps::default().any());
    }

    #[test]
    fn verdict_framing_is_tag_bits_le_len_reason() {
        assert_eq!(Verdict::Clear.encode(), vec![0x00]);
        let n = Verdict::Notify {
            bits: 0x1002,
            reason: "openresolvers".into(),
        };
        let mut want = vec![0x01, 0x02, 0x10, 13];
        want.extend_from_slice(b"openresolvers");
        assert_eq!(n.encode(), want, "bits must be little-endian");
        let b = Verdict::Block {
            bits: 0x0111,
            reason: "controller,rating_malicious".into(),
        };
        let enc = b.encode();
        assert_eq!(&enc[..4], &[0x02, 0x11, 0x01, 27]);
        assert_eq!(decode_verdict(&enc).unwrap(), (b.clone(), enc.len()));

        let long = Verdict::Block {
            bits: 1,
            reason: "é".repeat(200),
        };
        let enc = long.encode();
        assert_eq!(enc[3] as usize, 254);
        assert_eq!(enc.len(), 4 + 254);
        assert!(std::str::from_utf8(&enc[4..]).is_ok());
        assert!(decode_verdict(&[0x01, 0x00]).is_err());
        assert!(decode_verdict(&[0x07]).is_err());
    }

    #[test]
    fn flags_byte_is_read_after_the_trimmed_header() {
        let r = parse_stream_request(&[5, 1, 8, 8, 8, 8, 0, 53]).unwrap();
        assert_eq!(
            (r.host.as_str(), r.port, r.user_allowed),
            ("8.8.8.8", 53, false)
        );

        let r = parse_stream_request(&[5, 1, 8, 8, 8, 8, 0, 53, 0x01]).unwrap();
        assert_eq!(
            (r.host.as_str(), r.port, r.user_allowed),
            ("8.8.8.8", 53, true)
        );
        let r = parse_stream_request(&[5, 1, 8, 8, 8, 8, 0, 53, 0x00]).unwrap();
        assert!(!r.user_allowed);
        let r = parse_stream_request(&[5, 3, 3, b'a', b'.', b'b', 1, 0xbb, 0x01]).unwrap();
        assert_eq!(
            (r.host.as_str(), r.port, r.user_allowed),
            ("a.b", 443, true)
        );
        let mut v6 = vec![5u8, 4];
        v6.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        v6.extend_from_slice(&[0, 80, 0x01]);
        let r = parse_stream_request(&v6).unwrap();
        assert_eq!(
            (r.host.as_str(), r.port, r.user_allowed),
            ("2001:db8::1", 80, true)
        );

        assert!(parse_stream_request(&[5, 1, 8, 8, 8, 8, 0, 53, 0x02]).is_err());
        assert!(parse_stream_request(&[5, 1, 8, 8, 8, 8, 0, 53, 0x81]).is_err());
        assert!(parse_stream_request(&[5, 1, 8, 8, 8, 8, 0, 53, 0x00, 0x00]).is_err());

        assert!(parse_stream_request(&[4, 1, 0, 0]).is_err());
        assert!(parse_stream_request(&[5, 9, 0, 0]).is_err());
        assert!(parse_stream_request(&[5, 1, 8]).is_err());
    }

    #[test]
    fn bundle_verifies_signature_then_hashes_then_tables() {
        let signer = fixture::Signer::new();
        let raw = sample(&signer);
        let b = parse_bundle(&raw, &signer.pubkey, &tiers()).expect("good bundle loads");
        assert_eq!(b.counts(), (4, 2, 3));
        assert_eq!(b.feed_date, "2026-10-11");

        let other = fixture::Signer::new();
        assert!(parse_bundle(&raw, &other.pubkey, &tiers()).is_err());

        let mut t = raw.clone();
        let n = t.meta.len();
        t.meta[n - 2] ^= 0x01;
        assert!(parse_bundle(&t, &signer.pubkey, &tiers()).is_err());

        let mut t = raw.clone();
        t.v4[0] ^= 0x01;
        let e = parse_bundle(&t, &signer.pubkey, &tiers())
            .unwrap_err()
            .to_string();
        assert!(e.contains("sha256"), "{e}");

        let mut t = raw.clone();
        t.sig.pop();
        assert!(parse_bundle(&t, &signer.pubkey, &tiers()).is_err());

        let bad = fixture::build(
            &signer,
            "2026-10-12",
            &[(10, 20, BLOCK | CONTROLLER), (15, 30, BLOCK | CONTROLLER)],
            &[],
            &[],
        );
        let e = parse_bundle(&bad, &signer.pubkey, &tiers())
            .unwrap_err()
            .to_string();
        assert!(e.contains("overlaps"), "{e}");

        let bad = fixture::build(&signer, "x", &[(30, 20, 1)], &[], &[]);
        assert!(parse_bundle(&bad, &signer.pubkey, &tiers()).is_err());
        let mut unsorted = fixture::v4_bin(&[(1, 2, 1)]);
        unsorted.splice(0..0, fixture::v4_bin(&[(20, 30, 1)]));
        let bad = fixture::assemble(&signer, "x", unsorted, Vec::new(), fixture::domains_gz(&[]));
        let e = parse_bundle(&bad, &signer.pubkey, &tiers())
            .unwrap_err()
            .to_string();
        assert!(e.contains("out of order"), "{e}");

        assert!(parse_bundle(
            &raw,
            &signer.pubkey,
            &TierNames {
                block: vec!["nonexistent".into()],
                notify: vec![],
            },
        )
        .is_ok());
        let mut m: serde_json::Value = serde_json::from_slice(&raw.meta).unwrap();
        for (_, def) in m["bits"].as_object_mut().unwrap().iter_mut() {
            if def["kind"] == "block_reason" {
                def["kind"] = serde_json::json!("notify_reason");
            }
        }
        let meta = (serde_json::to_string_pretty(&m).unwrap() + "\n").into_bytes();
        let sig = signer.sign(&meta);
        let e = parse_bundle(
            &RawBundle {
                meta,
                sig,
                ..raw.clone()
            },
            &signer.pubkey,
            &TierNames::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("no block bit"), "{e}");
        assert_eq!(meta_version(&raw.meta).unwrap(), "2026-10-11");
    }

    #[test]
    fn version_is_the_meta_sha_and_generated_at_is_required() {
        let signer = fixture::Signer::new();
        let raw = sample(&signer);
        let b = parse_bundle(&raw, &signer.pubkey, &tiers()).unwrap();
        assert_eq!(b.version, hex::encode(sha2::Sha256::digest(&raw.meta)));
        assert!(version_matches(&b.version, &raw.meta));
        assert!(version_matches(&b.version.to_ascii_uppercase(), &raw.meta));
        assert!(
            !version_matches("2026-10-11", &raw.meta),
            "the old date form is not a version"
        );
        assert_eq!(
            b.generated_at,
            parse_generated_at("2026-10-12T00:00:00Z").unwrap()
        );
        assert_eq!(parse_generated_at("1970-01-01T00:01:40Z"), Some(100));
        assert_eq!(parse_generated_at("1970-01-01T00:01:40+00:00"), Some(100));
        assert_eq!(parse_generated_at("yesterday"), None);

        let again = fixture::assemble_at(
            &signer,
            "2026-10-11",
            "2026-10-12T06:00:00Z",
            raw.v4.clone(),
            raw.v6.clone(),
            raw.domains_gz.clone(),
        );
        let b2 = parse_bundle(&again, &signer.pubkey, &tiers()).unwrap();
        assert_ne!(b2.version, b.version);
        assert!(b2.generated_at > b.generated_at);

        let strip = |key: &str| {
            let mut m: serde_json::Value = serde_json::from_slice(&raw.meta).unwrap();
            m.as_object_mut().unwrap().remove(key);
            let meta = (serde_json::to_string_pretty(&m).unwrap() + "\n").into_bytes();
            let sig = signer.sign(&meta);
            RawBundle {
                meta,
                sig,
                ..raw.clone()
            }
        };
        let e = parse_bundle(&strip("generated_at"), &signer.pubkey, &tiers())
            .unwrap_err()
            .to_string();
        assert!(e.contains("generated_at"), "{e}");
        let e = parse_bundle(&strip("feed_date"), &signer.pubkey, &tiers())
            .unwrap_err()
            .to_string();
        assert!(e.contains("feed_date"), "{e}");
    }

    #[test]
    fn range_lookup_hits_boundaries_and_misses_gaps() {
        let signer = fixture::Signer::new();
        let b = parse_bundle(&sample(&signer), &signer.pubkey, &tiers()).unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(b.lookup_ip(&ip("1.12.74.49")), BLOCK | CONTROLLER | RATING);
        assert_eq!(b.lookup_ip(&ip("1.12.74.48")), 0);
        assert_eq!(b.lookup_ip(&ip("1.12.74.50")), 0);
        assert_eq!(b.lookup_ip(&ip("1.0.0.2")), NOTIFY | SCANNER);
        assert_eq!(b.lookup_ip(&ip("1.0.0.255")), NOTIFY | SCANNER);
        assert_eq!(b.lookup_ip(&ip("1.0.0.1")), 0);
        assert_eq!(b.lookup_ip(&ip("1.0.1.0")), 0);
        assert_eq!(b.lookup_ip(&ip("2.26.225.180")), BLOCK | PHISHING);
        assert_eq!(b.lookup_ip(&ip("8.8.8.8")), 0);
        assert_eq!(b.lookup_ip(&ip("0.0.0.0")), 0);
        assert_eq!(b.lookup_ip(&ip("255.255.255.255")), 0);
        assert_eq!(b.lookup_ip(&ip("2001:db8::5")), NOTIFY | PROXY);
        assert_eq!(b.lookup_ip(&ip("2001:db8::1:0")), 0);
        assert_eq!(b.lookup_ip(&ip("2a06:1::1")), BLOCK | CONTROLLER);
        assert_eq!(b.lookup_ip(&ip("2a06:1::2")), 0);

        assert_eq!(b.lookup_ip(&ip("::ffff:2.26.225.1")), BLOCK | PHISHING);

        let empty = parse_bundle(
            &fixture::build(&signer, "e", &[], &[], &[]),
            &signer.pubkey,
            &tiers(),
        )
        .unwrap();
        assert_eq!(empty.lookup_ip(&ip("1.2.3.4")), 0);
        assert_eq!(empty.lookup_ip(&ip("::1")), 0);
    }

    #[test]
    fn domains_match_exact_and_parent_labels() {
        let signer = fixture::Signer::new();
        let b = parse_bundle(&sample(&signer), &signer.pubkey, &tiers()).unwrap();
        assert!(b.domain_hit("evil.example"));
        assert!(b.domain_hit("www.evil.example"));
        assert!(b.domain_hit("a.b.c.evil.example"));
        assert!(b.domain_hit("c2.bad.example"));
        assert!(
            !b.domain_hit("bad.example"),
            "a child in the set does not taint its parent"
        );
        assert!(
            !b.domain_hit("notevil.example"),
            "suffix match must respect label boundaries"
        );
        assert!(!b.domain_hit("example"));
        assert!(!b.domain_hit("evil.example.com"));
        assert_eq!(normalize_host("WWW.Evil.Example."), "www.evil.example");
        assert_eq!(
            normalize_host("evil.example..."),
            "evil.example",
            "every trailing dot"
        );

        assert_eq!(
            normalize_host("bäd-example.test"),
            "xn--bd-example-q5a.test"
        );
        assert_eq!(
            normalize_host("BÄD-example.TEST."),
            "xn--bd-example-q5a.test"
        );
        assert_eq!(normalize_host("пример.рф"), "xn--e1afmkfd.xn--p1ai");
        assert!(normalize_host("www.bäd-example.test").starts_with("www.xn--"));
        assert!(matches!(
            normalize_host("already.lower"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn tiers_follow_the_configured_bit_names() {
        let signer = fixture::Signer::new();
        let raw = sample(&signer);
        let b = parse_bundle(&raw, &signer.pubkey, &tiers()).unwrap();
        assert_eq!(
            b.verdict_for_bits(BLOCK | CONTROLLER | RATING),
            Verdict::Block {
                bits: BLOCK | CONTROLLER | RATING,
                reason: "controller,rating_malicious".into()
            }
        );
        assert_eq!(
            b.verdict_for_bits(NOTIFY | SCANNER),
            Verdict::Notify {
                bits: NOTIFY | SCANNER,
                reason: "scanner".into()
            }
        );

        assert!(b
            .verdict_for_bits(BLOCK | NOTIFY | PHISHING | SCANNER)
            .is_block());
        assert_eq!(b.verdict_for_bits(0), Verdict::Clear);
        assert_eq!(
            b.verdict_for_bits(0x0004),
            Verdict::Clear,
            "BOGON alone is informational"
        );

        assert_eq!(
            b.verdict_for_bits_masked(BLOCK | PHISHING | RATING, PHISHING),
            Verdict::Block {
                bits: BLOCK | PHISHING | RATING,
                reason: "rating_malicious".into()
            }
        );
        assert_eq!(
            b.verdict_for_bits_masked(BLOCK | PHISHING | RATING, PHISHING | RATING),
            Verdict::Clear
        );
        assert!(matches!(
            b.verdict_for_bits_masked(BLOCK | NOTIFY | PHISHING | SCANNER, PHISHING),
            Verdict::Notify { .. }
        ));
        assert_eq!(UserRules::new(&[], CONTROLLER).categories_off, CONTROLLER);
        assert!(!UserRules::new(&[], CONTROLLER).is_empty());

        const MALWARE: u16 = 0x0020;
        assert!(b
            .verdict_for_bits_masked(BLOCK | CONTROLLER, CONTROLLER)
            .is_block());
        assert!(b
            .verdict_for_bits_masked(BLOCK | MALWARE, MALWARE | PHISHING)
            .is_block());
        assert!(b
            .verdict_for_bits_masked(BLOCK | CONTROLLER | MALWARE, 0xffff)
            .is_block());
        assert_eq!(
            b.verdict_for_bits_masked(BLOCK | PHISHING, 0xffff),
            Verdict::Clear
        );

        let moved = TierNames {
            block: vec!["controller".into()],
            notify: vec!["phishing".into()],
        };
        let b = parse_bundle(&raw, &signer.pubkey, &moved).unwrap();
        assert!(matches!(
            b.verdict_for_bits(BLOCK | PHISHING),
            Verdict::Notify { .. }
        ));
        assert!(
            b.verdict_for_bits(RATING).is_block(),
            "unnamed bits follow their kind"
        );

        let by_kind = parse_bundle(&raw, &signer.pubkey, &TierNames::default()).unwrap();
        assert!(by_kind.verdict_for_bits(BLOCK | CONTROLLER).is_block());
        assert!(by_kind.verdict_for_bits(BLOCK | RATING).is_block());
        assert!(matches!(
            by_kind.verdict_for_bits(NOTIFY | SCANNER),
            Verdict::Notify { .. }
        ));
        assert!(matches!(
            by_kind.verdict_for_bits(PROXY),
            Verdict::Notify { .. }
        ));

        let mut m: serde_json::Value = serde_json::from_slice(&raw.meta).unwrap();
        m["bits"]["ransomware"] =
            serde_json::json!({"bit": 15, "kind": "block_reason", "mask": "0x8000"});
        let meta = (serde_json::to_string_pretty(&m).unwrap()
            + "
")
        .into_bytes();
        let sig = signer.sign(&meta);
        let newer = RawBundle {
            meta,
            sig,
            ..raw.clone()
        };
        let b = parse_bundle(&newer, &signer.pubkey, &TierNames::default()).unwrap();
        assert_eq!(
            b.verdict_for_bits(BLOCK | 0x8000),
            Verdict::Block {
                bits: BLOCK | 0x8000,
                reason: "ransomware".into()
            }
        );

        m["bits"]["weird"] = serde_json::json!({"bit": 3, "kind": "something_else"});
        let meta = (serde_json::to_string_pretty(&m).unwrap()
            + "
")
        .into_bytes();
        let sig = signer.sign(&meta);
        let b = parse_bundle(
            &RawBundle {
                meta,
                sig,
                ..raw.clone()
            },
            &signer.pubkey,
            &TierNames::default(),
        )
        .unwrap();
        assert!(matches!(b.verdict_for_bits(0x0008), Verdict::Notify { .. }));
    }

    #[test]
    fn allow_hosts_and_user_rules_match_as_documented() {
        let cf = AllowHost::parse("*.cloudfront.net").unwrap();
        assert!(cf.matches("d1.cloudfront.net"));
        assert!(cf.matches("a.b.cloudfront.net"));
        assert!(cf.matches("cloudfront.net"));
        assert!(!cf.matches("notcloudfront.net"));
        let exact = AllowHost::parse("rostam.app").unwrap();
        assert!(exact.matches("rostam.app"));
        assert!(!exact.matches("www.rostam.app"));
        assert!(AllowHost::parse("  ").is_none());

        let rules = UserRules::from_allow(&[
            "Example.COM".into(),
            "10.9.0.0/16".into(),
            "10.9.1.1/32".into(),
            "2606:4700::1111".into(),
            "".into(),
        ]);
        assert!(rules.allows_host("example.com"));
        assert!(rules.allows_host("www.example.com"));
        assert!(!rules.allows_host("badexample.com"));
        assert!(
            rules.allows_ip(&"10.9.1.1".parse().unwrap()),
            "the /32 counts"
        );
        assert!(
            !rules.allows_ip(&"10.9.1.2".parse().unwrap()),
            "the /16 does not: wider than one destination"
        );
        assert!(!rules.allows_ip(&"10.10.1.1".parse().unwrap()));
        assert!(rules.allows_ip(&"2606:4700::1111".parse().unwrap()));
        assert!(UserRules::default().is_empty());

        for ok in [
            "a.example",
            "x-y_z.example",
            "1.2.3.4",
            "1.2.3.4/32",
            "::1",
            "::1/128",
        ] {
            assert!(valid_rule_entry(ok), "{ok}");
        }
        for bad in [
            "",
            "10.0.0.0/8",
            "::/0",
            "1.2.3.4/31",
            "a b.example",
            "a..b",
            "*.example",
            "a/b",
            &"x".repeat(254),
        ] {
            assert!(!valid_rule_entry(bad), "{bad:?}");
        }
        let many: Vec<String> = (0..300).map(|i| format!("h{i}.example")).collect();
        let r = UserRules::from_allow(&many);
        assert!(r.allows_host("h199.example"));
        assert!(
            !r.allows_host("h200.example"),
            "entries past the cap are ignored"
        );
    }

    #[test]
    fn hmget_reply_decodes_base64_fields() {
        use base64::Engine;
        let signer = fixture::Signer::new();
        let raw = sample(&signer);
        let b64 = |d: &[u8]| {
            base64::engine::general_purpose::STANDARD
                .encode(d)
                .into_bytes()
        };
        let reply = crate::valkey::Resp::Arr(vec![
            crate::valkey::Resp::Str(raw.meta.clone()),
            crate::valkey::Resp::Str(b64(&raw.sig)),
            crate::valkey::Resp::Str(b64(&raw.v4)),
            crate::valkey::Resp::Str(b64(&raw.v6)),
            crate::valkey::Resp::Str(b64(&raw.domains_gz)),
        ]);
        let got = raw_from_hmget(&reply).unwrap();
        assert_eq!(got.sig, raw.sig);
        assert_eq!(got.v4, raw.v4);
        assert_eq!(got.domains_gz, raw.domains_gz);
        assert!(parse_bundle(&got, &signer.pubkey, &tiers()).is_ok());
        let missing = crate::valkey::Resp::Arr(vec![crate::valkey::Resp::Nil; 5]);
        assert!(raw_from_hmget(&missing).is_err());
    }

    #[test]
    fn dir_roundtrip() {
        let signer = fixture::Signer::new();
        let raw = sample(&signer);
        let dir = std::env::temp_dir().join(format!("rs-protection-{}", std::process::id()));
        fixture::write_dir(&raw, &dir);
        let back = RawBundle::read_dir(&dir).unwrap();
        assert_eq!(back.meta, raw.meta);
        assert!(parse_bundle(&back, &signer.pubkey, &tiers()).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A measurement, not a test — run with `cargo test --lib memory_footprint --
    /// --ignored --nocapture`. Sizes the tables at 2x the real bundle (540k v4,
    /// 1.5k v6, 851 domains) and well beyond on domains.
    #[test]
    #[ignore]
    fn memory_footprint_300k_ranges_1m_domains() {
        fn rss_kb() -> u64 {
            let out = std::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse()
                .unwrap_or(0)
        }
        let signer = fixture::Signer::new();
        let v4: Vec<(u32, u32, u16)> = (0..300_000u32)
            .map(|i| {
                (
                    i * 16,
                    i * 16 + 7,
                    if i % 7 == 0 {
                        BLOCK | CONTROLLER
                    } else {
                        NOTIFY | SCANNER
                    },
                )
            })
            .collect();
        let v6: Vec<(u128, u128, u16)> = (0..300_000u128)
            .map(|i| (i << 64, (i << 64) + 0xffff, NOTIFY | PROXY))
            .collect();
        let domains: Vec<String> = (0..1_000_000u32)
            .map(|i| format!("h{i:07}.sub{}.example{}.test", i % 977, i % 13))
            .collect();
        let raw = {
            let refs: Vec<&str> = domains.iter().map(|s| s.as_str()).collect();
            fixture::build(&signer, "m", &v4, &v6, &refs)
        };
        drop(domains);
        drop(v4);
        drop(v6);
        let before = rss_kb();
        let t = std::time::Instant::now();
        let b = parse_bundle(&raw, &signer.pubkey, &tiers()).unwrap();
        let load = t.elapsed();
        drop(raw);
        let after = rss_kb();
        println!(
            "sizes: V4 {} B/entry, V6 {} B/entry; bundle {:?} loaded in {:?}; RSS {} KiB -> {} KiB (+{} KiB)",
            std::mem::size_of::<V4>(),
            std::mem::size_of::<V6>(),
            b.counts(),
            load,
            before,
            after,
            after.saturating_sub(before)
        );
        let t = std::time::Instant::now();
        let mut hits = 0u64;
        for i in 0..1_000_000u32 {
            if b.lookup_ip(&IpAddr::V4(i.wrapping_mul(2654435761).into())) != 0 {
                hits += 1;
            }
        }
        println!("1M v4 lookups: {:?} ({} hits)", t.elapsed(), hits);
        let t = std::time::Instant::now();
        let mut hits = 0u64;
        for i in 0..1_000_000u32 {
            let a = Ipv6Addr::from(((i as u128) << 64) + 5);
            if b.lookup_ip(&IpAddr::V6(a)) != 0 {
                hits += 1;
            }
        }
        println!("1M v6 lookups: {:?} ({} hits)", t.elapsed(), hits);
        let names: Vec<String> = (0..1_000_000u32)
            .map(|i| format!("x.h{:07}.sub{}.example{}.test", i, i % 977, i % 13))
            .collect();
        let t = std::time::Instant::now();
        let mut hits = 0u64;
        for n in &names {
            if b.domain_hit(n) {
                hits += 1;
            }
        }
        println!(
            "1M domain lookups with parent walk: {:?} ({} hits)",
            t.elapsed(),
            hits
        );
    }
}
