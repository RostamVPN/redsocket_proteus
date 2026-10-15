// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Mailbox messaging over the tunnel — Valkey hashes as the mailbox, the exit
//! as the postman, a yamux control stream inside the Noise session as the
//! route. Contract.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};

use crate::valkey::{Conn, Resp};

pub const CONTROL_MAGIC: u8 = 0xC0;
/// Largest downstream frame: what the `u16` length prefix can carry.
pub const MAX_FRAME: usize = u16::MAX as usize;
/// Largest upstream frame the exit will look at.
pub const MAX_UPSTREAM: usize = 8 * 1024;
/// Most `{rules}` writes per control stream per this long.
pub static RULES_INTERVAL_MS: AtomicU64 = AtomicU64::new(10_000);

pub fn rules_interval() -> Duration {
    Duration::from_millis(RULES_INTERVAL_MS.load(Ordering::Relaxed))
}
/// Newest entries kept in `msg:<cid>` by the exit's own writes.
pub const MAILBOX_CAP: u64 = 100;
/// Newest broadcast entries the dispatcher keeps for replay; older ones are the
/// publisher's to trim, and a trimmed hash is simply a smaller cache.
pub const BROADCAST_CACHE_CAP: usize = 500;
/// TTL on `msg:<cid>:last` and `msg:<cid>:seq`.
pub const COUNTER_TTL_SECS: u64 = 30 * 24 * 3600;
/// Downstream `scope`: which watermark the client advances on a message.
pub const SCOPE_BROADCAST: &str = "broadcast";
pub const SCOPE_CID: &str = "cid";
pub const CHANNEL: &[u8] = b"msg";
pub const BROADCAST_KEY: &str = "msg:broadcast";
pub const EVENTS_KEY: &[u8] = b"cid:events";
pub const MAILBOX_TTL_SECS: u64 = 7 * 24 * 3600;
const RECONNECT: Duration = Duration::from_secs(5);
const XREAD_BLOCK_MS: &[u8] = b"5000";
/// How long to wait for the client's `{since}` before replaying without it.
const SINCE_WAIT: Duration = Duration::from_secs(30);
/// Subscription idle before a PING keeps the link honest.
const SUB_IDLE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Msg {
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub ts: u64,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub payload: serde_json::Value,
    /// `"broadcast"` or `"cid"`, set by the exit on every downstream frame so the
    /// client advances the right watermark; absent in storage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl Msg {
    pub fn synthetic(kind: &str, payload: serde_json::Value) -> Msg {
        Msg {
            seq: 0,
            ts: now_secs(),
            kind: kind.to_string(),
            payload,
            scope: None,
        }
    }
    /// `payload.brand`, if the writer scoped the message to one brand.
    fn brand(&self) -> Option<&str> {
        self.payload.get("brand").and_then(|b| b.as_str())
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A mailbox HASH as `(field, json)` pairs → messages sorted by seq. A field
/// whose value does not parse is skipped; a message without `seq` takes it from
/// the field name.
pub fn parse_mailbox(pairs: &[(String, String)]) -> Vec<Msg> {
    let mut out: Vec<Msg> = pairs
        .iter()
        .filter_map(|(field, json)| {
            let mut m: Msg = serde_json::from_str(json).ok()?;
            if m.seq == 0 {
                m.seq = field.trim_start_matches('0').parse().unwrap_or(0);
            }
            Some(m)
        })
        .collect();
    out.sort_by_key(|m| m.seq);
    out
}

/// Per-cid replay: everything above the acked seq, in order.
pub fn replay_after(msgs: &[Msg], last: u64) -> Vec<Msg> {
    msgs.iter().filter(|m| m.seq > last).cloned().collect()
}

/// Broadcast selection: after `since_ts` (the client's highest seen `ts`; an
/// equal one is a duplicate), above `after_seq` (the client's `broadcast_seq`,
/// or what this stream already sent), and not scoped to another brand.
pub fn broadcast_select(msgs: &[Msg], since_ts: u64, after_seq: u64, brand: &str) -> Vec<Msg> {
    msgs.iter()
        .filter(|m| m.ts > since_ts && m.seq > after_seq)
        .filter(|m| m.brand().is_none_or(|b| b.eq_ignore_ascii_case(brand)))
        .cloned()
        .collect()
}

/// An ack only ever moves `last` forward.
pub fn advance_last(current: u64, ack: u64) -> Option<u64> {
    (ack > current).then_some(ack)
}

/// The entitlement message for a `cid:<cid>` ledger record (or a `cid:events`
/// entry), `None` when there is no state in it.
pub fn entitlement_from_fields(fields: &[(String, String)]) -> Option<Msg> {
    let get = |k: &str| {
        fields
            .iter()
            .find(|(f, _)| f == k)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    let state = get("state");
    if state.is_empty() && get("tier").is_empty() {
        return None;
    }
    Some(Msg::synthetic(
        "entitlement",
        serde_json::json!({
            "tier": get("tier"),
            "paid_until": get("paid_until"),
            "state": state,
        }),
    ))
}

/// The upstream frames a device sends.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct Upstream {
    /// Highest broadcast `ts` seen.
    pub since: Option<u64>,
    /// Highest broadcast seq seen; preferred when present.
    pub broadcast_seq: Option<u64>,
    pub ack: Option<u64>,
    pub rules: Option<RulesUp>,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct RulesUp {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    /// Block-reason bits the user switched off; see `protection::UserRules`.
    #[serde(default)]
    pub categories_off: u16,
}

/// `allow` list out of a `rules:<cid>` HASH or a `rules` message payload.
pub fn allow_list(json: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(json).unwrap_or_default()
}

/// `(allow, categories_off)` out of a `rules:<cid>` HASH.
pub fn rules_fields(pairs: &[(String, String)]) -> (Vec<String>, u16) {
    let get = |k: &str| pairs.iter().find(|(f, _)| f == k).map(|(_, v)| v.as_str());
    (
        get("allow").map(allow_list).unwrap_or_default(),
        get("categories_off")
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0),
    )
}

/// The same two out of a `rules` message payload.
pub fn rules_payload(payload: &serde_json::Value) -> (Vec<String>, u16) {
    let allow = payload
        .get("allow")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let off = payload
        .get("categories_off")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .min(u16::MAX as u64) as u16;
    (allow, off)
}

pub async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, body: &[u8]) -> anyhow::Result<()> {
    if body.len() > MAX_FRAME {
        anyhow::bail!("frame of {} bytes exceeds {}", body.len(), MAX_FRAME);
    }
    s.write_all(&(body.len() as u16).to_le_bytes()).await?;
    s.write_all(body).await?;
    s.flush().await?;
    Ok(())
}

pub async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> anyhow::Result<Vec<u8>> {
    read_frame_max(s, MAX_FRAME).await
}

/// Read one frame, refusing a length over `max` before reading its body.
pub async fn read_frame_max<S: AsyncRead + Unpin>(
    s: &mut S,
    max: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let n = u16::from_le_bytes(len) as usize;
    if n > max {
        if let Some(st) = STATE.get() {
            st.counters.rules_rejected.fetch_add(1, Ordering::Relaxed);
        }
        anyhow::bail!("frame of {} bytes exceeds the {} byte limit", n, max);
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// The upstream half of a control stream as a stream of frames.
pub type UpstreamFrames<R> =
    tokio_util::codec::FramedRead<R, tokio_util::codec::LengthDelimitedCodec>;

/// `max` is the largest body the caller will look at; the decoder itself
/// accepts anything the u16 prefix can express, so an oversize frame is skipped
/// rather than fatal.
pub fn upstream_frames<R: AsyncRead + Unpin>(r: R, max: usize) -> UpstreamFrames<R> {
    debug_assert!(max <= u16::MAX as usize);
    tokio_util::codec::LengthDelimitedCodec::builder()
        .little_endian()
        .length_field_length(2)
        .max_frame_length(u16::MAX as usize)
        .new_read(r)
}

/// Next upstream frame the exit will look at: `Ok(None)` at a clean end. A
/// frame over [`MAX_UPSTREAM`] is read, dropped unparsed and counted; the
/// stream goes on.
pub async fn next_upstream<R: AsyncRead + Unpin>(
    f: &mut UpstreamFrames<R>,
) -> anyhow::Result<Option<Vec<u8>>> {
    use futures::StreamExt;
    loop {
        match f.next().await {
            None => return Ok(None),
            Some(Ok(b)) => {
                if b.len() > MAX_UPSTREAM {
                    if let Some(st) = STATE.get() {
                        st.counters.rules_rejected.fetch_add(1, Ordering::Relaxed);
                    }
                    log::debug!(
                        "[messaging] upstream frame of {} bytes dropped (limit {})",
                        b.len(),
                        MAX_UPSTREAM
                    );
                    continue;
                }
                if crate::protection::debug_destinations() {
                    log::debug!(
                        "[messaging] upstream frame {} bytes: {}",
                        b.len(),
                        String::from_utf8_lossy(&b)
                    );
                }
                return Ok(Some(b.to_vec()));
            }
            Some(Err(e)) => return Err(e.into()),
        }
    }
}

/// Bounds on an upstream `{rules}`: at most
/// [`crate::protection::MAX_RULE_ENTRIES`] per list, every entry a single
/// destination.
pub fn validate_rules(r: &RulesUp) -> Result<(), String> {
    for (name, list) in [("allow", &r.allow), ("deny", &r.deny)] {
        if list.len() > crate::protection::MAX_RULE_ENTRIES {
            return Err(format!(
                "{name} has {} entries, limit {}",
                list.len(),
                crate::protection::MAX_RULE_ENTRIES
            ));
        }
        if let Some(bad) = list
            .iter()
            .find(|e| !crate::protection::valid_rule_entry(e))
        {
            return Err(format!(
                "{name} entry {bad:?} is not a single host or address"
            ));
        }
    }
    Ok(())
}

/// Per-stream gate on `{rules}` writes: at most one per [`rules_interval`]. It
/// never drops a set — the caller keeps the latest pending one and writes it
/// when [`RulesGate::opens_at`] passes.
pub struct RulesGate {
    last: Option<std::time::Instant>,
}

impl RulesGate {
    pub fn new() -> RulesGate {
        RulesGate { last: None }
    }
    /// May a write go now? Marks the write when it may.
    pub fn take(&mut self, now: std::time::Instant) -> bool {
        if self
            .last
            .is_some_and(|l| now.duration_since(l) < rules_interval())
        {
            return false;
        }
        self.last = Some(now);
        true
    }
    /// When the next write may go.
    pub fn opens_at(&self) -> std::time::Instant {
        match self.last {
            Some(l) => l + rules_interval(),
            None => std::time::Instant::now(),
        }
    }
}

impl Default for RulesGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate one upstream rules frame; `None` (counted) when it is not a set of
/// single destinations within the bounds.
fn admit_rules(r: RulesUp) -> Option<RulesUp> {
    if let Err(why) = validate_rules(&r) {
        log::debug!("[messaging] rules frame refused: {}", why);
        if let Some(st) = STATE.get() {
            st.counters.rules_rejected.fetch_add(1, Ordering::Relaxed);
        }
        return None;
    }
    Some(r)
}

/// Control streams without a mailbox, by id: where synthesised messages go when
/// there is no dispatcher for them. Works with `[messaging]` off.
static ACK_STREAMS: Mutex<Vec<(u64, mpsc::Sender<Msg>)>> = Mutex::new(Vec::new());
static ACK_NEXT_ID: AtomicU64 = AtomicU64::new(1);

pub fn ack_streams() -> usize {
    ACK_STREAMS.lock().map(|l| l.len()).unwrap_or(0)
}

/// The first byte of every control stream. Written by the tunnel task before it
/// serves any client stream, so the client never mistakes a verdict byte for
/// data.
pub async fn write_magic<S: AsyncWrite + Unpin>(s: &mut S) -> anyhow::Result<()> {
    s.write_all(&[CONTROL_MAGIC]).await?;
    s.flush().await?;
    Ok(())
}

struct AckGuard(u64);

impl Drop for AckGuard {
    fn drop(&mut self) {
        if let Ok(mut l) = ACK_STREAMS.lock() {
            l.retain(|(id, _)| *id != self.0);
        }
    }
}

/// Serve a control stream that has no mailbox: `blk1`-only tunnels, or any cap
/// tunnel while `[messaging]` is off. The magic is already written.
pub async fn run_ack_stream<S>(
    mut stream: S,
    ctx: Option<Arc<crate::protection::TunnelCtx>>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (tx, mut rx) = mpsc::channel::<Msg>(16);
    let id = ACK_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut l) = ACK_STREAMS.lock() {
        l.push((id, tx));
    }
    let _guard = AckGuard(id);

    let status = Msg {
        scope: Some(SCOPE_CID.to_string()),
        ..protection_status()
    };
    write_frame(&mut stream, &serde_json::to_vec(&status)?).await?;
    if let Some(st) = STATE.get() {
        st.counters.sent[kind_index(&status.kind)].fetch_add(1, Ordering::Relaxed);
    }
    let (r, mut w) = tokio::io::split(stream);
    let mut frames = upstream_frames(r, MAX_UPSTREAM);
    loop {
        tokio::select! {
            frame = next_upstream(&mut frames) => {
                let Some(body) = frame? else { break };
                if body.is_empty() {
                    continue;
                }
                let Ok(up) = serde_json::from_slice::<Upstream>(&body) else {
                    continue;
                };

                if let (Some(rules), Some(ctx)) = (up.rules.and_then(admit_rules), &ctx) {
                    if let Ok(mut r) = ctx.rules.write() {
                        *r = crate::protection::UserRules::new(&rules.allow, rules.categories_off);
                    }
                }
            }
            m = rx.recv() => {
                let Some(m) = m else { break };
                let body = serde_json::to_vec(&Msg { scope: Some(SCOPE_CID.to_string()), ..m.clone() })?;
                write_frame(&mut w, &body).await?;
                if let Some(st) = STATE.get() {
                    st.counters.sent[kind_index(&m.kind)].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Config {
    pub valkey: crate::valkey::Config,
}

/// What a connected tunnel receives from the dispatcher.
enum Event {
    /// The cid's whole mailbox, freshly read; the tunnel sends what is new.
    Mailbox(Arc<Vec<Msg>>),
    /// The broadcast mailbox, freshly read; same.
    Broadcast(Arc<Vec<Msg>>),
    /// One synthesised message to send as is.
    Direct(Msg),
}

struct Handle {
    id: u64,
    tx: mpsc::Sender<Event>,
}

/// What the dispatcher hands a tunnel at registration.
struct Initial {
    last: u64,
    mailbox: Vec<Msg>,
    broadcast: Arc<Vec<Msg>>,
    allow: Vec<String>,
    categories_off: u16,
    entitlement: Option<Msg>,
}

enum Work {
    Register {
        cid: String,
        handle: Handle,
        reply: oneshot::Sender<Initial>,
    },
    Ack {
        cid: String,
        seq: u64,
    },
    Rules {
        cid: String,
        allow: Vec<String>,
        deny: Vec<String>,
        categories_off: u16,
    },
    Wake(String),
    WakeAll,
}

struct Counters {
    tunnels: AtomicU64,
    sent: [AtomicU64; 5],
    replayed: AtomicU64,
    acks: AtomicU64,
    rules: AtomicU64,
    /// Upstream frames refused: over the size limit, or rules that are not single
    /// destinations / within the entry bound.
    rules_rejected: AtomicU64,
    /// Rules writes dropped by the per-stream interval.
    rules_throttled: AtomicU64,
    valkey_errors: AtomicU64,
    dropped: AtomicU64,
    connected: [AtomicBool; 3],
}

const KINDS: [&str; 5] = ["entitlement", "protection", "rules", "notice", "other"];

fn kind_index(kind: &str) -> usize {
    KINDS.iter().position(|k| *k == kind).unwrap_or(4)
}

struct State {
    cfg: Config,
    work: mpsc::Sender<Work>,
    registry: Mutex<HashMap<String, Vec<Handle>>>,
    next_id: AtomicU64,
    counters: Counters,
}

static STATE: OnceLock<State> = OnceLock::new();
static ENABLED: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub struct Stats {
    pub tunnels: u64,
    pub connected: [bool; 3],
    pub sent: [u64; 5],
    pub acks: u64,
    pub rules: u64,
    pub rules_rejected: u64,
    pub rules_throttled: u64,
}

pub fn stats() -> Option<Stats> {
    let st = STATE.get()?;
    let c = &st.counters;
    Some(Stats {
        tunnels: c.tunnels.load(Ordering::Relaxed),
        connected: [
            c.connected[0].load(Ordering::Relaxed),
            c.connected[1].load(Ordering::Relaxed),
            c.connected[2].load(Ordering::Relaxed),
        ],
        sent: std::array::from_fn(|i| c.sent[i].load(Ordering::Relaxed)),
        acks: c.acks.load(Ordering::Relaxed),
        rules: c.rules.load(Ordering::Relaxed),
        rules_rejected: c.rules_rejected.load(Ordering::Relaxed),
        rules_throttled: c.rules_throttled.load(Ordering::Relaxed),
    })
}

/// Start the dispatcher. Idempotent per process.
pub fn spawn(cfg: Config) {
    let (tx, rx) = mpsc::channel::<Work>(4096);
    let state = State {
        cfg: cfg.clone(),
        work: tx,
        registry: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        counters: Counters {
            tunnels: AtomicU64::new(0),
            sent: Default::default(),
            replayed: AtomicU64::new(0),
            acks: AtomicU64::new(0),
            rules: AtomicU64::new(0),
            rules_rejected: AtomicU64::new(0),
            rules_throttled: AtomicU64::new(0),
            valkey_errors: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            connected: Default::default(),
        },
    };
    if STATE.set(state).is_err() {
        return;
    }
    ENABLED.store(true, Ordering::Relaxed);
    crate::protection::set_caps_wanted(true);
    log::info!("[messaging] on; mailbox at {}", cfg.valkey.addr);
    tokio::spawn(command_worker(rx));
    tokio::spawn(subscription_task());
    tokio::spawn(events_task());
}

/// The `protection` status message: what this exit is actually checking right
/// now. Sent first on every control stream and again on every bundle switch;
/// `enabled.
pub fn protection_status() -> Msg {
    let (enabled, version, feed_date) = crate::protection::status();
    Msg::synthetic(
        "protection",
        serde_json::json!({"enabled": enabled, "list_version": version, "feed_date": feed_date}),
    )
}

/// Called by the protection loader on a bundle switch: every control stream
/// hears about it at once, without a round trip through Valkey — the ack
/// streams directly, the mailbox streams through their dispatcher events.
pub fn protection_switched(_version: &str, _feed_date: &str) {
    let msg = protection_status();
    if let Ok(list) = ACK_STREAMS.lock() {
        for (_, tx) in list.iter() {
            let _ = tx.try_send(msg.clone());
        }
    }
    if let Some(st) = STATE.get() {
        fan_out_all(st, |_| Event::Direct(msg.clone()));
    }
}

fn fan_out(st: &State, cid: &str, mk: impl Fn() -> Event) {
    let reg = st.registry.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(handles) = reg.get(cid) {
        for h in handles {
            if h.tx.try_send(mk()).is_err() {
                st.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn fan_out_all(st: &State, mk: impl Fn(&str) -> Event) {
    let reg = st.registry.lock().unwrap_or_else(|p| p.into_inner());
    for (cid, handles) in reg.iter() {
        for h in handles {
            if h.tx.try_send(mk(cid)).is_err() {
                st.counters.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn has_cid(st: &State, cid: &str) -> bool {
    st.registry
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .contains_key(cid)
}

/// Reconnect gate: after a failed connect the link is "down" for a backoff that
/// doubles up to [`Circuit::MAX`], and every command in that window fails at
/// once instead of paying the 10 s connect timeout.
#[derive(Debug, Clone)]
pub struct Circuit {
    backoff: Duration,
    down_until: Option<std::time::Instant>,
}

impl Circuit {
    pub const MIN: Duration = Duration::from_secs(1);
    pub const MAX: Duration = Duration::from_secs(60);

    pub fn new() -> Circuit {
        Circuit {
            backoff: Self::MIN,
            down_until: None,
        }
    }
    /// May a connect be attempted now?
    pub fn allows(&self, now: std::time::Instant) -> bool {
        self.down_until.is_none_or(|t| now >= t)
    }
    /// Seconds until the next attempt is allowed, for the log line.
    pub fn wait(&self, now: std::time::Instant) -> Duration {
        self.down_until
            .map(|t| t.saturating_duration_since(now))
            .unwrap_or_default()
    }
    pub fn failed(&mut self, now: std::time::Instant) {
        self.down_until = Some(now + self.backoff);
        self.backoff = (self.backoff * 2).min(Self::MAX);
    }
    pub fn succeeded(&mut self) {
        self.backoff = Self::MIN;
        self.down_until = None;
    }
}

impl Default for Circuit {
    fn default() -> Self {
        Self::new()
    }
}

struct Link {
    cfg: crate::valkey::Config,
    conn: Option<Conn>,
    slot: usize,
    circuit: Circuit,
}

impl Link {
    fn new(cfg: &crate::valkey::Config, slot: usize) -> Link {
        Link {
            cfg: cfg.clone(),
            conn: None,
            slot,
            circuit: Circuit::new(),
        }
    }
    async fn conn(&mut self) -> anyhow::Result<&mut Conn> {
        if self.conn.is_none() {
            let now = std::time::Instant::now();
            if !self.circuit.allows(now) {
                anyhow::bail!(
                    "valkey link down, next attempt in {:?}",
                    self.circuit.wait(now)
                );
            }
            match Conn::connect(&self.cfg).await {
                Ok(c) => {
                    self.conn = Some(c);
                    self.circuit.succeeded();
                    if let Some(st) = STATE.get() {
                        st.counters.connected[self.slot].store(true, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    self.circuit.failed(std::time::Instant::now());
                    if let Some(st) = STATE.get() {
                        st.counters.valkey_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(e);
                }
            }
        }
        Ok(self.conn.as_mut().expect("just set"))
    }
    fn drop_conn(&mut self) {
        self.conn = None;
        if let Some(st) = STATE.get() {
            st.counters.connected[self.slot].store(false, Ordering::Relaxed);
            st.counters.valkey_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// One command; a transport error drops the link so the next call reconnects. A
    /// Valkey `-ERR` is returned as an error without a drop.
    async fn cmd(&mut self, args: &[&[u8]]) -> anyhow::Result<Resp> {
        let r = match self.conn().await {
            Ok(c) => c.cmd(args).await,
            Err(e) => Err(e),
        };
        match r {
            Ok(Resp::Err(e)) => Err(anyhow::anyhow!("valkey: {}", e)),
            Ok(r) => Ok(r),
            Err(e) => {
                self.drop_conn();
                Err(e)
            }
        }
    }
    async fn hgetall(&mut self, key: &str) -> anyhow::Result<Vec<(String, String)>> {
        Ok(self.cmd(&[b"HGETALL", key.as_bytes()]).await?.pairs())
    }
    async fn get_u64(&mut self, key: &str) -> anyhow::Result<u64> {
        Ok(self
            .cmd(&[b"GET", key.as_bytes()])
            .await?
            .as_int()
            .unwrap_or(0)
            .max(0) as u64)
    }
}

async fn command_worker(mut rx: mpsc::Receiver<Work>) {
    let st = STATE.get().expect("spawned");
    let mut link = Link::new(&st.cfg.valkey, 0);
    let mut broadcast: Arc<Vec<Msg>> = Arc::new(Vec::new());

    if let Ok(pairs) = link.hgetall(BROADCAST_KEY).await {
        let mut all = parse_mailbox(&pairs);
        if all.len() > BROADCAST_CACHE_CAP {
            all.drain(..all.len() - BROADCAST_CACHE_CAP);
        }
        broadcast = Arc::new(all);
    }
    while let Some(w) = rx.recv().await {
        match w {
            Work::Register { cid, handle, reply } => {
                let last = link.get_u64(&format!("msg:{cid}:last")).await.unwrap_or(0);
                let mailbox = link
                    .hgetall(&format!("msg:{cid}"))
                    .await
                    .map(|p| parse_mailbox(&p))
                    .unwrap_or_default();
                let rules = link
                    .hgetall(&format!("rules:{cid}"))
                    .await
                    .unwrap_or_default();
                let (allow, categories_off) = rules_fields(&rules);
                let entitlement = link
                    .hgetall(&format!("cid:{cid}"))
                    .await
                    .ok()
                    .and_then(|p| entitlement_from_fields(&p));
                {
                    let mut reg = st.registry.lock().unwrap_or_else(|p| p.into_inner());
                    reg.entry(cid).or_default().push(handle);
                    st.counters.tunnels.store(
                        reg.values().map(|v| v.len() as u64).sum(),
                        Ordering::Relaxed,
                    );
                }
                let _ = reply.send(Initial {
                    last,
                    mailbox,
                    broadcast: broadcast.clone(),
                    allow,
                    categories_off,
                    entitlement,
                });
            }
            Work::Ack { cid, seq } => {
                let key = format!("msg:{cid}:last");
                let current = link.get_u64(&key).await.unwrap_or(0);
                if let Some(next) = advance_last(current, seq) {
                    if link
                        .cmd(&[b"SET", key.as_bytes(), next.to_string().as_bytes()])
                        .await
                        .is_ok()
                    {
                        st.counters.acks.fetch_add(1, Ordering::Relaxed);
                        let _ = link
                            .cmd(&[
                                b"EXPIRE",
                                key.as_bytes(),
                                COUNTER_TTL_SECS.to_string().as_bytes(),
                            ])
                            .await;
                    }
                }
            }
            Work::Rules {
                cid,
                allow,
                deny,
                categories_off,
            } => {
                let allow_json = serde_json::to_string(&allow).unwrap_or_else(|_| "[]".into());
                let deny_json = serde_json::to_string(&deny).unwrap_or_else(|_| "[]".into());
                let off = categories_off.to_string();
                let key = format!("rules:{cid}");

                let current = link.hgetall(&key).await.unwrap_or_default();
                let field = |k: &str, empty: &'static str| {
                    current
                        .iter()
                        .find(|(f, _)| f == k)
                        .map(|(_, v)| v.as_str())
                        .unwrap_or(empty)
                };
                if field("allow", "[]") == allow_json
                    && field("deny", "[]") == deny_json
                    && field("categories_off", "0") == off
                {
                    continue;
                }
                let updated = now_secs().to_string();
                let r = link
                    .cmd(&[
                        b"HSET",
                        key.as_bytes(),
                        b"allow",
                        allow_json.as_bytes(),
                        b"deny",
                        deny_json.as_bytes(),
                        b"categories_off",
                        off.as_bytes(),
                        b"updated",
                        updated.as_bytes(),
                    ])
                    .await;
                if r.is_ok() {
                    st.counters.rules.fetch_add(1, Ordering::Relaxed);
                    let payload = serde_json::json!({
                        "allow": allow,
                        "deny": deny,
                        "categories_off": categories_off,
                        "updated": updated,
                    });
                    let _ = append_message(&mut link, &cid, "rules", payload).await;
                }
            }
            Work::Wake(cid) => {
                if !has_cid(st, &cid) {
                    continue;
                }
                if let Ok(pairs) = link.hgetall(&format!("msg:{cid}")).await {
                    let msgs = Arc::new(parse_mailbox(&pairs));
                    fan_out(st, &cid, || Event::Mailbox(msgs.clone()));
                }
            }
            Work::WakeAll => {
                if let Ok(pairs) = link.hgetall(BROADCAST_KEY).await {
                    let mut fresh = parse_mailbox(&pairs);
                    let newest_old = broadcast.iter().map(|m| m.seq).max().unwrap_or(0);
                    let delta: Vec<Msg> = fresh
                        .iter()
                        .filter(|m| m.seq > newest_old)
                        .cloned()
                        .collect();
                    if delta.iter().any(|m| m.kind == "protection") {
                        crate::protection::request_reload();
                    }
                    if fresh.len() > BROADCAST_CACHE_CAP {
                        fresh.drain(..fresh.len() - BROADCAST_CACHE_CAP);
                    }
                    broadcast = Arc::new(fresh);
                    if !delta.is_empty() {
                        let d = Arc::new(delta);
                        fan_out_all(st, |_| Event::Broadcast(d.clone()));
                    }
                }
            }
        }
    }
}

/// Append one message to `msg:<cid>`, refresh the TTL, PUBLISH.
async fn append_message(
    link: &mut Link,
    cid: &str,
    kind: &str,
    payload: serde_json::Value,
) -> anyhow::Result<()> {
    let key = format!("msg:{cid}");
    let seq_key = format!("msg:{cid}:seq");
    let seq = link
        .cmd(&[b"INCR", seq_key.as_bytes()])
        .await?
        .as_int()
        .unwrap_or(0)
        .max(1) as u64;
    link.cmd(&[
        b"EXPIRE",
        seq_key.as_bytes(),
        COUNTER_TTL_SECS.to_string().as_bytes(),
    ])
    .await?;
    let msg = Msg {
        seq,
        ts: now_secs(),
        kind: kind.to_string(),
        payload,
        scope: None,
    };
    let field = format!("{seq:010}");
    let json = serde_json::to_vec(&msg)?;
    link.cmd(&[b"HSET", key.as_bytes(), field.as_bytes(), &json])
        .await?;
    if seq > MAILBOX_CAP {
        let old = format!("{:010}", seq - MAILBOX_CAP);
        link.cmd(&[b"HDEL", key.as_bytes(), old.as_bytes()]).await?;
    }
    link.cmd(&[
        b"EXPIRE",
        key.as_bytes(),
        MAILBOX_TTL_SECS.to_string().as_bytes(),
    ])
    .await?;
    link.cmd(&[b"PUBLISH", CHANNEL, cid.as_bytes()]).await?;
    Ok(())
}

/// SUBSCRIBE `msg` and turn every payload into a wake.
async fn subscription_task() {
    let st = STATE.get().expect("spawned");
    let mut link = Link::new(&st.cfg.valkey, 1);
    loop {
        if let Err(e) = subscribe_once(st, &mut link).await {
            log::warn!("[messaging] subscription: {} — retry in {:?}", e, RECONNECT);
            link.drop_conn();
        }
        tokio::time::sleep(RECONNECT).await;
    }
}

async fn subscribe_once(st: &State, link: &mut Link) -> anyhow::Result<()> {
    let conn = link.conn().await?;
    conn.send(&[b"SUBSCRIBE", CHANNEL]).await?;
    loop {
        let Some(r) = conn.read_opt_for(SUB_IDLE).await? else {
            conn.send(&[b"PING"]).await?;
            continue;
        };
        let Resp::Arr(items) = r else { continue };
        let Some(kind) = items.first().and_then(|k| k.as_bytes()) else {
            continue;
        };
        if kind != b"message" {
            continue;
        }
        let Some(payload) = items.get(2).and_then(|p| p.as_string()) else {
            continue;
        };

        let w = if payload == "*" || !crate::mux::valid_cid(&payload) {
            Work::WakeAll
        } else {
            Work::Wake(payload)
        };
        if st.work.try_send(w).is_err() {
            st.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Tail `cid:events`; a transition for a connected cid becomes an `entitlement`
/// message on its tunnels.
async fn events_task() {
    let st = STATE.get().expect("spawned");
    let mut link = Link::new(&st.cfg.valkey, 2);
    loop {
        if let Err(e) = events_once(st, &mut link).await {
            log::warn!(
                "[messaging] cid:events tail: {} — retry in {:?}",
                e,
                RECONNECT
            );
            link.drop_conn();
        }
        tokio::time::sleep(RECONNECT).await;
    }
}

async fn events_once(st: &State, link: &mut Link) -> anyhow::Result<()> {
    let mut last_id = {
        let r = link
            .cmd(&[b"XREVRANGE", EVENTS_KEY, b"+", b"-", b"COUNT", b"1"])
            .await?;
        match r {
            Resp::Arr(items) => items
                .first()
                .and_then(|e| match e {
                    Resp::Arr(parts) => parts.first().and_then(|id| id.as_string()),
                    _ => None,
                })
                .unwrap_or_else(|| "0-0".to_string()),
            _ => "0-0".to_string(),
        }
    };
    loop {
        let r = link
            .cmd(&[
                b"XREAD",
                b"BLOCK",
                XREAD_BLOCK_MS,
                b"STREAMS",
                EVENTS_KEY,
                last_id.as_bytes(),
            ])
            .await?;
        for (id, fields) in xread_entries(&r) {
            last_id = id;
            let cid = fields
                .iter()
                .find(|(k, _)| k == "cid")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            if cid.is_empty() || !has_cid(st, &cid) {
                continue;
            }
            if let Some(msg) = entitlement_from_fields(&fields) {
                fan_out(st, &cid, || Event::Direct(msg.clone()));
            }
        }
    }
}

/// `[[stream, [[id, [f, v, …]], …]]]` → `(id, fields)` in order; Nil → empty.
pub fn xread_entries(reply: &Resp) -> Vec<(String, Vec<(String, String)>)> {
    let mut out = Vec::new();
    let Resp::Arr(streams) = reply else {
        return out;
    };
    for stream in streams {
        let Resp::Arr(parts) = stream else { continue };
        let Some(Resp::Arr(entries)) = parts.get(1) else {
            continue;
        };
        for entry in entries {
            let Resp::Arr(ef) = entry else { continue };
            let (Some(id), Some(fields)) = (ef.first().and_then(|i| i.as_string()), ef.get(1))
            else {
                continue;
            };
            out.push((id, fields.pairs()));
        }
    }
    out
}

/// Serve one tunnel's mailbox control stream until it closes; the magic is
/// already written. `ctx` is the tunnel's protection context, if it has one:
/// the user's allow rules land there.
pub async fn run_control_stream<S>(
    stream: S,
    cid: String,
    brand: String,
    ctx: Option<Arc<crate::protection::TunnelCtx>>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(st) = STATE.get() else {
        return run_ack_stream(stream, ctx).await;
    };
    let (r, mut stream) = tokio::io::split(stream);
    let mut frames = upstream_frames(r, MAX_UPSTREAM);

    send(st, &mut stream, &protection_status(), false, SCOPE_CID).await?;

    let (since_ts, since_seq) =
        match tokio::time::timeout(SINCE_WAIT, next_upstream(&mut frames)).await {
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(body))) => match serde_json::from_slice::<Upstream>(&body).ok() {
                Some(Upstream {
                    broadcast_seq: Some(seq),
                    ..
                }) => (0, seq),
                Some(Upstream {
                    since: Some(ts), ..
                }) => (ts, 0),
                _ => (now_secs(), 0),
            },
            Ok(Err(e)) => return Err(e),
            Err(_) => (now_secs(), 0),
        };

    let id = st.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, mut rx) = mpsc::channel::<Event>(64);
    let (reply_tx, reply_rx) = oneshot::channel();
    st.work
        .send(Work::Register {
            cid: cid.clone(),
            handle: Handle { id, tx },
            reply: reply_tx,
        })
        .await
        .map_err(|_| anyhow::anyhow!("dispatcher gone"))?;
    let init = reply_rx
        .await
        .map_err(|_| anyhow::anyhow!("dispatcher dropped the registration"))?;
    let _unregister = Unregister {
        cid: cid.clone(),
        id,
    };

    let mut last = init.last;
    let mut sent_seq = last;
    let mut gate = RulesGate::new();

    let mut pending: Option<RulesUp> = None;
    let mut sent_bseq = init.broadcast.iter().map(|m| m.seq).max().unwrap_or(0);
    let apply_rules = |allow: &[String], categories_off: u16| {
        if let Some(ctx) = &ctx {
            if let Ok(mut r) = ctx.rules.write() {
                *r = crate::protection::UserRules::new(allow, categories_off);
            }
        }
    };
    apply_rules(&init.allow, init.categories_off);

    for m in replay_after(&init.mailbox, last) {
        sent_seq = sent_seq.max(m.seq);
        send(st, &mut stream, &m, true, SCOPE_CID).await?;
    }
    for m in broadcast_select(&init.broadcast, since_ts, since_seq, &brand) {
        send(st, &mut stream, &m, true, SCOPE_BROADCAST).await?;
    }
    if let Some(m) = &init.entitlement {
        send(st, &mut stream, m, false, SCOPE_CID).await?;
    }
    drop(init);

    loop {
        tokio::select! {
            frame = next_upstream(&mut frames) => {
                let Some(body) = frame? else { break };
                if body.is_empty() {
                    continue;
                }
                let Ok(up) = serde_json::from_slice::<Upstream>(&body) else {
                    log::debug!("[messaging] unparsable upstream frame from cid {}", cid);
                    continue;
                };

                if let Some(ack) = up.ack.filter(|a| *a <= sent_seq) {
                    if let Some(next) = advance_last(last, ack) {
                        last = next;
                        let _ = st.work.send(Work::Ack { cid: cid.clone(), seq: next }).await;
                    }
                }
                if let Some(rules) = up.rules.and_then(admit_rules) {
                    apply_rules(&rules.allow, rules.categories_off);
                    if gate.take(std::time::Instant::now()) {
                        let _ = st
                            .work
                            .send(Work::Rules {
                                cid: cid.clone(),
                                allow: rules.allow,
                                deny: rules.deny,
                                categories_off: rules.categories_off,
                            })
                            .await;
                    } else {
                        st.counters.rules_throttled.fetch_add(1, Ordering::Relaxed);
                        pending = Some(rules);
                    }
                }
            }
            ev = rx.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    Event::Mailbox(msgs) => {
                        let cutoff = sent_seq;
                        for m in msgs.iter().filter(|m| m.seq > cutoff) {
                            sent_seq = m.seq;
                            if m.kind == "rules" {
                                let (allow, off) = rules_payload(&m.payload);
                                apply_rules(&allow, off);
                            }
                            send(st, &mut stream, m, false, SCOPE_CID).await?;
                        }
                    }
                    Event::Broadcast(msgs) => {
                        for m in broadcast_select(&msgs, 0, sent_bseq, &brand) {
                            send(st, &mut stream, &m, false, SCOPE_BROADCAST).await?;
                        }
                        sent_bseq = sent_bseq.max(msgs.iter().map(|m| m.seq).max().unwrap_or(0));
                    }
                    Event::Direct(m) => send(st, &mut stream, &m, false, SCOPE_CID).await?,
                }
            }
            _ = tokio::time::sleep_until(gate.opens_at().into()), if pending.is_some() => {
                let rules = pending.take().expect("checked");
                gate.take(std::time::Instant::now());
                let _ = st
                    .work
                    .send(Work::Rules {
                        cid: cid.clone(),
                        allow: rules.allow,
                        deny: rules.deny,
                        categories_off: rules.categories_off,
                    })
                    .await;
            }
        }
    }
    Ok(())
}

struct Unregister {
    cid: String,
    id: u64,
}

impl Drop for Unregister {
    /// Synchronous, on the registry mutex: a tunnel's handle must leave the
    /// registry when the tunnel ends, whatever the worker's queue looks like.
    fn drop(&mut self) {
        let Some(st) = STATE.get() else {
            return;
        };
        let mut reg = st.registry.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(v) = reg.get_mut(&self.cid) {
            v.retain(|h| h.id != self.id);
            if v.is_empty() {
                reg.remove(&self.cid);
            }
        }
        st.counters.tunnels.store(
            reg.values().map(|v| v.len() as u64).sum(),
            Ordering::Relaxed,
        );
    }
}

async fn send<S: AsyncWrite + Unpin>(
    st: &State,
    stream: &mut S,
    m: &Msg,
    replay: bool,
    scope: &str,
) -> anyhow::Result<()> {
    let body = serde_json::to_vec(&Msg {
        scope: Some(scope.to_string()),
        ..m.clone()
    })?;
    write_frame(stream, &body).await?;
    st.counters.sent[kind_index(&m.kind)].fetch_add(1, Ordering::Relaxed);
    if replay {
        st.counters.replayed.fetch_add(1, Ordering::Relaxed);
    }
    Ok(())
}

pub fn prometheus(out: &mut String) {
    use std::fmt::Write;
    out.push_str("# HELP redsocket_messaging_ack_streams control streams without a mailbox (blk1-only, or messaging off)\n");
    out.push_str("# TYPE redsocket_messaging_ack_streams gauge\n");
    let _ = writeln!(out, "redsocket_messaging_ack_streams {}", ack_streams());
    let Some(st) = STATE.get() else {
        return;
    };
    let c = &st.counters;
    out.push_str("# HELP redsocket_messaging_tunnels tunnels with an open control stream\n");
    out.push_str("# TYPE redsocket_messaging_tunnels gauge\n");
    let _ = writeln!(
        out,
        "redsocket_messaging_tunnels {}",
        c.tunnels.load(Ordering::Relaxed)
    );
    out.push_str("# HELP redsocket_messaging_connected 1 while the Valkey link is up\n");
    out.push_str("# TYPE redsocket_messaging_connected gauge\n");
    for (i, name) in ["commands", "pubsub", "events"].iter().enumerate() {
        let _ = writeln!(
            out,
            "redsocket_messaging_connected{{link=\"{}\"}} {}",
            name,
            u8::from(c.connected[i].load(Ordering::Relaxed))
        );
    }
    out.push_str(
        "# HELP redsocket_messaging_sent_total messages written to control streams, by type\n",
    );
    out.push_str("# TYPE redsocket_messaging_sent_total counter\n");
    for (i, k) in KINDS.iter().enumerate() {
        let _ = writeln!(
            out,
            "redsocket_messaging_sent_total{{type=\"{}\"}} {}",
            k,
            c.sent[i].load(Ordering::Relaxed)
        );
    }
    for (name, v) in [
        ("replayed_total", &c.replayed),
        ("acks_total", &c.acks),
        ("rules_total", &c.rules),
        ("rules_rejected_total", &c.rules_rejected),
        ("rules_deferred_total", &c.rules_throttled),
        ("valkey_errors_total", &c.valkey_errors),
        ("dropped_total", &c.dropped),
    ] {
        let _ = writeln!(out, "# TYPE redsocket_messaging_{} counter", name);
        let _ = writeln!(
            out,
            "redsocket_messaging_{} {}",
            name,
            v.load(Ordering::Relaxed)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(seq: u64, ts: u64, kind: &str, payload: serde_json::Value) -> (String, String) {
        (
            format!("{seq:010}"),
            serde_json::json!({"seq": seq, "ts": ts, "type": kind, "payload": payload}).to_string(),
        )
    }

    /// A fake mailbox: HGETALL returns fields in hash order, not seq order, and may
    /// hold junk; the replay must still be in seq order above `last`.
    #[test]
    fn replay_is_ordered_above_the_acked_seq() {
        let pairs = vec![
            entry(3, 300, "notice", serde_json::json!({"title": "c"})),
            ("junk".to_string(), "not json".to_string()),
            entry(1, 100, "notice", serde_json::json!({"title": "a"})),
            entry(2, 200, "rules", serde_json::json!({"allow": ["x"]})),

            (
                "0000000004".to_string(),
                serde_json::json!({"ts": 400, "type": "notice", "payload": {}}).to_string(),
            ),
        ];
        let msgs = parse_mailbox(&pairs);
        assert_eq!(
            msgs.iter().map(|m| m.seq).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        let replay = replay_after(&msgs, 2);
        assert_eq!(replay.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![3, 4]);
        assert!(replay_after(&msgs, 4).is_empty());
        assert_eq!(replay_after(&msgs, 0).len(), 4);
    }

    #[test]
    fn broadcast_honours_since_seq_and_brand() {
        let pairs = vec![
            entry(1, 100, "notice", serde_json::json!({})),
            entry(
                2,
                200,
                "notice",
                serde_json::json!({"brand": "rostam"}),
            ),
            entry(3, 300, "notice", serde_json::json!({"brand": "other"})),
            entry(
                4,
                400,
                "protection",
                serde_json::json!({"list_version": "2026-10-12"}),
            ),
        ];
        let msgs = parse_mailbox(&pairs);

        let sel = broadcast_select(&msgs, 150, 0, "rostam");
        assert_eq!(sel.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![2, 4]);

        let sel = broadcast_select(&msgs, 200, 0, "rostam");
        assert_eq!(sel.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![4]);

        let sel = broadcast_select(&msgs, 0, 2, "Rostam");
        assert_eq!(sel.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![4]);

        let sel = broadcast_select(&msgs, 0, 0, "neither");
        assert_eq!(sel.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![1, 4]);

        let sel = broadcast_select(&msgs, 0, 2, "rostam");
        assert_eq!(sel.iter().map(|m| m.seq).collect::<Vec<_>>(), vec![4]);
        let u: Upstream = serde_json::from_str(r#"{"since": 1, "broadcast_seq": 3}"#).unwrap();
        assert_eq!((u.since, u.broadcast_seq), (Some(1), Some(3)));

        let stored = serde_json::to_string(&msgs[0]).unwrap();
        assert!(!stored.contains("scope"));
        let wire = Msg {
            scope: Some(SCOPE_BROADCAST.into()),
            ..msgs[0].clone()
        };
        assert!(serde_json::to_string(&wire)
            .unwrap()
            .contains(r#""scope":"broadcast""#));
    }

    #[test]
    fn rules_frames_are_bounded_to_single_destinations() {
        let ok = RulesUp {
            allow: vec!["a.example".into(), "1.2.3.4".into(), "::1/128".into()],
            deny: vec!["b.example".into()],
            categories_off: 0,
        };
        assert!(validate_rules(&ok).is_ok());
        let wide = RulesUp {
            allow: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        assert!(validate_rules(&wide).unwrap_err().contains("10.0.0.0/8"));
        let many = RulesUp {
            deny: (0..201).map(|i| format!("h{i}.example")).collect(),
            ..Default::default()
        };
        assert!(validate_rules(&many).unwrap_err().contains("201 entries"));
        assert!(admit_rules(wide.clone()).is_none(), "invalid is refused");
        assert!(admit_rules(ok.clone()).is_some());
        let t0 = std::time::Instant::now();
        let mut gate = RulesGate::new();
        assert!(gate.take(t0));
        assert!(
            !gate.take(t0 + Duration::from_millis(1)),
            "inside the window: defer"
        );
        assert_eq!(gate.opens_at(), t0 + rules_interval());
        assert!(gate.take(t0 + rules_interval()));
    }

    #[test]
    fn the_circuit_backs_off_and_resets() {
        let t0 = std::time::Instant::now();
        let mut c = Circuit::new();
        assert!(c.allows(t0));
        c.failed(t0);
        assert!(!c.allows(t0), "down right after a failure");
        assert!(!c.allows(t0 + Duration::from_millis(900)));
        assert!(c.allows(t0 + Circuit::MIN), "the first wait is MIN");

        let t1 = t0 + Circuit::MIN;
        c.failed(t1);
        assert!(!c.allows(t1 + Duration::from_millis(1900)));
        assert!(c.allows(t1 + Duration::from_secs(2)));
        let mut t = t1;
        for _ in 0..10 {
            t += Duration::from_secs(120);
            c.failed(t);
        }
        assert!(!c.allows(t + Circuit::MAX - Duration::from_millis(1)));
        assert!(c.allows(t + Circuit::MAX), "never longer than MAX");

        c.succeeded();
        assert!(c.allows(t));
        c.failed(t);
        assert!(c.allows(t + Circuit::MIN));
    }

    /// A frame that arrives in pieces while the other select arm keeps winning must
    /// still come out whole: the FramedRead owns the partial bytes, where
    /// `read_exact` in a `select!` dropped them.
    #[tokio::test]
    async fn partial_frames_survive_competing_events() {
        let (mut a, b) = tokio::io::duplex(4096);
        let mut frames = upstream_frames(b, MAX_UPSTREAM);
        let body = br#"{"ack":42}"#;
        let len = (body.len() as u16).to_le_bytes();
        a.write_all(&len[..1]).await.unwrap();

        {
            let fut = next_upstream(&mut frames);
            tokio::pin!(fut);
            assert!(futures::poll!(fut.as_mut()).is_pending());
        }
        a.write_all(&len[1..]).await.unwrap();
        a.write_all(&body[..4]).await.unwrap();
        {
            let fut = next_upstream(&mut frames);
            tokio::pin!(fut);
            assert!(futures::poll!(fut.as_mut()).is_pending());
        }
        a.write_all(&body[4..]).await.unwrap();
        let got = next_upstream(&mut frames).await.unwrap().unwrap();
        assert_eq!(got, body);

        let (mut a, b) = tokio::io::duplex(1 << 17);
        let mut frames = upstream_frames(b, MAX_UPSTREAM);
        a.write_all(&((MAX_UPSTREAM + 1) as u16).to_le_bytes())
            .await
            .unwrap();
        a.write_all(&vec![b'x'; MAX_UPSTREAM + 1]).await.unwrap();
        a.write_all(&(body.len() as u16).to_le_bytes())
            .await
            .unwrap();
        a.write_all(body).await.unwrap();
        assert_eq!(next_upstream(&mut frames).await.unwrap().unwrap(), body);
    }

    #[test]
    fn acks_only_move_forward() {
        assert_eq!(advance_last(0, 3), Some(3));
        assert_eq!(advance_last(3, 3), None);
        assert_eq!(advance_last(5, 3), None, "a stale ack must not rewind");
        assert_eq!(advance_last(5, 6), Some(6));
    }

    #[test]
    fn upstream_frames_parse_and_frames_are_u16_le() {
        let u: Upstream = serde_json::from_str(r#"{"since": 1700000000}"#).unwrap();
        assert_eq!(u.since, Some(1700000000));
        let u: Upstream = serde_json::from_str(r#"{"ack": 7}"#).unwrap();
        assert_eq!(u.ack, Some(7));
        let u: Upstream = serde_json::from_str(
            r#"{"rules": {"allow": ["a.example", "10.0.0.0/8"], "deny": ["b"], "categories_off": 16}}"#,
        )
        .unwrap();
        let r = u.rules.unwrap();
        assert_eq!(r.allow.len(), 2);
        assert_eq!(r.categories_off, 16);
        let u: Upstream = serde_json::from_str(r#"{"rules": {"allow": [], "deny": []}}"#).unwrap();
        assert_eq!(
            u.rules.unwrap().categories_off,
            0,
            "absent = nothing switched off"
        );
        let (allow, off) = rules_fields(&[
            ("allow".into(), r#"["x.example"]"#.into()),
            ("categories_off".into(), "48".into()),
        ]);
        assert_eq!((allow, off), (vec!["x.example".to_string()], 48));
        let (allow, off) = rules_payload(&serde_json::json!({"allow": ["y"], "categories_off": 3}));
        assert_eq!((allow, off), (vec!["y".to_string()], 3));

        let u: Upstream = serde_json::from_str(r#"{"hello": 1}"#).unwrap();
        assert_eq!(u, Upstream::default());

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut a, mut b) = tokio::io::duplex(1024);
            write_frame(&mut a, b"{\"ack\":1}").await.unwrap();
            let mut raw = [0u8; 11];
            b.read_exact(&mut raw).await.unwrap();
            assert_eq!(&raw[..2], &[9, 0], "length prefix must be little-endian");
            assert_eq!(&raw[2..], b"{\"ack\":1}");
            write_frame(&mut a, &[b'x'; 300]).await.unwrap();
            let got = read_frame(&mut b).await.unwrap();
            assert_eq!(got.len(), 300);

            let (mut a, mut b) = tokio::io::duplex(1 << 17);
            write_frame(&mut a, &vec![0u8; 65535]).await.unwrap();
            let mut hdr = [0u8; 2];
            b.read_exact(&mut hdr).await.unwrap();
            assert_eq!(u16::from_le_bytes(hdr), 65535);
            assert!(write_frame(&mut a, &vec![0u8; 65536]).await.is_err());
            assert!(write_frame(&mut a, &vec![0u8; MAX_FRAME + 1])
                .await
                .is_err());
        });
    }

    #[test]
    fn entitlement_is_derived_from_the_ledger_record() {
        let rec = vec![
            ("state".to_string(), "paid".to_string()),
            ("tier".to_string(), "pro".to_string()),
            ("paid_until".to_string(), "2027-01-01T00:00:00".to_string()),
            ("cid".to_string(), "abc".to_string()),
        ];
        let m = entitlement_from_fields(&rec).unwrap();
        assert_eq!(m.kind, "entitlement");
        assert_eq!(m.seq, 0, "synthesised: nothing to ack");
        assert_eq!(m.payload["tier"], "pro");
        assert_eq!(m.payload["paid_until"], "2027-01-01T00:00:00");
        assert_eq!(m.payload["state"], "paid");
        assert!(
            m.payload.get("cid").is_none(),
            "the cid never rides in a payload"
        );
        assert!(entitlement_from_fields(&[]).is_none());

        assert!(entitlement_from_fields(&[("state".into(), "".into())]).is_none());
    }

    #[test]
    fn xread_reply_shape() {
        let reply = Resp::Arr(vec![Resp::Arr(vec![
            Resp::Str(b"cid:events".to_vec()),
            Resp::Arr(vec![Resp::Arr(vec![
                Resp::Str(b"1-0".to_vec()),
                Resp::Arr(vec![
                    Resp::Str(b"cid".to_vec()),
                    Resp::Str(b"q1".to_vec()),
                    Resp::Str(b"state".to_vec()),
                    Resp::Str(b"throttle".to_vec()),
                ]),
            ])]),
        ])]);
        let e = xread_entries(&reply);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].0, "1-0");
        assert_eq!(e[0].1[1], ("state".to_string(), "throttle".to_string()));
        assert!(xread_entries(&Resp::Nil).is_empty());
        assert_eq!(kind_index("rules"), 2);
        assert_eq!(kind_index("whatever"), 4);
    }
}
