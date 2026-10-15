// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Proteus carrier — the only way into the server.
//!
//! Every accepted socket is driven by a Proteus interpreter compiled from the
//! PSF its first bytes select; the interpreter's application side is an
//! in-memory duplex on which the Noise NK handshake starts at once. Nothing is
//! ever answered in clear.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use proteus::lang::compiler::parser::parse_psf;
use proteus::lang::compiler::Compiler;
pub use proteus::lang::compiler::TaskGraphImpl;
use proteus::lang::interpreter::Interpreter;
use proteus::lang::ir::bridge::OldCompile;
use proteus::lang::types::{FieldSemantic, Psf};
pub use proteus::lang::Role;
use tokio::io::DuplexStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::noise_proxy;
use crate::proxy_protocol::{self, PpMode};

/// Capacity of the duplex between the interpreter and the tunnel.
const DUPLEX_CAP: usize = 64 * 1024;
/// Per-connection budget.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(600);
/// How long the interpreter may take to flush and unwind after the tunnel ends.
const UNWIND_GRACE: Duration = Duration::from_secs(30);
/// How long a connection has to send bytes that select a PSF.
const PEEK_DEADLINE: Duration = Duration::from_secs(5);
/// Interval between peeks while the first bytes are still ambiguous.
const PEEK_POLL: Duration = Duration::from_millis(20);
/// Smallest peek window; grows to fit the longest fixed prefix.
const PEEK_MIN: usize = 1024;

/// Run a PSF compilation step, turning the parser's panics into errors.
fn guarded<T>(psf_path: &str, step: impl FnOnce() -> anyhow::Result<T>) -> anyhow::Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(step)) {
        Ok(r) => {
            r.map_err(|e| anyhow::anyhow!("[PROTEUS] PSF {psf_path} failed to compile: {e:#}"))
        }
        Err(p) => {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            anyhow::bail!("[PROTEUS] PSF {psf_path} failed to compile: {msg}")
        }
    }
}

/// Compile PSF text for `role`, with `psf_path` in the error message.
pub fn compile_text(psf_path: &str, text: &str, role: Role) -> anyhow::Result<TaskGraphImpl> {
    guarded(psf_path, || Compiler::parse_content(text, role))
}

/// The password shipped in `proteus/shadowsocks.psf`, to be replaced before use.
const PLACEHOLDER_PASSWORD: &str = "REPLACE_WITH_PASSWORD";

/// Parse PSF text, refusing a crypto password left at the shipped placeholder.
fn parse(psf_path: &str, text: &str) -> anyhow::Result<Psf> {
    let psf = guarded(psf_path, || parse_psf(text))?;
    let password = psf.crypto_spec.as_ref().and_then(|c| c.password.as_ref());
    if password.is_some_and(|p| p.0 == PLACEHOLDER_PASSWORD) {
        anyhow::bail!(
            "[PROTEUS] PSF {psf_path} still has the placeholder password {PLACEHOLDER_PASSWORD}; \
             write your own into your copy"
        );
    }
    Ok(psf)
}

/// The bytes a client of this PSF sends first, when its first message opens
/// with a fixed field; `None` when the first client bytes are not predictable.
fn fixed_prefix(psf: &Psf) -> Option<Vec<u8>> {
    let first = psf.sequence.iter().find(|s| s.role == Role::Client)?;
    let fmt = psf.formats.get(&first.format)?;
    let field = fmt.format.format.fields.first()?;
    match fmt.semantics.as_ref().get(&field.name) {
        Some(FieldSemantic::FixedBytes(b)) => Some(b.clone()),
        Some(FieldSemantic::FixedString(s)) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

/// Where the first bytes of a connection send it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The PSF at this index of the table.
    Proteus(usize),
    /// Claimed by no PSF, or nothing was sent.
    Close,
    /// Still ambiguous; peek again once more bytes arrive.
    NeedMore,
}

/// Fixed-prefix dispatch table.
#[derive(Debug, Clone, Default)]
pub struct Table {
    /// `(prefix, index)`, longest prefix first.
    prefixes: Vec<(Vec<u8>, usize)>,
    /// The PSF for bytes no prefix claims.
    default: Option<usize>,
}

impl Table {
    pub fn new(mut prefixes: Vec<(Vec<u8>, usize)>, default: Option<usize>) -> Self {
        prefixes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Self { prefixes, default }
    }

    /// Bytes a peek must be able to hold to decide every prefix.
    fn peek_len(&self) -> usize {
        self.prefixes
            .first()
            .map_or(PEEK_MIN, |(p, _)| PEEK_MIN.max(p.len() + 1))
    }

    /// Classify bytes more of which may still arrive.
    pub fn route(&self, bytes: &[u8]) -> Route {
        if bytes.is_empty() {
            return Route::NeedMore;
        }
        self.classify(bytes, false)
    }

    /// Classify when no more bytes will come: a pending prefix no longer counts
    /// and a peer that sent nothing is closed.
    pub fn route_final(&self, bytes: &[u8]) -> Route {
        if bytes.is_empty() {
            return Route::Close;
        }
        self.classify(bytes, true)
    }

    fn classify(&self, bytes: &[u8], is_final: bool) -> Route {
        let mut pending = false;
        let mut matched = None;
        for (prefix, idx) in &self.prefixes {
            if bytes.len() >= prefix.len() {
                if matched.is_none() && bytes.starts_with(prefix) {
                    matched = Some(*idx);
                }
            } else if prefix.starts_with(bytes) {
                pending = true;
            }
        }
        if pending && !is_final {
            return Route::NeedMore;
        }
        match matched.or(self.default) {
            Some(i) => Route::Proteus(i),
            None => Route::Close,
        }
    }
}

/// The compiled PSFs of a listener, with their dispatch table.
pub struct Dispatch {
    /// File names without their directories, for the log.
    names: Vec<String>,
    protos: Vec<TaskGraphImpl>,
    table: Table,
}

impl Dispatch {
    /// Read and compile every PSF path.
    pub fn load(paths: &[String]) -> anyhow::Result<Self> {
        let mut sources = Vec::with_capacity(paths.len());
        for p in paths {
            let text = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("[PROTEUS] cannot read PSF {p}: {e}"))?;
            sources.push((p.clone(), text));
        }
        Self::from_sources(&sources)
    }

    /// Compile `(name, text)` pairs; at most one may lack a fixed prefix.
    pub fn from_sources(sources: &[(String, String)]) -> anyhow::Result<Self> {
        let mut names = Vec::with_capacity(sources.len());
        let mut protos = Vec::with_capacity(sources.len());
        let mut prefixes = Vec::new();
        let mut default = None;
        for (i, (name, text)) in sources.iter().enumerate() {
            let psf = parse(name, text)?;
            protos.push(compile_text(name, text, Role::Server)?);
            match fixed_prefix(&psf) {
                Some(p) => prefixes.push((p, i)),
                None => match default {
                    None => default = Some(i),
                    Some(d) => anyhow::bail!(
                        "[PROTEUS] {} and {} both start with unpredictable client bytes; \
                         only one PSF on a port may lack a fixed first message",
                        sources[d].0,
                        name
                    ),
                },
            }
            names.push(
                std::path::Path::new(name)
                    .file_name()
                    .map_or_else(|| name.clone(), |f| f.to_string_lossy().into_owned()),
            );
        }
        Ok(Self {
            names,
            protos,
            table: Table::new(prefixes, default),
        })
    }

    pub fn table(&self) -> &Table {
        &self.table
    }

    /// One line for the start-up log.
    pub fn describe(&self) -> String {
        self.names
            .iter()
            .enumerate()
            .map(
                |(i, n)| match self.table.prefixes.iter().find(|(_, idx)| *idx == i) {
                    Some((p, _)) => format!("{n} (prefix {} bytes)", p.len()),
                    None => format!("{n} (default)"),
                },
            )
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Bind with SO_REUSEADDR (restart over TIME_WAIT) and SO_REUSEPORT (N daemons
/// on one port, zero-downtime restarts).
async fn bind_listener(bind_addr: &str) -> anyhow::Result<TcpListener> {
    let addr: SocketAddr = bind_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address {bind_addr}: {e}"))?;
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, None)?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    if let Err(e) = sock.set_reuse_port(true) {
        log::warn!(
            "[PROTEUS] SO_REUSEPORT unsupported on this platform: {} (continuing)",
            e
        );
    }
    sock.bind(&addr.into())?;
    sock.listen(4096)?;
    TcpListener::from_std(sock.into()).map_err(Into::into)
}

/// Peek (never consume) the first bytes until they classify or the deadline passes.
async fn peek_route(stream: &TcpStream, table: &Table) -> std::io::Result<Route> {
    let deadline = tokio::time::Instant::now() + PEEK_DEADLINE;
    let mut buf = vec![0u8; table.peek_len()];
    let mut seen = 0;
    loop {
        let n = match tokio::time::timeout_at(deadline, stream.peek(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(table.route_final(&buf[..seen])),
        };
        if n == 0 {
            return Ok(table.route_final(&buf[..seen]));
        }
        seen = n;
        match table.route(&buf[..n]) {
            Route::NeedMore if n < buf.len() => {
                if tokio::time::timeout_at(deadline, tokio::time::sleep(PEEK_POLL))
                    .await
                    .is_err()
                {
                    return Ok(table.route_final(&buf[..n]));
                }
            }
            Route::NeedMore => return Ok(table.route_final(&buf[..n])),
            route => return Ok(route),
        }
    }
}

/// Listen on `bind` and serve every connection through the PSF its first
/// bytes select. Under memory shedding a socket is dropped before any peek or
/// buffer; a PROXY header, if enabled, is read before the first bytes are peeked.
pub async fn run(
    bind: &str,
    dispatch: Arc<Dispatch>,
    server_keys: Arc<Vec<[u8; 32]>>,
    pp_mode: PpMode,
    egress_ips: Arc<[String]>,
    socket_sndbuf: usize,
    socket_rcvbuf: usize,
) -> anyhow::Result<()> {
    let listener = bind_listener(bind).await?;
    log::info!(
        "[PROTEUS] Listening on {} (proxy_protocol={:?})",
        bind,
        pp_mode
    );

    loop {
        let (stream, edge_peer) = listener.accept().await?;
        let _ = stream.set_nodelay(true);

        {
            let sock = socket2::SockRef::from(&stream);
            if socket_sndbuf > 0 {
                let _ = sock.set_send_buffer_size(socket_sndbuf);
            }
            if socket_rcvbuf > 0 {
                let _ = sock.set_recv_buffer_size(socket_rcvbuf);
            }
            let ka = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(10));
            let _ = sock.set_tcp_keepalive(&ka);
        }

        let dispatch = dispatch.clone();
        let keys = server_keys.clone();
        let egress = egress_ips.clone();
        tokio::spawn(async move {
            if crate::shed::is_shedding() {
                crate::shed::note_refused();
                log::debug!("[SHED] refusing connection from {} — memory", edge_peer);
                return;
            }
            let mut stream = stream;
            let peer = match proxy_protocol::peek_and_strip(&mut stream, edge_peer, pp_mode).await
            {
                Ok(p) => p,
                Err(e) => {
                    log::debug!("[PROTEUS] PROXY parse from {}: {}", edge_peer, e);
                    return;
                }
            };
            match peek_route(&stream, &dispatch.table).await {
                Ok(Route::Proteus(i)) => {
                    log::debug!("[PROTEUS] {} -> {}", peer, dispatch.names[i]);
                    serve(stream, peer, keys, egress, dispatch.protos[i].clone()).await;
                }
                Ok(Route::Close | Route::NeedMore) => {
                    log::debug!("[PROTEUS] {} opened with no known PSF's bytes, closing", peer);
                }
                Err(e) => log::debug!("[PROTEUS] peek from {} failed: {}", peer, e),
            }
        });
    }
}

/// Put `proto` between `tcp` and the returned application-side stream. The
/// handle is the interpreter task; `peer` only names it in the log.
pub fn wrap(
    tcp: TcpStream,
    peer: SocketAddr,
    proto: TaskGraphImpl,
) -> (DuplexStream, JoinHandle<()>) {
    let (app_side, interp_side) = tokio::io::duplex(DUPLEX_CAP);
    let (net_r, net_w) = tcp.into_split();
    let (int_r, int_w) = tokio::io::split(interp_side);
    let task = tokio::spawn(async move {
        let mut interp = Interpreter::new(int_r, int_w, net_r, net_w, proto);
        if let Err(e) = interp.run_try_join().await {
            log::debug!("[PROTEUS] interpreter for {} ended: {}", peer, e);
        }
    });
    (app_side, task)
}

/// Run one connection: interpreter on the socket, Noise tunnel on the duplex.
async fn serve(
    tcp: TcpStream,
    peer: SocketAddr,
    keys: Arc<Vec<[u8; 32]>>,
    egress: Arc<[String]>,
    proto: TaskGraphImpl,
) {
    let (app_side, mut interp) = wrap(tcp, peer, proto);
    let real_ip = peer.ip().to_string();
    let capture = crate::stats::enabled().then(|| crate::stats::Capture::new(&real_ip, ""));

    match tokio::time::timeout(
        CONNECTION_TIMEOUT,
        noise_proxy::run_streaming_tunnel(app_side, &keys, &real_ip, egress, capture),
    )
    .await
    {
        Ok(Err(e)) => {
            log::debug!("[PROTEUS] {} tunnel error: {}", real_ip, e);
            crate::metrics::inc_hs_fail();
        }
        Err(_) => log::debug!("[PROTEUS] Connection timeout (600s) from {}", peer),
        _ => {}
    }

    if tokio::time::timeout(UNWIND_GRACE, &mut interp)
        .await
        .is_err()
    {
        interp.abort();
        log::debug!("[PROTEUS] interpreter for {} did not unwind in time", peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TLS_MIMIC: &str = include_str!("../proteus/tls_mimic.psf");
    const SHADOWSOCKS: &str = include_str!("../proteus/shadowsocks.psf");

    /// `shadowsocks.psf` with a password written in, as an operator's copy.
    fn shadowsocks() -> String {
        SHADOWSOCKS.replace(PLACEHOLDER_PASSWORD, "test-password")
    }

    /// The 166-byte ClientHello from `tls_mimic.psf`.
    fn client_hello() -> Vec<u8> {
        fixed_prefix(&parse("tls_mimic.psf", TLS_MIMIC).unwrap())
            .expect("tls_mimic opens with FIXED_BYTES")
    }

    fn table() -> Table {
        Table::new(
            vec![
                (vec![0x16, 0x03, 0x01], 0),
                (vec![0x16, 0x03, 0x01, 0x00, 0xa1], 1),
            ],
            Some(2),
        )
    }

    fn both() -> Dispatch {
        Dispatch::from_sources(&[
            ("tls_mimic.psf".to_string(), TLS_MIMIC.to_string()),
            ("shadowsocks.psf".to_string(), shadowsocks()),
        ])
        .unwrap()
    }

    #[test]
    fn the_longest_full_prefix_match_wins_and_shorter_ones_wait() {
        let t = table();
        assert_eq!(
            t.route(&[0x16, 0x03, 0x01, 0x00, 0xa1, 0x01]),
            Route::Proteus(1)
        );
        assert_eq!(t.route(&[0x16, 0x03, 0x01, 0x02]), Route::Proteus(0));
        assert_eq!(t.route(&[0x16, 0x03]), Route::NeedMore);
        assert_eq!(
            t.route(&[0x16, 0x03, 0x01]),
            Route::NeedMore,
            "longer prefix still pending"
        );
        assert_eq!(t.route(&[0x16, 0x03, 0x01, 0x00]), Route::NeedMore);
        assert_eq!(t.route_final(&[0x16, 0x03, 0x01]), Route::Proteus(0));
        assert_eq!(
            t.route_final(&[0x16, 0x03]),
            Route::Proteus(2),
            "unfinished prefix falls to the default"
        );
    }

    #[test]
    fn unclaimed_bytes_go_to_the_default_or_close_without_one() {
        let random = [0x9f, 0x41, 0x00, 0xe3, 0x7a, 0x2c, 0x55, 0x10];
        assert_eq!(table().route(&random), Route::Proteus(2));
        let no_default = Table::new(vec![(vec![0x16, 0x03, 0x01], 0)], None);
        assert_eq!(no_default.route(&random), Route::Close);
        assert_eq!(no_default.route_final(&[0x16]), Route::Close);
    }

    #[test]
    fn a_silent_peer_is_closed_whatever_the_table() {
        assert_eq!(table().route(&[]), Route::NeedMore);
        assert_eq!(table().route_final(&[]), Route::Close, "even with a default");
        assert_eq!(Table::new(Vec::new(), Some(0)).route_final(&[]), Route::Close);
    }

    /// Nothing answers HTTP: a request line is bytes like any other, taken by
    /// the default PSF or closed.
    #[test]
    fn an_http_request_line_is_claimed_by_no_psf() {
        let d = both();
        for line in [
            &b"GET /noise HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\n\r\n",
            b"POST /?cid=abc HTTP/1.1",
        ] {
            assert_eq!(d.table().route(line), Route::Proteus(1), "{line:?}");
        }
        let only_tls =
            Dispatch::from_sources(&[("tls_mimic.psf".to_string(), TLS_MIMIC.to_string())])
                .unwrap();
        assert_eq!(
            only_tls.table().route(b"GET /noise HTTP/1.1\r\n"),
            Route::Close
        );
        assert_eq!(only_tls.table().route(b"G"), Route::Close);
    }

    #[test]
    fn tls_mimic_dispatches_by_its_client_hello_and_shadowsocks_is_the_default() {
        let d = both();
        let hello = client_hello();
        assert_eq!(hello.len(), 166);
        assert_eq!(d.table().route(&hello), Route::Proteus(0));
        assert_eq!(d.table().route(&hello[..100]), Route::NeedMore);
        assert_eq!(d.table().route_final(&hello[..100]), Route::Proteus(1));
        assert_eq!(
            d.table().route(&[0x00, 0x2a, 0x11, 0x22]),
            Route::Proteus(1)
        );
        assert_eq!(d.table().peek_len(), PEEK_MIN);
        assert_eq!(
            d.describe(),
            "tls_mimic.psf (prefix 166 bytes), shadowsocks.psf (default)"
        );
        let by_path = Dispatch::from_sources(&[(
            "/etc/redsocket/proteus/tls_mimic.psf".to_string(),
            TLS_MIMIC.to_string(),
        )])
        .unwrap();
        assert_eq!(by_path.describe(), "tls_mimic.psf (prefix 166 bytes)");
    }

    #[test]
    fn two_psfs_without_a_fixed_prefix_are_rejected() {
        let err = Dispatch::from_sources(&[
            ("a.psf".to_string(), shadowsocks()),
            ("tls_mimic.psf".to_string(), TLS_MIMIC.to_string()),
            ("b.psf".to_string(), shadowsocks()),
        ])
        .err()
        .expect("two defaults must be rejected")
        .to_string();
        assert!(err.contains("a.psf and b.psf"), "{err}");
    }

    #[test]
    fn the_shipped_placeholder_password_is_refused() {
        let err =
            Dispatch::from_sources(&[("shadowsocks.psf".to_string(), SHADOWSOCKS.to_string())])
                .err()
                .expect("the placeholder password must be refused")
                .to_string();
        assert!(
            err.contains("shadowsocks.psf still has the placeholder password"),
            "{err}"
        );
    }

    #[test]
    fn a_malformed_psf_is_an_error_not_a_panic() {
        let err = compile_text("bad.psf", "@SEGMENT.FORMATS\n  nonsense", Role::Server)
            .err()
            .expect("malformed PSF must be rejected")
            .to_string();
        assert!(err.contains("bad.psf failed to compile"), "{err}");
    }
}
