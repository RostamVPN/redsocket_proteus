// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Proteus carrier — the HTTP Upgrade tunnel behind a programmable wire protocol.
//!
//! Each accepted socket is driven by a Proteus interpreter compiled from a PSF;
//! the interpreter's application side is an in-memory duplex that `http::serve_stream`
//! treats exactly like a client socket. A dedicated `[proteus]` listener wraps every
//! connection; the same-port mode (`[http] proteus_psf(s)`) peeks the first bytes of
//! a connection on the HTTP listener and wraps only those that are not HTTP.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use proteus::lang::compiler::parser::parse_psf;
use proteus::lang::compiler::{Compiler, TaskGraphImpl};
use proteus::lang::interpreter::Interpreter;
use proteus::lang::ir::bridge::OldCompile;
use proteus::lang::types::FieldSemantic;
use proteus::lang::Role;
use tokio::net::TcpStream;

use crate::http;

/// Capacity of the duplex between the interpreter and the HTTP handler.
const DUPLEX_CAP: usize = 64 * 1024;
/// Same per-connection budget as the TCP path.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(600);
/// How long the interpreter may take to flush and unwind after the tunnel ends.
const UNWIND_GRACE: Duration = Duration::from_secs(30);
/// Same-port classification shares the HTTP header deadline.
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

/// Compile a PSF file for `role`, with the path in the error message.
pub fn compile_psf(psf_path: &str, role: Role) -> anyhow::Result<TaskGraphImpl> {
    let text = std::fs::read_to_string(psf_path)
        .map_err(|e| anyhow::anyhow!("[PROTEUS] cannot read PSF {psf_path}: {e}"))?;
    compile_text(psf_path, &text, role)
}

/// Fail fast at start-up if the server-side PSF does not compile.
pub fn check_psf(psf_path: &str) -> anyhow::Result<()> {
    compile_psf(psf_path, Role::Server).map(|_| ())
}

/// The bytes a client of this PSF sends first, when its first message opens
/// with a fixed field; `None` when the first client bytes are not predictable.
pub fn fixed_prefix(psf_path: &str, text: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let psf = guarded(psf_path, || parse_psf(text))?;
    let Some(first) = psf.sequence.iter().find(|s| s.role == Role::Client) else {
        return Ok(None);
    };
    let Some(fmt) = psf.formats.get(&first.format) else {
        return Ok(None);
    };
    let Some(field) = fmt.format.format.fields.first() else {
        return Ok(None);
    };
    Ok(match fmt.semantics.as_ref().get(&field.name) {
        Some(FieldSemantic::FixedBytes(b)) => Some(b.clone()),
        Some(FieldSemantic::FixedString(s)) => Some(s.as_bytes().to_vec()),
        _ => None,
    })
}

/// Where the first bytes of a same-port connection send it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// An HTTP request line: a RedSocket client, or a browser owed the 404 decoy.
    Http,
    /// The PSF at this index of the table.
    Proteus(usize),
    /// Neither HTTP nor claimed by any PSF.
    Close,
    /// Still ambiguous; peek again once more bytes arrive.
    NeedMore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpVerdict {
    Yes,
    Prefix,
    No,
}

const METHODS: [&[u8]; 6] = [b"GET", b"POST", b"PUT", b"HEAD", b"OPTIONS", b"CONNECT"];

fn visible_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// Does `bytes` start with (or could it grow into) `METHOD /path HTTP/1.`?
fn http_verdict(bytes: &[u8]) -> HttpVerdict {
    let mut could_extend = false;
    let mut method_len = None;
    for m in METHODS {
        if bytes.len() >= m.len() {
            if bytes.starts_with(m) {
                method_len = Some(m.len());
                break;
            }
        } else if m.starts_with(bytes) {
            could_extend = true;
        }
    }
    let Some(method_len) = method_len else {
        return if could_extend {
            HttpVerdict::Prefix
        } else {
            HttpVerdict::No
        };
    };
    let rest = &bytes[method_len..];
    for (i, want) in b" /".iter().enumerate() {
        match rest.get(i) {
            None => return HttpVerdict::Prefix,
            Some(b) if b == want => {}
            Some(_) => return HttpVerdict::No,
        }
    }
    let rest = &rest[2..];
    let Some(space) = rest.iter().position(|&b| b == b' ') else {
        return if visible_ascii(rest) {
            HttpVerdict::Prefix
        } else {
            HttpVerdict::No
        };
    };
    if !visible_ascii(&rest[..space]) {
        return HttpVerdict::No;
    }
    let version = &rest[space + 1..];
    let want: &[u8] = b"HTTP/1.";
    if version.len() >= want.len() {
        if version.starts_with(want) {
            HttpVerdict::Yes
        } else {
            HttpVerdict::No
        }
    } else if want.starts_with(version) {
        HttpVerdict::Prefix
    } else {
        HttpVerdict::No
    }
}

/// Fixed-prefix dispatch table for the same-port mode.
#[derive(Debug, Clone, Default)]
pub struct Table {
    /// `(prefix, index)`, longest prefix first.
    prefixes: Vec<(Vec<u8>, usize)>,
    /// The PSF for non-HTTP bytes no prefix claims.
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
        match http_verdict(bytes) {
            HttpVerdict::Yes => Route::Http,
            HttpVerdict::Prefix => Route::NeedMore,
            HttpVerdict::No => self.route_proteus(bytes, false),
        }
    }

    /// Classify when no more bytes will come: an HTTP-looking start goes to the
    /// HTTP handler for its usual 400, a pending prefix no longer counts.
    pub fn route_final(&self, bytes: &[u8]) -> Route {
        match http_verdict(bytes) {
            HttpVerdict::Yes | HttpVerdict::Prefix => Route::Http,
            HttpVerdict::No => self.route_proteus(bytes, true),
        }
    }

    fn route_proteus(&self, bytes: &[u8], is_final: bool) -> Route {
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

/// The compiled PSFs sharing the HTTP listener, with their dispatch table.
pub struct Dispatch {
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
            protos.push(compile_text(name, text, Role::Server)?);
            match fixed_prefix(name, text)? {
                Some(p) => prefixes.push((p, i)),
                None => match default {
                    None => default = Some(i),
                    Some(d) => anyhow::bail!(
                        "[PROTEUS] {} and {} both start with unpredictable client bytes; \
                         only one PSF on a shared port may lack a fixed first message",
                        sources[d].0,
                        name
                    ),
                },
            }
            names.push(name.clone());
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

static SAME_PORT: OnceLock<Dispatch> = OnceLock::new();

/// Install the same-port dispatch for every HTTP listener.
pub fn set_same_port(dispatch: Dispatch) {
    let _ = SAME_PORT.set(dispatch);
}

pub fn same_port() -> Option<&'static Dispatch> {
    SAME_PORT.get()
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

/// Serve a connection from the HTTP listener in same-port mode.
pub async fn serve_same_port(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    keys: Arc<Vec<[u8; 32]>>,
    egress: Arc<[String]>,
    dispatch: &Dispatch,
) {
    let route = match peek_route(&stream, &dispatch.table).await {
        Ok(r) => r,
        Err(e) => {
            log::debug!("[PROTEUS] peek from {} failed: {}", peer, e);
            return;
        }
    };
    match route {
        Route::Http => http::serve_tcp(stream, peer, keys, egress).await,
        Route::Proteus(i) => {
            log::debug!("[PROTEUS] {} -> {}", peer, dispatch.names[i]);
            serve(stream, peer, keys, egress, dispatch.protos[i].clone()).await;
        }
        Route::Close | Route::NeedMore => {
            log::debug!(
                "[PROTEUS] {} is neither HTTP nor a known PSF, closing",
                peer
            );
        }
    }
}

/// Listen on `bind` and serve every connection through the interpreter.
pub async fn run(
    bind: &str,
    psf_path: &str,
    server_keys: Arc<Vec<[u8; 32]>>,
    egress_ips: Arc<[String]>,
    socket_sndbuf: usize,
    socket_rcvbuf: usize,
) -> anyhow::Result<()> {
    let proto = compile_psf(psf_path, Role::Server)?;
    let listener = http::bind_listener(bind).await?;
    log::info!("[PROTEUS] Listening on {} (psf={})", bind, psf_path);

    loop {
        let (stream, peer) = listener.accept().await?;
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

        let keys = server_keys.clone();
        let egress = egress_ips.clone();
        let proto = proto.clone();
        tokio::spawn(async move {
            serve(stream, peer, keys, egress, proto).await;
        });
    }
}

/// Run one connection: interpreter on the socket, HTTP handler on the duplex.
/// Under memory shedding the socket is dropped before any buffer is allocated.
pub async fn serve(
    tcp: TcpStream,
    peer: std::net::SocketAddr,
    keys: Arc<Vec<[u8; 32]>>,
    egress: Arc<[String]>,
    proto: TaskGraphImpl,
) {
    if crate::shed::is_shedding() {
        crate::shed::note_refused();
        log::debug!("[SHED] refusing proteus connection from {} — memory", peer);
        return;
    }

    let (app_side, interp_side) = tokio::io::duplex(DUPLEX_CAP);
    let (net_r, net_w) = tcp.into_split();
    let (int_r, int_w) = tokio::io::split(interp_side);

    let mut interp = tokio::spawn(async move {
        let mut interp = Interpreter::new(int_r, int_w, net_r, net_w, proto);
        if let Err(e) = interp.run_try_join().await {
            log::debug!("[PROTEUS] interpreter for {} ended: {}", peer, e);
        }
    });

    match tokio::time::timeout(
        CONNECTION_TIMEOUT,
        http::serve_stream(app_side, peer, keys, egress, None),
    )
    .await
    {
        Ok(Err(e)) => log::debug!("[PROTEUS] Connection error from {}: {}", peer, e),
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

    /// The 166-byte ClientHello from `tls_mimic.psf`.
    fn client_hello() -> Vec<u8> {
        fixed_prefix("tls_mimic.psf", TLS_MIMIC)
            .unwrap()
            .expect("tls_mimic opens with FIXED_BYTES")
    }

    #[test]
    fn an_http_request_line_is_http_and_a_partial_one_needs_more() {
        for line in [
            &b"GET /noise HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            b"GET / HTTP/1.0\r\n",
            b"POST /?cid=abc HTTP/1.1",
            b"CONNECT /x HTTP/1.",
            b"OPTIONS /x HTTP/1.1\r\n",
        ] {
            assert_eq!(http_verdict(line), HttpVerdict::Yes, "{line:?}");
        }
        for partial in [
            &b""[..],
            b"G",
            b"GET",
            b"GET ",
            b"GET /",
            b"GET /noise",
            b"GET /noise HTTP/1",
        ] {
            assert_eq!(http_verdict(partial), HttpVerdict::Prefix, "{partial:?}");
        }
    }

    #[test]
    fn tls_random_and_malformed_bytes_are_not_http() {
        let random = [
            0x9f, 0x41, 0x00, 0xe3, 0x7a, 0x2c, 0x55, 0x10, 0xff, 0x83, 0x6d, 0x1b,
        ];
        for bytes in [
            &client_hello()[..],
            &[0x16, 0x03, 0x01, 0x00, 0xa1],
            &random,
            b"FOO / HTTP/1.1\r\n",
            b"GET x HTTP/1.1\r\n",
            b"GET / HTTP/2\r\n",
            b"GET /\x00 HTTP/1.1",
            b"GETX / HTTP/1.1",
            b"get / HTTP/1.1",
        ] {
            assert_eq!(http_verdict(bytes), HttpVerdict::No, "{bytes:?}");
        }
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
        assert_eq!(
            no_default.route_final(&[]),
            Route::Http,
            "a silent peer gets the HTTP handler's 400"
        );
    }

    #[test]
    fn http_wins_over_every_prefix_and_a_partial_line_waits() {
        let t = table();
        assert_eq!(t.route(b"GET /noise HTTP/1.1\r\n"), Route::Http);
        assert_eq!(t.route(b"GET /no"), Route::NeedMore);
        assert_eq!(t.route_final(b"GET /no"), Route::Http);
        assert_eq!(
            t.route(b"GET / HTTP/1.1\r\n\r\n"),
            Route::Http,
            "non-upgrade requests still reach the 404 decoy"
        );
    }

    #[test]
    fn tls_mimic_dispatches_by_its_client_hello_and_shadowsocks_is_the_default() {
        let d = Dispatch::from_sources(&[
            ("tls_mimic.psf".to_string(), TLS_MIMIC.to_string()),
            ("shadowsocks.psf".to_string(), SHADOWSOCKS.to_string()),
        ])
        .unwrap();
        let hello = client_hello();
        assert_eq!(hello.len(), 166);
        assert_eq!(d.table().route(&hello), Route::Proteus(0));
        assert_eq!(d.table().route(&hello[..100]), Route::NeedMore);
        assert_eq!(
            d.table().route(&[0x00, 0x2a, 0x11, 0x22]),
            Route::Proteus(1)
        );
        assert_eq!(d.table().route(b"GET / HTTP/1.1\r\n"), Route::Http);
        assert_eq!(d.table().peek_len(), PEEK_MIN);
        assert_eq!(
            d.describe(),
            "tls_mimic.psf (prefix 166 bytes), shadowsocks.psf (default)"
        );
    }

    #[test]
    fn two_psfs_without_a_fixed_prefix_are_rejected() {
        let err = Dispatch::from_sources(&[
            ("a.psf".to_string(), SHADOWSOCKS.to_string()),
            ("tls_mimic.psf".to_string(), TLS_MIMIC.to_string()),
            ("b.psf".to_string(), SHADOWSOCKS.to_string()),
        ])
        .err()
        .expect("two defaults must be rejected")
        .to_string();
        assert!(err.contains("a.psf and b.psf"), "{err}");
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
