// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! RedSocket standalone client — Proteus + Noise NK + META + SOCKS5.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use proteus::lang::compiler::{Compiler, TaskGraphImpl};
use proteus::lang::interpreter::Interpreter;
use proteus::lang::ir::bridge::OldCompile;
use proteus::lang::Role;
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Compile a client-role PSF, with the path in the error message. The Proteus
/// parser panics on malformed input; that becomes an error here.
fn compile_client_psf(path: &str) -> Result<TaskGraphImpl> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("cannot read PSF {}: {}", path, e))?;
    let compiled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Compiler::parse_content(&text, Role::Client)
    }));
    match compiled {
        Ok(r) => r.map_err(|e| anyhow!("PSF {} failed to compile: {:#}", path, e)),
        Err(_) => Err(anyhow!("PSF {} failed to compile", path)),
    }
}

/// Put a Proteus interpreter between the TCP socket and the tunnel code.
fn wrap_proteus(tcp: TcpStream, proto: &TaskGraphImpl) -> tokio::io::DuplexStream {
    let (app_side, interp_side) = tokio::io::duplex(64 * 1024);
    let (net_r, net_w) = tcp.into_split();
    let (int_r, int_w) = tokio::io::split(interp_side);
    let proto = proto.clone();
    tokio::spawn(async move {
        let mut interp = Interpreter::new(int_r, int_w, net_r, net_w, proto);
        if let Err(e) = interp.run_try_join().await {
            log::debug!("[proteus] interpreter ended: {}", e);
        }
    });
    app_side
}

/// SOCKS5 reply X'07' — command not supported.
const SOCKS5_CMD_UNSUPPORTED: [u8; 10] = [0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MSG: usize = 65535;

/// Noise NK session — encrypts/decrypts length-prefixed frames.
struct NoiseSession {
    transport: snow::TransportState,
}

impl NoiseSession {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ct = vec![0u8; plaintext.len() + 16];
        let n = self
            .transport
            .write_message(plaintext, &mut ct)
            .map_err(|e| anyhow!("encrypt: {e}"))?;
        ct.truncate(n);
        Ok(ct)
    }
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut pt = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(ciphertext, &mut pt)
            .map_err(|e| anyhow!("decrypt: {e}"))?;
        pt.truncate(n);
        Ok(pt)
    }
}

/// Write a [u16 BE len][payload] frame to the stream.
async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> std::io::Result<()> {
    let len = (data.len() as u16).to_be_bytes();
    s.write_all(&len).await?;
    s.write_all(data).await?;
    s.flush().await
}

/// Read a [u16 BE len][payload] frame from the stream.
async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    s.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Perform Noise NK handshake as initiator (client).
async fn noise_handshake<R, W>(
    mut stream_r: R,
    mut stream_w: W,
    server_pubkey: &[u8; 32],
) -> Result<NoiseSession>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let builder = snow::Builder::new(NOISE_PATTERN.parse()?);
    let mut hs = builder
        .remote_public_key(server_pubkey)
        .build_initiator()
        .map_err(|e| anyhow!("noise init: {e}"))?;

    let mut msg1 = vec![0u8; MAX_NOISE_MSG];
    let n1 = hs.write_message(&[], &mut msg1)?;
    write_frame(&mut stream_w, &msg1[..n1]).await?;

    let msg2 = read_frame(&mut stream_r).await?;
    let mut payload = vec![0u8; MAX_NOISE_MSG];
    hs.read_message(&msg2, &mut payload)?;

    let transport = hs.into_transport_mode()?;
    Ok(NoiseSession { transport })
}

/// Generate a random cid (16 hex chars).
fn gen_cid() -> String {
    let mut buf = [0u8; 8];
    rand::Rng::fill(&mut rand::thread_rng(), &mut buf);
    hex::encode(buf)
}

/// Detect local timezone.
fn detect_tz() -> String {
    std::env::var("TZ").unwrap_or_else(|_| {
        String::new()
    })
}

/// Detect OS.
fn detect_os() -> String {
    #[cfg(target_os = "android")]
    {
        "android".to_string()
    }
    #[cfg(target_os = "linux")]
    {
        "linux".to_string()
    }
    #[cfg(target_os = "windows")]
    {
        "windows".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macos".to_string()
    }
    #[cfg(target_os = "ios")]
    {
        "ios".to_string()
    }
}

/// Client config (TOML). All settings in one file.
#[derive(Debug, Deserialize)]
struct ClientConfig {
    /// Server address (ip:port or just ip, default port 443).
    pub server: String,
    /// Server Noise public key (hex, 64 chars).
    pub pubkey: String,
    /// Local SOCKS5 listen port.
    #[serde(default = "default_listen")]
    pub listen: u16,
    /// Use MUX2 (yamux) — one carrier multiplexes all SOCKS5 requests.
    #[serde(default)]
    pub mux: bool,
    /// Max yamux streams per carrier (MUX2 mode only).
    #[serde(default = "default_max_streams")]
    pub max_streams: usize,
    /// Client ID (auto-generated if omitted).
    pub cid: Option<String>,
    /// Proteus protocol specification wrapped around the carrier; `--proteus-psf`
    /// overrides it, and one of the two is required.
    pub proteus_psf: Option<String>,
    /// META frame fields sent inside the encrypted channel.
    #[serde(default)]
    pub meta: MetaConfig,
}

#[derive(Debug, Default, Deserialize)]
pub struct MetaConfig {
    /// App namespace/package name (e.g. "com.example.app").
    #[serde(default = "default_app")]
    pub app: String,
    /// OS version (e.g. "android-14", "ios-17.5"). Auto-detected if omitted.
    pub os: Option<String>,
    /// Timezone (e.g. "Asia/Tehran"). Auto-detected if omitted.
    pub tz: Option<String>,
    /// Primary destination SNI hint (informational, sent in encrypted META).
    #[serde(default)]
    pub sni: String,
}

fn default_listen() -> u16 {
    1080
}
fn default_app() -> String {
    "redsocket-client".to_string()
}
fn default_max_streams() -> usize {
    256
}

impl ClientConfig {
    fn load(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow!("Failed to read config {}: {}", path, e))?;
        let config: ClientConfig =
            toml::from_str(&text).map_err(|e| anyhow!("Failed to parse config: {}", e))?;
        if config.pubkey.len() != 64 {
            anyhow::bail!(
                "pubkey must be 64 hex chars (32 bytes), got {}",
                config.pubkey.len()
            );
        }
        Ok(config)
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "redsocket-client",
    about = "RedSocket standalone SOCKS5 client"
)]
struct Args {
    /// Path to config file (TOML).
    #[arg(long, default_value = "/etc/redsocket/client.toml")]
    config: String,

    /// Proteus PSF to wrap the carrier in (overrides `proteus_psf` in the config).
    #[arg(long)]
    proteus_psf: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let args = Args::parse();
    let cfg = ClientConfig::load(&args.config)?;

    let (host, port) = match cfg.server.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse::<u16>().unwrap())
        }
        _ => (cfg.server.clone(), 443),
    };

    let pubkey_bytes = hex::decode(&cfg.pubkey).map_err(|e| anyhow!("bad pubkey hex: {e}"))?;
    let pubkey: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pubkey must be 32 bytes"))?;

    let cid = cfg.cid.unwrap_or_else(gen_cid);
    let tz = cfg.meta.tz.unwrap_or_else(detect_tz);
    let os = cfg.meta.os.unwrap_or_else(detect_os);
    let psf_path = args.proteus_psf.or(cfg.proteus_psf).ok_or_else(|| {
        anyhow!("proteus_psf is required: set it in the config or pass --proteus-psf")
    })?;
    let proto = compile_client_psf(&psf_path)?;

    eprintln!(
        "[client] config={} server={}:{} psf={} cid={} tz={} app={} os={} mux={}",
        args.config,
        host,
        port,
        psf_path,
        &cid[..8.min(cid.len())],
        tz,
        cfg.meta.app,
        os,
        cfg.mux
    );

    let listener = TcpListener::bind(format!("127.0.0.1:{}", cfg.listen)).await?;
    eprintln!(
        "[client] SOCKS5 listening on 127.0.0.1:{} ({})",
        cfg.listen,
        if cfg.mux { "MUX2/yamux" } else { "single-stream" }
    );

    let carrier = CarrierConfig {
        server_host: host,
        server_port: port,
        server_pubkey: pubkey,
        cid,
        tz,
        app: cfg.meta.app,
        os,
        sni: cfg.meta.sni,
        max_streams: cfg.max_streams,
        proto,
    };

    if cfg.mux {
        let open_tx = start_mux_supervisor(carrier).await?;

        loop {
            let (socks_conn, peer) = listener.accept().await?;
            let tx = open_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_socks_muxed(socks_conn, tx).await {
                    log::debug!("[client] {} mux stream error: {}", peer, e);
                }
            });
        }
    } else {
        let carrier = Arc::new(carrier);
        loop {
            let (socks_conn, peer) = listener.accept().await?;
            let carrier = carrier.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_socks(socks_conn, &carrier).await {
                    log::debug!("[client] {} tunnel error: {}", peer, e);
                }
            });
        }
    }
}

/// Handle a SOCKS5 connection: parse CONNECT, open tunnel, relay.
async fn handle_socks(mut socks: TcpStream, carrier: &CarrierConfig) -> Result<()> {
    let mut buf = [0u8; 257];
    socks.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 {
        return Err(anyhow!("not SOCKS5"));
    }
    let nmethods = buf[1] as usize;
    socks.read_exact(&mut buf[..nmethods]).await?;
    socks.write_all(b"\x05\x00").await?;

    socks.read_exact(&mut buf[..4]).await?;
    if buf[0] != 0x05 {
        return Err(anyhow!("not SOCKS5"));
    }
    if buf[1] != 0x01 {
        let _ = socks.write_all(&SOCKS5_CMD_UNSUPPORTED).await;
        return Err(anyhow!(
            "unsupported SOCKS5 command {} (single-stream mode)",
            buf[1]
        ));
    }
    let (dest_host, dest_port) = match buf[3] {
        0x01 => {
            socks.read_exact(&mut buf[..4]).await?;
            let addr = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            socks.read_exact(&mut buf[..2]).await?;
            (addr.to_string(), u16::from_be_bytes([buf[0], buf[1]]))
        }
        0x03 => {
            socks.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            socks.read_exact(&mut buf[..len]).await?;
            let name = String::from_utf8_lossy(&buf[..len]).to_string();
            socks.read_exact(&mut buf[..2]).await?;
            let port = u16::from_be_bytes([buf[0], buf[1]]);
            (name, port)
        }
        0x04 => {
            socks.read_exact(&mut buf[..16]).await?;
            let addr = std::net::Ipv6Addr::from([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            socks.read_exact(&mut buf[..2]).await?;
            (addr.to_string(), u16::from_be_bytes([buf[0], buf[1]]))
        }
        _ => return Err(anyhow!("bad addr type")),
    };

    log::info!(
        "[client] CONNECT {}:{} via {}:{}",
        dest_host,
        dest_port,
        carrier.server_host,
        carrier.server_port
    );

    socks
        .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        .await?;

    let tcp = TcpStream::connect(format!("{}:{}", carrier.server_host, carrier.server_port))
        .await
        .context("connect to server")?;
    let tcp = wrap_proteus(tcp, &carrier.proto);

    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);
    let mut noise = noise_handshake(&mut tcp_r, &mut tcp_w, &carrier.server_pubkey).await?;

    let meta = format!(
        "META|{}|{}|{}|{}|{}",
        carrier.tz, carrier.app, carrier.os, carrier.cid, carrier.sni
    );
    let meta_ct = noise.encrypt(meta.as_bytes())?;
    write_frame(&mut tcp_w, &meta_ct).await?;
    log::info!(
        "[client] META sent (tz={} app={} os={} cid={}...)",
        carrier.tz,
        carrier.app,
        carrier.os,
        &carrier.cid[..8.min(carrier.cid.len())]
    );

    let mut connect = Vec::with_capacity(256);
    connect.push(0x05);
    if let Ok(ip) = dest_host.parse::<std::net::Ipv4Addr>() {
        connect.push(0x01);
        connect.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = dest_host.parse::<std::net::Ipv6Addr>() {
        connect.push(0x04);
        connect.extend_from_slice(&ip.octets());
    } else {
        connect.push(0x03);
        connect.push(dest_host.len() as u8);
        connect.extend_from_slice(dest_host.as_bytes());
    }
    connect.extend_from_slice(&dest_port.to_be_bytes());
    let connect_ct = noise.encrypt(&connect)?;
    write_frame(&mut tcp_w, &connect_ct).await?;

    let (mut socks_r, mut socks_w) = socks.into_split();

    let session = Arc::new(std::sync::Mutex::new(noise));

    let s1 = session.clone();
    let c2t = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match socks_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let ct = match s1.lock().unwrap().encrypt(&buf[..n]) {
                        Ok(ct) => ct,
                        Err(_) => break,
                    };
                    if write_frame(&mut tcp_w, &ct).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let s2 = session.clone();
    let t2c = tokio::spawn(async move {
        loop {
            let frame = match read_frame(&mut tcp_r).await {
                Ok(f) => f,
                Err(_) => break,
            };
            let pt = match s2.lock().unwrap().decrypt(&frame) {
                Ok(pt) => pt,
                Err(_) => break,
            };
            if socks_w.write_all(&pt).await.is_err() {
                break;
            }
        }
    });

    let _ = c2t.await;
    let _ = t2c.await;

    Ok(())
}

/// Plaintext duplex view over an established Noise session. Two background
/// tasks handle Noise framing on the wire.
fn wrap_noise_stream<S>(tcp: S, session: NoiseSession) -> tokio::io::DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    let (caller_side, internal_side) = tokio::io::duplex(64 * 1024);
    let (mut pt_r, mut pt_w) = tokio::io::split(internal_side);
    let session = Arc::new(Mutex::new(session));
    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);

    let sess_d = session.clone();
    tokio::spawn(async move {
        loop {
            let mut len_buf = [0u8; 2];
            if tcp_r.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let ct_len = u16::from_be_bytes(len_buf) as usize;
            if ct_len == 0 {
                break;
            }
            let mut ct = vec![0u8; ct_len];
            if tcp_r.read_exact(&mut ct).await.is_err() {
                break;
            }
            let pt = {
                let mut s = sess_d.lock().await;
                match s.decrypt(&ct) {
                    Ok(p) => p,
                    Err(_) => break,
                }
            };
            if pt.is_empty() {
                continue;
            }
            if pt_w.write_all(&pt).await.is_err() {
                break;
            }
        }
    });

    let sess_e = session.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match pt_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let ct = {
                let mut s = sess_e.lock().await;
                match s.encrypt(&buf[..n]) {
                    Ok(ct) => ct,
                    Err(_) => break,
                }
            };
            let frame_len = (ct.len() as u16).to_be_bytes();
            if tcp_w.write_all(&frame_len).await.is_err() {
                break;
            }
            if tcp_w.write_all(&ct).await.is_err() {
                break;
            }
        }
        let _ = tcp_w.shutdown().await;
    });

    caller_side
}

/// Yamux client driver — owns one carrier generation and opens streams on
/// demand.
type OpenTx =
    tokio::sync::mpsc::Sender<tokio::sync::oneshot::Sender<std::io::Result<yamux::Stream>>>;
type SupervisorTx = tokio::sync::mpsc::Sender<SupervisorRequest>;

enum SupervisorRequest {
    Open(tokio::sync::oneshot::Sender<std::result::Result<yamux::Stream, String>>),
    Reset,
}

/// Everything a carrier needs: where the server is, who we are, and the PSF.
#[derive(Clone)]
struct CarrierConfig {
    server_host: String,
    server_port: u16,
    server_pubkey: [u8; 32],
    cid: String,
    tz: String,
    app: String,
    os: String,
    sni: String,
    max_streams: usize,
    proto: TaskGraphImpl,
}

fn spawn_yamux_driver(
    mut conn: yamux::Connection<tokio_util::compat::Compat<tokio::io::DuplexStream>>,
) -> (OpenTx, tokio::task::JoinHandle<()>) {
    use futures::future::poll_fn;
    use std::task::{Context as TaskContext, Poll};

    let (open_tx, mut open_rx) = tokio::sync::mpsc::channel(64);
    let driver = tokio::spawn(async move {
        let mut pending: std::collections::VecDeque<
            tokio::sync::oneshot::Sender<std::io::Result<yamux::Stream>>,
        > = Default::default();

        poll_fn(|cx: &mut TaskContext<'_>| -> Poll<()> {
            loop {
                match open_rx.poll_recv(cx) {
                    Poll::Ready(Some(tx)) => pending.push_back(tx),
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
            while !pending.is_empty() {
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(Ok(s)) => {
                        let _ = pending.pop_front().unwrap().send(Ok(s));
                    }
                    Poll::Ready(Err(e)) => {
                        log::warn!("[mux] yamux outbound error: {}", e);
                        while let Some(tx) = pending.pop_front() {
                            let _ = tx.send(Err(std::io::Error::other(format!("yamux outbound: {e}"))));
                        }
                        return Poll::Ready(());
                    }
                    Poll::Pending => break,
                }
            }
            loop {
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(_))) => {}
                    Poll::Ready(Some(Err(e))) => {
                        log::warn!("[mux] yamux inbound error: {}", e);
                        return Poll::Ready(());
                    }
                    Poll::Ready(None) => return Poll::Ready(()),
                    Poll::Pending => break,
                }
            }
            Poll::Pending
        })
        .await;
        while let Ok(tx) = open_rx.try_recv() {
            let _ = tx.send(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "mux driver closed",
            )));
        }
    });

    (open_tx, driver)
}

async fn open_yamux_stream(open_tx: &OpenTx) -> Result<yamux::Stream> {
    open_yamux_stream_timeout(open_tx, std::time::Duration::from_secs(10)).await
}

async fn open_yamux_stream_timeout(
    open_tx: &OpenTx,
    timeout: std::time::Duration,
) -> Result<yamux::Stream> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::time::timeout(timeout, open_tx.send(tx))
        .await
        .map_err(|_| anyhow!("mux stream open timed out while queueing"))?
        .map_err(|_| anyhow!("driver closed"))?;
    tokio::time::timeout(timeout, rx)
        .await
        .map_err(|_| anyhow!("mux stream open timed out"))??
        .map_err(|e| anyhow!("open stream: {e}"))
}

#[cfg(test)]
async fn retry_once_after_reconnect<C, T, Connect, ConnectFuture, Use, UseFuture>(
    mut connect: Connect,
    mut use_carrier: Use,
) -> Result<T>
where
    Connect: FnMut() -> ConnectFuture,
    ConnectFuture: std::future::Future<Output = Result<C>>,
    Use: FnMut(C) -> UseFuture,
    UseFuture: std::future::Future<Output = Result<T>>,
{
    let first = connect().await?;
    match use_carrier(first).await {
        Ok(value) => Ok(value),
        Err(first_error) => {
            log::warn!("[mux] carrier failed, reconnecting: {}", first_error);
            let replacement = connect().await?;
            use_carrier(replacement).await
        }
    }
}

async fn reconnect_mux_carrier(config: &CarrierConfig) -> (OpenTx, tokio::task::JoinHandle<()>) {
    let mut delay = std::time::Duration::from_millis(250);
    loop {
        match establish_mux2_carrier(config).await {
            Ok(carrier) => {
                log::info!("[mux] carrier connected");
                return carrier;
            }
            Err(e) => {
                log::warn!("[mux] reconnect failed: {}; retrying in {:?}", e, delay);
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(5));
            }
        }
    }
}

async fn start_mux_supervisor(config: CarrierConfig) -> Result<SupervisorTx> {
    let (mut carrier_tx, mut driver) = establish_mux2_carrier(&config).await?;
    let (supervisor_tx, mut requests) = tokio::sync::mpsc::channel::<SupervisorRequest>(64);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                request = requests.recv() => {
                    let Some(request) = request else {
                        driver.abort();
                        break;
                    };
                    let SupervisorRequest::Open(request) = request else {
                        log::warn!("[mux] carrier reset requested");
                        driver.abort();
                        (carrier_tx, driver) = reconnect_mux_carrier(&config).await;
                        continue;
                    };
                    let stream = match open_yamux_stream(&carrier_tx).await {
                        Ok(stream) => Ok(stream),
                        Err(e) => {
                            log::warn!("[mux] stream open failed, replacing carrier: {}", e);
                            driver.abort();
                            (carrier_tx, driver) = reconnect_mux_carrier(&config).await;
                            open_yamux_stream(&carrier_tx)
                                .await
                                .map_err(|retry_error| retry_error.to_string())
                        }
                    };
                    let _ = request.send(stream);
                }
                result = &mut driver => {
                    match result {
                        Ok(()) => log::warn!("[mux] carrier driver stopped; reconnecting"),
                        Err(e) => log::warn!("[mux] carrier driver failed: {}; reconnecting", e),
                    }
                    (carrier_tx, driver) = reconnect_mux_carrier(&config).await;
                }
            }
        }
    });

    Ok(supervisor_tx)
}

async fn open_supervised_yamux_stream(open_tx: &SupervisorTx) -> Result<yamux::Stream> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        open_tx.send(SupervisorRequest::Open(reply_tx)),
    )
    .await
    .map_err(|_| anyhow!("mux supervisor queue timed out"))?
    .map_err(|_| anyhow!("mux supervisor closed"))?;
    tokio::time::timeout(std::time::Duration::from_secs(60), reply_rx)
        .await
        .map_err(|_| anyhow!("mux carrier recovery timed out"))??
        .map_err(|e| anyhow!("mux stream open: {e}"))
}

async fn reset_mux_carrier(open_tx: &SupervisorTx) -> Result<()> {
    open_tx
        .send(SupervisorRequest::Reset)
        .await
        .map_err(|_| anyhow!("mux supervisor closed"))
}

async fn open_mux_target(
    open_tx: &SupervisorTx,
    connect: &[u8],
) -> Result<tokio_util::compat::Compat<yamux::Stream>> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    for attempt in 0..2 {
        let stream = open_supervised_yamux_stream(open_tx).await?;
        let mut stream = stream.compat();
        let setup = async {
            stream
                .write_all(&(connect.len() as u16).to_be_bytes())
                .await?;
            stream.write_all(connect).await?;
            stream.flush().await?;

            let mut reply = [0u8; 10];
            stream.read_exact(&mut reply).await?;
            if reply != [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0] {
                return Err(anyhow!("bad SOCKS5 reply from server"));
            }
            Ok::<(), anyhow::Error>(())
        };

        match tokio::time::timeout(std::time::Duration::from_secs(10), setup).await {
            Ok(Ok(())) => return Ok(stream),
            Ok(Err(e)) if attempt == 0 => {
                log::warn!("[mux] target stream setup failed: {}; replacing carrier", e);
                reset_mux_carrier(open_tx).await?;
            }
            Err(_) if attempt == 0 => {
                log::warn!("[mux] target stream setup timed out; replacing carrier");
                reset_mux_carrier(open_tx).await?;
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(anyhow!("mux target stream setup timed out after reconnect")),
        }
    }
    unreachable!()
}

/// Establish a MUX2 carrier: TCP → Proteus → Noise NK → MUX2 header → yamux.
async fn establish_mux2_carrier(
    carrier: &CarrierConfig,
) -> Result<(OpenTx, tokio::task::JoinHandle<()>)> {
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let tcp = TcpStream::connect(format!("{}:{}", carrier.server_host, carrier.server_port))
        .await
        .context("connect to server")?;

    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(30))
        .with_interval(std::time::Duration::from_secs(10));
    socket2::SockRef::from(&tcp)
        .set_tcp_keepalive(&keepalive)
        .context("set carrier TCP keepalive")?;
    let tcp = wrap_proteus(tcp, &carrier.proto);

    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);
    let mut noise = noise_handshake(&mut tcp_r, &mut tcp_w, &carrier.server_pubkey).await?;

    let mux2 = format!(
        "MUX2|{}|{}|{}|{}|{}",
        carrier.tz, carrier.app, carrier.os, carrier.cid, carrier.sni
    );
    let ct = noise.encrypt(mux2.as_bytes())?;
    write_frame(&mut tcp_w, &ct)
        .await
        .map_err(|e| anyhow!("send MUX2 header: {e}"))?;
    log::info!(
        "[mux] MUX2 header sent (cid={}...)",
        &carrier.cid[..8.min(carrier.cid.len())]
    );

    let tcp = tcp_r.unsplit(tcp_w);

    let noise_stream = wrap_noise_stream(tcp, noise).compat();
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(carrier.max_streams);
    cfg.set_split_send_size(64 * 1024);
    let conn = yamux::Connection::new(noise_stream, cfg, yamux::Mode::Client);
    let (open_tx, driver) = spawn_yamux_driver(conn);

    Ok((open_tx, driver))
}

/// Handle a SOCKS5 connection over a MUX2 yamux stream.
async fn handle_socks_muxed(mut socks: TcpStream, open_tx: SupervisorTx) -> Result<()> {
    let mut buf = [0u8; 257];
    socks.read_exact(&mut buf[..2]).await?;
    if buf[0] != 0x05 {
        return Err(anyhow!("not SOCKS5"));
    }
    let nmethods = buf[1] as usize;
    socks.read_exact(&mut buf[..nmethods]).await?;
    socks.write_all(b"\x05\x00").await?;

    socks.read_exact(&mut buf[..4]).await?;
    if buf[0] != 0x05 {
        return Err(anyhow!("not SOCKS5"));
    }
    let cmd = buf[1];
    let (dest_host, dest_port) = match buf[3] {
        0x01 => {
            socks.read_exact(&mut buf[..4]).await?;
            let addr = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            socks.read_exact(&mut buf[..2]).await?;
            (addr.to_string(), u16::from_be_bytes([buf[0], buf[1]]))
        }
        0x03 => {
            socks.read_exact(&mut buf[..1]).await?;
            let len = buf[0] as usize;
            socks.read_exact(&mut buf[..len]).await?;
            let name = String::from_utf8_lossy(&buf[..len]).to_string();
            socks.read_exact(&mut buf[..2]).await?;
            (name, u16::from_be_bytes([buf[0], buf[1]]))
        }
        0x04 => {
            socks.read_exact(&mut buf[..16]).await?;
            let addr = std::net::Ipv6Addr::from([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
            ]);
            socks.read_exact(&mut buf[..2]).await?;
            (addr.to_string(), u16::from_be_bytes([buf[0], buf[1]]))
        }
        _ => return Err(anyhow!("bad addr type")),
    };

    if cmd == 0x03 {
        return handle_socks_udp(socks, open_tx).await;
    }
    if cmd != 0x01 {
        let _ = socks.write_all(&SOCKS5_CMD_UNSUPPORTED).await;
        return Err(anyhow!("unsupported SOCKS5 command {}", cmd));
    }

    log::info!("[mux] CONNECT {}:{} via yamux stream", dest_host, dest_port);

    let mut connect = Vec::with_capacity(256);
    connect.push(0x05);
    if let Ok(ip) = dest_host.parse::<std::net::Ipv4Addr>() {
        connect.push(0x01);
        connect.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = dest_host.parse::<std::net::Ipv6Addr>() {
        connect.push(0x04);
        connect.extend_from_slice(&ip.octets());
    } else {
        connect.push(0x03);
        connect.push(dest_host.len() as u8);
        connect.extend_from_slice(dest_host.as_bytes());
    }
    connect.extend_from_slice(&dest_port.to_be_bytes());
    let s = open_mux_target(&open_tx, &connect).await?;

    socks
        .write_all(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        .await?;

    let (mut socks_r, mut socks_w) = socks.into_split();
    let (mut s_r, mut s_w) = tokio::io::split(s);

    let c2t = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match socks_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if s_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    let t2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 32768];
        loop {
            match s_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if socks_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    let _ = c2t.await;
    let _ = t2c.await;
    Ok(())
}

/// UDP ASSOCIATE request, sent on a yamux stream in place of a CONNECT. Mirrors
/// `proxy::UDP_ASSOCIATE` in the server (no shared lib crate here).
const UDP_ASSOCIATE: [u8; 2] = [0x05, 0xFD];

/// Open the association stream. Deliberately NOT `open_mux_target`: that treats
/// a failed stream setup as a broken carrier and replaces it, which aborts the
/// yamux driver and every live TCP stream with it.
async fn open_mux_udp(open_tx: &SupervisorTx) -> Result<tokio_util::compat::Compat<yamux::Stream>> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    let mut s = open_supervised_yamux_stream(open_tx).await?.compat();
    let setup = async {
        s.write_all(&(UDP_ASSOCIATE.len() as u16).to_be_bytes())
            .await?;
        s.write_all(&UDP_ASSOCIATE).await?;
        s.flush().await?;
        let mut reply = [0u8; 10];
        s.read_exact(&mut reply).await?;
        if reply != [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0] {
            return Err(anyhow!("server declined UDP ASSOCIATE: {:02x?}", reply));
        }
        Ok::<(), anyhow::Error>(())
    };
    match tokio::time::timeout(std::time::Duration::from_secs(10), setup).await {
        Ok(Ok(())) => Ok(s),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow!("UDP ASSOCIATE setup timed out")),
    }
}

/// SOCKS5 UDP ASSOCIATE: bind a local UDP port and carry the app's datagrams
/// over one yamux stream, framed `[u16 BE len][datagram]`.
async fn handle_socks_udp(mut socks: TcpStream, open_tx: SupervisorTx) -> Result<()> {
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let bnd_port = udp.local_addr()?.port();

    let stream = match open_mux_udp(&open_tx).await {
        Ok(s) => s,
        Err(e) => {
            let _ = socks.write_all(&SOCKS5_CMD_UNSUPPORTED).await;
            return Err(e);
        }
    };

    let mut reply = vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1];
    reply.extend_from_slice(&bnd_port.to_be_bytes());
    socks.write_all(&reply).await?;
    log::info!("[mux] UDP ASSOCIATE bound 127.0.0.1:{}", bnd_port);

    let mut first = vec![0u8; 65535];
    let mut eof = [0u8; 1];
    let (n0, peer) = tokio::select! {
        r = udp.recv_from(&mut first) => r?,
        _ = socks.read(&mut eof) => return Ok(()),
    };
    udp.connect(peer).await?;
    let udp = Arc::new(udp);

    let (mut s_r, mut s_w) = tokio::io::split(stream);
    let up_sock = udp.clone();
    let mut up = tokio::spawn(async move {
        let mut buf = first;
        let mut n = n0;
        loop {
            if n > 0 && n <= 65535 {
                let mut frame = Vec::with_capacity(2 + n);
                frame.extend_from_slice(&(n as u16).to_be_bytes());
                frame.extend_from_slice(&buf[..n]);
                if s_w.write_all(&frame).await.is_err() {
                    break;
                }
            }
            match up_sock.recv(&mut buf).await {
                Ok(got) => n = got,
                Err(_) => break,
            }
        }
    });
    let mut down = tokio::spawn(async move {
        let mut len_buf = [0u8; 2];
        let mut buf = vec![0u8; 65535];
        loop {
            if s_r.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let n = u16::from_be_bytes(len_buf) as usize;
            if n == 0 || s_r.read_exact(&mut buf[..n]).await.is_err() {
                break;
            }

            let _ = udp.send(&buf[..n]).await;
        }
    });

    tokio::select! {
        _ = socks.read(&mut eof) => {}
        _ = &mut up => {}
        _ = &mut down => {}
    }
    up.abort();
    down.abort();
    Ok(())
}

#[cfg(test)]
mod mux_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn stalled_mux_driver_open_times_out() {
        let (open_tx, mut open_rx) = tokio::sync::mpsc::channel(1);
        let stalled_driver = tokio::spawn(async move {
            let _request = open_rx.recv().await;
            std::future::pending::<()>().await;
        });

        let result =
            open_yamux_stream_timeout(&open_tx, std::time::Duration::from_millis(25)).await;

        stalled_driver.abort();
        assert!(result.unwrap_err().to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn supervisor_retries_request_on_new_generation() {
        let generations = AtomicUsize::new(0);
        let value = retry_once_after_reconnect(
            || {
                let generation = generations.fetch_add(1, Ordering::SeqCst);
                async move { Ok::<_, anyhow::Error>(generation) }
            },
            |generation| async move {
                if generation == 0 {
                    Err(anyhow!("dead carrier"))
                } else {
                    Ok(generation)
                }
            },
        )
        .await
        .unwrap();

        assert_eq!(value, 1);
        assert_eq!(generations.load(Ordering::SeqCst), 2);
    }
}
