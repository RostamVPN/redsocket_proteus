// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! In-process end-to-end test harness: a real `redsocket-http` listener on loopback, a
//! MUX2 client (HTTP Upgrade → Noise NK → yamux) that can announce any header,
//! an echo target, and a RESP2 fake of valkey-main.

pub mod fake_valkey;

use std::io;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, Result};
use futures::future::poll_fn;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};

pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
pub const SOCKS5_OK: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

pub struct Server {
    pub addr: String,
    pub pubkey: [u8; 32],
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start the real HTTP carrier on a free loopback port with a fresh key.
pub async fn start_server() -> Server {
    let (priv_key, pub_key) = redsocket_http::noise::generate_keypair().unwrap();
    let addr = format!("127.0.0.1:{}", free_port());
    let keys = Arc::new(vec![priv_key]);
    let egress: Arc<[String]> = Vec::<String>::new().into();
    let bind = addr.clone();
    tokio::spawn(async move {
        if let Err(e) = redsocket_http::http::run(
            &bind,
            keys,
            redsocket_http::proxy_protocol::PpMode::Disabled,
            egress,
            0,
            0,
        )
        .await
        {
            eprintln!("server exited: {e}");
        }
    });
    for _ in 0..200 {
        if TcpStream::connect(&addr).await.is_ok() {
            return Server {
                addr,
                pubkey: pub_key,
            };
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("server did not come up on {addr}");
}

pub const BANNER: &[u8] = b"TARGET\n";

/// A target that greets with [`BANNER`] and echoes everything back.
pub async fn start_echo(bind: &str) -> std::net::SocketAddr {
    let l = TcpListener::bind(bind).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = s.write_all(BANNER).await;
                let mut buf = [0u8; 4096];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

pub struct NoiseSession {
    transport: snow::TransportState,
}

impl NoiseSession {
    fn encrypt(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let mut ct = vec![0u8; pt.len() + 16];
        let n = self.transport.write_message(pt, &mut ct)?;
        ct.truncate(n);
        Ok(ct)
    }
    fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let mut pt = vec![0u8; ct.len()];
        let n = self.transport.read_message(ct, &mut pt)?;
        pt.truncate(n);
        Ok(pt)
    }
}

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> io::Result<()> {
    s.write_all(&(data.len() as u16).to_be_bytes()).await?;
    s.write_all(data).await?;
    s.flush().await
}

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// TCP → HTTP Upgrade → Noise NK handshake. Returns the socket and session.
pub async fn upgrade_and_handshake(server: &Server) -> Result<(TcpStream, NoiseSession)> {
    let mut tcp = TcpStream::connect(&server.addr).await?;
    tcp.set_nodelay(true)?;
    let req = "GET /noise HTTP/1.1\r\nHost: test.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    tcp.write_all(req.as_bytes()).await?;
    tcp.flush().await?;
    let mut hdr = Vec::new();
    let mut b = [0u8; 1];
    loop {
        tcp.read_exact(&mut b).await?;
        hdr.push(b[0]);
        if hdr.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let line = String::from_utf8_lossy(&hdr);
    if !line.starts_with("HTTP/1.1 101") {
        return Err(anyhow!(
            "upgrade refused: {}",
            line.lines().next().unwrap_or("")
        ));
    }
    let mut hs = snow::Builder::new(NOISE_PATTERN.parse()?)
        .remote_public_key(&server.pubkey)
        .build_initiator()?;
    let mut msg1 = vec![0u8; 65535];
    let n1 = hs.write_message(&[], &mut msg1)?;
    write_frame(&mut tcp, &msg1[..n1]).await?;
    let msg2 = read_frame(&mut tcp).await?;
    let mut payload = vec![0u8; 65535];
    hs.read_message(&msg2, &mut payload)?;
    Ok((
        tcp,
        NoiseSession {
            transport: hs.into_transport_mode()?,
        },
    ))
}

fn wrap_noise(tcp: TcpStream, session: NoiseSession) -> DuplexStream {
    let (caller_side, internal_side) = tokio::io::duplex(64 * 1024);
    let (mut pt_r, mut pt_w) = tokio::io::split(internal_side);
    let session = Arc::new(Mutex::new(session));
    let (mut tcp_r, mut tcp_w) = tokio::io::split(tcp);
    let sess_d = session.clone();
    tokio::spawn(async move {
        loop {
            let Ok(ct) = read_frame(&mut tcp_r).await else {
                break;
            };
            let pt = match sess_d.lock().await.decrypt(&ct) {
                Ok(p) => p,
                Err(_) => break,
            };
            if pt.is_empty() {
                continue;
            }
            if pt_w.write_all(&pt).await.is_err() {
                break;
            }
        }
        let _ = pt_w.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535 - 16];
        loop {
            let n = match pt_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let ct = match session.lock().await.encrypt(&buf[..n]) {
                Ok(c) => c,
                Err(_) => break,
            };
            if write_frame(&mut tcp_w, &ct).await.is_err() {
                break;
            }
        }
        let _ = tcp_w.shutdown().await;
    });
    caller_side
}

type OpenTx = mpsc::Sender<oneshot::Sender<io::Result<yamux::Stream>>>;

pub struct MuxClient {
    open_tx: OpenTx,
    /// Streams the SERVER opened (the messaging control stream).
    pub inbound: mpsc::Receiver<yamux::Stream>,
    driver: tokio::task::JoinHandle<()>,
}

impl MuxClient {
    /// Open a MUX2 carrier announcing `header` verbatim, e.g.
    /// `MUX2|Asia/Dubai|rostam||<cid>||blk1,msg1`.
    pub async fn connect(server: &Server, header: &str) -> Result<MuxClient> {
        use tokio_util::compat::TokioAsyncReadCompatExt;
        let (mut tcp, mut noise) = upgrade_and_handshake(server).await?;
        let ct = noise.encrypt(header.as_bytes())?;
        write_frame(&mut tcp, &ct).await?;
        let noise_stream = wrap_noise(tcp, noise).compat();
        let mut cfg = yamux::Config::default();
        cfg.set_max_num_streams(256);
        cfg.set_split_send_size(64 * 1024);
        let mut conn = yamux::Connection::new(noise_stream, cfg, yamux::Mode::Client);
        let (open_tx, mut open_rx) =
            mpsc::channel::<oneshot::Sender<io::Result<yamux::Stream>>>(64);
        let (in_tx, inbound) = mpsc::channel::<yamux::Stream>(16);
        let driver = tokio::spawn(async move {
            let mut pending: std::collections::VecDeque<
                oneshot::Sender<io::Result<yamux::Stream>>,
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
                            while let Some(tx) = pending.pop_front() {
                                let _ = tx.send(Err(io::Error::other(format!("open: {e}"))));
                            }
                            return Poll::Ready(());
                        }
                        Poll::Pending => break,
                    }
                }
                loop {
                    match conn.poll_next_inbound(cx) {
                        Poll::Ready(Some(Ok(s))) => {
                            let _ = in_tx.try_send(s);
                        }
                        Poll::Ready(Some(Err(_))) | Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => break,
                    }
                }
                Poll::Pending
            })
            .await;
        });
        Ok(MuxClient {
            open_tx,
            inbound,
            driver,
        })
    }

    pub async fn open(&self) -> Result<tokio_util::compat::Compat<yamux::Stream>> {
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .await
            .map_err(|_| anyhow!("driver gone"))?;
        let s = tokio::time::timeout(std::time::Duration::from_secs(5), rx)
            .await
            .map_err(|_| anyhow!("open timed out"))??
            .map_err(|e| anyhow!("{e}"))?;
        Ok(s.compat())
    }

    /// Open a stream and send `[u16 BE len][request]`.
    pub async fn request(&self, req: &[u8]) -> Result<tokio_util::compat::Compat<yamux::Stream>> {
        let mut s = self.open().await?;
        s.write_all(&(req.len() as u16).to_be_bytes()).await?;
        s.write_all(req).await?;
        s.flush().await?;
        Ok(s)
    }

    /// The next stream the server opened toward us.
    pub async fn next_inbound(&mut self) -> Result<tokio_util::compat::Compat<yamux::Stream>> {
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let s = tokio::time::timeout(std::time::Duration::from_secs(5), self.inbound.recv())
            .await
            .map_err(|_| anyhow!("no inbound stream within 5s"))?
            .ok_or_else(|| anyhow!("driver gone"))?;
        Ok(s.compat())
    }
}

impl Drop for MuxClient {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

fn push_addr(v: &mut Vec<u8>, host: &str, port: u16) {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        v.push(0x01);
        v.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        v.push(0x04);
        v.extend_from_slice(&ip.octets());
    } else {
        v.push(0x03);
        v.push(host.len() as u8);
        v.extend_from_slice(host.as_bytes());
    }
    v.extend_from_slice(&port.to_be_bytes());
}

/// Today's trimmed request: `[05][atyp][addr][port]`.
pub fn trimmed(host: &str, port: u16) -> Vec<u8> {
    let mut v = vec![0x05];
    push_addr(&mut v, host, port);
    v
}

/// A `blk1` stream header: the trimmed request plus one trailing flags byte
/// (bit 0 = the user allowed this destination).
pub fn flagged(host: &str, port: u16, flags: u8) -> Vec<u8> {
    let mut v = trimmed(host, port);
    v.push(flags);
    v
}

/// Read one verdict frame.
pub async fn read_verdict<S: AsyncRead + Unpin>(
    s: &mut S,
) -> Result<redsocket_http::protection::Verdict> {
    let mut tag = [0u8; 1];
    s.read_exact(&mut tag).await?;
    let mut buf = vec![tag[0]];
    if tag[0] != 0 {
        let mut hdr = [0u8; 3];
        s.read_exact(&mut hdr).await?;
        buf.extend_from_slice(&hdr);
        let mut reason = vec![0u8; hdr[2] as usize];
        s.read_exact(&mut reason).await?;
        buf.extend_from_slice(&reason);
    }
    Ok(redsocket_http::protection::decode_verdict(&buf)?.0)
}

pub async fn expect_ok<S: AsyncRead + Unpin>(s: &mut S) -> Result<()> {
    let mut ok = [0u8; 10];
    tokio::time::timeout(std::time::Duration::from_secs(10), s.read_exact(&mut ok)).await??;
    if ok != SOCKS5_OK {
        return Err(anyhow!("not a SOCKS5 OK: {ok:02x?}"));
    }
    Ok(())
}

/// Banner, then a ping/echo round trip.
pub async fn expect_echo<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<()> {
    let mut banner = vec![0u8; BANNER.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        s.read_exact(&mut banner),
    )
    .await??;
    if banner != BANNER {
        return Err(anyhow!("bad banner {banner:?}"));
    }
    s.write_all(b"ping-pong").await?;
    s.flush().await?;
    let mut back = [0u8; 9];
    tokio::time::timeout(std::time::Duration::from_secs(10), s.read_exact(&mut back)).await??;
    if &back != b"ping-pong" {
        return Err(anyhow!("echo mismatch"));
    }
    Ok(())
}

/// The stream must end without another byte.
pub async fn expect_eof<S: AsyncRead + Unpin>(s: &mut S) -> Result<()> {
    let mut b = [0u8; 1];
    match tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut b)).await? {
        Ok(0) => Ok(()),
        Ok(n) => Err(anyhow!("expected EOF, got {} byte(s) {:02x?}", n, &b[..n])),
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn ip4(s: &str) -> u32 {
    u32::from(s.parse::<std::net::Ipv4Addr>().unwrap())
}
pub fn ip6(s: &str) -> u128 {
    u128::from(s.parse::<std::net::Ipv6Addr>().unwrap())
}

/// A `redsocket-http` binary run as a child on a free loopback port with a
/// minimal config: loopback dialable, no stats, no shedding.
pub struct ExternalServer {
    pub server: Server,
    child: std::process::Child,
    dir: std::path::PathBuf,
}

impl Drop for ExternalServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub async fn start_external_server(bin: &str) -> ExternalServer {
    let (priv_key, pub_key) = redsocket_http::noise::generate_keypair().unwrap();
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("rs-ext-{}-{}", std::process::id(), port));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = format!(
        "private_key = \"{}\"\npublic_key = \"{}\"\ndeny_cidrs = []\n\n[http]\nbind = \"127.0.0.1:{port}\"\nproxy_protocol = \"disabled\"\n\n[metrics]\nbind = \"127.0.0.1:0\"\n\n[shed]\nenabled = false\n",
        hex::encode(priv_key),
        hex::encode(pub_key)
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, cfg).unwrap();
    let child = std::process::Command::new(bin)
        .arg("--config")
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {bin}: {e}"));
    let addr = format!("127.0.0.1:{port}");

    let ext = ExternalServer {
        server: Server {
            addr: addr.clone(),
            pubkey: pub_key,
        },
        child,
        dir,
    };
    for _ in 0..200 {
        if TcpStream::connect(&addr).await.is_ok() {
            return ext;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    drop(ext);
    panic!("{bin} did not come up on {addr}");
}
