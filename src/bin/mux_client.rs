// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! MUX2 test client — one carrier + Noise NK + yamux, 3 test streams.

use std::io;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, Context, Result};
use futures::future::poll_fn;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, Mutex};

const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MSG: usize = 65535;
const SOCKS5_OK: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

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

async fn write_frame<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8]) -> io::Result<()> {
    s.write_all(&(data.len() as u16).to_be_bytes()).await?;
    s.write_all(data).await?;
    s.flush().await
}

async fn read_frame<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    s.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Noise NK handshake as initiator.
async fn noise_handshake<R, W>(mut r: R, mut w: W, server_pubkey: &[u8; 32]) -> Result<NoiseSession>
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
    write_frame(&mut w, &msg1[..n1]).await?;

    let msg2 = read_frame(&mut r).await?;
    let mut payload = vec![0u8; MAX_NOISE_MSG];
    hs.read_message(&msg2, &mut payload)?;

    Ok(NoiseSession {
        transport: hs.into_transport_mode()?,
    })
}

fn gen_cid() -> String {
    let mut buf = [0u8; 8];
    rand::Rng::fill(&mut rand::thread_rng(), &mut buf);
    hex::encode(buf)
}

fn wrap_noise<S>(tcp: S, session: NoiseSession) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
            if tcp_w
                .write_all(&(ct.len() as u16).to_be_bytes())
                .await
                .is_err()
            {
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

type OpenTx = mpsc::Sender<oneshot::Sender<io::Result<yamux::Stream>>>;

fn spawn_driver(
    mut conn: yamux::Connection<tokio_util::compat::Compat<DuplexStream>>,
) -> (OpenTx, tokio::task::JoinHandle<()>) {
    let (open_tx, mut open_rx) = mpsc::channel::<oneshot::Sender<io::Result<yamux::Stream>>>(64);

    let driver = tokio::spawn(async move {
        let mut pending: std::collections::VecDeque<oneshot::Sender<io::Result<yamux::Stream>>> =
            Default::default();

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
                        eprintln!("[mux-client] yamux outbound error: {}", e);
                        while let Some(tx) = pending.pop_front() {
                            let _ = tx.send(Err(io::Error::other(format!("yamux outbound: {e}"))));
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
                        eprintln!("[mux-client] yamux inbound error: {}", e);
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
            let _ = tx.send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "mux driver closed",
            )));
        }
    });

    (open_tx, driver)
}

async fn open_stream(open_tx: &OpenTx) -> Result<yamux::Stream> {
    let (tx, rx) = oneshot::channel();
    open_tx
        .send(tx)
        .await
        .map_err(|_| anyhow!("driver closed"))?;
    rx.await?.map_err(|e| anyhow!("open stream: {e}"))
}

fn connect_ipv4(ip: std::net::Ipv4Addr, port: u16) -> Vec<u8> {
    let mut v = vec![0x05, 0x01];
    v.extend_from_slice(&ip.octets());
    v.extend_from_slice(&port.to_be_bytes());
    v
}

fn connect_domain(host: &str, port: u16) -> Vec<u8> {
    let mut v = vec![0x05, 0x03, host.len() as u8];
    v.extend_from_slice(host.as_bytes());
    v.extend_from_slice(&port.to_be_bytes());
    v
}

async fn run_stream(
    open_tx: OpenTx,
    id: usize,
    connect: Vec<u8>,
    request: String,
    expect: &'static str,
) -> Result<String> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    let stream = open_stream(&open_tx).await?;
    let mut s = stream.compat();

    s.write_all(&(connect.len() as u16).to_be_bytes()).await?;
    s.write_all(&connect).await?;
    s.flush().await?;

    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await?;
    if reply != SOCKS5_OK {
        return Err(anyhow!("stream {id}: bad SOCKS5 reply: {reply:02x?}"));
    }

    s.write_all(request.as_bytes()).await?;
    s.flush().await?;

    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        match tokio::time::timeout_at(deadline, s.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => body.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => return Err(anyhow!("stream {id}: read: {e}")),
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&body);
    let status_line = text.lines().next().unwrap_or("").to_string();
    let ok = text.contains(expect);
    Ok(format!(
        "stream {id}: socks5-reply OK | {} | {} bytes | expect '{}' => {}",
        status_line,
        body.len(),
        expect,
        if ok { "PASS" } else { "CHECK" }
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let server = std::env::var("MUX_SERVER").unwrap_or_else(|_| "172.33.21.20:80".to_string());
    let pubkey_hex = std::env::var("MUX_PUBKEY").unwrap_or_else(|_| {
        "49afd1323e4f6ed44133c91af2f8a98b7a2fad7996a13b5d127cd813e3e98844".to_string()
    });
    let (host, port) = match server.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap()),
        None => (server.clone(), 80),
    };
    let pubkey_bytes = hex::decode(&pubkey_hex).context("bad pubkey hex")?;
    let pubkey: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pubkey must be 32 bytes"))?;
    let cid = gen_cid();

    eprintln!("[mux-client] server={}:{} cid={}", host, port, &cid);

    let mut tcp = TcpStream::connect(format!("{}:{}", host, port))
        .await
        .context("connect server")?;
    let req = format!(
        "GET /noise HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        host
    );
    tcp.write_all(req.as_bytes()).await?;
    tcp.flush().await?;

    let mut resp = vec![0u8; 1024];
    let n = tcp.read(&mut resp).await?;
    let resp_str = std::str::from_utf8(&resp[..n]).unwrap_or("");
    if !resp_str.starts_with("HTTP/1.1 101") {
        return Err(anyhow!(
            "upgrade failed: {}",
            resp_str.lines().next().unwrap_or("")
        ));
    }
    eprintln!("[mux-client] 101 OK");

    let (mut tcp_r, mut tcp_w) = tcp.split();
    let mut noise = noise_handshake(&mut tcp_r, &mut tcp_w, &pubkey).await?;
    eprintln!("[mux-client] noise handshake done");

    let mux2 = format!("MUX2|Asia/Tehran|mux-client|linux|{}|", cid);
    let ct = noise.encrypt(mux2.as_bytes())?;
    write_frame(&mut tcp, &ct).await?;
    eprintln!("[mux-client] MUX2 header sent");

    use tokio_util::compat::TokioAsyncReadCompatExt;
    let noise_stream = wrap_noise(tcp, noise).compat();
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(256);
    cfg.set_split_send_size(64 * 1024);
    let conn = yamux::Connection::new(noise_stream, cfg, yamux::Mode::Client);
    let (open_tx, driver) = spawn_driver(conn);

    let ip = std::net::Ipv4Addr::new(82, 21, 21, 129);
    let get129 = "GET / HTTP/1.1\r\nHost: 172.33.21.129\r\nConnection: close\r\n\r\n".to_string();
    let get_ex = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".to_string();

    let h1 = tokio::spawn(run_stream(
        open_tx.clone(),
        1,
        connect_ipv4(ip, 80),
        get129.clone(),
        "Not Found",
    ));
    let h2 = tokio::spawn(run_stream(
        open_tx.clone(),
        2,
        connect_ipv4(ip, 80),
        get129,
        "Not Found",
    ));
    let h3 = tokio::spawn(run_stream(
        open_tx.clone(),
        3,
        connect_domain("example.com", 80),
        get_ex,
        "<html",
    ));

    let r1 = h1.await;
    let r2 = h2.await;
    let r3 = h3.await;

    for (i, r) in [r1, r2, r3].into_iter().enumerate() {
        match r {
            Ok(Ok(msg)) => println!("{}", msg),
            Ok(Err(e)) => println!("stream {}: FAIL: {}", i + 1, e),
            Err(e) => println!("stream {}: JOIN FAIL: {}", i + 1, e),
        }
    }

    driver.abort();
    Ok(())
}
