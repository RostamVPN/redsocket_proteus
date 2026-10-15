// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Load harness: open N concurrent tunnels (HTTPUpgrade + Noise NK + SOCKS5),
//! hold them open (idle), and optionally trickle bytes. Reproduces the
//! production resource profile: many long-lived concurrent connections.

use snow::Builder;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

static OPENED: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct Cfg {
    server: String,
    pubkey: [u8; 32],
    target: String,
    hold_secs: u64,
    trickle: bool,
}

async fn one_tunnel(cfg: Cfg) -> anyhow::Result<()> {
    let mut s = TcpStream::connect(&cfg.server).await?;
    s.set_nodelay(true)?;
    let req = format!(
        "GET /noise HTTP/1.1\r\nHost: {}\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        cfg.server
    );
    s.write_all(req.as_bytes()).await?;

    let mut hdr = Vec::new();
    let mut b = [0u8; 1];
    loop {
        s.read_exact(&mut b).await?;
        hdr.push(b[0]);
        if hdr.len() >= 4 && &hdr[hdr.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if hdr.len() > 4096 {
            anyhow::bail!("hdr");
        }
    }
    if !String::from_utf8_lossy(&hdr).starts_with("HTTP/1.1 101") {
        anyhow::bail!("no 101");
    }

    let mut hs = Builder::new(NOISE_PATTERN.parse()?)
        .remote_public_key(&cfg.pubkey)
        .build_initiator()?;
    let mut m1 = vec![0u8; 65535];
    let n1 = hs.write_message(&[], &mut m1)?;
    let mut f = (n1 as u16).to_be_bytes().to_vec();
    f.extend_from_slice(&m1[..n1]);
    s.write_all(&f).await?;

    let mut lb = [0u8; 2];
    s.read_exact(&mut lb).await?;
    let l2 = u16::from_be_bytes(lb) as usize;
    let mut m2 = vec![0u8; l2];
    s.read_exact(&mut m2).await?;
    let mut rb = vec![0u8; 65535];
    hs.read_message(&m2, &mut rb)?;
    let mut t = hs.into_transport_mode()?;

    let (th, tp) = cfg.target.rsplit_once(':').unwrap();
    let tp: u16 = tp.parse()?;
    let mut conn = vec![0x05u8, 0x03, th.len() as u8];
    conn.extend_from_slice(th.as_bytes());
    conn.extend_from_slice(&tp.to_be_bytes());
    let mut ct = vec![0u8; 65535];
    let cl = t.write_message(&conn, &mut ct)?;
    let mut f2 = (cl as u16).to_be_bytes().to_vec();
    f2.extend_from_slice(&ct[..cl]);
    s.write_all(&f2).await?;
    s.flush().await?;

    OPENED.fetch_add(1, Ordering::Relaxed);

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    let deadline = Instant::now() + std::time::Duration::from_secs(cfg.hold_secs);
    while Instant::now() < deadline {
        interval.tick().await;
        if cfg.trickle {
            let mut ct2 = vec![0u8; 65535];
            let n = t.write_message(b"x", &mut ct2)?;
            let mut f3 = (n as u16).to_be_bytes().to_vec();
            f3.extend_from_slice(&ct2[..n]);
            if s.write_all(&f3).await.is_err() {
                break;
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    let get = |k: &str, d: &str| {
        a.windows(2)
            .find(|w| w[0] == k)
            .map(|w| w[1].clone())
            .unwrap_or(d.into())
    };
    let server = get("--server", "");
    let pubkey_hex = get("--pubkey", "");
    let conns: usize = get("--conns", "1000").parse()?;
    let batch: usize = get("--batch", "500").parse()?;
    let hold_secs: u64 = get("--hold-secs", "120").parse()?;
    let trickle = a.iter().any(|x| x == "--trickle");
    let target = get("--target", "example.com:80");
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&hex::decode(&pubkey_hex)?);

    let cfg = Cfg {
        server: server.clone(),
        pubkey,
        target,
        hold_secs,
        trickle,
    };
    println!(
        "[*] {} conns → {} (batch {}, hold {}s, trickle={})",
        conns, server, batch, hold_secs, trickle
    );

    let t0 = Instant::now();
    let mut handles = Vec::new();
    let mut launched = 0usize;
    while launched < conns {
        let n = (conns - launched).min(batch);
        for _ in 0..n {
            let c = cfg.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = one_tunnel(c).await {
                    let n = FAILED.fetch_add(1, Ordering::Relaxed);
                    if n < 5 {
                        eprintln!("[!] tunnel failed: {e}");
                    }
                }
            }));
        }
        launched += n;
        println!(
            "[*] launched {}/{} — opened={} failed={} ({}ms)",
            launched,
            conns,
            OPENED.load(Ordering::Relaxed),
            FAILED.load(Ordering::Relaxed),
            t0.elapsed().as_millis()
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let reporter = tokio::spawn(async move {
        let mut iv = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            iv.tick().await;
            println!(
                "[stats] opened={} failed={}",
                OPENED.load(Ordering::Relaxed),
                FAILED.load(Ordering::Relaxed)
            );
        }
    });

    for h in handles {
        let _ = h.await;
    }
    reporter.abort();
    println!(
        "[done] opened={} failed={} in {:?}",
        OPENED.load(Ordering::Relaxed),
        FAILED.load(Ordering::Relaxed),
        t0.elapsed()
    );
    Ok(())
}
