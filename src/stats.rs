// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

static STATS_FLAGS: std::sync::OnceLock<StatsFlags> = std::sync::OnceLock::new();

#[derive(Clone, Debug)]
pub struct StatsFlags {
    pub cids: bool,
}

impl Default for StatsFlags {
    fn default() -> Self {
        Self { cids: true }
    }
}

pub fn set_flags(flags: StatsFlags) {
    let _ = STATS_FLAGS.set(flags);
}

static HOSTNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn init_hostname() {
    let host = std::env::var("REDSOCKET_HOSTNAME").unwrap_or_else(|_| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });
    let _ = HOSTNAME.set(host);
}

#[inline]
pub fn hostname() -> &'static str {
    HOSTNAME.get().map(|s| s.as_str()).unwrap_or("unknown")
}

#[inline]
fn cids_enabled() -> bool {
    STATS_FLAGS.get().map(|f| f.cids).unwrap_or(true)
}

pub struct Capture {
    timestamp: String,
    real_ip: String,
    cid: String,
}

impl Capture {
    pub fn new(real_ip: &str, cid: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            real_ip: real_ip.to_owned(),
            cid: cid.to_owned(),
        }
    }

    pub fn emit(mut self, cid: &str, tz: &str, app: &str, os: &str, sni: &str) {
        if !cid.is_empty() {
            self.cid.clear();
            self.cid.push_str(cid);
        }
        if self.cid.is_empty() {
            return;
        }
        record_cid(&cid_row(&self.timestamp, &self.real_ip, &self.cid, tz, app, os, sni));
    }
}

fn cid_row(timestamp: &str, real_ip: &str, cid: &str, tz: &str, app: &str, os: &str, sni: &str) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\ttunnel",
        timestamp,
        real_ip,
        tsv_field(cid),
        tsv_field(tz),
        tsv_field(app),
        tsv_field(os),
        tsv_field(sni),
    )
}

const FLUSH_BATCH: usize = 200;
const RECONNECT_SECS: u64 = 5;
const QUEUE_CAP: usize = 200_000;

#[derive(Clone)]
pub struct Config {
    pub addr: String,
    pub password: String,
    pub ca_pem: String,
    pub server_name: String,
}

static DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn dropped_records() -> u64 {
    DROPPED.load(std::sync::atomic::Ordering::Relaxed)
}

#[inline]
fn enqueue(tx: &mpsc::Sender<String>, msg: String) {
    if tx.try_send(msg).is_err() {
        DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

static TX: std::sync::OnceLock<mpsc::Sender<String>> = std::sync::OnceLock::new();

#[inline]
pub fn enabled() -> bool {
    TX.get().is_some() && cids_enabled()
}

fn tsv_field(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\t' | '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}' => ' ',
            c if (c as u32) < 0x20 => ' ',
            c => c,
        })
        .collect()
}

pub fn spawn(cfg: Config) {
    let (tx, rx) = mpsc::channel::<String>(QUEUE_CAP);
    if TX.set(tx).is_err() {
        return;
    }
    log::info!("[STATS] cid stats -> {} (TLS, sni={})", cfg.addr, cfg.server_name);
    tokio::spawn(async move { run(cfg, rx).await });
}

pub fn record_cid(tsv: &str) {
    if !cids_enabled() {
        return;
    }
    if let Some(tx) = TX.get() {
        enqueue(tx, format!("CID\n{tsv}\t{}", hostname()));
    }
}

pub fn record_tunnel_closed(cid: &str, start_ts: u64, duration_secs: u64, bytes_up: u64, bytes_down: u64) {
    if cid.is_empty() || !cids_enabled() {
        return;
    }
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if let Some(tx) = TX.get() {
        enqueue(
            tx,
            format!(
                "TUNNEL\n{now_ts}\t{cid}\t{start_ts}\t{duration_secs}\t{bytes_up}\t{bytes_down}\t{host}",
                cid = tsv_field(cid),
                host = hostname()
            ),
        );
    }
}

async fn run(cfg: Config, mut rx: mpsc::Receiver<String>) {
    loop {
        match connect(&cfg).await {
            Ok(mut stream) => {
                if let Err(e) = auth(&mut stream, &cfg.password).await {
                    log::warn!("[STATS] AUTH failed: {} - retrying in {}s", e, RECONNECT_SECS);
                    tokio::time::sleep(std::time::Duration::from_secs(RECONNECT_SECS)).await;
                    continue;
                }
                log::info!("[STATS] connected to {}", cfg.addr);
                let mut pending: Vec<String> = Vec::with_capacity(FLUSH_BATCH);
                loop {
                    let first = match rx.recv().await {
                        Some(r) => r,
                        None => return,
                    };
                    pending.push(first);
                    while pending.len() < FLUSH_BATCH {
                        match rx.try_recv() {
                            Ok(r) => pending.push(r),
                            Err(_) => break,
                        }
                    }
                    if let Err(e) = write_batch(&mut stream, &pending).await {
                        log::warn!("[STATS] write failed: {} - reconnecting", e);
                        break;
                    }
                    pending.clear();
                }
            }
            Err(e) => {
                log::warn!("[STATS] connect {} failed: {} - retry in {}s", cfg.addr, e, RECONNECT_SECS);
                tokio::time::sleep(std::time::Duration::from_secs(RECONNECT_SECS)).await;
            }
        }
    }
}

async fn connect(cfg: &Config) -> anyhow::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<_> = rustls_pemfile::certs(&mut cfg.ca_pem.as_bytes()).collect::<Result<_, _>>()?;
    for c in certs {
        roots.add(c)?;
    }
    let tls_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
    let tcp = tokio::net::TcpStream::connect(&cfg.addr).await?;
    tcp.set_nodelay(true)?;
    let name = rustls::pki_types::ServerName::try_from(cfg.server_name.clone())?;
    Ok(connector.connect(name, tcp).await?)
}

fn resp_cmd(args: &[&[u8]]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    out
}

const MAX_BULK: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 32;

async fn read_reply<S: AsyncReadExt + Unpin>(s: &mut S) -> anyhow::Result<()> {
    read_reply_depth(s, 0).await
}

async fn read_reply_depth<S: AsyncReadExt + Unpin>(s: &mut S, depth: usize) -> anyhow::Result<()> {
    if depth > MAX_DEPTH {
        anyhow::bail!("RESP nesting too deep");
    }
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    match b[0] {
        b'+' | b':' => {
            read_line(s).await?;
            Ok(())
        }
        b'-' => {
            let line = read_line(s).await?;
            anyhow::bail!("valkey error: {}", String::from_utf8_lossy(&line))
        }
        b'$' => {
            let line = read_line(s).await?;
            let n: i64 = std::str::from_utf8(&line)?.trim().parse()?;
            if n >= 0 {
                let n = n as usize;
                if n > MAX_BULK {
                    anyhow::bail!("RESP bulk too large");
                }
                let mut buf = vec![0u8; n + 2];
                s.read_exact(&mut buf).await?;
            }
            Ok(())
        }
        b'*' => {
            let line = read_line(s).await?;
            let n: i64 = std::str::from_utf8(&line)?.trim().parse()?;
            for _ in 0..n.max(0) {
                Box::pin(read_reply_depth(s, depth + 1)).await?;
            }
            Ok(())
        }
        t => anyhow::bail!("unexpected RESP type {}", t as char),
    }
}

async fn read_line<S: AsyncReadExt + Unpin>(s: &mut S) -> anyhow::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(64);
    let mut b = [0u8; 1];
    loop {
        s.read_exact(&mut b).await?;
        line.push(b[0]);
        if line.len() >= 2 && &line[line.len() - 2..] == b"\r\n" {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
        if line.len() > 4096 {
            anyhow::bail!("RESP line too long");
        }
    }
}

async fn auth<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, pass: &str) -> anyhow::Result<()> {
    s.write_all(&resp_cmd(&[b"AUTH", pass.as_bytes()])).await?;
    read_reply(s).await
}

async fn write_batch<S: AsyncReadExt + AsyncWriteExt + Unpin>(s: &mut S, records: &[String]) -> anyhow::Result<()> {
    let mut wire = Vec::with_capacity(64 * 1024);
    let mut n_cmds = 0usize;
    for rec in records {
        let Some((kind, body)) = rec.split_once('\n') else {
            continue;
        };
        let b = body.as_bytes();
        match kind {
            "CID" => {
                wire.extend_from_slice(&resp_cmd(&[b"RPUSH", b"stats:cid", b]));
                n_cmds += 1;
            }
            "TUNNEL" => {
                wire.extend_from_slice(&resp_cmd(&[b"RPUSH", b"stats:tunnel-closed", b]));
                n_cmds += 1;
            }
            _ => {}
        }
    }
    if n_cmds == 0 {
        return Ok(());
    }
    s.write_all(&wire).await?;
    s.flush().await?;
    for _ in 0..n_cmds {
        read_reply(s).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tsv_field_neutralises_every_line_and_column_break() {
        for hostile in ["a\tb", "a\nb", "a\rb", "a\u{2028}b", "a\u{2029}b", "a\u{85}b", "a\u{01}b"] {
            let out = tsv_field(hostile);
            assert_eq!(out, "a b", "{hostile:?} -> {out:?}");
        }
        assert_eq!(tsv_field("plain-cid-0123"), "plain-cid-0123");
    }

    #[test]
    fn cid_row_has_eight_columns_in_exporter_order() {
        let row = cid_row("2026-01-01T00:00:00Z", "203.0.113.7", "abc\tdef", "Asia/Tehran", "brand", "android-14", "sni\nx");
        let cols: Vec<&str> = row.split('\t').collect();
        assert_eq!(cols.len(), 8, "{row:?}");
        assert_eq!(cols[2], "abc def");
        assert_eq!(cols[6], "sni x");
        assert_eq!(cols[7], "tunnel");
    }

    #[test]
    fn resp_cmd_is_length_prefixed() {
        assert_eq!(
            resp_cmd(&[b"RPUSH", b"stats:cid", b"a\r\nb"]),
            b"*3\r\n$5\r\nRPUSH\r\n$9\r\nstats:cid\r\n$4\r\na\r\nb\r\n".to_vec()
        );
    }
}
