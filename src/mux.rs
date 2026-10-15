// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! MUX2 (v2) multiplexed tunnel — yamux over the established Noise NK stream.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::noise::NoiseSession;
use crate::noise_proxy::{initial_buf, C2T_CAP as MUX_BUF_CAP};
use crate::protection::{Caps, TunnelCtx};

/// Run a MUX2 tunnel. `noise_session` is the post-handshake transport;
/// `header_pt` is the already-decrypted MUX2 header frame.
#[allow(clippy::too_many_arguments)]
pub async fn run_muxed_tunnel<S>(
    stream: S,
    noise_session: NoiseSession,
    header_pt: &[u8],
    real_ip: &str,
    egress_ips: std::sync::Arc<[String]>,
    mut capture: Option<crate::stats::Capture>,
    server_pubkey_hex: String,
    inherited_caps: Caps,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let mut client_cid: Option<String> = None;
    let mut caps = inherited_caps;

    let mut ctx: Option<Arc<TunnelCtx>> = None;

    let mut brand = String::new();
    if let Ok(meta_str) = std::str::from_utf8(header_pt) {
        let parts: Vec<&str> = meta_str.splitn(7, '|').collect();
        let tz = parts.get(1).unwrap_or(&"");
        let app = parts.get(2).unwrap_or(&"");
        let os = parts.get(3).unwrap_or(&"");
        let cid = parts.get(4).unwrap_or(&"");
        let sni = parts.get(5).unwrap_or(&"");
        log::debug!(
            "[MUX2] tunnel open: tz={} app={} os={} cid={} sni={} ip={}",
            tz,
            app,
            os,
            cid,
            sni,
            real_ip
        );
        if !cid.is_empty() {
            client_cid = Some(cid.to_string());
        }
        if crate::protection::caps_wanted() {
            caps = caps.merge(crate::protection::header_caps(meta_str));

            if caps.any() && !valid_cid(cid) {
                note_invalid_cid(real_ip);
                caps = Caps::default();
            }
            if caps.blk1 {
                ctx = crate::protection::tunnel_ctx(app);
            }
            if caps.any() {
                brand = app.to_string();
            }
            if caps.any() {
                log::debug!(
                    "[MUX2] caps blk1={} msg1={} app={} checked={}",
                    caps.blk1,
                    caps.msg1,
                    app,
                    ctx.is_some()
                );
            }
        }
        if let Some(c) = capture.take() {
            c.emit(cid, tz, app, os, sni);
        }
    }

    let tunnel = crate::metrics::TunnelGuard::open(client_cid.as_deref().unwrap_or(""));
    let tunnel_bytes = tunnel.bytes.clone();

    let noise_stream = crate::noise_stream::wrap(stream, noise_session).compat();

    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(256);
    cfg.set_split_send_size(64 * 1024);
    let mut conn = yamux::Connection::new(noise_stream, cfg, yamux::Mode::Server);
    log::debug!("[MUX2] yamux server up, awaiting streams");

    if caps.any() {
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        match futures::future::poll_fn(|cx| conn.poll_new_outbound(cx)).await {
            Ok(ctl) => {
                let mut ctl = ctl.compat();
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    crate::messaging::write_magic(&mut ctl),
                )
                .await
                {
                    Ok(Ok(())) => {
                        let ctx = ctx.clone();
                        let mailbox = caps.msg1 && crate::messaging::enabled();
                        let cid = client_cid.clone();
                        tokio::spawn(async move {
                            let r = match (mailbox, cid) {
                                (true, Some(cid)) => {
                                    crate::messaging::run_control_stream(ctl, cid, brand, ctx).await
                                }
                                _ => crate::messaging::run_ack_stream(ctl, ctx).await,
                            };
                            if let Err(e) = r {
                                log::debug!("[MUX2] control stream ended: {}", e);
                            }
                        });
                    }
                    Ok(Err(e)) => {
                        log::warn!(
                            "[MUX2] control stream magic not written: {} — tunnel served as legacy",
                            e
                        );
                        caps = Caps::default();
                        ctx = None;
                    }
                    Err(_) => {
                        log::warn!("[MUX2] control stream magic not written: timed out — tunnel served as legacy");
                        caps = Caps::default();
                        ctx = None;
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "[MUX2] could not open the control stream: {} — tunnel served as legacy",
                    e
                );
                caps = Caps::default();
                ctx = None;
            }
        }
    }

    loop {
        match futures::future::poll_fn(|cx| conn.poll_next_inbound(cx)).await {
            Some(Ok(stream)) => {
                log::debug!("[MUX2] inbound stream accepted");
                let eg = egress_ips.clone();
                let cid = client_cid.clone();
                let rip = real_ip.to_string();
                let pubkey = server_pubkey_hex.clone();
                let bytes = tunnel_bytes.clone();
                let blk1 = caps.blk1;
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_muxed_stream(stream, eg, cid, rip, pubkey, bytes, blk1, ctx).await
                    {
                        log::debug!("[MUX2] stream error: {}", e);
                    }
                });
            }
            Some(Err(e)) => {
                log::debug!("[MUX2] yamux accept error: {}", e);
                break;
            }
            None => break,
        }
    }

    let (up, down) = tunnel.bytes.get();
    log::info!(
        "[MUX2] tunnel closed ip={} cid={} age={}s bytes_up={} bytes_down={}",
        real_ip,
        client_cid.as_deref().unwrap_or(""),
        tunnel.age().as_secs(),
        up,
        down
    );

    drop(tunnel);
    Ok(())
}

const SOCKS5_OK: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

/// A capability tunnel's cid: 16 to 64 lowercase hex characters, nothing else.
/// This is the only shape the clients generate (`gen_cid`.
pub fn valid_cid(cid: &str) -> bool {
    (16..=64).contains(&cid.len())
        && cid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// At most one warning a minute: a hostile or broken client could otherwise
/// write a line per connect.
fn note_invalid_cid(real_ip: &str) {
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
        log::warn!(
            "[MUX2] capability hello with an invalid cid from {} — served as legacy (logged at most once a minute)",
            real_ip
        );
    }
}

/// Write a verdict as the first bytes of a `blk1` stream.
async fn write_verdict<S: AsyncWrite + Unpin>(
    stream: &mut S,
    verdict: &crate::protection::Verdict,
) -> anyhow::Result<()> {
    let mut buf = [0u8; crate::protection::VERDICT_MAX];
    let n = verdict.encode_into(&mut buf);
    stream.write_all(&buf[..n]).await?;
    stream.flush().await?;
    Ok(())
}

/// One inner stream: [u16 BE][CONNECT] → (verdict on `blk1`) → 10B reply →
/// bidirectional relay.
#[allow(clippy::too_many_arguments)]
async fn handle_muxed_stream(
    stream: yamux::Stream,
    egress_ips: std::sync::Arc<[String]>,
    client_cid: Option<String>,
    real_ip: String,
    server_pubkey_hex: String,
    bytes: crate::metrics::TunnelBytes,
    blk1: bool,
    ctx: Option<Arc<TunnelCtx>>,
) -> anyhow::Result<()> {
    use tokio_util::compat::FuturesAsyncReadCompatExt;
    let mut stream = stream.compat();

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let connect_len = u16::from_be_bytes(len_buf) as usize;
    if connect_len == 0 || connect_len > 512 {
        anyhow::bail!("invalid CONNECT length {}", connect_len);
    }
    let mut connect_bytes = vec![0u8; connect_len];
    stream.read_exact(&mut connect_bytes).await?;

    let sticky_key = client_cid.as_deref().unwrap_or(real_ip.as_str());

    if connect_bytes == crate::proxy::UDP_ASSOCIATE {
        log::debug!(
            "[MUX2] udp associate (cid={})",
            client_cid.as_deref().unwrap_or("")
        );

        if blk1 {
            write_verdict(&mut stream, &crate::protection::Verdict::Clear).await?;
        }

        return relay_udp(
            stream,
            egress_ips,
            bytes,
            real_ip,
            client_cid.unwrap_or_default(),
            ctx,
        )
        .await;
    }

    let (host, port, user_allowed) = if blk1 {
        let r = crate::protection::parse_stream_request(&connect_bytes)?;
        (r.host, r.port, r.user_allowed)
    } else {
        let (h, p) = crate::proxy::parse_connect_request(&connect_bytes)?;
        (h, p, false)
    };
    log::debug!("[MUX2] stream CONNECT → {}:{}", host, port);

    if crate::proxy::is_control_channel(&host) {
        if blk1 {
            write_verdict(&mut stream, &crate::protection::Verdict::Clear).await?;
        }

        stream.write_all(&SOCKS5_OK).await?;
        stream.flush().await?;
        let cid_ref = client_cid.as_deref().unwrap_or("");
        log::debug!("[MUX2] _rs control: {} (cid={})", host, cid_ref);
        return crate::control::handle(&mut stream, &host, &server_pubkey_hex, cid_ref).await;
    }

    let mut resolved: Option<crate::proxy::Resolved> = None;
    if blk1 {
        let verdict = match &ctx {
            Some(ctx) if !user_allowed => match crate::protection::judge_host(ctx, &host) {
                crate::protection::HostVerdict::Allowed => crate::protection::Verdict::Clear,
                crate::protection::HostVerdict::Blocked(v) => v,
                crate::protection::HostVerdict::Unknown => {
                    let r = match crate::proxy::resolve(&host, port).await {
                        Ok(r) => r,
                        Err(e) => {
                            write_verdict(&mut stream, &crate::protection::Verdict::Clear).await?;
                            anyhow::bail!("DNS lookup failed for {}:{}: {}", host, port, e);
                        }
                    };
                    let v = crate::protection::judge_addrs(ctx, &r.addrs);
                    resolved = Some(r);
                    v
                }
            },
            _ => crate::protection::Verdict::Clear,
        };
        if let Some(ctx) = &ctx {
            crate::protection::record(ctx, &verdict, user_allowed);
            crate::protection::log_block(ctx, &host, port, &verdict, &real_ip);
        }
        write_verdict(&mut stream, &verdict).await?;
        if verdict.is_block() {
            return Ok(());
        }
    }

    let dial = async {
        match &resolved {
            Some(r) => {
                crate::proxy::connect_resolved(&host, port, &r.addrs, &egress_ips, sticky_key).await
            }
            None => {
                crate::proxy::connect_via(
                    &host,
                    port,
                    &egress_ips,
                    sticky_key,
                    &real_ip,
                    client_cid.as_deref().unwrap_or_default(),
                )
                .await
            }
        }
    };
    let target = match dial.await {
        Ok(t) => t,
        Err(e) => {
            log::warn!("[MUX2] target connect {}:{} failed: {}", host, port, e);
            return Err(e);
        }
    };
    {
        let sock = socket2::SockRef::from(&target);
        let ka = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(60))
            .with_interval(std::time::Duration::from_secs(15));
        let _ = sock.set_tcp_keepalive(&ka);
    }

    stream.write_all(&SOCKS5_OK).await?;
    stream.flush().await?;
    log::debug!("[MUX2] socks5 reply sent → {}:{}", host, port);

    let _relay_guard = crate::metrics::RelayGuard::new();
    crate::metrics::inc_connection();

    let (mut stream_r, mut stream_w) = tokio::io::split(stream);

    let v6 = target.peer_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    let (mut target_r, mut target_w) = target.into_split();

    let bytes_up = bytes.clone();
    let bytes_down = bytes;
    let c2t = tokio::spawn(async move {
        let mut buf = vec![0u8; initial_buf(MUX_BUF_CAP)];
        loop {
            match stream_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if n == buf.len() && buf.len() < MUX_BUF_CAP {
                        buf.resize(MUX_BUF_CAP, 0);
                    }
                    crate::metrics::add_bytes_up(n as u64, v6);
                    bytes_up.add(n as u64, true);
                    if target_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = target_w.shutdown().await;
    });

    let t2c = tokio::spawn(async move {
        let mut buf = vec![0u8; initial_buf(MUX_BUF_CAP)];
        loop {
            match target_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if n == buf.len() && buf.len() < MUX_BUF_CAP {
                        buf.resize(MUX_BUF_CAP, 0);
                    }
                    crate::metrics::add_bytes_down(n as u64, v6);
                    bytes_down.add(n as u64, false);
                    if stream_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = stream_w.shutdown().await;
    });

    tokio::pin!(c2t, t2c);
    tokio::select! {
        _ = &mut c2t => { t2c.abort(); let _ = t2c.await; }
        _ = &mut t2c => { c2t.abort(); let _ = c2t.await; }
    }
    Ok(())
}

const UDP_IDLE: std::time::Duration = std::time::Duration::from_secs(120);
/// 2-byte length prefix ceiling; also the largest datagram worth carrying.
const UDP_FRAME_CAP: usize = 65535;
/// Pinned targets per association. A real client talks to a handful of hosts;
/// the cap only exists so a hostile one cannot make the map the memory leak.
const MAX_UDP_TARGETS: usize = 64;
/// Bytes held in front of each received datagram: 2 for the length prefix plus
/// the largest SOCKS5 UDP header (3 + 1 + 16 + 2, the IPv6 form).
const HDR_RESERVE: usize = 24;

/// Relay `[u16 BE len][SOCKS5 UDP datagram]` frames over one stream, using a
/// single unconnected UDP socket for every target in the association.
async fn relay_udp<S>(
    stream: S,
    egress_ips: std::sync::Arc<[String]>,
    bytes: crate::metrics::TunnelBytes,
    _real_ip: String,
    cid: String,
    ctx: Option<Arc<TunnelCtx>>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = stream;
    stream.write_all(&SOCKS5_OK).await?;
    stream.flush().await?;

    let _relay_guard = crate::metrics::RelayGuard::new();
    crate::metrics::inc_connection();

    let (mut stream_r, mut stream_w) = tokio::io::split(stream);
    let (sock_tx, sock_rx) =
        tokio::sync::oneshot::channel::<std::sync::Arc<tokio::net::UdpSocket>>();

    let bytes_up = bytes.clone();
    let started = std::time::Instant::now();
    let sent = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let recv = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (sent_c, recv_c) = (sent.clone(), recv.clone());

    let c2t = tokio::spawn(async move {
        let mut len_buf = [0u8; 2];

        let mut frame = vec![0u8; 2048];

        let mut targets: Vec<(String, u16, std::net::SocketAddr)> = Vec::new();
        let mut sock: Option<std::sync::Arc<tokio::net::UdpSocket>> = None;
        let mut sock_tx = Some(sock_tx);
        loop {
            let head = match &sock {
                Some(_) => stream_r.read_exact(&mut len_buf).await.map(|_| ()),
                None => {
                    match tokio::time::timeout(UDP_IDLE, stream_r.read_exact(&mut len_buf)).await {
                        Ok(r) => r.map(|_| ()),
                        Err(_) => break,
                    }
                }
            };
            if head.is_err() {
                break;
            }
            let n = u16::from_be_bytes(len_buf) as usize;
            if n == 0 {
                break;
            }
            if frame.len() < n {
                frame.resize(n, 0);
            }
            if stream_r.read_exact(&mut frame[..n]).await.is_err() {
                break;
            }
            let Ok((host, port, off)) = crate::proxy::parse_udp_header(&frame[..n]) else {
                continue;
            };

            let dst = match targets.iter().find(|(h, p, _)| *p == port && h == &host) {
                Some((_, _, a)) => *a,
                None => {
                    let Ok(resolved) = crate::proxy::resolve(&host, port).await else {
                        continue;
                    };

                    let want_v6 = match &sock {
                        Some(s) => s.local_addr().map(|a| a.is_ipv6()).unwrap_or(false),
                        None => crate::proxy::prefer_ipv6(),
                    };
                    let chosen = resolved.addrs.iter().find(|a| a.is_ipv6() == want_v6).or(
                        if sock.is_none() {
                            resolved.addrs.first()
                        } else {
                            None
                        },
                    );
                    let Some(a) = chosen.copied() else {
                        continue;
                    };

                    if crate::proxy::is_unroutable(&a.ip()) {
                        crate::metrics::inc_egress_refused_unroutable();
                        continue;
                    }

                    if let Some(ctx) = &ctx {
                        if crate::protection::judge_one(ctx, &host, &a.ip()).is_block() {
                            crate::protection::inc_udp_dropped();
                            continue;
                        }
                    }

                    if targets.len() >= MAX_UDP_TARGETS {
                        targets.remove(0);
                    }
                    targets.push((host, port, a));
                    a
                }
            };
            if sock.is_none() {
                let bound = match bind_egress_udp(&egress_ips, &cid, dst.is_ipv6()).await {
                    Ok(s) => std::sync::Arc::new(s),
                    Err(e) => {
                        log::warn!("[MUX2] udp bind failed: {}", e);
                        break;
                    }
                };
                crate::metrics::inc_egress(dst.is_ipv6());
                if let Some(tx) = sock_tx.take() {
                    let _ = tx.send(bound.clone());
                }
                sock = Some(bound);
            }
            let payload = &frame[off..n];

            let Some(s) = sock.as_ref() else { break };
            if s.send_to(payload, dst).await.is_err() {
                continue;
            }
            crate::metrics::add_bytes_up(payload.len() as u64, dst.is_ipv6());
            bytes_up.add(payload.len() as u64, true);
            sent_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });

    let t2c = tokio::spawn(async move {
        let Ok(sock) = sock_rx.await else {
            return;
        };

        let mut buf = vec![0u8; HDR_RESERVE + 9216];
        loop {
            let (n, from) =
                match tokio::time::timeout(UDP_IDLE, sock.recv_from(&mut buf[HDR_RESERVE..])).await
                {
                    Ok(Ok(v)) => v,
                    _ => break,
                };
            if HDR_RESERVE + n == buf.len() && buf.len() < HDR_RESERVE + UDP_FRAME_CAP {
                buf.resize(HDR_RESERVE + UDP_FRAME_CAP, 0);
                continue;
            }
            let hdr = crate::proxy::udp_header(&from);
            let total = hdr.len() + n;
            if total > UDP_FRAME_CAP {
                continue;
            }
            let start = HDR_RESERVE - 2 - hdr.len();
            buf[start..start + 2].copy_from_slice(&(total as u16).to_be_bytes());
            buf[start + 2..HDR_RESERVE].copy_from_slice(&hdr);
            if stream_w
                .write_all(&buf[start..HDR_RESERVE + n])
                .await
                .is_err()
            {
                break;
            }
            crate::metrics::add_bytes_down(n as u64, from.is_ipv6());
            bytes.add(n as u64, false);
            recv_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        let _ = stream_w.shutdown().await;
    });

    tokio::pin!(c2t, t2c);
    tokio::select! {
        _ = &mut c2t => { t2c.abort(); let _ = t2c.await; }
        _ = &mut t2c => { c2t.abort(); let _ = c2t.await; }
    }
    log::debug!(
        "[MUX2] udp association closed age={}s sent={} recv={} datagrams",
        started.elapsed().as_secs(),
        sent.load(std::sync::atomic::Ordering::Relaxed),
        recv.load(std::sync::atomic::Ordering::Relaxed)
    );
    Ok(())
}

/// Bind a UDP socket of the requested family to this client's sticky egress IP,
/// falling back to the OS default source when the pool has no address of that
/// family or the bind fails.
async fn bind_egress_udp(
    egress_ips: &[String],
    cid: &str,
    v6: bool,
) -> std::io::Result<tokio::net::UdpSocket> {
    let wildcard: std::net::SocketAddr = if v6 {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let local = crate::proxy::pick_egress_family(egress_ips, cid, v6)
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .map(|ip| std::net::SocketAddr::new(ip, 0))
        .unwrap_or(wildcard);
    match tokio::net::UdpSocket::bind(local).await {
        Ok(s) => Ok(s),
        Err(e) if local != wildcard => {
            log::warn!(
                "[MUX2] udp bind {} failed: {} — OS default source",
                local,
                e
            );
            tokio::net::UdpSocket::bind(wildcard).await
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::valid_cid;

    #[test]
    fn a_capability_cid_is_plain_hex_and_nothing_else() {
        assert!(valid_cid("4f2a9c1e8b7d3a60"));
        assert!(valid_cid(&"0".repeat(64)));

        assert!(!valid_cid("broadcast"));
        assert!(!valid_cid("*"));
        assert!(!valid_cid("4f2a9c1e8b7d3a60:last"));
        assert!(!valid_cid("4f2a9c1e8b7d3a60:seq"));
        assert!(!valid_cid(""));

        assert!(
            !valid_cid("4F2A9C1E8B7D3A60"),
            "uppercase is not what any client sends"
        );
        assert!(!valid_cid("4f2a9c1e8b7d3a6"), "15 chars");
        assert!(!valid_cid(&"a".repeat(65)));
        assert!(!valid_cid("cid-msg-a"));
        assert!(!valid_cid("4f2a9c1e8b7d3a6g"));
    }
}
