// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Noise Proxy — streaming Noise NK tunnel on the carrier's plaintext side.

use crate::noise::NoiseHandshake;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

static INITIAL_RELAY_BUF: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub const C2T_CAP: usize = 65535;
pub const T2C_CAP: usize = 32768;

/// Called once from main() after config load. 0 keeps legacy full-size buffers.
pub fn set_initial_relay_buffer(n: usize) {
    INITIAL_RELAY_BUF.store(n, std::sync::atomic::Ordering::Relaxed);
}

#[inline]
pub fn initial_buf(cap: usize) -> usize {
    let n = INITIAL_RELAY_BUF.load(std::sync::atomic::Ordering::Relaxed);
    if n == 0 || n > cap {
        cap
    } else {
        n
    }
}

/// Serve one tunnel from its first byte: the Noise NK handshake, then META /
/// MUX2 / CONNECT. `real_ip` is the socket peer or the PROXY-protocol source.
pub async fn run_streaming_tunnel<S>(
    mut stream: S,
    server_keys: &[[u8; 32]],
    real_ip: &str,
    egress_ips: std::sync::Arc<[String]>,
    mut capture: Option<crate::stats::Capture>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let server_pubkey_hex = server_keys
        .first()
        .map(|k| hex::encode(crate::noise::pubkey_from_private(k)))
        .unwrap_or_default();

    let msg1_len = read_u16_be(&mut stream).await?;
    let mut msg1 = vec![0u8; msg1_len as usize];
    stream.read_exact(&mut msg1).await?;

    let (handshake, msg2) =
        NoiseHandshake::process_msg1_multi(&msg1, server_keys).inspect_err(|_| {
            crate::metrics::inc_hs_fail();
        })?;
    let mut noise_session = handshake.into_transport()?;

    write_u16_be(&mut stream, msg2.len() as u16).await?;
    stream.write_all(&msg2).await?;
    stream.flush().await?;

    crate::metrics::inc_hs_ok();
    log::debug!("[NoiseProxy] Handshake complete from ip={}", real_ip);

    let first_ct_len = read_u16_be(&mut stream).await?;
    let mut first_ct = vec![0u8; first_ct_len as usize];
    stream.read_exact(&mut first_ct).await?;
    let first_pt = noise_session.decrypt(&first_ct)?;

    if first_pt.starts_with(b"MUX2|") {
        return crate::mux::run_muxed_tunnel(
            stream,
            noise_session,
            &first_pt,
            real_ip,
            egress_ips,
            capture,
            server_pubkey_hex,
            crate::protection::Caps::default(),
        )
        .await;
    }

    let mut client_tz = String::new();
    let mut client_cid: Option<String> = None;

    let mut meta_caps = crate::protection::Caps::default();

    let connect_pt = if first_pt.starts_with(b"META|") {
        if let Ok(meta_str) = std::str::from_utf8(&first_pt) {
            let parts: Vec<&str> = meta_str.splitn(7, '|').collect();
            let tz = parts.get(1).unwrap_or(&"");
            let app = parts.get(2).unwrap_or(&"");
            let os = parts.get(3).unwrap_or(&"");
            let cid = parts.get(4).unwrap_or(&"");
            let sni = parts.get(5).unwrap_or(&"");
            if crate::protection::caps_wanted() {
                meta_caps = crate::protection::header_caps(meta_str);
            }

            log::debug!(
                "[NoiseProxy] Client meta: tz={} app={} os={} cid={} sni={} ip={}",
                tz,
                app,
                os,
                cid,
                sni,
                real_ip
            );
            log::debug!(
                "metric=tunnel.opened cid=\"{}\" brand=\"{}\" tz=\"{}\" os=\"{}\" sni=\"{}\" ip=\"{}\"",
                cid, app, tz, os, sni, real_ip
            );

            client_tz = tz.to_string();
            if !cid.is_empty() {
                client_cid = Some(cid.to_string());
            }

            if let Some(c) = capture.take() {
                c.emit(cid, tz, app, os, sni);
            }
        }

        let ct_len = read_u16_be(&mut stream).await?;
        let mut ct = vec![0u8; ct_len as usize];
        stream.read_exact(&mut ct).await?;
        let second_pt = noise_session.decrypt(&ct)?;

        if second_pt.starts_with(b"MUX2|") {
            return crate::mux::run_muxed_tunnel(
                stream,
                noise_session,
                &second_pt,
                real_ip,
                egress_ips,
                capture,
                server_pubkey_hex,
                meta_caps,
            )
            .await;
        }
        second_pt
    } else {
        log::debug!("[NoiseProxy] Legacy client (no META) ip={}", real_ip);
        if let Some(c) = capture.take() {
            c.emit("", "", "", "", "");
        }
        first_pt
    };

    let (host, port) = crate::proxy::parse_connect_request(&connect_pt)?;

    if crate::proxy::is_control_channel(&host) {
        log::info!(
            "[_rs] control CONNECT: {} (ip={} cid={})",
            host,
            real_ip,
            client_cid.as_deref().unwrap_or("")
        );
        let mut noise_stream = crate::noise_stream::wrap(stream, noise_session);
        let cid_ref = client_cid.as_deref().unwrap_or("");
        return crate::control::handle(&mut noise_stream, &host, &server_pubkey_hex, cid_ref).await;
    }

    let sticky_key = client_cid.as_deref().unwrap_or(real_ip);

    log::debug!(
        "[NoiseProxy] Tunnel → {}:{} from ip={}",
        host,
        port,
        real_ip
    );

    let target = crate::proxy::connect_via(
        &host,
        port,
        &egress_ips,
        sticky_key,
        real_ip,
        client_cid.as_deref().unwrap_or_default(),
    )
    .await?;

    {
        let sock = socket2::SockRef::from(&target);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(60))
            .with_interval(std::time::Duration::from_secs(15));
        let _ = sock.set_tcp_keepalive(&keepalive);
    }

    let session = std::sync::Arc::new(std::sync::Mutex::new(noise_session));
    let _relay_guard = crate::metrics::RelayGuard::new();
    crate::metrics::inc_connection();

    let tunnel = crate::metrics::TunnelGuard::open(client_cid.as_deref().unwrap_or(""));
    let tunnel_id = tunnel.id;
    let bytes_c2t = tunnel.bytes.clone();
    let bytes_t2c = tunnel.bytes.clone();

    let (mut stream_r, mut stream_w) = tokio::io::split(stream);
    let v6 = target.peer_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    let (mut target_r, mut target_w) = target.into_split();

    let session_c2t = session.clone();
    let c2t = tokio::spawn(async move {
        let mut ct_buf = vec![0u8; initial_buf(C2T_CAP)];
        let mut bytes: u64 = 0;
        loop {
            let mut len_buf = [0u8; 2];
            if stream_r.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let ct_len = u16::from_be_bytes(len_buf) as usize;
            if ct_len == 0 || ct_len > 65535 {
                break;
            }
            ct_buf.resize(ct_len, 0);
            if stream_r.read_exact(&mut ct_buf[..ct_len]).await.is_err() {
                break;
            }

            let decrypted = match session_c2t.lock().unwrap().decrypt(&ct_buf[..ct_len]) {
                Ok(pt) => pt,
                Err(_) => break,
            };
            if decrypted.is_empty() {
                continue;
            }

            let plaintext = decrypted;
            bytes += plaintext.len() as u64;
            crate::metrics::add_bytes_up(plaintext.len() as u64, v6);
            bytes_c2t.add(plaintext.len() as u64, true);
            if target_w.write_all(&plaintext).await.is_err() {
                break;
            }
        }
        bytes
    });

    let session_t2c = session.clone();
    let t2c = tokio::spawn(async move {
        let mut buf = vec![0u8; initial_buf(T2C_CAP)];
        let mut bytes: u64 = 0;
        loop {
            match target_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if n == buf.len() && buf.len() < T2C_CAP {
                        buf.resize(T2C_CAP, 0);
                    }
                    bytes += n as u64;
                    crate::metrics::add_bytes_down(n as u64, v6);
                    bytes_t2c.add(n as u64, false);
                    let ciphertext = match session_t2c.lock().unwrap().encrypt(&buf[..n]) {
                        Ok(ct) => ct,
                        Err(_) => break,
                    };
                    let len_bytes = (ciphertext.len() as u16).to_be_bytes();
                    if stream_w.write_all(&len_bytes).await.is_err() {
                        break;
                    }
                    if stream_w.write_all(&ciphertext).await.is_err() {
                        break;
                    }
                }
            }
        }
        bytes
    });

    tokio::pin!(c2t, t2c);

    tokio::select! {
        _ = &mut c2t => { t2c.abort(); let _ = t2c.await; }
        _ = &mut t2c => { c2t.abort(); let _ = c2t.await; }
    }

    let (bytes_up, bytes_down) = tunnel.bytes.get();

    let age = tunnel.age();
    let age_secs = age.as_secs();
    let kbps = if age_secs > 0 {
        (bytes_up + bytes_down) / 1024 / age_secs
    } else {
        0
    };
    log::debug!(
        "metric=tunnel.closed id={id} cid=\"{cid}\" carrier=\"proteus\" \
         dest=\"{host}:{port}\" tz=\"{tz}\" age_ms={age_ms} \
         bytes_up={bytes_up} bytes_down={bytes_down} avg_kbps={kbps}",
        id = tunnel_id,
        cid = client_cid.as_deref().unwrap_or(""),
        tz = client_tz,
        age_ms = age.as_millis() as u64,
    );
    drop(tunnel);

    Ok(())
}

async fn read_u16_be<S: AsyncReadExt + Unpin>(stream: &mut S) -> anyhow::Result<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

async fn write_u16_be<S: AsyncWriteExt + Unpin>(stream: &mut S, val: u16) -> anyhow::Result<()> {
    stream.write_all(&val.to_be_bytes()).await?;
    Ok(())
}
