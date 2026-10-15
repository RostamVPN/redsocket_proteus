// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! HTTP Carrier — HTTP Upgrade tunnel on port 80.

use std::os::unix::io::RawFd;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::noise_proxy;
use crate::proxy_protocol;

/// Parsed HTTP request with borrowed header slices — zero heap allocation.
struct HttpRequest<'a> {
    method: &'a str,
    path: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

impl<'a> HttpRequest<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        let text = std::str::from_utf8(data).ok()?;

        let mut lines = text.split("\r\n");

        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?;
        let path = parts.next()?;

        let mut headers = Vec::with_capacity(12);
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.push((key.trim(), value.trim()));
            }
        }

        Some(HttpRequest {
            method,
            path,
            headers,
        })
    }

    /// Case-insensitive header lookup — zero allocation, linear scan.
    fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| *v)
    }
}

/// Find \r\n\r\n in the buffer using memchr (SIMD-accelerated).
fn find_header_end(buf: &[u8]) -> Option<usize> {
    memchr::memmem::find(buf, b"\r\n\r\n").map(|p| p + 4)
}

/// Extract real client IP from CDN headers, in priority order: 1. CloudFront-
/// Viewer-Address  ("IP:port" — set by CloudFront, unspoofable when origin is
/// locked to CF; the leftmost value is the true client) 2.
fn extract_real_ip(request: &HttpRequest, peer_ip: &str) -> String {
    fn ip(s: &str) -> Option<String> {
        s.trim()
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|a| a.to_string())
    }

    if let Some(v) = request.header("cloudfront-viewer-address") {
        let host = v.trim();
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.find(']').map(|end| &h[..end]))
            .or_else(|| host.rsplit_once(':').map(|(h, _)| h))
            .unwrap_or(host);
        if let Some(a) = ip(bare) {
            return a;
        }
    }
    for header in ["true-client-ip", "cf-connecting-ip", "x-real-ip"] {
        if let Some(a) = request.header(header).and_then(ip) {
            return a;
        }
    }
    if let Some(a) = request
        .header("x-forwarded-for")
        .and_then(|v| v.split(',').next())
        .and_then(ip)
    {
        return a;
    }
    peer_ip.to_string()
}

#[cfg(test)]
mod real_ip_tests {
    use super::*;

    /// Build a raw request. Returned as an owned String because `HttpRequest`
    /// borrows from it.
    fn raw(headers: &[(&str, &str)]) -> String {
        let mut r = String::from("GET / HTTP/1.1\r\n");
        for (k, v) in headers {
            r.push_str(k);
            r.push_str(": ");
            r.push_str(v);
            r.push_str("\r\n");
        }
        r.push_str("\r\n");
        r
    }

    fn real_ip(headers: &[(&str, &str)], peer: &str) -> String {
        let raw = raw(headers);
        let req = HttpRequest::parse(raw.as_bytes()).expect("parses");
        extract_real_ip(&req, peer)
    }

    #[test]
    fn cdn_headers_win_in_priority_order() {
        assert_eq!(
            real_ip(&[("cf-connecting-ip", "203.0.113.7")], "10.0.0.1"),
            "203.0.113.7"
        );
        assert_eq!(
            real_ip(
                &[("cloudfront-viewer-address", "[2606::1]:443")],
                "10.0.0.1"
            ),
            "2606::1"
        );
        assert_eq!(
            real_ip(
                &[("cloudfront-viewer-address", "203.0.113.7:443")],
                "10.0.0.1"
            ),
            "203.0.113.7"
        );

        assert_eq!(
            real_ip(
                &[("x-forwarded-for", "203.0.113.7, 70.41.3.18")],
                "10.0.0.1"
            ),
            "203.0.113.7"
        );
    }

    /// Anyone can reach :80 and set these headers, and `real_ip` lands in the stats
    /// — JSON records and the positional TSV cid rows. A non-address value must
    /// never be trusted; it falls through to the socket peer.
    #[test]
    fn non_address_headers_fall_through_to_peer() {
        for hostile in [
            "1.2.3.4\",\"server\":\"pwned",
            "not-an-ip",
            "",
            "1.2.3.4\tinjected\tcolumns",
            "1.2.3.4 ; DROP",
        ] {
            assert_eq!(
                real_ip(&[("x-forwarded-for", hostile)], "10.0.0.1"),
                "10.0.0.1",
                "hostile XFF {hostile:?} was trusted"
            );
        }
    }

    /// Bare-LF header smuggling. `lines()` would turn this single header into two
    /// and hand the client a forged higher-priority header — the same trick forges
    /// CloudFront-Viewer-Address, which this function trusts as unspoofable.
    #[test]
    fn bare_lf_cannot_smuggle_a_higher_priority_header() {
        assert_eq!(
            real_ip(
                &[("x-forwarded-for", "1.2.3.4\nx-real-ip: 9.9.9.9")],
                "10.0.0.1"
            ),
            "10.0.0.1"
        );
        assert_eq!(
            real_ip(
                &[(
                    "x-forwarded-for",
                    "1.2.3.4\ncloudfront-viewer-address: 9.9.9.9:443"
                )],
                "10.0.0.1"
            ),
            "10.0.0.1"
        );
    }

    #[test]
    fn a_bad_cdn_header_does_not_shadow_a_good_one() {
        assert_eq!(
            real_ip(
                &[
                    ("true-client-ip", "garbage"),
                    ("cf-connecting-ip", "203.0.113.7")
                ],
                "10.0.0.1"
            ),
            "203.0.113.7"
        );
    }

    #[test]
    fn peer_is_used_when_no_headers_present() {
        assert_eq!(real_ip(&[], "10.0.0.1"), "10.0.0.1");
    }
}

/// Extract and sanitize ?cid= from the request path. The URL cid is attacker-
/// controlled (anyone can reach :80), so whitelist hard: 1–64 chars of
/// [a-zA-Z0-9-], matching the metrics validator.
fn extract_cid(path: &str) -> Option<&str> {
    let raw = path.split("cid=").nth(1)?.split('&').next()?;
    if raw.is_empty()
        || raw.len() > 64
        || !raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return None;
    }
    Some(raw)
}

/// Log every HTTP request with full header dump for analytics.
fn log_http_request(peer: &std::net::SocketAddr, real_ip: &str, request: &HttpRequest) {
    if !log::log_enabled!(log::Level::Debug) {
        return;
    }
    let ua = request.header("user-agent").unwrap_or("-");
    let host = request.header("host").unwrap_or("-");
    let accept = request.header("accept").unwrap_or("-");
    let accept_lang = request.header("accept-language").unwrap_or("-");
    let accept_enc = request.header("accept-encoding").unwrap_or("-");
    let conn = request.header("connection").unwrap_or("-");
    let upgrade = request.header("upgrade").unwrap_or("-");
    let xff = request.header("x-forwarded-for").unwrap_or("-");
    let true_ip = request.header("true-client-ip").unwrap_or("-");
    let via = request.header("via").unwrap_or("-");
    let cf_ray = request.header("cf-ray").unwrap_or("-");
    let x_amz_cf_id = request.header("x-amz-cf-id").unwrap_or("-");

    log::debug!(
        "[HTTP] {} {} from edge={} real_ip={} ua=\"{}\" host={} \
         accept=\"{}\" lang=\"{}\" enc=\"{}\" conn=\"{}\" upgrade=\"{}\" \
         xff=\"{}\" true_ip=\"{}\" via=\"{}\" cf_ray=\"{}\" amz_cf_id=\"{}\"",
        request.method,
        request.path,
        peer.ip(),
        real_ip,
        ua,
        host,
        accept,
        accept_lang,
        accept_enc,
        conn,
        upgrade,
        xff,
        true_ip,
        via,
        cf_ray,
        x_amz_cf_id
    );

    for (k, v) in &request.headers {
        log::debug!("[HTTP_HDR] {} {}: {}", real_ip, k, v);
    }
}

/// Bind with the "good stuff": SO_REUSEADDR (restart over TIME_WAIT) and
/// SO_REUSEPORT (kernel load-balances accepts across processes/instances — lets
/// you run N daemons on :80, and zero-downtime restarts).
pub(crate) async fn bind_listener(bind_addr: &str) -> anyhow::Result<TcpListener> {
    let addr: std::net::SocketAddr = bind_addr
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
            "[HTTP] SO_REUSEPORT unsupported on this platform: {} (continuing)",
            e
        );
    }
    sock.bind(&addr.into())?;
    sock.listen(4096)?;
    TcpListener::from_std(sock.into()).map_err(Into::into)
}

pub async fn run(
    bind_addr: &str,
    server_keys: std::sync::Arc<Vec<[u8; 32]>>,
    pp_mode: proxy_protocol::PpMode,
    egress_ips: std::sync::Arc<[String]>,
    socket_sndbuf: usize,
    socket_rcvbuf: usize,
) -> anyhow::Result<()> {
    let listener = bind_listener(bind_addr).await?;
    log::info!(
        "[HTTP] Listening on {} (proxy_protocol={:?})",
        bind_addr,
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
        }

        {
            let sock = socket2::SockRef::from(&stream);
            let ka = socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(30))
                .with_interval(std::time::Duration::from_secs(10));
            let _ = sock.set_tcp_keepalive(&ka);
        }

        let key = server_keys.clone();
        let pp = pp_mode;
        let egress = egress_ips.clone();

        tokio::spawn(async move {
            let mut stream = stream;

            let real_peer = match proxy_protocol::peek_and_strip(&mut stream, edge_peer, pp).await {
                Ok(p) => p,
                Err(e) => {
                    log::debug!("[HTTP] PROXY parse from {}: {}", edge_peer, e);
                    return;
                }
            };

            match crate::proteus_carrier::same_port() {
                Some(dispatch) => {
                    crate::proteus_carrier::serve_same_port(stream, real_peer, key, egress, dispatch)
                        .await
                }
                None => serve_tcp(stream, real_peer, key, egress).await,
            }
        });
    }
}

/// Serve a plain TCP client under the 600 s connection budget.
pub(crate) async fn serve_tcp(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    server_keys: std::sync::Arc<Vec<[u8; 32]>>,
    egress_ips: std::sync::Arc<[String]>,
) {
    let raw_fd = {
        use std::os::unix::io::AsRawFd;
        stream.as_raw_fd()
    };
    match tokio::time::timeout(
        std::time::Duration::from_secs(600),
        serve_stream(stream, peer, server_keys, egress_ips, Some(raw_fd)),
    )
    .await
    {
        Ok(Err(e)) => log::debug!("[HTTP] Connection error from {}: {}", peer, e),
        Err(_) => log::debug!("[HTTP] Connection timeout (600s) from {}", peer),
        _ => {}
    }
}

/// Hosts permitted to receive a 101. Empty = allow any (fleet default).
static ALLOWED_UPGRADE_HOSTS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

pub fn set_allowed_upgrade_hosts(hosts: Vec<String>) {
    let _ = ALLOWED_UPGRADE_HOSTS.set(hosts);
}

/// Case-insensitive, port-insensitive: `Host: h.example:80` matches
/// `h.example`.
fn upgrade_host_allowed(host: &str) -> bool {
    let allowed = match ALLOWED_UPGRADE_HOSTS.get() {
        Some(v) if !v.is_empty() => v,
        _ => return true,
    };
    let bare = host.split(':').next().unwrap_or("").trim();
    allowed.iter().any(|a| a.eq_ignore_ascii_case(bare))
}

#[cfg(test)]
mod probe_gate_tests {
    use super::*;

    #[test]
    fn unknown_host_is_refused_and_known_host_passes() {
        set_allowed_upgrade_hosts(vec!["secret.example".to_string()]);
        assert!(!upgrade_host_allowed("a.b"), "prober must not be allowed");
        assert!(
            !upgrade_host_allowed(""),
            "missing Host must not be allowed"
        );
        assert!(upgrade_host_allowed("secret.example"));
        assert!(
            upgrade_host_allowed("SECRET.EXAMPLE:80"),
            "host is case/port insensitive"
        );
    }
}

/// Serve one carrier connection: parse the Upgrade request, answer 101 and run
/// the Noise tunnel. `raw_fd` is the client socket for the io_uring relay when
/// the stream is a plain TCP socket, `None` when it is wrapped.
pub async fn serve_stream<S>(
    mut stream: S,
    peer: std::net::SocketAddr,
    server_keys: std::sync::Arc<Vec<[u8; 32]>>,
    egress_ips: std::sync::Arc<[String]>,
    raw_fd: Option<RawFd>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut buf = Vec::with_capacity(4096);
    let headers_end = {
        let mut tmp = [0u8; 4096];
        let mut end = None;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(pos) = find_header_end(&buf) {
                end = Some(pos);
                break;
            }
            if buf.len() >= 16384 {
                break;
            }
            match tokio::time::timeout_at(deadline, stream.read(&mut tmp)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&tmp[..n]),
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }
        }
        end
    };
    let n_headers = match headers_end {
        Some(e) => e,
        None => {
            log::debug!(
                "[HTTP] Incomplete headers from {} ({} bytes)",
                peer,
                buf.len()
            );
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            let _ = stream.write_all(response.as_bytes()).await;
            return Ok(());
        }
    };
    if n_headers == 0 || buf.is_empty() {
        return Ok(());
    }

    let request = match HttpRequest::parse(&buf[..n_headers]) {
        Some(r) => r,
        None => {
            log::debug!("[HTTP] Unparseable request from {}", peer);
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            let _ = stream.write_all(response.as_bytes()).await;
            return Ok(());
        }
    };

    let peer_ip = peer.ip().to_string();
    let real_ip = extract_real_ip(&request, &peer_ip);
    drop(peer_ip);

    log_http_request(&peer, &real_ip, &request);

    let request_ua = request.header("user-agent").unwrap_or("");
    let cid = extract_cid(request.path).unwrap_or("").to_string();

    let is_upgrade = request.header("upgrade").is_some()
        && upgrade_host_allowed(request.header("host").unwrap_or(""));
    let is_ws = is_upgrade && request.header("sec-websocket-key").is_some();
    let ws_key = if is_ws {
        request.header("sec-websocket-key").map(|s| s.to_string())
    } else {
        None
    };
    let mut capture = if crate::stats::enabled() {
        Some(crate::stats::Capture::new(&real_ip, &cid))
    } else {
        None
    };
    if !is_upgrade {
        if let Some(c) = capture.take() {
            c.emit("", "", "", "", "");
        }
    }

    if is_upgrade {
        if crate::shed::is_shedding() {
            crate::shed::note_refused();
            log::debug!("[SHED] refusing upgrade from {} — memory", real_ip);
            let _ = stream
                .write_all(crate::shed::SHED_RESPONSE.as_bytes())
                .await;
            let _ = stream.flush().await;
            return Ok(());
        }
        let ua = request_ua.to_string();

        if is_ws {
            log::debug!(
                "[HTTP] WebSocket upgrade from {} path={} ua=\"{}\"",
                real_ip,
                "ws",
                ua
            );
            let accept = crate::ws::accept_key(ws_key.as_deref().unwrap_or(""));
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\
                 \r\n",
                accept
            );
            stream.write_all(response.as_bytes()).await?;

            let leftover = buf.split_off(n_headers);
            let ws_stream = crate::ws::wrap(stream, leftover);
            if let Err(e) = noise_proxy::run_streaming_tunnel_with_prefix(
                ws_stream,
                Vec::new(),
                &server_keys,
                &real_ip,
                &ua,
                egress_ips,
                &cid,
                capture,
                None,
            )
            .await
            {
                log::debug!("[WS/Noise] {} tunnel error: {}", real_ip, e);
                crate::metrics::inc_hs_fail();
            }
            return Ok(());
        }

        log::debug!("[HTTP] HTTPUpgrade from {} ua=\"{}\"", real_ip, ua);

        let response = "HTTP/1.1 101 Switching Protocols\r\n\
                        Connection: Upgrade\r\n\
                        \r\n";
        stream.write_all(response.as_bytes()).await?;

        let leftover = buf.split_off(n_headers);
        if let Err(e) = noise_proxy::run_streaming_tunnel_with_prefix(
            stream,
            leftover,
            &server_keys,
            &real_ip,
            &ua,
            egress_ips,
            &cid,
            capture,
            raw_fd,
        )
        .await
        {
            log::debug!("[HTTP/Noise] {} tunnel error: {}", real_ip, e);
            crate::metrics::inc_hs_fail();
        }
        return Ok(());
    }

    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\nNot Found\n").await;
    Ok(())
}
