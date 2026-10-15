// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PROXY protocol v1 + v2 parser.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
const V1_PREFIX: &[u8] = b"PROXY ";
/// How long a peer has to complete a PROXY header once one may be expected.
const DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PpMode {
    #[default]
    Disabled,
    Auto,
    Required,
}

impl<'de> serde::Deserialize<'de> for PpMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        match s.to_ascii_lowercase().as_str() {
            "off" | "disabled" | "none" => Ok(PpMode::Disabled),
            "auto" | "optional" => Ok(PpMode::Auto),
            "required" | "force" | "strict" => Ok(PpMode::Required),
            other => Err(serde::de::Error::custom(format!(
                "invalid proxy_protocol mode: {other:?}"
            ))),
        }
    }
}

/// Consume a PROXY header if one is present and return the address to record
/// for the connection: the header's source under `Required`, the socket peer
/// otherwise. `Auto` strips a header without trusting it, since any direct
/// peer could have written one. A header not completed within [`DEADLINE`] is
/// an error.
pub async fn peek_and_strip(
    stream: &mut TcpStream,
    edge_peer: SocketAddr,
    mode: PpMode,
) -> std::io::Result<SocketAddr> {
    if matches!(mode, PpMode::Disabled) {
        return Ok(edge_peer);
    }
    tokio::time::timeout(DEADLINE, strip(stream, edge_peer, mode))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "PROXY header not completed in time",
            )
        })?
}

async fn strip(
    stream: &mut TcpStream,
    edge_peer: SocketAddr,
    mode: PpMode,
) -> std::io::Result<SocketAddr> {
    let mut probe = [0u8; 12];
    let n = stream.peek(&mut probe).await?;
    let is_v2 = n >= 12 && probe == V2_SIG;
    let is_v1 = n >= V1_PREFIX.len() && &probe[..V1_PREFIX.len()] == V1_PREFIX;
    if !is_v1 && !is_v2 {
        return match mode {
            PpMode::Required => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PROXY protocol header required but not present",
            )),
            _ => Ok(edge_peer),
        };
    }
    match accept_optional(stream).await? {
        ProxyHeader::Present { src } if mode == PpMode::Required => Ok(src),
        _ => Ok(edge_peer),
    }
}

/// A header carrying a source address, or none to honour: no header, a v1
/// `UNKNOWN` line, a v2 `LOCAL` command or an `AF_UNSPEC` family, for which the
/// real connection endpoints apply.
pub enum ProxyHeader {
    Present { src: SocketAddr },
    Absent,
}

pub async fn accept_optional(stream: &mut TcpStream) -> std::io::Result<ProxyHeader> {
    let mut probe = [0u8; 12];
    let mut filled = 0usize;
    while filled < 12 {
        match stream.read(&mut probe[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(e),
        }
    }
    if filled == 0 {
        return Ok(ProxyHeader::Absent);
    }
    if filled >= 12 && probe == V2_SIG {
        return parse_v2(stream).await;
    }
    if filled >= V1_PREFIX.len() && &probe[..V1_PREFIX.len()] == V1_PREFIX {
        return parse_v1(stream, &probe[..filled]).await;
    }
    Ok(ProxyHeader::Absent)
}

async fn parse_v1(stream: &mut TcpStream, already_read: &[u8]) -> std::io::Result<ProxyHeader> {
    let mut line = already_read.to_vec();
    let mut byte = [0u8; 1];
    while !line.windows(2).any(|w| w == b"\r\n") {
        if line.len() > 107 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "PROXY v1 too long",
            ));
        }
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
    }
    let crlf = line.windows(2).position(|w| w == b"\r\n").unwrap();
    let header = std::str::from_utf8(&line[..crlf])
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "PROXY v1 not utf-8"))?;
    let parts: Vec<&str> = header.split_whitespace().collect();
    if parts.len() < 2 || parts[0] != "PROXY" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PROXY v1 bad prefix",
        ));
    }
    if parts[1] == "UNKNOWN" {
        return Ok(ProxyHeader::Absent);
    }
    if parts.len() != 6 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PROXY v1 wrong field count",
        ));
    }
    let src_ip: IpAddr = parts[2].parse().map_err(invalid)?;
    let src_port: u16 = parts[4].parse().map_err(invalid)?;
    Ok(ProxyHeader::Present {
        src: SocketAddr::new(src_ip, src_port),
    })
}

async fn parse_v2(stream: &mut TcpStream) -> std::io::Result<ProxyHeader> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    let ver_cmd = hdr[0];
    let fam_proto = hdr[1];
    let body_len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if (ver_cmd >> 4) != 0x2 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PROXY v2 wrong version",
        ));
    }
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;
    if ver_cmd & 0x0F == 0x0 {
        return Ok(ProxyHeader::Absent);
    }
    let family = fam_proto >> 4;
    match family {
        0x1 => {
            if body_len < 12 {
                return Err(invalid("v2 ipv4 body short"));
            }
            let src_ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let src_port = u16::from_be_bytes([body[8], body[9]]);
            Ok(ProxyHeader::Present {
                src: SocketAddr::new(IpAddr::V4(src_ip), src_port),
            })
        }
        0x2 => {
            if body_len < 36 {
                return Err(invalid("v2 ipv6 body short"));
            }
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&body[0..16]);
            let src_port = u16::from_be_bytes([body[32], body[33]]);
            Ok(ProxyHeader::Present {
                src: SocketAddr::new(IpAddr::V6(Ipv6Addr::from(src_bytes)), src_port),
            })
        }
        _ => Ok(ProxyHeader::Absent),
    }
}

fn invalid<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    /// Drive the real parser over a real socket pair — this module's whole job is
    /// reading bytes off a TcpStream, so a fake would test nothing.
    async fn parse(header: &[u8], mode: PpMode) -> std::io::Result<SocketAddr> {
        parse_with_edge(header, mode).await.0
    }

    /// Also returns the edge peer the listener reported. Never assume that is
    /// 127.0.0.1.
    async fn parse_with_edge(
        header: &[u8],
        mode: PpMode,
    ) -> (std::io::Result<SocketAddr>, SocketAddr) {
        let header = header.to_vec();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            let _ = c.write_all(&header).await;
            let _ = c.flush().await;

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });
        let (mut server, edge) = listener.accept().await.unwrap();
        let res = peek_and_strip(&mut server, edge, mode).await;
        writer.abort();
        (res, edge)
    }

    #[tokio::test]
    async fn v1_tcp4_yields_the_real_client() {
        let got = parse(
            b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 80\r\n",
            PpMode::Required,
        )
        .await
        .unwrap();
        assert_eq!(got, "203.0.113.7:51234".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn v1_tcp6_yields_the_real_client() {
        let got = parse(
            b"PROXY TCP6 2606:4700::1 2606:4700::2 51234 80\r\n",
            PpMode::Required,
        )
        .await
        .unwrap();
        assert_eq!(got, "[2606:4700::1]:51234".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn v1_unknown_falls_back_to_the_edge_peer() {
        let (got, edge) = parse_with_edge(b"PROXY UNKNOWN\r\n", PpMode::Auto).await;
        assert_eq!(got.unwrap(), edge);
    }

    #[tokio::test]
    async fn v1_with_a_wrong_field_count_is_rejected() {
        let err = parse(b"PROXY TCP4 203.0.113.7 10.0.0.1\r\n", PpMode::Auto).await;
        assert!(err.is_err(), "half a v1 header was accepted");
    }

    #[tokio::test]
    async fn v1_with_an_unparseable_address_is_rejected() {
        let err = parse(b"PROXY TCP4 not-an-ip 10.0.0.1 1 80\r\n", PpMode::Auto).await;
        assert!(err.is_err(), "garbage source address was accepted");
    }

    #[tokio::test]
    async fn an_over_long_v1_line_is_rejected_rather_than_read_forever() {
        let mut h = b"PROXY ".to_vec();
        h.extend(std::iter::repeat_n(b'A', 200));
        let err = parse(&h, PpMode::Auto).await;
        assert!(err.is_err(), "unbounded v1 line accepted");
    }

    fn v2(cmd: u8, family: u8, body: &[u8]) -> Vec<u8> {
        let mut h = V2_SIG.to_vec();
        h.push(0x20 | cmd);
        h.push(family << 4);
        h.extend_from_slice(&(body.len() as u16).to_be_bytes());
        h.extend_from_slice(body);
        h
    }

    #[tokio::test]
    async fn v2_ipv4_yields_the_real_client() {
        let mut body = Vec::new();
        body.extend_from_slice(&[203, 0, 113, 9]);
        body.extend_from_slice(&[10, 0, 0, 1]);
        body.extend_from_slice(&4242u16.to_be_bytes());
        body.extend_from_slice(&80u16.to_be_bytes());
        let got = parse(&v2(0x1, 0x1, &body), PpMode::Required)
            .await
            .unwrap();
        assert_eq!(got, "203.0.113.9:4242".parse::<SocketAddr>().unwrap());
    }

    /// Any direct peer can write a header, so `Auto` strips one without
    /// recording its address.
    #[tokio::test]
    async fn auto_strips_a_header_but_records_the_edge_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            c.write_all(b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 80\r\nhello")
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let (mut server, edge) = listener.accept().await.unwrap();
        let got = peek_and_strip(&mut server, edge, PpMode::Auto).await.unwrap();
        assert_eq!(got, edge);
        let mut rest = [0u8; 5];
        server.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"hello", "the header must still be consumed");
        writer.abort();
    }

    /// A peer that opens a header and stalls is closed at the deadline instead
    /// of holding a task until it leaves.
    #[tokio::test]
    async fn a_stalled_header_is_an_error_at_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
            c.write_all(b"PROXY ").await.unwrap();
            tokio::time::sleep(DEADLINE * 4).await;
        });
        let (mut server, edge) = listener.accept().await.unwrap();
        let started = std::time::Instant::now();
        let err = peek_and_strip(&mut server, edge, PpMode::Auto)
            .await
            .expect_err("a stalled header was accepted");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < DEADLINE * 2, "{:?}", started.elapsed());
        writer.abort();
    }

    #[tokio::test]
    async fn v2_local_and_unspec_fall_back_to_the_edge_peer() {
        for h in [v2(0x0, 0x1, &[0u8; 12]), v2(0x1, 0x0, &[])] {
            let (got, edge) = parse_with_edge(&h, PpMode::Auto).await;
            assert_eq!(got.unwrap(), edge, "{h:02x?}");
        }
    }

    #[tokio::test]
    async fn v2_with_a_short_ipv4_body_is_rejected() {
        let err = parse(&v2(0x1, 0x1, &[0u8; 8]), PpMode::Auto).await;
        assert!(err.is_err(), "short v2 body accepted");
    }

    #[tokio::test]
    async fn v2_wrong_version_nibble_is_rejected() {
        let mut h = V2_SIG.to_vec();
        h.push(0x31);
        h.push(0x11);
        h.extend_from_slice(&12u16.to_be_bytes());
        h.extend_from_slice(&[0u8; 12]);
        let err = parse(&h, PpMode::Auto).await;
        assert!(err.is_err(), "v2 header with version 3 accepted");
    }

    /// A plain HTTP request must be left completely alone in Auto mode — and
    /// crucially its bytes must not be consumed, which `peek_and_strip` guarantees
    /// by peeking before it reads.
    #[tokio::test]
    async fn a_plain_request_falls_back_to_the_edge_peer() {
        let (got, edge) =
            parse_with_edge(b"GET /noise HTTP/1.1\r\nHost: x\r\n\r\n", PpMode::Auto).await;
        assert_eq!(
            got.unwrap(),
            edge,
            "should have fallen back to the edge peer"
        );
    }

    #[tokio::test]
    async fn disabled_mode_never_looks_at_the_bytes() {
        let (got, edge) = parse_with_edge(
            b"PROXY TCP4 203.0.113.7 10.0.0.1 51234 80\r\n",
            PpMode::Disabled,
        )
        .await;

        let got = got.unwrap();
        assert_eq!(got, edge);
        assert_ne!(
            got.ip(),
            "203.0.113.7".parse::<IpAddr>().unwrap(),
            "Disabled mode must not honour the header"
        );
    }

    #[tokio::test]
    async fn required_mode_refuses_a_connection_with_no_header() {
        let err = parse(b"GET / HTTP/1.1\r\n\r\n", PpMode::Required).await;
        assert!(
            err.is_err(),
            "Required mode accepted a header-less connection"
        );
    }

    #[test]
    fn mode_parses_every_documented_spelling() {
        for (s, want) in [
            ("off", PpMode::Disabled),
            ("disabled", PpMode::Disabled),
            ("none", PpMode::Disabled),
            ("auto", PpMode::Auto),
            ("optional", PpMode::Auto),
            ("required", PpMode::Required),
            ("force", PpMode::Required),
            ("strict", PpMode::Required),
            ("REQUIRED", PpMode::Required),
            ("Off", PpMode::Disabled),
        ] {
            let toml = format!("mode = \"{s}\"");
            #[derive(serde::Deserialize)]
            struct W {
                mode: PpMode,
            }
            let got: W = toml::from_str(&toml).unwrap_or_else(|e| panic!("{s:?}: {e}"));
            assert!(
                matches!(
                    (&got.mode, &want),
                    (PpMode::Disabled, PpMode::Disabled)
                        | (PpMode::Auto, PpMode::Auto)
                        | (PpMode::Required, PpMode::Required)
                ),
                "{s:?} parsed wrong"
            );
        }
    }

    #[test]
    fn an_unknown_mode_is_a_config_error_not_a_silent_default() {
        #[derive(serde::Deserialize)]
        struct W {
            mode: PpMode,
        }
        assert!(toml::from_str::<W>("mode = \"banana\"").is_err());
        let w: W = toml::from_str("mode = \"required\"").unwrap();
        assert!(matches!(w.mode, PpMode::Required));
    }

    #[test]
    fn the_default_mode_is_disabled() {
        assert_eq!(PpMode::default(), PpMode::Disabled);
        assert_eq!(
            toml::from_str::<crate::config::Config>(
                "private_key = \"aa\"\npublic_key = \"bb\"\n[proteus]\npsfs = [\"x.psf\"]\n"
            )
            .unwrap()
            .proteus
            .proxy_protocol,
            PpMode::Disabled,
            "a [proteus] section without the key must not trust PROXY headers"
        );
    }
}
