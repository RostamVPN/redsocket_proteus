// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Legacy (pre-META) standalone client — mirrors redsocket-core v2 noise.rs
//! BEFORE commit 8bf0853: HTTP upgrade + Noise NK + immediate SOCKS5 CONNECT,
//! NO META frame. Uses cleartext URL cid like production legacy clients. Usage.

use snow::Builder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

struct Args {
    server: String,
    pubkey: String,
    cid: String,
    target: String,
    ws: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        server: String::new(),
        pubkey: String::new(),
        cid: "0123456789abcdef".into(),
        target: "example.com:80".into(),
        ws: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        match k.as_str() {
            "--server" => a.server = it.next().unwrap(),
            "--pubkey" => a.pubkey = it.next().unwrap(),
            "--cid" => a.cid = it.next().unwrap(),
            "--target" => a.target = it.next().unwrap(),
            "--ws" => a.ws = true,
            other => panic!("unknown arg {other}"),
        }
    }
    assert!(!a.server.is_empty() && !a.pubkey.is_empty());
    a
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let mut server_pubkey = [0u8; 32];
    server_pubkey.copy_from_slice(&hex::decode(&args.pubkey)?);

    let mut stream = TcpStream::connect(&args.server).await?;
    stream.set_nodelay(true)?;
    println!("[+] TCP connected to {}", args.server);

    let req = format!(
        "GET /noise?cid={} HTTP/1.1\r\n\
         Host: {}\r\n\
         Connection: upgrade\r\n\
         Upgrade: websocket\r\n\
         User-Agent: Amazon CloudFront\r\n\
         \r\n",
        args.cid, args.server
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut hdr = Vec::new();
    let mut b = [0u8; 1];
    loop {
        stream.read_exact(&mut b).await?;
        hdr.push(b[0]);
        if hdr.len() >= 4 && &hdr[hdr.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if hdr.len() > 8192 {
            panic!("headers too long");
        }
    }
    let hs = String::from_utf8_lossy(&hdr);
    assert!(
        hs.starts_with("HTTP/1.1 101"),
        "expected 101: {}",
        hs.lines().next().unwrap_or("")
    );
    println!("[+] 101 Switching Protocols");

    let mut hs_state = Builder::new(NOISE_PATTERN.parse()?)
        .remote_public_key(&server_pubkey)
        .build_initiator()?;
    let mut msg1 = vec![0u8; 65535];
    let n1 = hs_state.write_message(&[], &mut msg1)?;
    let mut f1 = (n1 as u16).to_be_bytes().to_vec();
    f1.extend_from_slice(&msg1[..n1]);
    send(&mut stream, &f1, args.ws).await?;

    let msg2_len = {
        let mut lb = [0u8; 2];
        read_frame(&mut stream, &mut lb, args.ws).await?;
        u16::from_be_bytes(lb) as usize
    };
    let mut msg2 = vec![0u8; msg2_len];
    read_frame(&mut stream, &mut msg2, args.ws).await?;
    let mut rb = vec![0u8; 65535];
    hs_state.read_message(&msg2, &mut rb)?;
    let mut transport = hs_state.into_transport_mode()?;
    println!("[+] Noise NK handshake complete (legacy, no META)");

    let (thost, tport) = args.target.rsplit_once(':').unwrap();
    let tport: u16 = tport.parse()?;
    let mut connect = vec![0x05u8, 0x03, thost.len() as u8];
    connect.extend_from_slice(thost.as_bytes());
    connect.extend_from_slice(&tport.to_be_bytes());
    let mut ct = vec![0u8; 65535];
    let cl = transport.write_message(&connect, &mut ct)?;
    let mut f2 = (cl as u16).to_be_bytes().to_vec();
    f2.extend_from_slice(&ct[..cl]);
    send(&mut stream, &f2, args.ws).await?;
    println!("[*] SOCKS5 CONNECT {}:{} (legacy path)", thost, tport);

    println!(
        "[+] legacy tunnel open to {}:{} (server sends no reply)",
        thost, tport
    );

    let mut pt = vec![0u8; 65535];
    let probe = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        thost
    );
    let cl = transport.write_message(probe.as_bytes(), &mut ct)?;
    let mut f3 = (cl as u16).to_be_bytes().to_vec();
    f3.extend_from_slice(&ct[..cl]);
    send(&mut stream, &f3, args.ws).await?;

    let rlen = {
        let mut lb = [0u8; 2];
        read_frame(&mut stream, &mut lb, args.ws).await?;
        u16::from_be_bytes(lb) as usize
    };
    let mut rct = vec![0u8; rlen];
    read_frame(&mut stream, &mut rct, args.ws).await?;
    let pl = transport.read_message(&rct, &mut pt)?;
    let resp = &pt[..pl];
    let line = String::from_utf8_lossy(resp)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    println!("[+] through-tunnel response: {}", line);
    assert!(line.contains("HTTP/"), "no HTTP response");
    println!("LEGACY FULL TUNNEL OK");
    Ok(())
}

async fn send(s: &mut TcpStream, data: &[u8], ws: bool) -> Result<(), Box<dyn std::error::Error>> {
    if ws {
        let mask: [u8; 4] = rand::random();
        let mut v = vec![0x82u8];
        if data.len() < 126 {
            v.push(0x80 | data.len() as u8);
        } else {
            v.push(0x80 | 126);
            v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        }
        v.extend_from_slice(&mask);
        v.extend(data.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
        s.write_all(&v).await?;
    } else {
        s.write_all(data).await?;
    }
    s.flush().await?;
    Ok(())
}

/// Read exactly buf.len() bytes of the *byte stream*, unwrapping WS frames if
/// ws.
async fn read_frame(
    s: &mut TcpStream,
    buf: &mut [u8],
    ws: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !ws {
        s.read_exact(buf).await?;
        return Ok(());
    }
    let mut got = 0usize;
    while got < buf.len() {
        let mut h = [0u8; 2];
        s.read_exact(&mut h).await?;
        let op = h[0] & 0x0F;
        let mut len = (h[1] & 0x7F) as usize;
        if len == 126 {
            let mut e = [0u8; 2];
            s.read_exact(&mut e).await?;
            len = u16::from_be_bytes(e) as usize;
        } else if len == 127 {
            let mut e = [0u8; 8];
            s.read_exact(&mut e).await?;
            len = u64::from_be_bytes(e) as usize;
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            s.read_exact(&mut payload).await?;
        }
        if op == 0x9 {
            continue;
        }
        let take = (buf.len() - got).min(payload.len());
        buf[got..got + take].copy_from_slice(&payload[..take]);
        got += take;
        assert!(
            take == payload.len(),
            "ws frame straddles read boundary — test client limitation"
        );
    }
    Ok(())
}
