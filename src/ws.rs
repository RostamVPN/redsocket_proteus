// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! WebSocket framing — RFC 6455 server-side codec.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

const OP_CONT: u8 = 0x0;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

const MAX_FRAME: u64 = 16 * 1024 * 1024;
const DUPLEX_CAP: usize = 16 * 1024;

/// Wrap a post-101 socket in the WS codec.
pub fn wrap<S>(stream: S, leftover: Vec<u8>) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use std::sync::Arc;
    use tokio::sync::Mutex;

    let (tunnel_end, pump_end) = tokio::io::duplex(DUPLEX_CAP);
    let (mut pump_r, mut pump_w) = tokio::io::split(pump_end);
    let (mut rd, wr) = tokio::io::split(stream);
    let wr = Arc::new(Mutex::new(wr));

    let wr_reader = wr.clone();
    tokio::spawn(async move {
        let mut pending = leftover;
        let mut frag: Vec<u8> = Vec::new();
        loop {
            let Some((fin, op, mut payload)) = read_frame(&mut rd, &mut pending).await else {
                break;
            };
            match op {
                OP_CLOSE => {
                    let mut w = wr_reader.lock().await;
                    let _ = w.write_all(&frame_bytes(OP_CLOSE, &[])).await;
                    let _ = w.flush().await;
                    break;
                }
                OP_PING => {
                    let mut w = wr_reader.lock().await;
                    if w.write_all(&frame_bytes(OP_PONG, &payload)).await.is_err() {
                        break;
                    }
                    if w.flush().await.is_err() {
                        break;
                    }
                }
                OP_PONG => {}
                OP_BINARY | OP_CONT => {
                    frag.append(&mut payload);
                    if fin {
                        if pump_w.write_all(&frag).await.is_err() {
                            break;
                        }
                        frag.clear();
                    }
                }
                _ => {}
            }
        }
    });

    tokio::spawn(async move {
        let mut up_buf = vec![0u8; 32 * 1024];
        loop {
            let n = match pump_r.read(&mut up_buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut w = wr.lock().await;
            if w.write_all(&frame_bytes(OP_BINARY, &up_buf[..n]))
                .await
                .is_err()
            {
                break;
            }
            if w.flush().await.is_err() {
                break;
            }
        }
        let _ = wr.lock().await.shutdown().await;
    });

    tunnel_end
}

fn frame_bytes(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 10);
    v.push(0x80 | op);
    if payload.len() < 126 {
        v.push(payload.len() as u8);
    } else if payload.len() <= 0xFFFF {
        v.push(126);
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        v.push(127);
        v.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    v.extend_from_slice(payload);
    v
}

/// Read one WS frame: (fin, opcode, unmasked payload). None on EOF/error.
async fn read_frame<R: AsyncRead + Unpin>(
    rd: &mut R,
    pending: &mut Vec<u8>,
) -> Option<(bool, u8, Vec<u8>)> {
    let h = read_exact(rd, pending, 2).await?;
    let fin = h[0] & 0x80 != 0;
    let op = h[0] & 0x0F;
    let masked = h[1] & 0x80 != 0;
    let mut len = (h[1] & 0x7F) as u64;
    if len == 126 {
        let e = read_exact(rd, pending, 2).await?;
        len = u16::from_be_bytes([e[0], e[1]]) as u64;
    } else if len == 127 {
        let e = read_exact(rd, pending, 8).await?;
        len = u64::from_be_bytes(e[..8].try_into().ok()?);
    }
    if len > MAX_FRAME {
        return None;
    }
    let mask = if masked {
        let m = read_exact(rd, pending, 4).await?;
        Some([m[0], m[1], m[2], m[3]])
    } else {
        None
    };
    let mut payload = read_exact(rd, pending, len as usize).await?;
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i & 3];
        }
    }
    Some((fin, op, payload))
}

async fn read_exact<R: AsyncRead + Unpin>(
    rd: &mut R,
    pending: &mut Vec<u8>,
    n: usize,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    if !pending.is_empty() {
        let take = pending.len().min(n);
        out.extend_from_slice(&pending[..take]);
        pending.drain(..take);
    }
    if out.len() < n {
        let mut rest = vec![0u8; n - out.len()];
        rd.read_exact(&mut rest).await.ok()?;
        out.extend_from_slice(&rest);
    }
    Some(out)
}

/// RFC 6455 §4.2.2 accept key: base64(SHA-1(key + GUID)).
pub fn accept_key(key: &str) -> String {
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(key.as_bytes());
    h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, h.finalize())
}
