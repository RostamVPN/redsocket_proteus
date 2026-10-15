// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! NoiseStream — plaintext duplex view over an established Noise NK session.

use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::Mutex;

use crate::noise::NoiseSession;

const DUPLEX_BUFFER: usize = 64 * 1024;
/// One read becomes one Noise transport message, and snow refuses to write a
/// message whose ciphertext exceeds 65535 bytes — so the plaintext ceiling is
/// 65535 minus the 16-byte ChaChaPoly tag.
const MAX_PLAINTEXT: usize = 65535 - 16;

pub fn wrap<S>(tcp: S, session: NoiseSession) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (caller_side, internal_side) = tokio::io::duplex(DUPLEX_BUFFER);
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
            if ct_len == 0 || ct_len > 65535 {
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

        let _ = pt_w.shutdown().await;
    });

    let sess_e = session.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PLAINTEXT];
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
            let frame_len = (ct.len() as u16).to_be_bytes();
            if tcp_w.write_all(&frame_len).await.is_err() {
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
