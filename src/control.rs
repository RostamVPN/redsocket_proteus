// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! In-tunnel app↔server control channel — `_rs.<cmd>:<port>` CONNECTs.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Extract subcommand from `_rs.<cmd>` (dropping the `_rs.` prefix).
pub fn subcommand(host: &str) -> Option<&str> {
    host.strip_prefix("_rs.")
}

/// Dispatch a `_rs.*` CONNECT to the appropriate handler. Returns Ok when the
/// handler completed (whether or not it wrote anything).
pub async fn handle<S>(
    stream: &mut S,
    host: &str,
    server_pubkey_hex: &str,
    cid: &str,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(cmd) = subcommand(host) else {
        anyhow::bail!("not a control-channel host: {}", host);
    };
    match cmd {
        "config" => handle_config(stream, server_pubkey_hex).await,
        "ping" => handle_ping(stream).await,
        "stat" => handle_stat(stream, cid).await,
        "notify" => handle_notify(stream).await,
        other => {
            log::debug!("[_rs] unknown subcommand {:?} (cid={})", other, cid);
            let msg = format!("HTTP/1.1 404 unknown _rs subcommand: {}\n", other);
            stream.write_all(msg.as_bytes()).await?;
            Ok(())
        }
    }
}

async fn handle_config<S: AsyncWrite + Unpin>(
    stream: &mut S,
    server_pubkey_hex: &str,
) -> anyhow::Result<()> {
    let body = format!(
        r#"{{"noise_pubkey":"{}","carriers":["proteus"],"server":"redsocket-http"}}"#,
        server_pubkey_hex
    );

    let len_bytes = (body.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn handle_ping<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> anyhow::Result<()> {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).await?;
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

async fn handle_stat<S: AsyncWrite + Unpin>(stream: &mut S, cid: &str) -> anyhow::Result<()> {
    let (active, total) = (
        crate::metrics::active_tunnels(),
        crate::metrics::total_tunnels(),
    );
    let body = format!(
        r#"{{"cid":"{}","active_tunnels":{},"total_tunnels":{},"bytes_up":{},"bytes_down":{}}}"#,
        cid,
        active,
        total,
        crate::metrics::total_bytes_up(),
        crate::metrics::total_bytes_down()
    );
    let len_bytes = (body.len() as u32).to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn handle_notify<S: AsyncWrite + Unpin>(stream: &mut S) -> anyhow::Result<()> {
    let len_bytes = 0u32.to_be_bytes();
    stream.write_all(&len_bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subcommand_strips_the_reserved_prefix() {
        assert_eq!(subcommand("_rs.ping"), Some("ping"));
        assert_eq!(subcommand("_rs.config"), Some("config"));
        assert_eq!(subcommand("example.com"), None);
    }

    #[tokio::test]
    async fn ping_echoes_the_clients_nonce() {
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move { handle_ping(&mut server).await.unwrap() });
        client.write_all(&[1, 2, 3, 4, 5, 6, 7, 8]).await.unwrap();
        let mut echo = [0u8; 8];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(echo, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[tokio::test]
    async fn config_is_length_prefixed_json() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move { handle_config(&mut server, "abcd").await.unwrap() });
        let mut len = [0u8; 4];
        client.read_exact(&mut len).await.unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(
            String::from_utf8(body).unwrap(),
            r#"{"noise_pubkey":"abcd","carriers":["proteus"],"server":"redsocket-http"}"#
        );
    }

    #[tokio::test]
    async fn an_unknown_subcommand_answers_instead_of_hanging() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            handle(&mut server, "_rs.bogus", "abcd", "cid")
                .await
                .unwrap()
        });
        let mut buf = vec![0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("404"));
    }
}
