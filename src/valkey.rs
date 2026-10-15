// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Minimal RESP2 client for valkey-main — the instance that holds the cashier's
//! cid ledger, the message mailboxes and the protection bundle.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Connection settings for one Valkey instance. `cert_file`/`key_file` empty
/// means TLS without client auth (the stats instance's mode).
#[derive(Clone, serde::Deserialize, PartialEq, Eq)]
pub struct Config {
    pub addr: String,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub ca_file: String,
    #[serde(default)]
    pub cert_file: String,
    #[serde(default)]
    pub key_file: String,
}

/// Everything but the password, which `{:?}` of a `protection::Source` would
/// otherwise put in the start-up log.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("addr", &self.addr)
            .field("tls", &self.tls)
            .field("server_name", &self.server_name)
            .field("password", &"<redacted>")
            .field("ca_file", &self.ca_file)
            .field("cert_file", &self.cert_file)
            .field("key_file", &self.key_file)
            .finish()
    }
}

fn default_true() -> bool {
    true
}

impl Config {
    /// What a connect would trip over, caught at startup instead: TLS needs a
    /// server name to verify and a CA to verify against, and a client cert needs
    /// its key.
    pub fn validate(&self, section: &str) -> anyhow::Result<()> {
        if self.addr.trim().is_empty() {
            anyhow::bail!("[{section}] addr is empty");
        }
        if self.tls {
            if self.server_name.trim().is_empty() {
                anyhow::bail!("[{section}] tls = true but server_name is empty (the name on valkey-main's certificate)");
            }
            if self.ca_file.trim().is_empty() {
                anyhow::bail!("[{section}] tls = true but ca_file is empty");
            }
            if self.cert_file.is_empty() != self.key_file.is_empty() {
                anyhow::bail!("[{section}] cert_file and key_file must be set together");
            }
        }
        Ok(())
    }

    /// Plaintext, no auth — the test fake.
    pub fn plain(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            tls: false,
            server_name: String::new(),
            password: String::new(),
            ca_file: String::new(),
            cert_file: String::new(),
            key_file: String::new(),
        }
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longer than any BLOCK we issue, so a dead peer is noticed and a live one is
/// not.
pub const READ_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resp {
    Nil,
    Str(Vec<u8>),
    Int(i64),
    Err(String),
    Arr(Vec<Resp>),
}

impl Resp {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Resp::Str(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_string(&self) -> Option<String> {
        self.as_bytes()
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Resp::Int(i) => Some(*i),
            Resp::Str(b) => std::str::from_utf8(b).ok()?.trim().parse().ok(),
            _ => None,
        }
    }
    /// A flat `[k, v, k, v, …]` reply (HGETALL) as pairs; anything else is empty.
    pub fn pairs(&self) -> Vec<(String, String)> {
        let Resp::Arr(items) = self else {
            return Vec::new();
        };
        items
            .chunks_exact(2)
            .filter_map(|kv| Some((kv[0].as_string()?, kv[1].as_string()?)))
            .collect()
    }
    pub fn into_err(self) -> anyhow::Result<Resp> {
        match self {
            Resp::Err(e) => anyhow::bail!("valkey: {}", e),
            r => Ok(r),
        }
    }
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub struct Conn {
    io: BufReader<Box<dyn Io>>,
}

impl Conn {
    pub async fn connect(cfg: &Config) -> anyhow::Result<Conn> {
        let tcp = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&cfg.addr))
            .await
            .map_err(|_| anyhow::anyhow!("connect timeout to {}", cfg.addr))??;
        tcp.set_nodelay(true)?;
        let io: Box<dyn Io> = if cfg.tls {
            let mut roots = rustls::RootCertStore::empty();
            let ca = std::fs::read(&cfg.ca_file)
                .map_err(|e| anyhow::anyhow!("read ca_file {}: {}", cfg.ca_file, e))?;
            for c in rustls_pemfile::certs(&mut ca.as_slice()) {
                roots.add(c?)?;
            }
            let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
            let tls_cfg = if cfg.cert_file.is_empty() {
                builder.with_no_client_auth()
            } else {
                let cert = std::fs::read(&cfg.cert_file)
                    .map_err(|e| anyhow::anyhow!("read cert_file {}: {}", cfg.cert_file, e))?;
                let key = std::fs::read(&cfg.key_file)
                    .map_err(|e| anyhow::anyhow!("read key_file {}: {}", cfg.key_file, e))?;
                let certs: Vec<_> =
                    rustls_pemfile::certs(&mut cert.as_slice()).collect::<Result<_, _>>()?;
                let key = rustls_pemfile::private_key(&mut key.as_slice())?
                    .ok_or_else(|| anyhow::anyhow!("no private key in {}", cfg.key_file))?;
                builder.with_client_auth_cert(certs, key)?
            };
            let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
            let name = rustls::pki_types::ServerName::try_from(cfg.server_name.clone())?;
            let tls = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
                .await
                .map_err(|_| anyhow::anyhow!("tls handshake timeout"))??;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };
        let mut conn = Conn {
            io: BufReader::with_capacity(1 << 16, io),
        };
        if !cfg.password.is_empty() {
            if let Resp::Err(e) = conn.cmd(&[b"AUTH", cfg.password.as_bytes()]).await? {
                anyhow::bail!("AUTH refused: {}", e);
            }
        }
        Ok(conn)
    }

    /// Send one command and read its reply (errors come back as `Resp::Err`).
    pub async fn cmd(&mut self, args: &[&[u8]]) -> anyhow::Result<Resp> {
        self.send(args).await?;
        self.read().await
    }

    /// Same, with its own read deadline — for a reply known to be large.
    pub async fn cmd_for(&mut self, args: &[&[u8]], d: Duration) -> anyhow::Result<Resp> {
        self.send(args).await?;
        self.read_for(d).await
    }

    pub async fn send(&mut self, args: &[&[u8]]) -> anyhow::Result<()> {
        self.io.write_all(&encode(args)).await?;
        self.io.flush().await?;
        Ok(())
    }

    /// Read one reply, bounded by [`READ_TIMEOUT`].
    pub async fn read(&mut self) -> anyhow::Result<Resp> {
        self.read_for(READ_TIMEOUT).await
    }

    pub async fn read_for(&mut self, d: Duration) -> anyhow::Result<Resp> {
        tokio::time::timeout(d, read_resp(&mut self.io))
            .await
            .map_err(|_| anyhow::anyhow!("valkey read timeout"))?
    }

    /// Like [`read_for`](Self::read_for) but a timeout is `Ok(None)` — for a
    /// subscription, where silence is normal and only a dead socket is not.
    pub async fn read_opt_for(&mut self, d: Duration) -> anyhow::Result<Option<Resp>> {
        match tokio::time::timeout(d, read_resp(&mut self.io)).await {
            Ok(r) => r.map(Some),
            Err(_) => Ok(None),
        }
    }
}

pub fn encode(args: &[&[u8]]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    out
}

async fn read_line<R: AsyncBufReadExt + Unpin>(r: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut line = Vec::with_capacity(32);
    let n = r.read_until(b'\n', &mut line).await?;
    if n == 0 {
        anyhow::bail!("valkey closed the connection");
    }
    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        line.pop();
    }
    Ok(line)
}

/// Largest bulk string accepted. The biggest legitimate reply is the ~7 MB
/// base64 `v4` field; a hostile or confused peer announcing a 2 GB bulk must be
/// an error, not an allocation (the binary runs with `panic = "abort"`).
pub const MAX_BULK: usize = 16 << 20;
/// Most elements in one array reply (HGETALL of a 1M-cid hash is ~1.6M).
pub const MAX_ARRAY: usize = 1 << 21;
/// Deepest array nesting. XREAD replies are four levels.
pub const MAX_DEPTH: usize = 32;

/// Parse one RESP2 value. Iterative: an explicit stack of unfinished arrays, so
/// reply depth or size never maps to native stack depth, and every wire-
/// supplied length is checked before anything is allocated from it.
pub async fn read_resp<R: AsyncBufReadExt + AsyncReadExt + Unpin>(
    r: &mut R,
) -> anyhow::Result<Resp> {
    let mut stack: Vec<(usize, Vec<Resp>)> = Vec::new();
    loop {
        let t = r.read_u8().await?;
        let value = match t {
            b'+' => Resp::Str(read_line(r).await?),
            b'-' => Resp::Err(String::from_utf8_lossy(&read_line(r).await?).into_owned()),
            b':' => Resp::Int(std::str::from_utf8(&read_line(r).await?)?.trim().parse()?),
            b'$' => {
                let n: i64 = std::str::from_utf8(&read_line(r).await?)?.trim().parse()?;
                if n < 0 {
                    Resp::Nil
                } else {
                    let n = usize::try_from(n)?;
                    if n > MAX_BULK {
                        anyhow::bail!("RESP bulk of {} bytes exceeds {}", n, MAX_BULK);
                    }
                    let mut buf = vec![0u8; n + 2];
                    r.read_exact(&mut buf).await?;
                    buf.truncate(n);
                    Resp::Str(buf)
                }
            }
            b'*' => {
                let n: i64 = std::str::from_utf8(&read_line(r).await?)?.trim().parse()?;
                if n < 0 {
                    Resp::Nil
                } else if n == 0 {
                    Resp::Arr(Vec::new())
                } else {
                    let n = usize::try_from(n)?;
                    if n > MAX_ARRAY {
                        anyhow::bail!("RESP array of {} elements exceeds {}", n, MAX_ARRAY);
                    }
                    if stack.len() >= MAX_DEPTH {
                        anyhow::bail!("RESP nesting deeper than {}", MAX_DEPTH);
                    }
                    stack.push((n, Vec::with_capacity(n.min(1 << 16))));
                    continue;
                }
            }
            other => anyhow::bail!("unexpected RESP type byte {:#x}", other),
        };
        let mut value = value;
        loop {
            match stack.last_mut() {
                None => return Ok(value),
                Some((remaining, items)) => {
                    items.push(value);
                    *remaining -= 1;
                    if *remaining > 0 {
                        break;
                    }
                    let (_, done) = stack.pop().expect("non-empty");
                    value = Resp::Arr(done);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(wire: &[u8]) -> Resp {
        let mut r = BufReader::new(wire);
        read_resp(&mut r).await.unwrap()
    }

    #[tokio::test]
    async fn resp_shapes() {
        assert_eq!(parse(b"+OK\r\n").await, Resp::Str(b"OK".to_vec()));
        assert_eq!(parse(b":42\r\n").await, Resp::Int(42));
        assert_eq!(parse(b"$-1\r\n").await, Resp::Nil);
        assert_eq!(parse(b"$3\r\nabc\r\n").await, Resp::Str(b"abc".to_vec()));
        assert_eq!(parse(b"*0\r\n").await, Resp::Arr(vec![]));
        assert_eq!(parse(b"*-1\r\n").await, Resp::Nil);
        assert_eq!(
            parse(b"-ERR nope\r\n").await,
            Resp::Err("ERR nope".to_string())
        );

        let nested = parse(
            b"*1\r\n*2\r\n$3\r\nmsg\r\n*1\r\n*2\r\n$3\r\n1-0\r\n*2\r\n$1\r\nk\r\n$1\r\nv\r\n",
        )
        .await;
        match nested {
            Resp::Arr(outer) => assert_eq!(outer.len(), 1),
            other => panic!("{other:?}"),
        }

        let h = parse(b"*4\r\n$1\r\na\r\n$1\r\n1\r\n$1\r\nb\r\n$1\r\n2\r\n").await;
        assert_eq!(
            h.pairs(),
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
    }

    #[test]
    fn config_validation_catches_what_a_connect_would() {
        let mut c = Config::plain("127.0.0.1:6379");
        assert!(c.validate("x").is_ok(), "plaintext needs nothing else");
        c.tls = true;
        let e = c.validate("messaging.valkey").unwrap_err().to_string();
        assert!(
            e.contains("server_name") && e.contains("[messaging.valkey]"),
            "{e}"
        );
        c.server_name = "valkey-main".into();
        assert!(c.validate("x").unwrap_err().to_string().contains("ca_file"));
        c.ca_file = "/etc/ca.crt".into();
        assert!(c.validate("x").is_ok());
        c.cert_file = "/etc/client.crt".into();
        assert!(c
            .validate("x")
            .unwrap_err()
            .to_string()
            .contains("key_file"));
        c.key_file = "/etc/client.key".into();
        assert!(c.validate("x").is_ok());
        c.addr = " ".into();
        assert!(c.validate("x").unwrap_err().to_string().contains("addr"));
    }

    /// Wire-supplied lengths are errors past the clamps, never allocations: the
    /// binary runs with panic = "abort", so a 2 GB bulk announced by a hostile
    /// Valkey would otherwise take the node down.
    #[tokio::test]
    async fn hostile_lengths_are_errors_not_allocations() {
        let mut r = BufReader::new(&b"$2147483647\r\n"[..]);
        let e = read_resp(&mut r).await.unwrap_err().to_string();
        assert!(e.contains("exceeds"), "{e}");
        let mut r = BufReader::new(&b"*999999999\r\n"[..]);
        assert!(read_resp(&mut r)
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds"));
        let deep: Vec<u8> = b"*1\r\n".repeat(MAX_DEPTH + 1);
        let mut r = BufReader::new(deep.as_slice());
        assert!(read_resp(&mut r)
            .await
            .unwrap_err()
            .to_string()
            .contains("nesting"));

        let mut r = BufReader::new(&b"$-5\r\n"[..]);
        assert_eq!(read_resp(&mut r).await.unwrap(), Resp::Nil);
        let mut r = BufReader::new(&b"$abc\r\n"[..]);
        assert!(read_resp(&mut r).await.is_err());

        let mut big = format!("${}\r\n", 1024).into_bytes();
        big.extend(std::iter::repeat_n(b'x', 1024));
        big.extend_from_slice(b"\r\n");
        let mut r = BufReader::new(big.as_slice());
        assert!(matches!(read_resp(&mut r).await.unwrap(), Resp::Str(v) if v.len() == 1024));
    }

    #[test]
    fn encode_is_resp2_bulk_array() {
        assert_eq!(
            encode(&[b"HGET", b"k", b"f"]),
            b"*3\r\n$4\r\nHGET\r\n$1\r\nk\r\n$1\r\nf\r\n".to_vec()
        );
    }

    /// `protection::Source` is logged with `{:?}` at start-up; the password
    /// must never be in it, the rest must.
    #[test]
    fn debug_output_redacts_the_password() {
        let mut c = Config::plain("127.0.0.1:6379");
        c.password = "hunter2-very-secret".into();
        c.server_name = "valkey.example.net".into();
        c.ca_file = "/etc/redsocket/ca.crt".into();
        for dbg in [
            format!("{c:?}"),
            format!("{c:#?}"),
            format!("{:?}", crate::protection::Source::Valkey(c.clone())),
        ] {
            assert!(!dbg.contains("hunter2-very-secret"), "{dbg}");
            assert!(dbg.contains("password: \"<redacted>\""), "{dbg}");
            for shown in [
                "addr: \"127.0.0.1:6379\"",
                "tls: ",
                "server_name: \"valkey.example.net\"",
                "ca_file: \"/etc/redsocket/ca.crt\"",
                "cert_file: ",
                "key_file: ",
            ] {
                assert!(dbg.contains(shown), "{dbg} lacks {shown}");
            }
        }
    }
}
