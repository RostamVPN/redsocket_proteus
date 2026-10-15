// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! An in-process RESP2 fake of valkey-main: just the commands the exit uses
//! (strings, hashes, one stream, Pub/Sub, blocking XREAD). The store is shared
//! with the test so it can seed mailboxes and publish wakes.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

/// One stream entry: `(id number, fields)`; ids are rendered `<n>-0`.
pub type Entry = (u64, Vec<(String, String)>);

#[derive(Default)]
pub struct Store {
    pub strings: HashMap<String, String>,
    pub hashes: HashMap<String, BTreeMap<String, String>>,
    pub streams: HashMap<String, Vec<Entry>>,
    next_stream_id: u64,
    pub commands: Vec<String>,
}

pub struct FakeValkey {
    pub addr: String,
    pub store: Arc<Mutex<Store>>,
    pub published: broadcast::Sender<(String, String)>,
}

impl FakeValkey {
    pub async fn start() -> FakeValkey {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let store = Arc::new(Mutex::new(Store::default()));
        let (published, _) = broadcast::channel::<(String, String)>(256);
        let st = store.clone();
        let pb = published.clone();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = l.accept().await else {
                    break;
                };
                let st = st.clone();
                let pb = pb.clone();
                tokio::spawn(async move {
                    let _ = serve(sock, st, pb).await;
                });
            }
        });
        FakeValkey {
            addr,
            store,
            published,
        }
    }

    pub fn hset(&self, key: &str, field: &str, value: &str) {
        self.store
            .lock()
            .unwrap()
            .hashes
            .entry(key.to_string())
            .or_default()
            .insert(field.to_string(), value.to_string());
    }
    pub fn hget(&self, key: &str, field: &str) -> Option<String> {
        self.store
            .lock()
            .unwrap()
            .hashes
            .get(key)
            .and_then(|h| h.get(field).cloned())
    }
    pub fn set(&self, key: &str, value: &str) {
        self.store
            .lock()
            .unwrap()
            .strings
            .insert(key.to_string(), value.to_string());
    }
    pub fn get(&self, key: &str) -> Option<String> {
        self.store.lock().unwrap().strings.get(key).cloned()
    }
    /// A mailbox entry in the schema's shape.
    pub fn mailbox_put(
        &self,
        key: &str,
        seq: u64,
        ts: u64,
        kind: &str,
        payload: serde_json::Value,
    ) {
        let json = serde_json::json!({"seq": seq, "ts": ts, "type": kind, "payload": payload});
        self.hset(key, &format!("{seq:010}"), &json.to_string());
    }
    pub fn publish(&self, channel: &str, payload: &str) {
        let _ = self
            .published
            .send((channel.to_string(), payload.to_string()));
    }
    pub fn xadd(&self, key: &str, fields: &[(&str, &str)]) -> String {
        let mut st = self.store.lock().unwrap();
        st.next_stream_id += 1;
        let id = st.next_stream_id;
        st.streams.entry(key.to_string()).or_default().push((
            id,
            fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ));
        format!("{id}-0")
    }
    pub fn commands(&self) -> Vec<String> {
        self.store.lock().unwrap().commands.clone()
    }
}

fn bulk(s: &[u8]) -> Vec<u8> {
    let mut v = format!("${}\r\n", s.len()).into_bytes();
    v.extend_from_slice(s);
    v.extend_from_slice(b"\r\n");
    v
}
fn arr(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut v = format!("*{}\r\n", items.len()).into_bytes();
    for i in items {
        v.extend_from_slice(&i);
    }
    v
}
fn int(i: i64) -> Vec<u8> {
    format!(":{i}\r\n").into_bytes()
}
const OK: &[u8] = b"+OK\r\n";
const NIL: &[u8] = b"$-1\r\n";

async fn read_command<R: AsyncBufReadExt + AsyncReadExt + Unpin>(r: &mut R) -> Option<Vec<String>> {
    let mut line = String::new();
    if r.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let n: usize = line.trim().strip_prefix('*')?.parse().ok()?;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        line.clear();
        r.read_line(&mut line).await.ok()?;
        let len: usize = line.trim().strip_prefix('$')?.parse().ok()?;
        let mut buf = vec![0u8; len + 2];
        r.read_exact(&mut buf).await.ok()?;
        buf.truncate(len);
        out.push(String::from_utf8_lossy(&buf).into_owned());
    }
    Some(out)
}

fn parse_id(s: &str) -> u64 {
    s.split('-')
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

async fn serve(
    sock: tokio::net::TcpStream,
    store: Arc<Mutex<Store>>,
    published: broadcast::Sender<(String, String)>,
) -> std::io::Result<()> {
    let (r, mut w) = sock.into_split();
    let mut r = BufReader::new(r);
    loop {
        let Some(cmd) = read_command(&mut r).await else {
            return Ok(());
        };
        let name = cmd[0].to_ascii_uppercase();
        store.lock().unwrap().commands.push(cmd.join(" "));
        let reply: Vec<u8> = match name.as_str() {
            "AUTH" | "PING" => OK.to_vec(),
            "GET" => match store.lock().unwrap().strings.get(&cmd[1]) {
                Some(v) => bulk(v.as_bytes()),
                None => NIL.to_vec(),
            },
            "SET" => {
                store
                    .lock()
                    .unwrap()
                    .strings
                    .insert(cmd[1].clone(), cmd[2].clone());
                OK.to_vec()
            }
            "INCR" => {
                let mut st = store.lock().unwrap();
                let v: i64 = st
                    .strings
                    .get(&cmd[1])
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0)
                    + 1;
                st.strings.insert(cmd[1].clone(), v.to_string());
                int(v)
            }
            "EXPIRE" => int(1),
            "HDEL" => {
                let mut st = store.lock().unwrap();
                let n = st
                    .hashes
                    .get_mut(&cmd[1])
                    .map(|h| cmd[2..].iter().filter(|f| h.remove(*f).is_some()).count())
                    .unwrap_or(0);
                int(n as i64)
            }
            "HGET" => match store
                .lock()
                .unwrap()
                .hashes
                .get(&cmd[1])
                .and_then(|h| h.get(&cmd[2]))
            {
                Some(v) => bulk(v.as_bytes()),
                None => NIL.to_vec(),
            },
            "HMGET" => {
                let st = store.lock().unwrap();
                let h = st.hashes.get(&cmd[1]);
                arr(cmd[2..]
                    .iter()
                    .map(|f| match h.and_then(|h| h.get(f)) {
                        Some(v) => bulk(v.as_bytes()),
                        None => NIL.to_vec(),
                    })
                    .collect())
            }
            "HGETALL" => {
                let st = store.lock().unwrap();
                let mut items = Vec::new();
                if let Some(h) = st.hashes.get(&cmd[1]) {
                    for (k, v) in h {
                        items.push(bulk(k.as_bytes()));
                        items.push(bulk(v.as_bytes()));
                    }
                }
                arr(items)
            }
            "HSET" => {
                let mut st = store.lock().unwrap();
                let h = st.hashes.entry(cmd[1].clone()).or_default();
                let mut n = 0;
                for kv in cmd[2..].chunks_exact(2) {
                    if h.insert(kv[0].clone(), kv[1].clone()).is_none() {
                        n += 1;
                    }
                }
                int(n)
            }
            "PUBLISH" => {
                let n = published
                    .send((cmd[1].clone(), cmd[2].clone()))
                    .unwrap_or(0);
                int(n as i64)
            }
            "SUBSCRIBE" => {
                w.write_all(&arr(vec![
                    bulk(b"subscribe"),
                    bulk(cmd[1].as_bytes()),
                    int(1),
                ]))
                .await?;
                let mut rx = published.subscribe();
                loop {
                    tokio::select! {
                        msg = rx.recv() => {
                            let Ok((ch, payload)) = msg else { continue };
                            if ch == cmd[1] {
                                w.write_all(&arr(vec![bulk(b"message"), bulk(ch.as_bytes()), bulk(payload.as_bytes())])).await?;
                            }
                        }
                        c = read_command(&mut r) => {
                            match c {
                                None => return Ok(()),
                                Some(c) if c[0].eq_ignore_ascii_case("PING") => {
                                    w.write_all(&arr(vec![bulk(b"pong"), bulk(b"")])).await?;
                                }
                                Some(_) => {}
                            }
                        }
                    }
                }
            }
            "XADD" => {
                let mut st = store.lock().unwrap();
                st.next_stream_id += 1;
                let id = st.next_stream_id;
                let fields: Vec<(String, String)> = cmd[3..]
                    .chunks_exact(2)
                    .map(|kv| (kv[0].clone(), kv[1].clone()))
                    .collect();
                st.streams
                    .entry(cmd[1].clone())
                    .or_default()
                    .push((id, fields));
                bulk(format!("{id}-0").as_bytes())
            }
            "XREVRANGE" => {
                let st = store.lock().unwrap();
                match st.streams.get(&cmd[1]).and_then(|s| s.last()) {
                    Some((id, fields)) => arr(vec![arr(vec![
                        bulk(format!("{id}-0").as_bytes()),
                        arr(fields
                            .iter()
                            .flat_map(|(k, v)| [bulk(k.as_bytes()), bulk(v.as_bytes())])
                            .collect()),
                    ])]),
                    None => arr(vec![]),
                }
            }
            "XREAD" => {
                let block_ms: u64 = cmd[2].parse().unwrap_or(0);
                let key = cmd[4].clone();
                let after = parse_id(&cmd[5]);
                let deadline =
                    tokio::time::Instant::now() + std::time::Duration::from_millis(block_ms);
                loop {
                    let entries: Vec<Entry> = store
                        .lock()
                        .unwrap()
                        .streams
                        .get(&key)
                        .map(|s| s.iter().filter(|(id, _)| *id > after).cloned().collect())
                        .unwrap_or_default();
                    if !entries.is_empty() {
                        break arr(vec![arr(vec![
                            bulk(key.as_bytes()),
                            arr(entries
                                .iter()
                                .map(|(id, fields)| {
                                    arr(vec![
                                        bulk(format!("{id}-0").as_bytes()),
                                        arr(fields
                                            .iter()
                                            .flat_map(|(k, v)| {
                                                [bulk(k.as_bytes()), bulk(v.as_bytes())]
                                            })
                                            .collect()),
                                    ])
                                })
                                .collect()),
                        ])]);
                    }
                    if tokio::time::Instant::now() >= deadline {
                        break b"*-1\r\n".to_vec();
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
            other => format!("-ERR unknown command '{other}'\r\n").into_bytes(),
        };
        w.write_all(&reply).await?;
    }
}
