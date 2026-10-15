# redsocket_proteus

The RostamVPN exit server wrapped in [Proteus](https://github.com/unblockable/proteus)
programmable protocols. It is a strict superset of `redsocket_http`: the same
exit-node tunnel that hides inside plain HTTP on port 80 (a client performs an
ordinary HTTP Upgrade, then runs a Noise NK session over the upgraded socket and
asks the server to CONNECT to TCP destinations, or to relay UDP datagrams, on
its behalf), with the same optional modules for egress-IP pinning, destination
deny lists, exit-side domain/IP blocking from a signed bundle, mailbox messaging
to clients, load shedding, Prometheus metrics and telemetry stats into a Valkey
list. On top of that, any Proteus protocol specification file (PSF) can be put
in front of the carrier, on its own port or sharing port 80 with plain clients,
so the bytes on the wire look like whatever the PSF describes while the tunnel
inside is unchanged. This repository is intended to replace `redsocket_http`
once proven and expanded to more protocols.

## Wire protocol

1. Client sends `GET / HTTP/1.1` with `Upgrade: websocket` and
   `Connection: Upgrade`; the server answers `HTTP/1.1 101 Switching Protocols`.
   If `allowed_upgrade_hosts` is set, any other `Host:` gets a 404 instead.
2. The socket now carries `Noise_NK_25519_ChaChaPoly_BLAKE2s`. Every Noise
   message is framed as `[u16 BE len][ciphertext]`; the client already knows
   the server's static X25519 public key.
3. The first encrypted frame is either `META|tz|app|os|cid|sni|caps` (single
   stream, "v1") or `MUX2|tz|app|os|cid|sni|caps` (a yamux carrier). `caps` is a
   comma list such as `blk1,msg1`.
4. v1: the next frame is a SOCKS5-style CONNECT, `[0x05][atyp][addr][port]`,
   with no reply; the tunnel then relays bytes until either side closes.
5. MUX2: every yamux stream opens with the same CONNECT request and receives a
   10-byte reply `05 00 00 01 00 00 00 00 00 00` before relaying.
6. A MUX2 stream whose request is the 2-byte marker `0x05 0xFD` becomes a UDP
   association: after the 10-byte reply it carries `[u16 BE len][SOCKS5 UDP
   datagram]` in both directions, and `len == 0` closes it (`docs/udp-over-mux2.md`).
7. CONNECTs to the pseudo-host `_rs.<cmd>` are in-tunnel control calls.

With a Proteus carrier the whole exchange above runs inside the PSF's messages;
see "Proteus carrier".

## Build

    cargo build --release
    cargo test

All dependencies are vendored in `vendor/` and `.cargo/config.toml` points
cargo at them, so `cargo build --offline --release` works with no network.
Proteus itself is vendored in the tree at `third_party/proteus/` and used as a
path dependency outside the workspace; its `rust-toolchain.toml` applies only
when cargo is run from inside that directory, so a build from here uses the
default toolchain (the crate is edition 2024, so Rust 1.85 or newer).
Binaries: `redsocket-http` (the server), plus `client`, `mux_client`,
`legacy_client` and `flooder` test clients. Linux builds can select an
io_uring relay; other platforms always use the tokio relay.

## Keys

    redsocket-http --keygen

prints a fresh `private_key` / `public_key` pair (hex). Put both in the config;
clients need only the public key. `--config`, `--bind`, `--private-key` and
`--public-key` override the file at start-up.

## Configuration (`config.toml`)

Top level:

- `private_key` — server static X25519 private key, 64 hex chars (required).
- `public_key` — matching public key, 64 hex chars (required).
- `extra_private_keys` — older private keys still accepted during a rotation.
- `egress_ips` — pool of local source IPs; each cid is pinned to one by hash.
- `prefer_ipv6` — try a destination's AAAA before its A record.
- `deny_cidrs` — destination ranges refused before connecting (default: private,
  loopback, link-local and similar; set `[]` to disable).
- `allow_cidrs` — carve-outs checked before `deny_cidrs`.
- `[valkey]` — fallback stats connection if `[stats.valkey]` is absent (same keys).

`[http]`:

- `bind` — listen address, default `0.0.0.0:80`.
- `extra_binds` — additional listen addresses.
- `proxy_protocol` — `disabled`, `auto` or `required` PROXY protocol v1/v2 on accept.
- `socket_sndbuf` / `socket_rcvbuf` — accepted-socket buffer sizes; 0 keeps the kernel default.
- `allowed_upgrade_hosts` — `Host:` values that may receive a 101; empty allows any.
- `proteus_psf` — one PSF whose clients share `bind` and `extra_binds` with
  plain HTTP clients (same-port mode, see "Proteus carrier").
- `proteus_psfs` — the list form of the same; `proteus_psf`, if also set, comes first.

`[proteus]` (a dedicated Proteus-wrapped listener; absent by default):

- `bind` — listen address of the wrapped carrier.
- `psf` — path to the protocol specification file, compiled once at start-up;
  a PSF that does not compile stops the server, naming the file.
- `extra_binds` — additional listen addresses for the same PSF.

`[metrics]`:

- `bind` — Prometheus endpoint, default `127.0.0.1:9090`.
- `allow_public` — required before `bind` may be a non-loopback address.

`[stats]`:

- `cids` — emit cid and tunnel-closed rows (default `true`).
- `[stats.valkey]` — `addr`, `password`, `ca_file`, `server_name` of the stats
  instance; TLS is always on for this connection.

`[relay]`:

- `initial_buffer` — initial relay buffer size in bytes; 0 allocates the full
  64 KiB / 32 KiB up front, otherwise buffers grow on demand.
- `io_backend` — `epoll` (default) or `iouring` for the v1 relay loop (Linux only).

`[shed]`:

- `enabled` — refuse new tunnels with a 503 as memory runs out (default `true`).
- `high_pct` — percent of the memory limit at which refusing starts.
- `low_pct` — percent at which accepting resumes; must be below `high_pct`.
- `interval_secs` — seconds between memory samples (default 2).

`[protection]` (exit-side blocking, off by default):

- `enabled` — turn the module on.
- `pubkey` — Ed25519 public key (hex) that signs the bundle's `meta.json`.
- `brands` — META `app` values whose `blk1` tunnels are checked (default
  `["rostam"]`, the value the RostamVPN clients send).
- `allow_hosts` — names never judged: exact, or `*.suffix` (default
  `["rostam.app", "*.rostam.app", "*.cloudfront.net", "*.amazonaws.com"]`,
  the app's own control plane; set `[]` to judge everything).
- `block_bits` — bundle reason bits forced to block.
- `notify_bits` — bundle reason bits forced to notify only.
- `debug_log_destinations` — log destination host/port/client per block.
- `reload_secs` — bundle refresh interval (default 300; SIGHUP reloads at once).
- `bundle_dir` — load the bundle from a directory instead of Valkey.
- `[protection.valkey]` — where `protection:bundle` lives; absent uses `[messaging.valkey]`.

`[messaging]` (mailbox messages to `msg1` tunnels, off by default):

- `enabled` — turn the module on.
- `[messaging.valkey]` — the instance holding `msg:*`, `rules:*` and `cid:*`.

`[protection.valkey]` and `[messaging.valkey]` share one shape: `addr`, `tls`
(default `true`), `server_name`, `password`, `ca_file`, `cert_file`, `key_file`
(the last two together enable client-certificate auth).

## Proteus carrier

A PSF describes a wire protocol: message layouts, which fields carry the
length and the payload, fixed bytes, padding, an optional cipher, and who sends
what in which order. `src/proteus_carrier.rs` runs a Proteus interpreter on
each accepted socket and gives the HTTP handler the interpreter's application
side, an in-memory duplex that it treats exactly like a client socket:

```
TCP socket  ->  Proteus interpreter (server role, compiled once from the PSF)
            ->  in-memory duplex (64 KiB)
            ->  HTTP Upgrade request, 101 Switching Protocols
            ->  Noise NK handshake, META / MUX2, SOCKS-style CONNECT
            ->  relay to the destination (single stream or yamux MUX2)
```

When the tunnel ends the duplex is dropped, the interpreter sees EOF, flushes
and shuts the socket down; if it has not unwound after 30 s it is aborted.
Shedding, the 600 s per-connection budget, socket buffers and keepalives apply
as on `[http]`; the relay stays on tokio (the io_uring backend is not used
behind a PSF). The standalone client is the mirror image: `proteus_psf` in
`client.toml`, or `--proteus-psf <path>` on the command line, compiles the same
PSF in the client role and puts the interpreter on both of its connect paths
(single stream and MUX2). Both ends must use the same PSF; with
`proteus/shadowsocks.psf` both must also share the password written into their
copy, never the `REPLACE_WITH_PASSWORD` placeholder.

### Separate port

`[proteus]` binds its own listener; every connection on it goes through the
interpreter. The PSF is compiled at start-up, so a PSF that does not compile
stops the server with the path in the error.

```toml
[proteus]
bind = "0.0.0.0:443"
psf = "/etc/redsocket/proteus/tls_mimic.psf"
extra_binds = ["[::]:443"]
```

### Same port

`[http] proteus_psf` or `proteus_psfs` lets wrapped clients share the HTTP
listener (and every `extra_binds`) with plain clients. After the PROXY-protocol
step the server peeks at a connection's first bytes, consuming nothing, for at
most the usual 5 s header deadline, and routes:

- a request line `METHOD /path HTTP/1.` with METHOD one of GET, POST, PUT,
  HEAD, OPTIONS or CONNECT goes to the HTTP handler unchanged — RedSocket
  clients get their 101, anything else the 404 decoy, as before;
- otherwise the bytes are matched against the fixed opening bytes of the
  configured PSFs, longest first; for `tls_mimic.psf` that is its 166-byte
  ClientHello;
- otherwise the one PSF whose first client message has no fixed opening (the
  default, e.g. `shadowsocks.psf`) takes the connection; with no default it is
  closed.

```toml
[http]
bind = "0.0.0.0:80"
proteus_psfs = ["/etc/redsocket/proteus/tls_mimic.psf", "/etc/redsocket/proteus/shadowsocks.psf"]
```

Every PSF is compiled at start-up and the log line `proteus shared:` names
each with `(prefix N bytes)` or `(default)`. `[proteus]` and the same-port keys
can be combined. Limits of the same-port mode, by design:

- there is no version byte or other marker; dispatch relies on what a PSF's
  first client message looks like;
- two PSFs whose first client bytes are not fixed (random, encrypted,
  length-prefixed) cannot be told apart, so the server refuses to start with
  more than one such PSF in the list;
- a fixed opening that is itself a valid HTTP request line is routed as HTTP;
- non-HTTP bytes that no PSF claims go to the default PSF, which fails inside
  the interpreter and closes, or are closed outright, instead of the 400/404 a
  plain listener answers;
- a peer that sends an HTTP-looking fragment and then stalls is handed to the
  HTTP handler at the peek deadline, so its 400 can take up to 10 s instead of 5.

### Experimental status

Proteus's own README says: "Proteus is experimental and not recommended for
security-critical applications." Treat the PSF layer as shaping and
obfuscation only. Confidentiality and server authentication come from the Noise
NK session that still runs inside the carrier: the client knows the server's
static X25519 key and every tunnel frame is encrypted and authenticated there,
whatever the PSF does on the outside. The password in `shadowsocks.psf` keys
the outer frames only.

### Writing or choosing a PSF

Two PSFs ship in `proteus/`:

- `tls_mimic.psf` — a fixed 166-byte ClientHello, a fixed 746-byte ServerHello,
  then `17 03 03 | u16 length | payload` records. No encryption of its own. Its
  fixed first message makes it dispatchable on a shared port.
- `shadowsocks.psf` — `u16 length | 16-byte tag | payload | 16-byte tag`, all
  ChaCha20-Poly1305 under a key derived from `PASSWORD`. Nothing fixed on the
  wire, so on a shared port it can only be the default.

A PSF has four segments: `@SEGMENT.FORMATS` (message layouts),
`@SEGMENT.SEMANTICS` (which field is the length, the payload, fixed bytes,
padding or a public key), `@SEGMENT.SEQUENCE` (who sends which format in the
HANDSHAKE and DATA phases) and, optionally, `@SEGMENT.CRYPTO` (password,
cipher, which fields are encrypted). The upstream examples are in
`third_party/proteus/tests/fixtures/` and the grammar is
`third_party/proteus/src/lang/compiler/proteus_lite.pest`. For your own: keep
one length field and one payload field per data message, keep the length a
`u16` so a 64 KiB relay chunk fits, and give the first client message a
`FIXED_BYTES` or `FIXED_STRING` first field if the PSF is meant for a shared
port. The server validates a PSF at start-up and refuses one that does not
compile, naming the file.

### End-to-end script

```
./scripts/proteus-e2e.sh
```

builds the debug `redsocket-http` and `client` binaries and runs the whole
stack on loopback: a small HTTP origin, the server with `[http]` on 18080 and
`[proteus]` on 18443, and `curl` through the client's SOCKS5 port. For
`tls_mimic.psf` and `shadowsocks.psf` (with a random password patched into a
temporary copy) it proves that the origin file comes back through the Proteus
carrier on both the single-stream and the MUX2 path, that a clear-text HTTP
Upgrade to the Proteus port never gets a 101 while the same request to the
HTTP port does, and, for `tls_mimic`, that the fixed ClientHello is answered
with the fixed ServerHello. It then restarts the server with both PSFs on the
HTTP port alone and proves that a plain, a tls_mimic and a shadowsocks client
all work on that one port, that a GET without Upgrade still gets the 404 decoy
and that a clear-text Upgrade still gets 101. `ORIGIN_PORT`, `HTTP_PORT`,
`PROTEUS_PORT`, `METRICS_PORT` and `SOCKS_PORT` override the ports; the script
refuses to start on a port already in use and kills every process it started
on exit.

### Vendored Proteus

`third_party/proteus/` is upstream commit `75ba9f4`, copied without `.git`,
`.github` and `assets`, with three edits so the crate can be used as a
library: `src/lib.rs` was added (`pub mod cli; pub mod crypto; pub mod lang;
pub mod net; pub mod util;`), `src/main.rs` was reduced to a call into
`proteus::cli::run`, and `src/lang/mod.rs` exports `pub mod types` so the
server can read a parsed PSF's field semantics to find same-port dispatch
prefixes. Nothing else was touched; its own `LICENSE`, `README.md`,
`rust-toolchain.toml` and tests are as upstream.

## Telemetry stats

With a stats connection configured and `stats.cids = true`, the server batches
rows and sends them with `RPUSH` over TLS to two Valkey lists:

- `stats:cid` — one TSV row per tunnel open:
  `timestamp  real_ip  cid  tz  app  os  sni  tunnel  hostname`
  (`timestamp` is UTC RFC 3339; tabs and newlines inside fields become spaces).
- `stats:tunnel-closed` — one TSV usage row per tunnel close:
  `now_ts  cid  start_ts  duration_secs  bytes_up  bytes_down  hostname`
  (Unix seconds and byte counts in both directions).

Rows are dropped, and counted in metrics, if the queue backs up or the stats
instance is unreachable; the tunnel itself is never delayed by the stats.

## Tests

`cargo test` runs the unit tests, including the same-port classifier and the
`[proteus]` / `proteus_psfs` config keys, and six end-to-end tests. Each e2e
test is its own binary because the protection module is initialised once per
process; the shared harness (in-process server, MUX2 client, echo target and a
RESP2 fake of Valkey) lives in `tests/harness/`. The Proteus carrier is proven
with the real binaries by `scripts/proteus-e2e.sh` (see above).

## License

The code in this repository is Apache-2.0; see `LICENSE` and the SPDX headers
in each source file. The vendored Proteus crate in `third_party/proteus/` is
used under its own license, reproduced verbatim as `PROTEUS-LICENSE` at the
repository root (and as `third_party/proteus/LICENSE`). Its first paragraph
reads:

> To the extent that a federal employee is an author of a portion of
> this software or a derivative work thereof, no copyright is claimed by
> the United States Government, as represented by the Secretary of the
> Navy ("GOVERNMENT") under Title 17, U.S. Code. All Other Rights 
> Reserved.

The other vendored dependencies in `vendor/` keep their own license files.

## Related repositories

| Repository | Contents |
|---|---|
| `redsocket_http` | The exit server this repository extends (Rust). |
| `rostamvpn-android` | The Android app, the shared Rust client core (`redsocket-http-core/`) and the WireGuard-over-TCP core. |
| `rostamvpn-ios` | The iOS app and its Network Extension; its core frameworks are built from the cores in `rostamvpn-android`. |
| `redsocket_pfe` | AF_XDP triangle-routing front-end. |
| `redsocket_wgtcp` | The userspace WireGuard-over-TCP client library and tools; vendored into `rostamvpn-android` for the Android core. |

## Removed for publication

Deployment and infrastructure documents, exporter scripts, release artifacts,
signing material and API keys (replaced by `REPLACE_WITH_*` placeholders),
server telemetry other than the cid stats, other brands, narrative comments,
and dead code. All third-party dependencies are vendored in the tree and keep
their own license files.
