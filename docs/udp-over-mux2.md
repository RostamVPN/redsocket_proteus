# UDP over MUX2 — the spec the clients implement

Server side is done and deployed-ready (`src/mux.rs`, `src/proxy.rs`). This is
what a client must do to use it. The reference implementation is
`src/bin/client.rs` (`handle_socks_udp`, `open_mux_udp`) — it is a working
SOCKS5 proxy, not pseudocode.

## Why

QUIC/HTTP-3 is UDP. The tunnel carried TCP only, so every QUIC attempt failed
and the app fell back to TCP — silently and slowly, because the local SOCKS5
server closed the connection instead of refusing it, costing the app a connect
timeout per flow.

## Wire format

Inside an established MUX2 (yamux) carrier, a stream is opened exactly as for a
CONNECT, but the request is a fixed 2-byte marker:

    client → server:  [u16 BE len = 2][0x05][0xFD]
    server → client:  [0x05 0x00 0x00 0x01 0 0 0 0 0 0]     (the usual 10-byte OK)

After the OK, that stream carries datagrams in **both** directions as:

    [u16 BE len][SOCKS5 UDP datagram]

where the SOCKS5 UDP datagram is RFC 1928 §7 verbatim — `[RSV RSV][FRAG][ATYP]
[ADDR][PORT][payload]`. `len` covers header + payload. Client→server the header
names the **destination**; server→client it names the **source** the datagram
came from (ATYP 1 or 4, never a name).

**`len == 0` is the CLOSE marker, not a datagram.** The server breaks its
read loop on it (`src/mux.rs`, `relay_udp`), so a client must never forward an
empty datagram upstream — an app sending one (legal UDP, and meaningless here,
since RFC 1928 wants a 10-byte header at minimum) would tear down its own
association. Drop it client-side, the way any UDP relay drops a datagram it
cannot parse. This rule was implicit in the server code and cost the Android
client a real bug before it was written down: the symptom is a QUIC flow that
dies for no visible reason, and it looks exactly like a POP without UDP support.

The client does not parse the datagram at all: it forwards what the app sent,
and hands back what the server sent. The header the app already built is the
addressing.

`0xFD` is not a valid ATYP and the request is shorter than any CONNECT, so a
server without this patch fails to parse it and closes the stream **without a
reply**. That closure is the capability probe — see "Fallback" below.

## What the server guarantees

- One unconnected UDP socket per association, so one association reaches any
  number of destinations. Bound to the cid's sticky egress IP, same as TCP.
- Each target is resolved **once** and pinned for the life of the association.
  Domain ATYP is fine and preferred — it keeps passive-DNS analytics and the on-device
  blocklist working on real names.
- The association ends when the stream ends. Closing the stream is the whole
  teardown; there is nothing else to send.
- 120 s idle cut-off measured on the downlink. A flow with no inbound traffic
  for two minutes is closed and the close reaches the app.
- FRAG ≠ 0, malformed headers, and unresolvable targets are dropped
  individually; the association survives.
- Datagrams up to 9 KiB pass without loss. Larger ones cost one dropped
  datagram while the buffer grows (ordinary UDP loss; QUIC never sees it).
- UDP bytes are metered exactly like TCP bytes.

## What the client must do

1. App sends SOCKS5 CMD `0x03` (UDP ASSOCIATE). Parse and **discard** the
   DST.ADDR/PORT it carries — it is not the destination, and apps send zeros.
2. Bind a local UDP socket on `127.0.0.1:0`.
3. Open the association stream (marker above) and wait for the 10-byte OK.
4. Reply to the app: `05 00 00 01 7f 00 00 01 <BND.PORT u16 BE>`.
5. Learn the app's UDP source from its first datagram, then `connect()` the
   local socket to it. One association per app socket is what RFC 1928 means.
6. Relay: local datagram → `[u16 len][datagram]` on the stream; stream frame →
   local socket, payload verbatim.
7. **The association lives exactly as long as the app's TCP control
   connection.** Read that TCP socket; `0` bytes means tear everything down.
   Also stop when the stream ends (server-side idle or shutdown).

## Fallback — this part is not optional

If the stream closes before the 10-byte OK, the server does not support UDP.
Answer the app `05 07 00 01 00 00 00 00 00 00` (X'07', command not supported).
That is what makes QUIC fall back to TCP immediately rather than on a timeout.
Never just close the socket: hev reconnects hard against a silent close, which
is what made the app OOM before.

**Do not reuse a CONNECT helper that replaces the carrier when stream setup
fails.** A tun opens one association per QUIC flow; against an older POP that
turns every QUIC attempt into a mass reset of the user's working TCP streams.
Measured in this repo: 0/3 live streams survived with the retrying helper, 3/3
with a plain open. See `open_mux_udp` vs `open_mux_target` in
`src/bin/client.rs`.

## Old clients

Nothing here changes the CONNECT path, the 10-byte reply, the `_rs` control
channel or the v1 (non-MUX2) path. A client that never sends the marker cannot
tell the difference: the `legacy_client`/`mux_client` fixtures exercise the
new server across v1 and MUX2, domain, IPv4 and IPv6 forms.

One thing does change for an old client: **IPv6 CONNECT starts working.** The
parser demanded 22 bytes for a 20-byte form, so ATYP 4 was refused for every
client that ever tried it. Sharing the address parser with the UDP header fixed
the bound.

## Scope

MUX2 only. A non-muxed carrier still declines UDP with X'07' and falls back to
TCP — by design. UDP therefore rides on whatever gates MUX2 in the OTA config.

## Verifying

Echo-server tests are not enough: drive a real QUIC version-negotiation
exchange against a public HTTP/3 host through the tunnel before calling a
client implementation done.
