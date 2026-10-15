#!/usr/bin/env bash
# Copyright 2026 Internet Mastering & Company, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HERE/target}"
ORIGIN_PORT="${ORIGIN_PORT:-18999}"
PROTEUS_PORT="${PROTEUS_PORT:-18443}"
METRICS_PORT="${METRICS_PORT:-19090}"
SOCKS_PORT="${SOCKS_PORT:-11080}"

TMP="$(mktemp -d)"
PIDS=()
FAILED=0

cleanup() {
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

port_open() {
    python3 -I -c "import socket,sys; s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$1))==0 else 1)"
}

wait_port() {
    local port=$1 i
    for i in $(seq 1 100); do
        port_open "$port" && return 0
        sleep 0.1
    done
    echo "port $port never opened"; return 1
}

for port in "$ORIGIN_PORT" "$PROTEUS_PORT" "$METRICS_PORT" "$SOCKS_PORT"; do
    if port_open "$port"; then
        echo "port $port is already in use; override ORIGIN_PORT/PROTEUS_PORT/METRICS_PORT/SOCKS_PORT"
        exit 2
    fi
done

(cd "$HERE" && cargo build --offline --bin redsocket-http --bin client)
SERVER="$CARGO_TARGET_DIR/debug/redsocket-http"
CLIENT="$CARGO_TARGET_DIR/debug/client"

mkdir -p "$TMP/www"
CONTENT="proteus-e2e-ok-$RANDOM$RANDOM"
echo "$CONTENT" > "$TMP/www/hello.txt"
(cd "$TMP/www" && exec python3 -I -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 >"$TMP/origin.log" 2>&1) &
PIDS+=($!)
wait_port "$ORIGIN_PORT"

"$SERVER" --keygen > "$TMP/keys"
PRIV=$(sed -n 's/^private_key = "\(.*\)"/\1/p' "$TMP/keys")
PUB=$(sed -n 's/^public_key  *= "\(.*\)"/\1/p' "$TMP/keys")

PASSWORD="e2e-$RANDOM$RANDOM"
TLS_PSF="$HERE/proteus/tls_mimic.psf"
SS_PSF="$TMP/shadowsocks.psf"
sed "s/REPLACE_WITH_PASSWORD/$PASSWORD/" "$HERE/proteus/shadowsocks.psf" > "$SS_PSF"

echo "=== server: tls_mimic.psf + shadowsocks.psf on :$PROTEUS_PORT ==="
cat > "$TMP/server.toml" <<EOT
private_key = "$PRIV"
public_key = "$PUB"
deny_cidrs = []

[proteus]
bind = "127.0.0.1:$PROTEUS_PORT"
psfs = ["$TLS_PSF", "$SS_PSF"]

[metrics]
bind = "127.0.0.1:$METRICS_PORT"

[shed]
enabled = false
EOT
RUST_LOG=info "$SERVER" --config "$TMP/server.toml" >"$TMP/server.log" 2>&1 &
SERVER_PID=$!
PIDS+=($SERVER_PID)
wait_port "$PROTEUS_PORT"
grep -m1 "proteus psfs" "$TMP/server.log" || true

run_client() {
    local psf=$1 mux=$2
    cat > "$TMP/client.toml" <<EOT
server = "127.0.0.1:$PROTEUS_PORT"
pubkey = "$PUB"
listen = $SOCKS_PORT
proteus_psf = "$psf"
mux = $mux
EOT
    RUST_LOG=info "$CLIENT" --config "$TMP/client.toml" >"$TMP/client-$(basename "$psf")-$mux.log" 2>&1 &
    CLIENT_PID=$!
    PIDS+=($CLIENT_PID)
    wait_port "$SOCKS_PORT"
}

stop_client() {
    kill "$CLIENT_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
}

fetch_via_socks() {
    curl -sS --max-time 15 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
        "http://127.0.0.1:$ORIGIN_PORT/hello.txt" || true
}

for PSF in "$TLS_PSF" "$SS_PSF"; do
    NAME=$(basename "$PSF")
    for MUX in false true; do
        run_client "$PSF" "$MUX"
        GOT=$(fetch_via_socks)
        echo "curl ($NAME mux=$MUX): $GOT"
        if [ "$GOT" = "$CONTENT" ]; then
            pass "$NAME mux=$MUX relayed the origin file through the Proteus carrier"
        else
            fail "$NAME mux=$MUX expected '$CONTENT'"
            cat "$TMP/client-$NAME-$MUX.log"
        fi
        stop_client
    done
done

# Send $2 to the Proteus port and print the first response line, or what
# happened instead of one.
probe() {
    python3 -I - "$PROTEUS_PORT" "$1" <<'EOT'
import os, socket, sys
port, kind = int(sys.argv[1]), sys.argv[2]
if kind == "get":
    data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
elif kind == "upgrade":
    data = b"GET /noise HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
else:
    data = os.urandom(70000)
s = socket.create_connection(("127.0.0.1", port), timeout=3)
try:
    s.sendall(data)
    got = s.recv(4096)
except socket.timeout:
    print("<silence: no bytes within 3s>")
except OSError as e:
    print("<connection reset: %s>" % e.strerror)
else:
    print(got.split(b"\r\n", 1)[0].decode("latin1") if got else "<connection closed>")
EOT
}

for KIND in get upgrade; do
    GOT=$(probe "$KIND")
    echo "clear-text $KIND to :$PROTEUS_PORT -> $GOT"
    case "$GOT" in
        "HTTP/1.1 101"*) fail "clear-text $KIND got a 101" ;;
        "HTTP/1.1 404"*) fail "clear-text $KIND got the 404 decoy" ;;
        "<silence"*) pass "clear-text $KIND gets neither 101 nor 404: silence (held by the default PSF's interpreter until the 600 s cap)" ;;
        "<connection"*) pass "clear-text $KIND gets neither 101 nor 404: the connection was closed" ;;
        *) fail "clear-text $KIND got unexpected bytes: $GOT" ;;
    esac
done

HELLO=$(python3 -I - "$TLS_PSF" "$PROTEUS_PORT" <<'EOT'
import re, socket, sys
psf = open(sys.argv[1]).read()
def fixed(fmt):
    m = re.search(r"FORMAT: %s; FIELD: fixed;\s*SEMANTIC:\s*FIXED_BYTES\(0x([0-9a-fA-F]+)\)" % fmt, psf)
    return bytes.fromhex(m.group(1))
ch, sh = fixed("ClientHello"), fixed("ServerHello")
s = socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=5)
s.sendall(ch)
got = b""
while len(got) < len(sh):
    chunk = s.recv(len(sh) - len(got))
    if not chunk:
        break
    got += chunk
print("sent ClientHello %d bytes, received %d bytes, matches fixed ServerHello: %s"
      % (len(ch), len(got), got == sh))
EOT
)
echo "$HELLO"
case "$HELLO" in
    "sent ClientHello 166 bytes, received 746 bytes, matches fixed ServerHello: True")
        pass "the fixed ClientHello is answered with the fixed ServerHello" ;;
    *) fail "tls_mimic fixed handshake bytes" ;;
esac

GOT=$(probe garbage)
echo "70000 random bytes to :$PROTEUS_PORT -> $GOT"
case "$GOT" in
    "<connection"*) pass "garbage bytes get the connection closed ($GOT)" ;;
    *) fail "garbage bytes should get the connection closed, got: $GOT" ;;
esac

curl -sS --max-time 5 "http://127.0.0.1:$METRICS_PORT/metrics" | grep "^redsocket_hs_\|^redsocket_total_tunnels" || true

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

if [ "$FAILED" -ne 0 ]; then
    echo "e2e: FAILED"
    exit 1
fi
echo "e2e: all checks passed"
