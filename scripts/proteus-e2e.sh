#!/usr/bin/env bash
# Copyright 2026 Internet Mastering & Company, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${CARGO_TARGET_DIR:-$HERE/target}"
ORIGIN_PORT="${ORIGIN_PORT:-18999}"
HTTP_PORT="${HTTP_PORT:-18080}"
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

for port in "$ORIGIN_PORT" "$HTTP_PORT" "$PROTEUS_PORT" "$METRICS_PORT" "$SOCKS_PORT"; do
    if port_open "$port"; then
        echo "port $port is already in use; override ORIGIN_PORT/HTTP_PORT/PROTEUS_PORT/METRICS_PORT/SOCKS_PORT"
        exit 2
    fi
done

(cd "$HERE" && cargo build --bin redsocket-http --bin client)
SERVER="$TARGET/debug/redsocket-http"
CLIENT="$TARGET/debug/client"

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
sed "s/REPLACE_WITH_PASSWORD/$PASSWORD/" "$HERE/proteus/shadowsocks.psf" > "$TMP/shadowsocks.psf"

run_client() {
    local server_port=$1 mux=$2 psf=${3:-}
    local flags=()
    [ -n "$psf" ] && flags=(--proteus-psf "$psf")
    cat > "$TMP/client.toml" <<EOT
server = "127.0.0.1:$server_port"
pubkey = "$PUB"
listen = $SOCKS_PORT
host = "example.com"
mux = $mux
EOT
    RUST_LOG=info "$CLIENT" --config "$TMP/client.toml" "${flags[@]}" \
        >"$TMP/client-$mux.log" 2>&1 &
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

probe_upgrade() {
    python3 -I - "$1" "${2:-upgrade}" <<'EOT'
import socket, sys
port = int(sys.argv[1])
if sys.argv[2] == "plain":
    req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
else:
    req = b"GET /noise HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
s = socket.create_connection(("127.0.0.1", port), timeout=3)
s.sendall(req)
try:
    data = s.recv(4096)
except socket.timeout:
    print("<no response within 3s>")
except OSError as e:
    print("<connection reset: %s>" % e.strerror)
else:
    print(data.split(b"\r\n", 1)[0].decode("latin1") if data else "<connection closed>")
EOT
}

for PSF in "$HERE/proteus/tls_mimic.psf" "$TMP/shadowsocks.psf"; do
    NAME=$(basename "$PSF")
    echo "=== $NAME ==="
    cat > "$TMP/server.toml" <<EOT
private_key = "$PRIV"
public_key = "$PUB"
deny_cidrs = []

[http]
bind = "127.0.0.1:$HTTP_PORT"

[proteus]
bind = "127.0.0.1:$PROTEUS_PORT"
psf = "$PSF"

[metrics]
bind = "127.0.0.1:$METRICS_PORT"

[shed]
enabled = false
EOT
    RUST_LOG=info "$SERVER" --config "$TMP/server.toml" >"$TMP/server-$NAME.log" 2>&1 &
    SERVER_PID=$!
    PIDS+=($SERVER_PID)
    wait_port "$HTTP_PORT"
    wait_port "$PROTEUS_PORT"
    grep -m1 "PROTEUS" "$TMP/server-$NAME.log" || true

    for MUX in false true; do
        run_client "$PROTEUS_PORT" "$MUX" "$PSF"
        GOT=$(fetch_via_socks)
        echo "curl (mux=$MUX): $GOT"
        if [ "$GOT" = "$CONTENT" ]; then
            pass "$NAME mux=$MUX relayed the origin file through the Proteus carrier"
        else
            fail "$NAME mux=$MUX expected '$CONTENT'"
            cat "$TMP/client-$MUX.log"
        fi
        stop_client
    done

    PLAIN=$(probe_upgrade "$HTTP_PORT")
    echo "clear-text Upgrade to :$HTTP_PORT -> $PLAIN"
    case "$PLAIN" in
        "HTTP/1.1 101"*) pass "plain HTTP port answers 101" ;;
        *) fail "plain HTTP port should answer 101" ;;
    esac
    WRAPPED=$(probe_upgrade "$PROTEUS_PORT")
    echo "clear-text Upgrade to :$PROTEUS_PORT -> $WRAPPED"
    case "$WRAPPED" in
        "HTTP/1.1 101"*) fail "$NAME port must not answer a clear-text Upgrade with 101" ;;
        *) pass "$NAME port does not answer a clear-text Upgrade with 101" ;;
    esac

    if [ "$NAME" = "tls_mimic.psf" ]; then
        HELLO=$(python3 -I - "$PSF" "$PROTEUS_PORT" <<'EOT'
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
                pass "tls_mimic fixed handshake bytes" ;;
            *) fail "tls_mimic fixed handshake bytes" ;;
        esac
    fi

    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
done

echo "=== same port: plain + tls_mimic.psf + shadowsocks.psf on :$HTTP_PORT ==="
cat > "$TMP/server.toml" <<EOT
private_key = "$PRIV"
public_key = "$PUB"
deny_cidrs = []

[http]
bind = "127.0.0.1:$HTTP_PORT"
proteus_psfs = ["$HERE/proteus/tls_mimic.psf", "$TMP/shadowsocks.psf"]

[metrics]
bind = "127.0.0.1:$METRICS_PORT"

[shed]
enabled = false
EOT
RUST_LOG=info "$SERVER" --config "$TMP/server.toml" >"$TMP/server-same-port.log" 2>&1 &
SERVER_PID=$!
PIDS+=($SERVER_PID)
wait_port "$HTTP_PORT"
grep -m1 "proteus shared" "$TMP/server-same-port.log" || true

for CASE in "plain:" "tls_mimic:$HERE/proteus/tls_mimic.psf" "shadowsocks:$TMP/shadowsocks.psf"; do
    LABEL=${CASE%%:*}
    PSF=${CASE#*:}
    run_client "$HTTP_PORT" false "$PSF"
    GOT=$(fetch_via_socks)
    echo "curl ($LABEL client on :$HTTP_PORT): $GOT"
    if [ "$GOT" = "$CONTENT" ]; then
        pass "same port: $LABEL client relayed the origin file"
    else
        fail "same port: $LABEL client expected '$CONTENT'"
        cat "$TMP/client-false.log"
    fi
    stop_client
done

DECOY=$(probe_upgrade "$HTTP_PORT" plain)
echo "raw GET without Upgrade to :$HTTP_PORT -> $DECOY"
case "$DECOY" in
    "HTTP/1.1 404"*) pass "same port: a non-upgrade GET still gets the 404 decoy" ;;
    *) fail "same port: non-upgrade GET should get the 404 decoy" ;;
esac
SHARED=$(probe_upgrade "$HTTP_PORT")
echo "clear-text Upgrade to :$HTTP_PORT -> $SHARED"
case "$SHARED" in
    "HTTP/1.1 101"*) pass "same port: a clear-text Upgrade still gets 101" ;;
    *) fail "same port: clear-text Upgrade should get 101" ;;
esac

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

if [ "$FAILED" -ne 0 ]; then
    echo "e2e: FAILED"
    exit 1
fi
echo "e2e: all checks passed"
