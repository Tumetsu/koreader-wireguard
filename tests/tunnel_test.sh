#!/bin/sh
# End-to-end test of wgctl.sh with a real WireGuard handshake on loopback.
# A second wireproxy plays the home server (TCPServerTunnel), so no root,
# kernel module or `wg` tool is needed. With busybox installed, wgctl.sh runs
# against busybox applets only, as it would on a PocketBook.
#
#   WIREPROXY=/path/to/native/wireproxy sh tests/tunnel_test.sh
# shellcheck disable=SC2015,SC2119,SC2120,SC2317
set -eu

: "${WIREPROXY:?set WIREPROXY to a native wireproxy binary}"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CTL="$ROOT/wireguard.koplugin/wgctl.sh"
WORK=$(mktemp -d)
PIDS=""
FAILED=0

cleanup() {
    for p in $PIDS; do kill "$p" 2>/dev/null || true; done
    sh "$CTL" stop "$WORK/client.pid" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

ok() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; FAILED=1; }

SH="sh"
if command -v busybox >/dev/null 2>&1; then
    mkdir "$WORK/bb"
    for applet in sh cat tr grep kill sleep rm chmod; do
        ln -s "$(command -v busybox)" "$WORK/bb/$applet"
    done
    SH="$WORK/bb/sh"
    CTL_PATH="$WORK/bb"
    echo "# running wgctl.sh under busybox applets"
else
    CTL_PATH="$PATH"
fi
ctl() { PATH="$CTL_PATH" "$SH" "$CTL" "$@"; }

# Raw X25519 keys from openssl, base64 as WireGuard expects.
genkey() {
    openssl genpkey -algorithm X25519 -out "$WORK/$1.pem" 2>/dev/null
    openssl pkey -in "$WORK/$1.pem" -outform DER | tail -c 32 | base64
}
pubkey() {
    openssl pkey -in "$WORK/$1.pem" -pubout -outform DER | tail -c 32 | base64
}
freeport() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'
}

SERVER_KEY=$(genkey server); SERVER_PUB=$(pubkey server)
CLIENT_KEY=$(genkey client); CLIENT_PUB=$(pubkey client)
WG_PORT=$(freeport); HTTP_PORT=$(freeport); LOCAL_PORT=$(freeport); INFO_PORT=$(freeport)

# "Home" web service.
mkdir "$WORK/www"
echo "hello from home" >"$WORK/www/index.html"
python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$WORK/www" >/dev/null 2>&1 &
PIDS="$PIDS $!"

cat >"$WORK/server.conf" <<EOF
[Interface]
PrivateKey = $SERVER_KEY
Address = 10.9.0.1/32
ListenPort = $WG_PORT

[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = 10.9.0.2/32

[TCPServerTunnel]
ListenPort = 8000
Target = 127.0.0.1:$HTTP_PORT
EOF
"$WIREPROXY" -s -c "$WORK/server.conf" >"$WORK/server.log" 2>&1 &
PIDS="$PIDS $!"

cat >"$WORK/client.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_KEY
Address = 10.9.0.2/32

[Peer]
PublicKey = $SERVER_PUB
Endpoint = localhost:$WG_PORT
AllowedIPs = 10.9.0.1/32
PersistentKeepalive = 25

[TCPClientTunnel]
BindAddress = 127.0.0.1:$LOCAL_PORT
Target = 10.9.0.1:8000
EOF

# Stand-in for the KOReader process the watchdog follows.
sleep 600 &
KO_PID=$!
PIDS="$PIDS $KO_PID"

start() {
    ctl start "$WIREPROXY" "$WORK/client.conf" "$WORK/client.pid" \
        "$WORK/client.log" "$KO_PID" "127.0.0.1:$INFO_PORT" "${1:-0}"
}

sleep 1
if start; then ok "start exits 0"; else fail "start exits 0"; cat "$WORK/client.log"; fi
if ctl status "$WORK/client.pid"; then ok "status reports running"; else fail "status reports running"; fi
FIRST_PID=$(cat "$WORK/client.pid")
start && [ "$(cat "$WORK/client.pid")" = "$FIRST_PID" ] \
    && ok "second start is a no-op" || fail "second start is a no-op"

BODY=$(curl -fsS --max-time 10 "http://127.0.0.1:$LOCAL_PORT/" || true)
[ "$BODY" = "hello from home" ] && ok "HTTP through the tunnel" || fail "HTTP through the tunnel (got '$BODY')"

POST_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X POST -d x=1 "http://127.0.0.1:$LOCAL_PORT/" || true)
# python's http.server answers POST with 501: it reached the server.
[ "$POST_CODE" = "501" ] && ok "POST reaches the home server" || fail "POST reaches the home server (got $POST_CODE)"

METRICS=$(curl -fsS --max-time 5 "http://127.0.0.1:$INFO_PORT/metrics" || true)
echo "$METRICS" | grep -q '^last_handshake_time_sec=[1-9]' \
    && ok "metrics show a completed handshake" || fail "metrics show a completed handshake"

ctl stop "$WORK/client.pid"
if ctl status "$WORK/client.pid"; then fail "stop"; else ok "stop"; fi
[ -d "/proc/$FIRST_PID" ] && fail "process gone after stop" || ok "process gone after stop"

sed 's/^PrivateKey = .*/PrivateKey = not-a-key/' "$WORK/client.conf" >"$WORK/bad.conf"
set +e
ctl start "$WIREPROXY" "$WORK/bad.conf" "$WORK/client.pid" "$WORK/client.log" "$KO_PID" "127.0.0.1:$INFO_PORT" 0
CODE=$?
set -e
[ "$CODE" = 2 ] && ok "invalid config exits 2" || fail "invalid config exits 2 (got $CODE)"

# Port already taken: wireproxy dies after the config check passes.
python3 -c 'import socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1",'"$LOCAL_PORT"')); s.listen(); time.sleep(30)' &
PIDS="$PIDS $!"
sleep 0.5
set +e
start
CODE=$?
set -e
[ "$CODE" = 3 ] && ok "bind failure exits 3" || fail "bind failure exits 3 (got $CODE)"
kill "$!" 2>/dev/null || true
sleep 0.5

start
WP_PID=$(cat "$WORK/client.pid")
kill "$KO_PID"
i=0
while [ $i -lt 25 ] && [ -d "/proc/$WP_PID" ]; do sleep 1; i=$((i + 1)); done
[ -d "/proc/$WP_PID" ] && fail "watchdog stops wireproxy after KOReader exits" \
    || ok "watchdog stops wireproxy after KOReader exits (${i}s)"
[ -f "$WORK/client.pid" ] && fail "watchdog removes pidfile" || ok "watchdog removes pidfile"

exit $FAILED
