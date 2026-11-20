#!/usr/bin/env bash
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# 60-second realistic Doppel kill-chain demo simulator.
#
# Spins up a local Hub (development flags strictly isolated to this script),
# registers a local node and 6 decoys on high non-privileged ports, and runs
# a scripted attacker kill-chain:
#   1. Port scan / recon (tcp-tarpit)
#   2. SSH brute-force (remote-access-decoy)
#   3. PostgreSQL login attempt (database-decoy)
#   4. Web router recon & login (web-router-decoy)
#   5. Lure file theft (file-canary) + Honeytoken credential reuse (SSH/Postgres/Web)
#   6. DNS + HTTP beacon callbacks (token-receiver)
#
# Usage:
#   ./scripts/demo/run-demo.sh           # run simulation and keep Hub alive for UI demo
#   ./scripts/demo/run-demo.sh --smoke   # run simulation, verify all events, and exit 0
#
# Runs natively on Linux and macOS (bash 3.2+), or with only Docker:
#   docker compose -f docker/demo/compose.yaml up --build
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# Normalise the work dir: macOS TMPDIR ends in "/" (the Hub rejects "//" in
# lure paths) and lives under the /var -> /private/var alias.
TMP_BASE="${TMPDIR:-/tmp}"
W=$(mktemp -d "${TMP_BASE%/}/doppel-demo.XXXXXX")
W=$(cd "$W" && pwd -P)

DEMO_HUB_PORT="${DEMO_HUB_PORT:-18080}"
# Interface the Hub binds; 0.0.0.0 inside the demo container so Docker can
# publish it (the compose file publishes it on host loopback only).
DEMO_LISTEN_HOST="${DEMO_LISTEN_HOST:-127.0.0.1}"
HOST_OS=$(uname -s)
DEMO_REG_PORT="${DEMO_REG_PORT:-18081}"
DEMO_TARPIT_PORTS="${DEMO_TARPIT_PORTS:-12220,12221}"
DEMO_SSH_PORT="${DEMO_SSH_PORT:-12222}"
DEMO_POSTGRES_PORT="${DEMO_POSTGRES_PORT:-15432}"
DEMO_WEB_PORT="8080"
DEMO_BEACON_DNS_PORT="${DEMO_BEACON_DNS_PORT:-15353}"
DEMO_BEACON_HTTP_PORT="${DEMO_BEACON_HTTP_PORT:-18089}"
DEMO_ADMIN_PASSWORD="${DEMO_ADMIN_PASSWORD:-doppel-demo-admin-2026}"
DEMO_NO_WAIT="${DEMO_NO_WAIT:-0}"
DEMO_SKIP_UI_BUILD="${DEMO_SKIP_UI_BUILD:-0}"

for arg in "$@"; do
	case "$arg" in
		--smoke|--no-wait) DEMO_NO_WAIT=1 ;;
		--skip-ui-build) DEMO_SKIP_UI_BUILD=1 ;;
		-h|--help)
			sed -n '2,18p' "$0"
			exit 0
			;;
		*)
			echo "unknown argument: $arg" >&2
			exit 2
			;;
	esac
done

HUB="http://127.0.0.1:${DEMO_HUB_PORT}"
PIDS=()

step() { printf '\n=== %s\n' "$*"; }
fail() { printf 'DEMO FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
	rc=$?
	if [ "$rc" -ne 0 ]; then
		echo "--- hub log (tail)" >&2
		tail -n 50 "$W/hub.log" >&2 2>/dev/null || true
		for f in "$W"/sensor-*.log; do
			[ -f "$f" ] || continue
			echo "--- $(basename "$f") (tail)" >&2
			tail -n 20 "$f" >&2 2>/dev/null || true
		done
	fi
	for pid in "${PIDS[@]:-}"; do
		[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
	rm -rf "$W"
	exit "$rc"
}
trap cleanup EXIT INT TERM

for cmd in go python3 curl jq; do
	command -v "$cmd" >/dev/null 2>&1 || fail "missing required command: $cmd"
done

step "1/7 Build UI (if needed), Hub, registry tool, and 6 demo decoys"
if [ "$DEMO_SKIP_UI_BUILD" != "1" ] && [ ! -f "$ROOT/hub/internal/webui/dist/index.html" ]; then
	if command -v npm >/dev/null 2>&1; then
		if [ -d "$ROOT/ui/node_modules" ]; then
			(cd "$ROOT/ui" && npm run build >/dev/null)
		else
			(cd "$ROOT/ui" && npm ci --ignore-scripts --no-audit --no-fund >/dev/null && npm run build >/dev/null)
		fi
	else
		echo "note: npm not found; Hub will run without rebuilt UI bundle"
	fi
fi

mkdir -p "$W/bin" "$W/reg" "$W/lures"
(cd "$ROOT/hub" && CGO_ENABLED=0 go build -o "$W/bin/doppel-hub" ./cmd/doppel-hub && CGO_ENABLED=0 go build -o "$W/bin/ts-registry" ./cmd/ts-registry)

DEMO_SENSORS=(tcp-tarpit remote-access-decoy database-decoy web-router-decoy file-canary token-receiver)
for s in "${DEMO_SENSORS[@]}"; do
	(cd "$ROOT/sensors/$s" && CGO_ENABLED=0 go build -o "$W/bin/$s" .)
done

step "2/7 Serve local manifest catalogue (dev unsigned manifests isolated to demo)"
DUMMY_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"
for s in "${DEMO_SENSORS[@]}"; do
	v=$(jq -r .version "$ROOT/sensors/$s/manifest.json")
	img="demo.local/ts-sensor-$s"
	jq --arg r "$img" '.image.repository = $r | if .init then .init.image.repository = $r else . end' \
		"$ROOT/sensors/$s/manifest.json" > "$W/src-$s.json"
	d="$W/reg/sensors/$s/$v"
	mkdir -p "$d"
	"$W/bin/ts-registry" fill -in "$W/src-$s.json" -out "$d/manifest.json" \
		-name "$s" -version "$v" -repository "$img" -tag "$v" -digest "$DUMMY_DIGEST"
	echo '{}' > "$d/manifest.json.sigstore.json"
done
"$W/bin/ts-registry" index -dir "$W/reg"
(cd "$W/reg" && exec python3 -m http.server "$DEMO_REG_PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
PIDS+=($!)
for _ in $(seq 50); do
	curl -fsS "http://127.0.0.1:${DEMO_REG_PORT}/index.json" >/dev/null 2>&1 && break
	sleep 0.2
done
curl -fsS "http://127.0.0.1:${DEMO_REG_PORT}/index.json" >/dev/null || fail "manifest server did not start on port $DEMO_REG_PORT"

step "3/7 Start local Doppel Hub on $HUB"
"$W/bin/doppel-hub" kek-generate > "$W/kek"
chmod 600 "$W/kek"
SETUP_TOKEN="demo-setup-token-0123456789abcdef"
TS_KEK_FILE="$W/kek" \
TS_ENV="development" \
TS_SETUP_TOKEN="$SETUP_TOKEN" \
TS_DB_PATH="$W/demo.db" \
TS_LISTEN_ADDR="$DEMO_LISTEN_HOST" \
TS_LISTEN_PORT="$DEMO_HUB_PORT" \
TS_METRICS_ADDR="off" \
TS_REGISTRY_URL="http://127.0.0.1:${DEMO_REG_PORT}/" \
TS_DEV_ALLOW_UNSIGNED_MANIFESTS="1" \
TS_UPDATE_CHECK_URL="https://127.0.0.1:1/none" \
	"$W/bin/doppel-hub" serve > "$W/hub.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 50); do
	curl -fsS "$HUB/v3/version" >/dev/null 2>&1 && break
	sleep 0.2
done
curl -fsS "$HUB/v3/version" >/dev/null || fail "Hub did not start on $HUB"

JAR="$W/cookies.txt"
api() {
	local m=$1 p=$2
	shift 2
	curl -sS -b "$JAR" -c "$JAR" -H "Origin: $HUB" -H 'Content-Type: application/json' -X "$m" "$HUB/api/v3$p" "$@"
}

api POST /setup -d "{\"setup_token\":\"$SETUP_TOKEN\",\"password\":\"$DEMO_ADMIN_PASSWORD\",\"public_endpoint\":\"$HUB\"}" \
	| jq -e .ok >/dev/null || fail "Hub setup failed"
api POST /session/login -d "{\"password\":\"$DEMO_ADMIN_PASSWORD\"}" \
	| jq -e .ok >/dev/null || fail "Admin login failed"
api POST /catalogue/refresh | jq -e .ok >/dev/null || fail "Catalogue refresh failed"

api PUT /assets -d '{"assets":[
	{"name":"corp-workstation-01","address":"127.0.0.1","criticality":"high","owner":"secops","tags":["demo","internal"]},
	{"name":"prod-billing-db","address":"10.20.4.15","criticality":"critical","owner":"data-eng","tags":["pci","postgres"]}
]}' | jq -e .ok >/dev/null || fail "Seed assets failed"

step "4/7 Link demo node and register decoys on high ports"
node_resp=$(api POST /nodes -d '{"alias":"demo-edge-01","tags":["demo","dmz"]}')
NODE_ID=$(echo "$node_resp" | jq -r .node.id)
NODE_KEY=$(echo "$node_resp" | jq -r .node_key)
[ -n "$NODE_ID" ] && [ "$NODE_ID" != "null" ] || fail "Create node failed: $node_resp"

# Register each decoy at the version its manifest declares.
ver() { jq -r .version "$ROOT/sensors/$1/manifest.json"; }

add_sensor() {
	local resp
	resp=$(api POST "/nodes/$NODE_ID/sensors" -d "$1")
	echo "$resp" | jq -e '.sensor.id' >/dev/null || fail "Register sensor failed: $resp"
}

add_sensor "{\"catalogue_name\":\"tcp-tarpit\",\"version\":\"$(ver tcp-tarpit)\",\"config\":{\"TS_PORTS\":\"${DEMO_TARPIT_PORTS}\",\"TS_MODE\":\"close\",\"TS_EVENT_COOLDOWN_SEC\":\"0\"}}"
add_sensor "{\"catalogue_name\":\"remote-access-decoy\",\"version\":\"$(ver remote-access-decoy)\",\"config\":{\"TS_ENABLE_SSH\":\"true\",\"TS_SSH_PORT\":\"${DEMO_SSH_PORT}\",\"TS_ENABLE_TELNET\":\"false\",\"TS_ENABLE_FTP\":\"false\",\"TS_EVENT_COOLDOWN_SEC\":\"0\"}}"
add_sensor "{\"catalogue_name\":\"database-decoy\",\"version\":\"$(ver database-decoy)\",\"config\":{\"TS_ENABLE_POSTGRES\":\"true\",\"TS_POSTGRES_PORT\":\"${DEMO_POSTGRES_PORT}\",\"TS_ENABLE_MYSQL\":\"false\",\"TS_ENABLE_MSSQL\":\"false\",\"TS_EVENT_COOLDOWN_SEC\":\"0\"}}"
add_sensor "{\"catalogue_name\":\"web-router-decoy\",\"version\":\"$(ver web-router-decoy)\",\"config\":{\"TS_PORT\":\"${DEMO_WEB_PORT}\",\"TS_SKIN\":\"router\",\"TS_LOGIN_COOLDOWN_SEC\":\"0\",\"TS_PROBE_COOLDOWN_SEC\":\"0\"}}"
add_sensor "{\"catalogue_name\":\"file-canary\",\"version\":\"$(ver file-canary)\",\"config\":{\"TS_LURES\":\"$W/lures/prod-db.env,$W/lures/vpn-creds.txt\",\"TS_ACCESS_ALERTS\":\"true\",\"TS_ACCESS_COOLDOWN_SEC\":\"0\",\"TS_TAMPER_COOLDOWN_SEC\":\"0\"}}"
add_sensor "{\"catalogue_name\":\"token-receiver\",\"version\":\"$(ver token-receiver)\",\"config\":{\"TS_BEACON_DOMAIN\":\"beacon.demo.local\",\"TS_ANSWER_IPV4\":\"127.0.0.1\",\"TS_DNS_PORT\":\"${DEMO_BEACON_DNS_PORT}\",\"TS_HTTP_PORT\":\"${DEMO_BEACON_HTTP_PORT}\",\"TS_ALERT_COOLDOWN_SEC\":\"0\"}}"

# Fetch Hub-rendered compose so every sensor receives exact Hub-derived keys
# (TS_CAPTURE_KEY, TS_HONEYTOKEN, TS_BEACON_KEY, TS_SENSOR_ID, TS_CONFIG_REVISION).
curl -fsS -H "Authorization: Bearer $NODE_KEY" -H "X-TrueSignal-CLI-Version: 3.0.0" \
	"$HUB/v3/node/compose" > "$W/compose.json"
REV=$(jq -r .revision "$W/compose.json")
curl -fsS -H "Authorization: Bearer $NODE_KEY" -H "X-TrueSignal-CLI-Version: 3.0.0" \
	-H "Content-Type: application/json" -X POST \
	-d "{\"revision\":\"$REV\",\"result\":\"applied\"}" \
	"$HUB/v3/node/applied" >/dev/null

# Create HTTP web-bug and DNS beacons backed by token-receiver.
# The admin API never returns a beacon token (json:"-"); it only appears in
# the downloadable artefact, so read it from there.
web_beacon=$(api POST /beacons -d '{"type":"web-bug","name":"Q4-Finance-Spreadsheet","memo":"Planted in finance share"}')
WEB_BEACON_ID=$(echo "$web_beacon" | jq -r .beacon.id)
WEB_BEACON_TOKEN=$(api GET "/beacons/$WEB_BEACON_ID/artefact" | sed -n 's|.*/static/\([a-z0-9]*\)\.gif.*|\1|p')
dns_beacon=$(api POST /beacons -d '{"type":"dns","name":"Prod-Kubeconfig-Lure","memo":"Planted in jumpbox ~/.kube/config"}')
DNS_BEACON_ID=$(echo "$dns_beacon" | jq -r .beacon.id)
DNS_BEACON_TOKEN=$(api GET "/beacons/$DNS_BEACON_ID/artefact" | sed -n 's|^\([a-z0-9]*\)\..*|\1|p')
[ -n "$WEB_BEACON_TOKEN" ] && [ "$WEB_BEACON_TOKEN" != "null" ] || fail "Create web-bug beacon failed: $web_beacon"
[ -n "$DNS_BEACON_TOKEN" ] && [ "$DNS_BEACON_TOKEN" != "null" ] || fail "Create dns beacon failed: $dns_beacon"

step "5/7 Launch all 6 decoys locally and wait for Hub heartbeats"
python3 - "$W/compose.json" "$W/bin" "$W" "$NODE_KEY" "$HUB" <<'PY' > "$W/launch.sh"
import json, os, shlex, sys
compose_path, bin_dir, work_dir, node_key, hub_url = sys.argv[1:6]
doc = json.load(open(compose_path))["compose"]
services = doc.get("services", {})
for svc_name, svc in sorted(services.items()):
    if svc_name.endswith("-init"):
        continue
    env = dict(svc.get("environment", {}))
    env["TS_NODE_KEY"] = node_key
    env["TS_HUB_ENDPOINT"] = hub_url
    env["TS_DEV_ALLOW_HTTP"] = "true"
    img = svc.get("image", "")
    # Extract catalogue name from image "demo.local/ts-sensor-<name>:<ver>@sha256:..."
    base = img.split("@")[0].rsplit("/", 1)[-1].split(":", 1)[0]
    bin_name = base.removeprefix("ts-sensor-")
    bin_path = os.path.join(bin_dir, bin_name)
    env_prefix = " ".join(f"{k}={shlex.quote(str(v))}" for k, v in sorted(env.items()))
    if bin_name == "file-canary":
        # Run init once to plant lures containing TS_HONEYTOKEN before watching.
        print(f"env {env_prefix} {shlex.quote(bin_path)} init")
        if "TS_HONEYTOKEN" in env:
            with open(os.path.join(work_dir, "honeytoken.txt"), "w") as hf:
                hf.write(str(env["TS_HONEYTOKEN"]))
    log_path = os.path.join(work_dir, f"sensor-{bin_name}.log")
    print(f"env {env_prefix} {shlex.quote(bin_path)} > {shlex.quote(log_path)} 2>&1 &")
    print("PIDS+=($!)")
PY
# shellcheck source=/dev/null
source "$W/launch.sh"

ok=""
for _ in $(seq 40); do
	online=$(api GET "/nodes/$NODE_ID" | jq '[.node.sensors[] | select(.status=="online")] | length')
	if [ "$online" -eq 6 ]; then
		ok=1
		break
	fi
	sleep 0.5
done
[ -n "$ok" ] || fail "Expected 6 online sensors, got ${online:-0}"
echo "All 6 decoys online and heartbeating."

step "6/7 Run scripted attacker kill-chain (scan -> SSH -> Postgres -> Web -> Honeytoken -> Beacon)"
HT_RAW=$(cat "$W/honeytoken.txt")
# TS_HONEYTOKEN is JSON {"id","username","secret"} (sensors/file-canary/lure.go).
HT_USER=$(echo "$HT_RAW" | jq -r .username)
HT_PASS=$(echo "$HT_RAW" | jq -r .secret)
[ -n "$HT_USER" ] && [ "$HT_USER" != "null" ] || fail "Unreadable TS_HONEYTOKEN: $HT_RAW"

# Helper for real SSH password auth against remote-access-decoy using the
# already-cached golang.org/x/crypto/ssh dependency in sensors/remote-access-decoy.
cat > "$W/ssh_probe.go" <<'GO'
package main

import (
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) < 4 {
		os.Exit(2)
	}
	addr, user, pass := os.Args[1], os.Args[2], os.Args[3]
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-2.0-OpenSSH_9.2p1",
		Timeout:         3 * time.Second,
	}
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		os.Exit(1)
	}
	defer c.Close()
	conn, _, _, err := ssh.NewClientConn(c, addr, cfg)
	if err == nil {
		conn.Close()
	}
}
GO

echo "  [1/6] Port scan / recon against tcp-tarpit ($DEMO_TARPIT_PORTS)"
python3 - "$DEMO_TARPIT_PORTS" <<'PY'
import socket, sys
for p in sys.argv[1].split(","):
    s = socket.create_connection(("127.0.0.1", int(p.strip())), timeout=3)
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    s.close()
PY

echo "  [2/6] SSH brute-force against remote-access-decoy (127.0.0.1:$DEMO_SSH_PORT)"
(cd "$ROOT/sensors/remote-access-decoy" && go run "$W/ssh_probe.go" "127.0.0.1:${DEMO_SSH_PORT}" "root" "Summer2026!")
(cd "$ROOT/sensors/remote-access-decoy" && go run "$W/ssh_probe.go" "127.0.0.1:${DEMO_SSH_PORT}" "deploy" "admin123")

echo "  [3/6] PostgreSQL credential attempt against database-decoy (127.0.0.1:$DEMO_POSTGRES_PORT)"
python3 - "$DEMO_POSTGRES_PORT" "postgres" "P@ssw0rd2026" <<'PY'
import socket, struct, sys

def pg_login(port, user, password):
    s = socket.create_connection(("127.0.0.1", int(port)), timeout=3)
    params = f"user\x00{user}\x00database\x00prod_billing\x00application_name\x00psql\x00\x00".encode()
    startup = struct.pack("!II", len(params) + 8, 196608) + params
    s.sendall(startup)
    s.recv(64)
    pw_body = password.encode() + b"\x00"
    s.sendall(b"p" + struct.pack("!I", len(pw_body) + 4) + pw_body)
    s.recv(512)
    s.close()

pg_login(sys.argv[1], sys.argv[2], sys.argv[3])
PY

echo "  [4/6] Web router recon & login against web-router-decoy (127.0.0.1:$DEMO_WEB_PORT)"
python3 - "$DEMO_WEB_PORT" <<'PY'
import sys, urllib.error, urllib.parse, urllib.request
base = f"http://127.0.0.1:{sys.argv[1]}"
for path in ("/", "/admin/config.bak"):
    try:
        urllib.request.urlopen(base + path, timeout=3).read()
    except urllib.error.HTTPError:
        pass
data = urllib.parse.urlencode({"username": "admin", "password": "RouterPassword!"}).encode()
req = urllib.request.Request(base + "/login", data=data, method="POST")
try:
    urllib.request.urlopen(req, timeout=3).read()
except urllib.error.HTTPError:
    pass
PY

echo "  [5/6] Lure file theft (file-canary) + honeytoken reuse across SSH, Postgres & Web"
cat "$W/lures/prod-db.env" >/dev/null
if [ "$HOST_OS" != "Linux" ]; then
	# No inotify here: file-canary polls, and read detection depends on atime
	# (best-effort). The attacker also locks down the stolen file, which the
	# poller always sees as tampering.
	chmod 0600 "$W/lures/vpn-creds.txt"
fi
(cd "$ROOT/sensors/remote-access-decoy" && go run "$W/ssh_probe.go" "127.0.0.1:${DEMO_SSH_PORT}" "$HT_USER" "$HT_PASS")
python3 - "$DEMO_POSTGRES_PORT" "$DEMO_WEB_PORT" "$HT_USER" "$HT_PASS" <<'PY'
import socket, struct, sys, urllib.error, urllib.parse, urllib.request
pg_port, web_port, user, password = sys.argv[1:5]
s = socket.create_connection(("127.0.0.1", int(pg_port)), timeout=3)
params = f"user\x00{user}\x00database\x00prod_billing\x00application_name\x00psql\x00\x00".encode()
s.sendall(struct.pack("!II", len(params) + 8, 196608) + params)
s.recv(64)
pw_body = password.encode() + b"\x00"
s.sendall(b"p" + struct.pack("!I", len(pw_body) + 4) + pw_body)
s.recv(512)
s.close()

data = urllib.parse.urlencode({"username": user, "password": password}).encode()
req = urllib.request.Request(f"http://127.0.0.1:{web_port}/login", data=data, method="POST")
try:
    urllib.request.urlopen(req, timeout=3).read()
except urllib.error.HTTPError:
    pass
PY

echo "  [6/6] DNS + HTTP beacon callbacks against token-receiver"
python3 - "$DEMO_BEACON_HTTP_PORT" "$WEB_BEACON_TOKEN" "$DEMO_BEACON_DNS_PORT" "$DNS_BEACON_TOKEN" <<'PY'
import socket, struct, sys, urllib.request
http_port, web_tok, dns_port, dns_tok = sys.argv[1:5]
urllib.request.urlopen(f"http://127.0.0.1:{http_port}/{web_tok}.gif", timeout=3).read()

qname = f"{dns_tok}.beacon.demo.local"
labels = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
pkt = struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
sock.sendto(pkt, ("127.0.0.1", int(dns_port)))
sock.recvfrom(512)
sock.close()
PY

step "7/7 Verify kill-chain events, honeytoken match, and analytics projections"
WANT_TRIGGERS="tcp_connection ssh_login postgres_login web_page_view web_path_probe web_login_attempt decoy_file_accessed beacon_triggered"
if [ "$HOST_OS" != "Linux" ]; then
	# Either lure signal proves file-canary end to end (see step 5).
	WANT_TRIGGERS="${WANT_TRIGGERS/decoy_file_accessed/decoy_file_accessed|decoy_file_tampered}"
fi
missing=""
for _ in $(seq 30); do
	got=$(api GET '/events?limit=200&archived=any' | jq -r '[.events[].trigger] | unique | join(" ")')
	missing=""
	for t in $WANT_TRIGGERS; do
		hit=""
		for alt in ${t//|/ }; do
			case " $got " in
				*" $alt "*) hit=1 ;;
			esac
		done
		[ -n "$hit" ] || missing="$missing $t"
	done
	ht_hits=$(api GET '/events?limit=200&archived=any' | jq '[.events[] | select(.trigger == "honeytoken_used")] | length')
	if [ -z "$missing" ] && [ "$ht_hits" -ge 1 ]; then
		break
	fi
	sleep 0.5
done

[ -z "$missing" ] || fail "Missing expected kill-chain triggers:$missing (got: $got)"
[ "${ht_hits:-0}" -ge 1 ] || fail "Expected at least 1 honeytoken reuse match, got 0"

total_events=$(api GET '/events?limit=200&archived=any' | jq '.events | length')
insights_json=$(api GET '/analytics/projections/insights?days=7')
touched_ratio=$(echo "$insights_json" | jq -r '.data.touched.ratio // 0')
attack_count=$(api GET '/analytics/projections/attack_matrix?days=7' | jq '.data.techniquesObserved // 0')

echo ""
echo "============================================================"
echo " Doppel Demo Ready"
echo "============================================================"
echo "  Hub UI:             $HUB"
echo "  Admin password:     $DEMO_ADMIN_PASSWORD"
echo "  Events captured:    $total_events"
echo "  Triggers seen:      $got"
echo "  Honeytoken matches: $ht_hits"
echo "  ATT&CK techniques:  $attack_count"
echo "  Touched decoy %:    $touched_ratio"
echo "============================================================"

if [ "$DEMO_NO_WAIT" = "1" ]; then
	echo "Smoke mode (--smoke / DEMO_NO_WAIT=1): all kill-chain assertions passed."
	exit 0
fi

echo "Press Ctrl-C to stop the demo Hub and decoys."
while true; do
	sleep 5
done
