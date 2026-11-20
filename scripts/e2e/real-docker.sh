#!/bin/sh
# Copyright (c) 2026 TrueSignal Deception. All rights reserved.
#
# End-to-end test on a real Docker host (CI job `real-docker`, acceptance
# §14.11/§14.12): sensor images pushed by digest to a local registry, a real
# Hub, the real CLI applying the Hub-rendered compose with `docker compose`,
# real connections to the decoys, events and heartbeats arriving, container
# hardening as rendered (§6.12), fire drill (flagged, analytics unchanged:
# F-001), idempotent re-apply, uninstall.
# KEEP=1 stops before the uninstall and leaves the POC running (docs/poc.md);
# it builds the real admin UI first (needs Node 22+, else it fails with a clear message).
#
# Needs: docker with the compose plugin, go, jq, curl, python3. On Linux the
# CLI runs as root via passwordless sudo. On macOS (Docker Desktop with host
# networking enabled) it runs as the invoking user with its config and work
# dir inside the workspace; Docker Desktop needs no root.
# Development flag used: unsigned manifests (the local registry is not
# signed by a release workflow); images are still pinned by digest.
#
# Overrides: E2E_HOST_IP (address containers use to reach the Hub),
# E2E_REG_PORT (local registry port; default 5000, 5055 on macOS where
# AirPlay Receiver holds 5000).
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
W=$(mktemp -d)
W=$(cd "$W" && pwd -P)
OS=$(uname -s)
if [ "$OS" = Darwin ]; then
	REG_PORT="${E2E_REG_PORT:-5055}"
	HOSTIP="${E2E_HOST_IP:-$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)}"
	# No sudo: the CLI runs as this user against Docker Desktop. Sensor
	# images are built for the native architecture (arm64 on Apple Silicon).
	export TS_CONFIG_FILE="$W/doppel/config.json" TS_WORK_DIR="$W/doppel/work" TS_ALLOW_NON_AMD64=true
	RUN=""
else
	REG_PORT="${E2E_REG_PORT:-5000}"
	HOSTIP="${E2E_HOST_IP:-$(hostname -I | awk '{print $1}')}"
	RUN="sudo -n"
fi
[ -n "$HOSTIP" ] || { echo "E2E FAIL: cannot determine host IP; set E2E_HOST_IP" >&2; exit 1; }
REG=127.0.0.1:$REG_PORT
REGISTRY_IMAGE='registry:3.1.2@sha256:d4032d4cc323c1731c707931ecada07a53076eac38e3b61ae57533f170f2c6c3'
HUB="http://$HOSTIP:18080"
PW='e2e-correct-horse-battery-staple'
SENSORS="tcp-tarpit template web-router-decoy"
mkdir -p "$W/bin"; CLI="$W/bin/doppel"
# Command as printed for the user to rerun from their own shell (macOS needs the TS_* paths).
if [ "$OS" = Darwin ]; then
	PCLI="env TS_CONFIG_FILE=$TS_CONFIG_FILE TS_WORK_DIR=$TS_WORK_DIR TS_ALLOW_NON_AMD64=true TS_DEV_ALLOW_HTTP=true $CLI"
else
	PCLI="env TS_DEV_ALLOW_HTTP=true $CLI"
fi
fail() { echo "E2E FAIL: $*" >&2; exit 1; }
step() { echo; echo "=== $*"; }

cleanup() {
	rc=$?
	if [ "$rc" -ne 0 ]; then
		echo "--- hub log (tail)"; tail -n 60 "$W/hub.log" 2>/dev/null || true
		echo "--- containers"; docker ps -a --filter label=io.truesignal.role=sensor || true
		for c in $(docker ps -aq --filter label=io.truesignal.role=sensor); do echo "--- logs $c"; docker logs --tail 30 "$c" 2>&1 || true; done
	fi
	if [ "${KEEP:-0}" = 1 ] && [ "$rc" -eq 0 ]; then exit 0; fi # POC mode: leave everything running
	$RUN env TS_DEV_ALLOW_HTTP=true "$CLI" uninstall --yes >/dev/null 2>&1 || true
	[ -f "$W/hub.pid" ] && kill "$(cat "$W/hub.pid")" 2>/dev/null || true
	docker rm -f ts-e2e-registry >/dev/null 2>&1 || true
	[ -n "${REGPID:-}" ] && kill "$REGPID" 2>/dev/null || true
	exit "$rc"
}
trap cleanup EXIT

if [ "${KEEP:-0}" = 1 ]; then
	# POC mode shows the real admin UI: build it (make ui) before the Hub embeds it.
	step "build the admin UI (KEEP=1)"
	command -v node >/dev/null 2>&1 || fail "KEEP=1 needs Node 22+ to build the admin UI (make ui); node not found. Install Node 22 or run without KEEP=1"
	node_major=$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)
	[ "$node_major" -ge 22 ] 2>/dev/null || fail "KEEP=1 needs Node 22+ to build the admin UI (make ui); found $(node --version 2>/dev/null || echo unknown)"
	command -v npm >/dev/null 2>&1 || fail "KEEP=1 needs npm (ships with Node 22+) to build the admin UI"
	(cd "$ROOT" && make ui)
fi

step "build Hub, CLI and registry tool"
(cd "$ROOT/hub" && CGO_ENABLED=0 go build -o "$W/hub" ./cmd/doppel-hub && go build -o "$W/ts-registry" ./cmd/ts-registry)
(cd "$ROOT/cli" && CGO_ENABLED=0 go build -o "$CLI" ./cmd/doppel)

step "local image registry; build and push sensor images by digest"
docker run -d --name ts-e2e-registry -p "$REG:5000" "$REGISTRY_IMAGE" >/dev/null
mkdir -p "$W/reg"
for n in $SENSORS; do
	v=$(jq -r .version "$ROOT/sensors/$n/manifest.json")
	img="$REG/ts-sensor-$n"
	docker build -q -f "$ROOT/sensors/$n/Dockerfile" -t "$img:$v" "$ROOT" >/dev/null
	docker push -q "$img:$v" >/dev/null
	digest=$(docker inspect --format '{{index .RepoDigests 0}}' "$img:$v" | sed 's/.*@//')
	echo "$n $v $digest"
	jq --arg r "$img" '.image.repository = $r | if .init then .init.image.repository = $r else . end' \
		"$ROOT/sensors/$n/manifest.json" > "$W/src-$n.json"
	d="$W/reg/sensors/$n/$v"; mkdir -p "$d"
	"$W/ts-registry" fill -in "$W/src-$n.json" -out "$d/manifest.json" -name "$n" -version "$v" -repository "$img" -tag "$v" -digest "$digest"
	echo '{}' > "$d/manifest.json.sigstore.json"
done
"$W/ts-registry" index -dir "$W/reg"
(cd "$W/reg" && exec python3 -m http.server 18081 --bind 127.0.0.1 >/dev/null 2>&1) &
REGPID=$!

step "start the Hub (secrets sealed under a generated KEK)"
"$W/hub" kek-generate > "$W/kek"; chmod 600 "$W/kek"
start_hub() {
	TS_KEK_FILE="$W/kek" TS_ENV=development TS_SETUP_TOKEN=e2e-setup-token-0123456789abcdef TS_DB_PATH="$W/ts.db" \
		TS_LISTEN_ADDR="$HOSTIP" TS_LISTEN_PORT=18080 TS_METRICS_ADDR="127.0.0.1:19090" \
		TS_REGISTRY_URL=http://127.0.0.1:18081/ TS_DEV_ALLOW_UNSIGNED_MANIFESTS=1 \
		TS_UPDATE_CHECK_URL=https://127.0.0.1:1/none "$W/hub" serve >> "$W/hub.log" 2>&1 &
	echo $! > "$W/hub.pid"
	for _ in $(seq 50); do curl -fsS "$HUB/v3/version" >/dev/null 2>&1 && break; sleep 0.2; done
	curl -fsS "$HUB/v3/version" || fail "hub did not start"; echo
	curl -fsS "$HUB/healthz" | jq -e '.status == "ok"' >/dev/null || fail "/healthz failed"
	curl -fsS "$HUB/readyz" | jq -e '.status == "ok"' >/dev/null || fail "/readyz failed"
	curl -fsS "http://127.0.0.1:19090/metrics" | grep -q 'doppel_build_info{' || fail "/metrics scrape failed on loopback listener"
	if curl -fsS "$HUB/metrics" 2>/dev/null | grep -q 'doppel_build_info{'; then
		fail "/metrics must never be exposed on the public Hub port"
	fi
}
start_hub

J="$W/jar"
api() { m=$1 p=$2; shift 2; curl -sS -b "$J" -c "$J" -H "Origin: $HUB" -H 'Content-Type: application/json' -X "$m" "$HUB/api/v3$p" "$@"; }
api POST /setup -d "{\"setup_token\":\"e2e-setup-token-0123456789abcdef\",\"password\":\"$PW\",\"public_endpoint\":\"$HUB\"}" | jq -e .ok >/dev/null || fail "setup"
api POST /session/login -d "{\"password\":\"$PW\"}" | jq -e .ok >/dev/null || fail "login"
api POST /catalogue/refresh >/dev/null
api GET /catalogue | jq -r '.sensors[] | "\(.name) available=\(.versions[0].available)"'

step "create node and sensors via the admin API"
node=$(api POST /nodes -d '{"alias":"e2e-node","tags":["ci"]}')
KEY=$(echo "$node" | jq -r .node_key); NODE=$(echo "$node" | jq -r .node.id)
[ -n "$KEY" ] && [ "$KEY" != null ] || fail "node key"
add() { api POST "/nodes/$NODE/sensors" -d "$1" | jq -e '.sensor.id' >/dev/null || fail "add sensor $1"; }
add '{"catalogue_name":"tcp-tarpit","version":"1.0.0","config":{"TS_PORTS":"2222","TS_MODE":"close","TS_EVENT_COOLDOWN_SEC":"0"}}'
add '{"catalogue_name":"template","version":"1.0.0","config":{"TS_TEMPLATE_PORT":"9099","TS_TEMPLATE_COOLDOWN_SEC":"0"}}'
add '{"catalogue_name":"web-router-decoy","version":"1.0.0","config":{"TS_PORT":"8081"}}'

step "link and apply with the real CLI and docker compose"
if $RUN env TS_NODE_KEY="$KEY" "$CLI" link "$HUB" >/dev/null 2>&1; then
	fail "CLI accepted plain http:// without TS_DEV_ALLOW_HTTP=true"
fi
$RUN env TS_NODE_KEY="$KEY" TS_DEV_ALLOW_HTTP=true "$CLI" link "$HUB"
$RUN env TS_DEV_ALLOW_HTTP=true "$CLI" apply
docker ps --filter label=io.truesignal.role=sensor --format '{{.Names}}\t{{.Image}}\t{{.Status}}'

step "rendered hardening holds on the running containers (§6.12)"
for c in $(docker ps -q --filter label=io.truesignal.role=sensor); do
	docker inspect "$c" | jq -e '.[0] |
		(.Config.Image | test("@sha256:[0-9a-f]{64}$")) and
		.HostConfig.ReadonlyRootfs and
		(.HostConfig.CapDrop | index("ALL") != null) and
		(.HostConfig.SecurityOpt | index("no-new-privileges:true") != null) and
		(.HostConfig.Privileged | not) and
		((.HostConfig.Binds // []) | map(test("docker.sock")) | any | not)' >/dev/null ||
		fail "container $(docker inspect -f '{{.Name}}' "$c") is not hardened as rendered"
done
echo "all sensor containers: digest-pinned, read-only, cap_drop ALL, no-new-privileges, unprivileged, no docker.sock"

step "sensors come online (heartbeats reach the Hub)"
ok=""
for _ in $(seq 60); do
	n=$(api GET "/nodes/$NODE" | jq '[.node.sensors[] | select(.status=="online")] | length')
	[ "$n" = 3 ] && ok=1 && break
	sleep 1
done
api GET "/nodes/$NODE" | jq -r '.node.sensors[] | "\(.id) \(.status) sdk=\(.sdk_version)"'
[ -n "$ok" ] || fail "sensors did not all come online"

step "real interactions with the decoys"
if command -v nc >/dev/null 2>&1; then
	printf 'SSH-2.0-e2e\r\n' | nc -w 2 127.0.0.1 2222 >/dev/null 2>&1 || true
	nc -z -w 2 127.0.0.1 9099 >/dev/null 2>&1 || true
else
	python3 - <<'PY'
import socket
for port, payload in ((2222, b"SSH-2.0-e2e\r\n"), (9099, b"")):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    if payload:
        s.sendall(payload)
    s.close()
PY
fi
want_two="tcp_connection template_connection"
for _ in $(seq 30); do
	got=$(api GET '/events?limit=200&archived=any' | jq -r '[.events[].trigger] | unique | join(" ")')
	missing=""; for t in $want_two; do echo " $got " | grep -q " $t " || missing="$missing $t"; done
	[ -z "$missing" ] && break
	sleep 1
done
[ -z "$missing" ] || fail "host-network decoy events missing:$missing"
api GET '/analytics/projections/sources' | jq -e '
	(.data.sources | length == 1) and
	(.data.sources[0].source == "127.0.0.1") and
	(.data.sources[0].decoys == 2) and
	((.data.sources[0].labels // []) | index("multi-decoy") != null) and
	((.data.sources[0].labels // []) | index("host_local") != null)' >/dev/null ||
	fail "expected 1 correlated multi-decoy source in /api/v3/analytics/projections/sources after hitting two decoys (F-002)"

python3 - <<'PY'
import urllib.request, urllib.error
for path in ("/", "/does-not-exist"):
    try:
        urllib.request.urlopen("http://127.0.0.1:8081" + path, timeout=5).read()
    except urllib.error.HTTPError:
        pass
PY
want="tcp_connection template_connection web_page_view"
for _ in $(seq 30); do
	got=$(api GET '/events?limit=200&archived=any' | jq -r '[.events[].trigger] | unique | join(" ")')
	missing=""; for t in $want; do echo " $got " | grep -q " $t " || missing="$missing $t"; done
	[ -z "$missing" ] && break
	sleep 1
done
echo "triggers seen: $got"
[ -z "$missing" ] || fail "events missing:$missing"

step "fire drill reaches the Hub from every sensor, flagged and out of the analytics (F-001)"
counts() { api GET /analytics/summary | jq -c '.summary | {events_total, events_unread, events_24h, critical_24h}'; }
before=$(counts)
$RUN "$CLI" firedrill
for _ in $(seq 30); do
	d=$(api GET '/events?limit=200&archived=any' | jq '[.events[] | select(.source=="Fire drill") | .sensor_id] | unique | length')
	[ "$d" -ge 3 ] && break
	sleep 1
done
[ "$d" -ge 3 ] || fail "fire drill events from $d of 3 sensors"
drills=$(api GET '/events?view=drills&limit=200')
n=$(echo "$drills" | jq '.events | length')
[ "$n" = 3 ] || fail "view=drills returned $n events, want 3"
echo "$drills" | jq -e '[.events[] | .drill and .severity == "info" and (.details.original_severity | type == "string")] | all' >/dev/null ||
	fail "drill events not stored as flagged info events with original_severity"
api GET '/events?limit=200' | jq -e '[.events[] | select(.drill)] | length == 0' >/dev/null || fail "drills in the Active view"
after=$(counts)
[ "$before" = "$after" ] || fail "analytics summary changed after the fire drill: $before -> $after"
echo "drills: $n flagged; summary unchanged: $after"
api GET '/analytics/projections/sources' | jq -e '[.data.sources[].source] | index("Fire drill") == null' >/dev/null ||
	fail "fire drill events should be excluded from /api/v3/analytics/projections/sources (F-002)"

step "status, idempotent re-apply, applied revision"
$RUN env TS_DEV_ALLOW_HTTP=true "$CLI" status
$RUN env TS_DEV_ALLOW_HTTP=true "$CLI" apply 2>&1 | tee "$W/apply2.txt"
grep -q "nothing to do" "$W/apply2.txt" || fail "second apply was not a no-op"
api GET "/nodes/$NODE" | jq -e '.node.health.in_sync' >/dev/null || fail "node not in sync after apply"
api GET "/nodes/$NODE" | jq -e '[.node.sensors[].dropped_events | type == "number"] | all' >/dev/null ||
	fail "sensor view lacks dropped_events (F-603)"

step "kill -9 the Hub mid-burst: no acknowledged event is lost (F-603)"
# Post batches as the node (sensor tcp-tarpit), record every event_id the Hub
# acknowledged, SIGKILL the Hub while batches are in flight, then count the
# acknowledged ids in the database after WAL recovery.
BURST_SENSOR=$(api GET "/nodes/$NODE" | jq -r '[.node.sensors[] | select(.catalogue_name=="tcp-tarpit")][0].id')
HUB="$HUB" KEY="$KEY" SENSOR="$BURST_SENSOR" PID="$(cat "$W/hub.pid")" DB="$W/ts.db" python3 - <<'PY' || fail "acknowledged events lost after kill -9"
import json, os, signal, sqlite3, threading, time, urllib.error, urllib.request, uuid
hub, key, sensor, pid, db = (os.environ[k] for k in ("HUB", "KEY", "SENSOR", "PID", "DB"))
acked, lock, killed = set(), threading.Lock(), threading.Event()
cut = [0]

def uuid7():
    ms = int(time.time() * 1000)
    r = int.from_bytes(os.urandom(10), "big")
    v = (ms << 80) | (0x7 << 76) | ((r >> 62) & 0xFFF) << 64 | (0b10 << 62) | (r & ((1 << 62) - 1))
    return str(uuid.UUID(int=v))

def worker(w):
    while not killed.is_set():
        ids = [uuid7() for _ in range(50)]
        evs = [{"event_id": i, "sensor_id": sensor, "trigger": "tcp_connection", "severity": "low",
                "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source": "192.0.2.77:40000",
                "target": "e2e burst", "details": {"w": w}} for i in ids]
        req = urllib.request.Request(hub + "/v3/ingest/events", data=json.dumps({"events": evs}).encode(),
                                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            out = json.load(urllib.request.urlopen(req, timeout=10))
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(0.2)
                continue
            raise
        except Exception:
            with lock:
                cut[0] += 1
            return  # Hub gone: this batch was not acknowledged
        assert out["accepted"] + out["duplicates"] == len(ids) and not out["rejected"], out
        with lock:
            acked.update(ids)
            if len(acked) >= 1000 and not killed.is_set():
                os.kill(int(pid), signal.SIGKILL)
                killed.set()

ts = [threading.Thread(target=worker, args=(w,)) for w in range(6)]
for t in ts: t.start()
for t in ts: t.join()
time.sleep(0.5)
con = sqlite3.connect(db)
stored = {r[0] for r in con.execute("SELECT event_id FROM events WHERE sensor_id = ? AND target = 'e2e burst'", (sensor,))}
con.close()
lost = acked - stored
print(f"acknowledged {len(acked)}, stored {len(stored)}, lost acknowledged {len(lost)}, requests cut by the kill {cut[0]}")
assert killed.is_set() and len(acked) >= 1000, "burst did not reach the kill"
assert not lost, f"{len(lost)} acknowledged events lost"
PY
start_hub
for _ in $(seq 60); do
	n=$(api GET "/nodes/$NODE" | jq '[.node.sensors[] | select(.status=="online")] | length')
	[ "$n" = 3 ] && break
	sleep 1
done
[ "$n" = 3 ] || fail "sensors did not come back online after the Hub restart"

step "silence window and docker stop tamper detection (F-005)"
api POST "/nodes/$NODE/sensors/$BURST_SENSOR/silence" -d '{"reason":"e2e maintenance","duration_seconds":3600}' |
	jq -e '.silenced == true and .silenced_reason == "e2e maintenance" and (.silenced_until | type == "string")' >/dev/null ||
	fail "silence window rejected (F-005)"
api POST "/nodes/$NODE/sensors/$BURST_SENSOR/unsilence" |
	jq -e '.silenced == false' >/dev/null ||
	fail "unsilence failed (F-005)"

docker stop "$BURST_SENSOR" >/dev/null
tamper=""
for _ in $(seq 75); do
	t=$(api GET '/events?trigger=sensor_tamper_suspected&limit=20&archived=any' | jq --arg s "$BURST_SENSOR" '[.events[] | select(.sensor_id==$s and .severity=="high")] | length')
	[ "$t" -ge 1 ] && tamper=1 && break
	sleep 1
done
[ -n "$tamper" ] || fail "docker stop on $BURST_SENSOR did not produce sensor_tamper_suspected within 2 intervals (F-005)"
docker start "$BURST_SENSOR" >/dev/null
for _ in $(seq 60); do
	n=$(api GET "/nodes/$NODE" | jq '[.node.sensors[] | select(.status=="online")] | length')
	[ "$n" = 3 ] && break
	sleep 1
done
[ "$n" = 3 ] || fail "stopped sensor did not recover after docker start (F-005)"

if [ "${KEEP:-0}" = 1 ]; then
	step "POC mode (KEEP=1): everything stays running"
	cat <<POC
Admin UI:      $HUB   (password: $PW)
Decoys:        tcp-tarpit on 2222, template on 9099, web-router-decoy on 8081
Try:           curl -s -X POST -d 'username=admin&password=x' http://127.0.0.1:8081/login
               nc -z 127.0.0.1 2222; $RUN $PCLI firedrill
Stop:          $RUN $PCLI uninstall --yes; kill \$(cat $W/hub.pid) $REGPID; docker rm -f ts-e2e-registry
Workspace:     $W
POC
	exit 0
fi

step "uninstall"
$RUN env TS_DEV_ALLOW_HTTP=true "$CLI" uninstall --yes
[ -z "$(docker ps -aq --filter label=io.truesignal.role=sensor)" ] || fail "containers left after uninstall"
echo
echo "E2E PASS: real Docker deployment of $SENSORS"
