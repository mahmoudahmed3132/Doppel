# Sensors

Spec §11. All sensors use the Go SDK (test mode, fire drill, heartbeats,
graceful stop), read only manifest-declared `TS_` variables, never forward
traffic, never execute received data, keep per-source state bounded and
rate-limit events per source with a `suppressed_since_last` counter.

## Privileges

Docker grants capabilities added with `cap_add` only to UID 0 (Compose has
no ambient capabilities), and `no-new-privileges` (§6.12.2) disables file
capabilities. Sensors that need a privilege therefore run as **UID 0 with
`cap_drop: ALL` plus exactly one capability**, on a read-only root filesystem
with no-new-privileges, pids and memory limits. Every sensor logs its real
uid and effective capability mask at start (`running with privileges`).

| Sensor | User | Capability | Network | Why |
|---|---|---|---|---|
| `tcp-tarpit` | 0 | `NET_BIND_SERVICE` | host | decoy ports below 1024 (SSH 22, Telnet 23, FTP 21) |
| `icmp-canary` | 0 | `NET_RAW` | host | raw ICMP socket |
| `network-scan-detector` | 0 | `NET_RAW` | host | AF_PACKET capture (headers only) |
| `file-canary` (sensor) | 0 | `DAC_OVERRIDE` | bridge | watch lure directories owned by other users; mounts are **read-only** |
| `file-canary` (init) | 0 | `DAC_OVERRIDE` | none | create lures in directories owned by other users |
| `web-router-decoy` | 65532 | none | bridge | listens on 8080 in the container; the Hub publishes host port `TS_PORT` (e.g. 80) to it |
| `token-receiver` | 0 | `NET_BIND_SERVICE` | host | DNS on 53 (UDP+TCP) and web bugs on 80, internet-facing |
| `template` | 65532 | none | host | reference |

## Triggers

| Sensor | Trigger | Default severity | Key details |
|---|---|---|---|
| tcp-tarpit | `tcp_connection` | medium | `dst_port, phase=connect, action_taken` |
| tcp-tarpit | `tcp_session_payload` | high | `dst_port, bytes_received, duration_sec, payload` (first 2 KiB, `\xHH`-escaped), `phase=close` |
| icmp-canary | `icmp_scan_received` | low | `icmp_type, icmp_code, icmp_id, icmp_seq, packet_size, ip_version` |
| network-scan-detector | `network_scan_detected` | high | `scan_type` (syn, fin, null, xmas, connect, udp), `tool_guess` (nmap, masscan, zmap or empty), `ports_hit` (≤ 64, sorted), `count, window_sec, protocol` |
| file-canary | `decoy_file_accessed` | high | `path, action` (open, read), `category`; source `local` |
| file-canary | `decoy_file_tampered` | critical | `path, action` (modify, delete, rename, attrib), `category`; source `local` |
| web-router-decoy | `web_page_view` | low | `path, method, user_agent, dst_port, skin` (once per source per window) |
| web-router-decoy | `web_path_probe` | medium | `path, method, user_agent, dst_port` |
| web-router-decoy | `web_login_attempt` | critical | `username`, `password_hmac` (default) or `password`, `auth` (form, basic), `skin`, `form_<field>` (≤ 20), `path, method, user_agent, dst_port` |
| `token-receiver` | `beacon_triggered` | critical (Hub: medium if unknown) | `token`, `channel` (dns/http), `query_name`, `query_type`, `transport`, `resolver`, `client_subnet`, `method`, `host`, `path`, `user_agent`, `referer`, `proxy`, `repeats_since_last` |
| `token-receiver` | `receiver_saturated` | medium | `listener`, `refused_per_source`, `refused_total_cap`, `distinct_sources`, `top_source_refusals` |

## Honeytoken matching contract (for the PORTED matcher)

`password_hmac` = lowercase hex of HMAC-SHA256(*capture key*, password),
where *capture key* = HMAC-SHA256(capture master key, node id) — the bytes
the Hub injects as hex in `TS_CAPTURE_KEY`. The matcher recomputes it for
the honeytoken secret with the event's node id.

## PORTED seams in sensors

| Sensor | Seam | Module / stub |
|---|---|---|
| file-canary | `LureGenerator{Content(path, honeytoken) (bytes, category), Category(path)}` (`sensors/file-canary/lure.go`) | **installed** (`lures_generated.go`, merge import S1): `.env`, PHP config, `.pgpass`, SQL dump / `.bak`, VPN/WireGuard key file, generic note, chosen by file name; every lure embeds the honeytoken, all other secrets are random, all hosts loopback. The plain `stubLures` stays as the test stub |
| web-router-decoy | `Skins{Skin(name)}` / `Skin{Name, LoginPaths, Render(kind, request)}` (`sensors/web-router-decoy/skin.go`) | **installed** (`skins_builtin.go`, merge import S2): `TS_SKIN` = `generic` (base page), `router`, `nas`, `vpn`, `webmail`, `admin` or `basic` (HTTP Basic challenge); every value is rendered through `html/template`, and every page carries a realistic `Server` header. `stubSkins` stays as the test stub. Custom skins (TrueSignal `TS_SKIN_JSON`) are not imported |

## Notes per sensor

* **tcp-tarpit** — `hold` reads 64 bytes per second until the peer gives up or
  `TS_MAX_DURATION_SEC`; `echo` returns bytes slowly; `close` sends the banner
  and closes. Caps: `TS_MAX_CONNS` total, `TS_MAX_PER_SOURCE` per IP (excess
  connections are closed silently).
* **icmp-canary** — reports requests only (IPv4 types 8, 13, 15, 17; ICMPv6 128,
  139); replies and errors are answers to the host's own traffic. The kernel
  keeps answering pings.
* **network-scan-detector** — counts only TCP segments without ACK/RST and UDP
  datagrams arriving for this host (`PACKET_HOST`), so established traffic
  and the kernel's RSTs never count. One event per source per window.
  Every inbound frame is read in user space (no BPF filter yet): CPU grows
  with packet rate.
* **file-canary** — lure directories must exist; the init container never
  overwrites a file and never follows a symlink (`O_EXCL|O_NOFOLLOW`). The
  sensor cannot see the process that touched a lure; correlate with EDR.
* **web-router-decoy** — logins always fail after a 0.3–0.9 s delay; bodies
  ≤ 16 KiB, headers ≤ 16 KiB, short timeouts; nothing is served from disk.
* **token-receiver** (merge import S4) — authoritative-only DNS for
  `TS_BEACON_DOMAIN` (SOA/NS at the apex, A from `TS_ANSWER_IPV4` inside the
  zone, NODATA for other types, REFUSED outside it; never recursion or
  forwarding) and a fixed 1x1 GIF on HTTP. A name or path counts only when it
  carries a token with a valid tag under `TS_BEACON_KEY`; one event per token
  and channel per `TS_ALERT_COOLDOWN_SEC`. TCP clients are capped (DNS 128,
  4 per source; HTTP 256, 8 per source); refusals raise `receiver_saturated`
  at most every 5 minutes per listener. The Hub resolves the token to its
  beacon; the zone must be the only deployed receiver zone for the Beacons
  page to create beacons.
