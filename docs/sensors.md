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
| `remote-access-decoy` | 0 | `NET_BIND_SERVICE` | host | SSH 22, Telnet 23 and FTP 21 (ports below 1024 in host networking) |
| `database-decoy` | 65532 | none | host | MySQL 3306, PostgreSQL 5432 and MS SQL Server 1433 (all default ports ≥ 1024) |
| `identity-decoy` | 0 | `NET_BIND_SERVICE` | host | LDAP 389 and LDAPS 636 (ports below 1024 in host networking), plus RDP 3389 |
| `network-service-decoy` | 0 | `NET_BIND_SERVICE` | host | SNMP UDP 161 and DNS UDP/TCP 53 (ports below 1024 in host networking) |
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
| `remote-access-decoy` | `ssh_login` | high | `protocol=ssh, dst_port, username, method` (`password`, `keyboard-interactive`, `publickey`), `client_version`, `password_hmac`/`password_length` (or `key_type`/`key_fingerprint`), `suppressed_since_last` |
| `remote-access-decoy` | `ssh_connection` | medium | `protocol=ssh, dst_port, client_version` (when sent), `suppressed_since_last` |
| `remote-access-decoy` | `telnet_login` | high | `protocol=telnet, dst_port, username, env_user` (when sent via RFC 1572), `password_hmac`/`password_length`, `suppressed_since_last` |
| `remote-access-decoy` | `telnet_connection` | medium | `protocol=telnet, dst_port, env_user` (when sent), `suppressed_since_last` |
| `remote-access-decoy` | `ftp_login` | high | `protocol=ftp, dst_port, username, anonymous, password_hmac`/`password_length`, `suppressed_since_last` |
| `remote-access-decoy` | `ftp_connection` | medium | `protocol=ftp, dst_port, username` (when `USER` sent without `PASS`), `suppressed_since_last` |
| `database-decoy` | `mysql_login` | high | `protocol=mysql, dst_port, username, database, auth_plugin, client_name, client_version, program_name, password_supplied, auth_response_hmac`/`auth_response_length`, `suppressed_since_last` |
| `database-decoy` | `mysql_connection` | medium | `protocol=mysql, dst_port, ssl_requested` (when `SSLRequest` sent), `suppressed_since_last` |
| `database-decoy` | `postgres_login` | high | `protocol=postgres, dst_port, username, database, application_name, password_hmac`/`password_length`, `suppressed_since_last` |
| `database-decoy` | `postgres_connection` | medium | `protocol=postgres, dst_port, username, database, application_name, ssl_requested, gss_requested`, `suppressed_since_last` |
| `database-decoy` | `mssql_login` | high | `protocol=mssql, dst_port, username, hostname, app_name, server_name, library_name, database, password_hmac`/`password_length`, `suppressed_since_last` |
| `database-decoy` | `mssql_connection` | medium | `protocol=mssql, dst_port, suppressed_since_last` |
| `identity-decoy` | `ldap_login` | high | `protocol=ldap, dst_port, auth` (`simple`, `ntlm`), `bind_dn`, `username`, `domain`, `workstation`, `sasl_mechanism`, `password_hmac`/`password_length` or `ntlm_response_hmac`/`ntlm_response_length`, `suppressed_since_last` |
| `identity-decoy` | `ldap_query` | medium | `protocol=ldap, dst_port, base_dn, scope, filter`, `suppressed_since_last` |
| `identity-decoy` | `ldap_connection` | medium | `protocol=ldap, dst_port, suppressed_since_last` |
| `identity-decoy` | `ldaps_login` | high | `protocol=ldaps, dst_port, auth` (`simple`, `ntlm`), `bind_dn`, `username`, `domain`, `workstation`, `sasl_mechanism`, `password_hmac`/`password_length` or `ntlm_response_hmac`/`ntlm_response_length`, `suppressed_since_last` |
| `identity-decoy` | `ldaps_query` | medium | `protocol=ldaps, dst_port, base_dn, scope, filter`, `suppressed_since_last` |
| `identity-decoy` | `ldaps_connection` | medium | `protocol=ldaps, dst_port, suppressed_since_last` |
| `identity-decoy` | `rdp_login` | high | `protocol=rdp, dst_port, auth=credssp_ntlm, username, domain, workstation, cookie_user, ntlm_challenge, ntlm_response_hmac`/`ntlm_response_length`, `suppressed_since_last` |
| `identity-decoy` | `rdp_connection` | medium | `protocol=rdp, dst_port, nla_offered, username`/`cookie_user` (when `mstshash=` cookie sent), `suppressed_since_last` |
| `network-service-decoy` | `snmp_query` | medium (`high` for `SetRequest`) | `protocol=snmp, dst_port, version` (`1`, `2c`, `3`), `pdu_type`, `oids` (≤ 16), `community_hmac`/`community_length` (v1/v2c), `username`, `security_level`, `engine_discovery` (v3), `suppressed_since_last` |
| `network-service-decoy` | `dns_query` | medium (`high` for TCP `AXFR`/`IXFR`) | `protocol=dns, transport` (`udp`, `tcp`), `dst_port, qname, qtype, qclass, suppressed_since_last` |

## Honeytoken matching contract (for the PORTED matcher)

`password_hmac` = lowercase hex of HMAC-SHA256(*capture key*, password),
where *capture key* = HMAC-SHA256(capture master key, node id) — the bytes
the Hub injects as hex in `TS_CAPTURE_KEY`. The matcher recomputes it for
the honeytoken secret with the event's node id.

## PORTED seams in sensors

| Sensor | Seam | Module / stub |
|---|---|---|
| file-canary | `LureGenerator{Content(path, honeytoken) (bytes, category), Category(path)}` (`sensors/file-canary/lure.go`) | **installed** (`lures_generated.go`, merge import S1): `.env`, PHP config, `.pgpass`, SQL dump / `.bak`, VPN/WireGuard key file, generic note, chosen by file name; every lure embeds the honeytoken, all other secrets are random, all hosts loopback. The plain `stubLures` stays as the test stub |
| web-router-decoy | `Skins{Skin(name)}` / `Skin{Name, LoginPaths, Render(kind, request)}` (`sensors/web-router-decoy/skin.go`) | **installed** (`skins_builtin.go`, merge import S2): `TS_SKIN` = `generic` (base page), `router`, `nas`, `vpn`, `webmail`, `admin` or `basic` (HTTP Basic challenge); every value is rendered through `html/template`, and every page carries a realistic `Server` header. `stubSkins` stays as the test stub. Custom skins (Doppel `TS_SKIN_JSON`) are not imported |

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
* **remote-access-decoy** — emulates SSH 2.0 (`golang.org/x/crypto/ssh`),
  Telnet (RFC 854/1572 IAC state machine) and FTP (RFC 959). Every login fails
  with wire-accurate rejection responses; no shells, data channels or
  forwarding exist. The SSH Ed25519 host key is derived deterministically in
  memory from `TS_CAPTURE_KEY` and `TS_SENSOR_ID` (never written to disk).
  Per-protocol `enabled_key` flags ensure disabled protocols do not hold ports.
* **database-decoy** — emulates MySQL/MariaDB (Protocol 10 handshake,
  `HandshakeResponse41`, `ERR 1045` / SQLSTATE `28000`), PostgreSQL v3
  (`SSLRequest`/`GSSENCRequest` → `'N'`, `CancelRequest` silent close,
  `StartupMessage`, `AuthenticationCleartextPassword`, `ErrorResponse 28P01`)
  and Microsoft SQL Server / MS-TDS 7.x (`PRELOGIN` with `ENCRYPT_NOT_SUP`,
  `LOGIN7` with nibble-swap + XOR `0xA5` password de-obfuscation, `ERROR 18456`
  + `DONE`). Stdlib only; runs unprivileged (`65532:65532`, no capabilities)
  with per-protocol `enabled_key` flags.
* **identity-decoy** — emulates Active Directory LDAP (389), LDAPS (636) and
  RDP with NLA/CredSSP (3389) using `sdk/go/ber` for all BER/DER parsing and
  encoding, plus a shared MS-NLMP (NTLM Type 1/2/3 + SPNEGO) engine. Generates
  a fresh ephemeral self-signed ECDSA P-256 TLS certificate in memory at
  startup for the persona hostname (never written to disk). LDAP supports
  simple bind (AD `data 52e` diagnostic), anonymous bind + RootDSE search,
  SASL/Sicily NTLM, and refuses StartTLS (`unavailable`); RDP negotiates
  X.224 + `mstshash=` cookie + TLS upgrade + CredSSP `TSRequest` NTLM and
  fails with `STATUS_LOGON_FAILURE`. Per-protocol `enabled_key` flags ensure
  disabled protocols do not hold ports.
* **network-service-decoy** — emulates SNMP v1/v2c/v3 (UDP 161, parsed and
  encoded strictly via `sdk/go/ber`) and log-only DNS (UDP/TCP 53, RFC 1035)
  using `sdk/go/decoy.ServePacket` for UDP listeners. SNMP v1/v2c answers only
  `GetRequest`/`GetNextRequest` for the system group (`1.3.6.1.2.1.1.{1..6}`)
  when `TS_SNMP_COMMUNITY` is set and matches in constant time (silent drop
  otherwise); `SetRequest` is reported at `high` severity and never applied;
  SNMP v3 replies only with a USM `Report` PDU (`usmStatsUnknownEngineIDs`)
  carrying a deterministic engine ID for engine discovery. DNS never resolves,
  recurses or forwards, replying `REFUSED` echoing only the question (`AXFR`/
  `IXFR` over TCP at `high` severity). Strict anti-amplification guards enforce
  a per-source UDP reply rate limiter (`TS_REPLY_RATE_PER_SEC`), DNS reply
  size ≤ request size, and SNMP reply size ≤ request size + 64 bytes.

## Helpers for service decoys (clean specs)

- `sdk/go/ber`: strict BER reader and small writer (definite lengths only; length checked against the bytes present before slicing; fixed maxima for message size, tag number, length field and nesting depth; minimal-encoding integers and OIDs). Used by LDAP and SNMP. `FuzzReader` covers the reader.
- `sdk/go/decoy.ServePacket(ctx, pc, maxSize, handle)`: UDP counterpart of `Accept`. Datagrams are copied, truncated at `maxSize`, and handled on the read goroutine (handlers must not block). Replies must not exceed the request (anti-amplification).
- Manifest `runtime.listen_ports[].enabled_key`: a decoy declares one `bool` enable flag and one `port` key per protocol; while the flag is `false` the port is not conflict-checked (rule 7) or published. UID and capabilities in a manifest are static, so a decoy whose defaults are below 1024 runs UID 0 with `NET_BIND_SERVICE` only (Q47, Q73).
