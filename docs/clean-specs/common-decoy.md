# Common requirements for the service decoys

Applies to `identity-decoy.md`, `database-decoy.md`, `remote-access-decoy.md`
and `network-service-decoy.md`.

## Foundations already in the repository (use them, do not write your own)

These land on `main` with the branch that carries `docs/plan/ROADMAP.md` Phase 0. Branch `clean/<spec>` from a `main` that has them.

- `sdk/go/ber`: strict BER reader and writer (LDAP, SNMP). Fuzzed. Never hand-roll BER.
- `sdk/go/decoy.ServePacket`: UDP read loop with bounded buffer and clean shutdown (SNMP, DNS).
- Manifest `runtime.listen_ports[].enabled_key`: point it at the per-protocol enable flag (a `bool` key) so a disabled protocol does not claim its default port (Q73). The CLI's discovery (`cli/internal/discover`) does not read `enabled_key`; set `discovery.defaults` for the port keys you want proposed.
- Manifest user and capabilities are static (Q73): a decoy with default ports below 1024 declares UID 0 plus `NET_BIND_SERVICE`, as `tcp-tarpit` does.

## Platform

- A Go module under `sensors/<name>`, added to `go.work`, built by a
  Dockerfile following the existing sensors (pinned base images, static
  binary, distroless runtime), and a manifest v3 (`docs/manifest-v3.md`)
  validated by `scripts/validate-docs.py`.
- Use `sdk/go/sensor` (`sensor.Main`, settings, fire drill, heartbeats,
  graceful stop) and the helpers in `sdk/go/decoy`: listener lists, the accept
  loop, sanitising, the per-source limiter and password capture. Do not add
  third-party modules unless the spec names one; record any addition in
  `THIRD_PARTY.md` (permissive licences only).
- Runtime: host networking; UID 0 with every capability dropped except
  `NET_BIND_SERVICE` when a configured port is below 1024, otherwise run
  unprivileged. Read-only filesystem, no-new-privileges, bounded memory.
- Image `ghcr.io/mahmoudahmed3132/ts-sensor-<name>`. Version `1.0.0`.

## Configuration (manifest `config`)

- One setting per protocol listener: an enable flag and a port, with the
  well-known port as default. Every enabled port is declared in
  `runtime.listen_ports` with its protocol, so the Hub refuses port conflicts
  (compose rule 7).
- `TS_PASSWORD_CAPTURE` (`hash` default, `plain`, `none`) and the
  Hub-reserved `TS_CAPTURE_KEY`, exactly as `sdk/go/decoy` reads them. In
  `hash` mode a password is reported only as `password_hmac` (lowercase hex
  HMAC-SHA256 under the node capture key) plus `password_length`, which is
  what the Hub's honeytoken matcher expects (`docs/sensors.md`).
- A per-source event cooldown and a cap on concurrent connections, total and
  per source, with sane defaults.
- Persona settings where the protocol shows identity (host name, domain,
  product version strings), with plausible defaults that never name Doppel.

## Behaviour

- **Never grant access.** Every authentication attempt fails with the
  response a real server gives for a wrong password. The decoy never runs a
  command, proxies, forwards, resolves recursively, or returns real data.
- **Bounded everything.** Read deadlines on every connection (for example 30 s
  idle, 2 min total), maximum message sizes per protocol, bounded per-source
  state, and the per-source limiter on events, with `suppressed_since_last`
  on the next event.
- **Evidence, not secrets.** Report: source address, destination port,
  protocol, attempted user name, authentication method, client software or
  version string when the protocol sends one, and password evidence per the
  capture policy. Sanitise and cap every attacker-supplied string
  (`sdk/go/decoy`). Hashes that are themselves credentials (for example
  NetNTLMv2 responses) follow the same policy: HMAC by default.
- **Triggers.** `<protocol>_login` for authentication attempts, at severity
  high (critical when the Hub matches a honeytoken; the Hub raises
  `honeytoken_used` itself) and `<protocol>_connection` for connections that
  never authenticate, at medium. These names are what Doppel's ATT&CK table
  (`docs/siem/attack-mapping.md`) and detection rules
  (`docs/siem/detection-rules.md`) already map. Use them unchanged, and add
  any new trigger to both, with a QUESTIONS entry.
- **Fire drill.** One synthetic `<protocol>_login` event with user `drill`.

## Tests

- Unit tests per protocol parser (well-formed, truncated, oversized and
  malformed input never panic and never allocate without bound).
- One end-to-end test per protocol with a real client library or hand-built
  client frames: connect, authenticate with a wrong password, see the
  failure, and see the reported fields through a fake `sensor.Reporter`.
- A fuzz test for each parser that handles untrusted bytes.
- Add the sensor to `scripts/e2e/real-docker.sh` only if it can run in CI
  without privileged ports (configure high ports there).
