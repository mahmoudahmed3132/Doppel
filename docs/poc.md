# Try Doppel locally (POC)

One Linux host with Docker (compose plugin), Go 1.27.4+, Node 22, `jq`,
`curl` and passwordless `sudo`. From a clone of Doppel:

```bash
make ui
```

```bash
KEEP=1 scripts/e2e/real-docker.sh
```

The script builds the Hub, the `doppel` CLI and every sensor image, pushes the
images by digest to a local registry, starts the Hub in development mode,
creates a node with three decoys, links and applies with the real CLI, and
checks events, heartbeats, hardening and the fire drill. With `KEEP=1` it
stops before uninstalling and prints the admin URL, the password, the decoy
ports, and the commands to stop everything.

What to try in the UI (admin password printed by the script):

- **Events:** hit the decoys (`curl` the web decoy's login, `nc` the
  tarpit) and watch the live feed. Each event shows ATT&CK, asset and
  location enrichment.
- **Settings → MFA:** enrol with any authenticator app (issuer "Doppel").
- **Assets:** paste an inventory (format on the page) and see `source_asset`
  on new events.
- **Beacons:** needs a deployed Token Receiver with `TS_BEACON_DOMAIN`. For a
  local test, add the `token-receiver` sensor with high ports
  (`TS_DNS_PORT=5353`, `TS_HTTP_PORT=8088`) and resolve the planted name
  with `dig @127.0.0.1 -p 5353 <token>.<zone>`.
- **Analytics:** Scans, Geo map, Attack path, Report and the ATT&CK matrix
  with the Navigator layer download. For locations, put a DB-IP City Lite
  file at the path in `docs/operations.md` §5a.
- **SIEM:** Settings → SIEM, `tcp` with format `ecs` to
  `nc -lk 127.0.0.1 5140` shows the ECS documents. The rules in
  `docs/siem/` can be replayed with `scripts/siem-rules/run-elastic.sh`.

This is a development-mode Hub (unsigned local manifests, plain HTTP). Do
not expose it. Production deployment: `docs/operations.md`.
