# Operations guide

Deploy, upgrade, roll back and recover a TrueSignal Hub, nodes and the sensor
registry. Image: `ghcr.io/mahmoudahmed3132/ts-hub`; sensors:
`ghcr.io/mahmoudahmed3132/ts-sensor-<name>` (Q60).

## 1. Verify before you run anything

Every Hub image, CLI binary and sensor manifest is signed keyless by the
workflow that built it, at the release tag. Verify the identity, not just
"a valid signature":

```sh
# Hub image (digest from the release notes)
cosign verify ghcr.io/mahmoudahmed3132/ts-hub@sha256:<digest> \
  --certificate-identity https://github.com/mahmoudahmed3132/TrueSignal-Rewrite/.github/workflows/publish-hub.yml@refs/tags/hub/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# CLI binary (install.sh does this automatically when cosign is installed)
cosign verify-blob --bundle truesignal-linux-amd64.sigstore.json \
  --certificate-identity https://github.com/mahmoudahmed3132/TrueSignal-Rewrite/.github/workflows/publish-cli.yml@refs/tags/cli/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com truesignal-linux-amd64
```

Sensor manifests are verified by the Hub itself (PORTED verifier) against
`publish-sensor.yml@refs/tags/sensor/<name>/v<version>`; production Hubs
refuse unsigned manifests and unpinned images.

## 2. Deploy the Hub

1. Copy `deploy/compose.yaml`, replace `<digest>` with the verified digest.
   Never deploy `:latest` in production: `:latest` exists for discovery only
   and always equals the highest signature-verified release.
2. `docker compose up -d`, then read the one-time setup token from the log:
   `docker compose logs hub | grep setup_token`.
3. Put a TLS reverse proxy in front (the Hub listens on 127.0.0.1:8080). It
   must pass WebSocket upgrades for `/api/v3/live` and set
   `X-Forwarded-For` / `X-Forwarded-Proto`; list its address in
   `TS_TRUSTED_PROXIES` (otherwise client IPs, lockout and HSTS are wrong).
   Example (nginx):

   ```nginx
   location / {
     proxy_pass http://127.0.0.1:8080;
     proxy_http_version 1.1;
     proxy_set_header Upgrade $http_upgrade;
     proxy_set_header Connection $connection_upgrade;   # map $http_upgrade
     proxy_set_header Host $host;
     proxy_set_header X-Forwarded-For $remote_addr;      # overwrite, do not append
     proxy_set_header X-Forwarded-Proto https;
     client_max_body_size 2m;
   }
   ```
4. Open the UI, complete setup (token, password ≥ 12, the public https
   endpoint nodes will use), enrol MFA (`TS_REQUIRE_MFA=true` forces it).
5. Settings → SIEM output: TLS syslog to your collector, then **Send test
   record**. Audit records and events flow there; the Hub is not the system
   of record for PCI DSS 10.x retention.

Back up the `hub-data` volume (SQLite database) with the Hub stopped, or use
`sqlite3 truesignal.db ".backup out.db"` while running. It contains the argon2id
password hash, node-key hashes and, **in plaintext**, the Hub master keys, the SIEM
token, the webhook URL and the TOTP seed: encrypt backups and restrict the
volume to the Hub user (see THREATMODEL.md R1).

## 3. Upgrade the Hub

1. Read the release notes; verify the new digest (§1).
2. Edit the digest in `compose.yaml`, `docker compose up -d`.
3. On a schema change the Hub writes `<db>.pre-v<N>-<timestamp>.bak` next to
   the database (`VACUUM INTO`) **before** migrating, and refuses to migrate
   if the snapshot fails.

## 4. Roll back the Hub

* Same schema: put the previous digest back and restart.
* After a migration: the old binary refuses a newer schema (by design). Stop
  the Hub, replace the database with the `.pre-v<N>-…bak` snapshot, start the
  previous digest. Events received since the upgrade are lost from the Hub
  (they remain in the SIEM).

## 5. Nodes and the CLI

Install with the verified installer (checks `SHA256SUMS`, the `--sha256` pin
and, with cosign present, the signature):

```sh
curl -fsSLO https://raw.githubusercontent.com/mahmoudahmed3132/TrueSignal-Rewrite/cli/v<version>/install.sh
sudo sh install.sh --version <version> --sha256 <hash from SHA256SUMS>
sudo TS_NODE_KEY=<key> truesignal link https://hub.example.com
sudo truesignal apply
```

The node key is shown once at node creation; rotate it from the node page if
it may have leaked (the old key stops working immediately). Upgrade the CLI by
re-running the installer with the new version.

## 6. Sensor registry rollback

A bad sensor version is withdrawn by **Actions → registry-rollback → Run
workflow** (sensor name, typed twice). The latest version is marked
`deprecated`; Hubs stop offering it and the previous version becomes latest
at their next catalogue refresh (Settings → Catalogue → Refresh now to force
it). Nothing is deleted; versions are immutable. Deployed instances keep
running the deprecated version until you upgrade/downgrade them from the
node page.

## 7. Sigstore trusted root and signer identity

Hubs verify sensor manifests offline against the Sigstore public-good trusted
root embedded in the binary (`hub/internal/signing/trusted_root.json`, sha256
recorded next to its `//go:embed` in `signing.go`). Signatures must come from
`https://github.com/<TS_MANIFEST_SIGNER_REPO>/.github/workflows/publish-sensor.yml@refs/tags/sensor/<name>/v<version>`
(default repository `mahmoudahmed3132/TrueSignal-Rewrite`).

* **Refresh the embedded root** (with a Hub release, or when Sigstore rotates
  keys): fetch `trusted_root.json` through the TUF client of the
  `sigstore/root-signing` repository (for example `sigstore-go`'s
  `pkg/tuf` client), never by a plain download; replace the
  file, update the sha256 comment, run `go test ./internal/signing` (it
  verifies the real published bundles), release the Hub.
* **Override at runtime** without a release: `TS_SIGSTORE_TRUSTED_ROOT=/path/trusted_root.json`.
  An unreadable or invalid file stops the Hub (fail closed).
* **Private registry or fork:** set `TS_MANIFEST_SIGNER_REPO=owner/repo` to the
  repository whose `publish-sensor.yml` signs your registry.

## 8. MFA break-glass

If every factor is lost:

```sh
docker compose stop hub
docker compose run --rm hub mfa-reset      # same volume, Hub stopped
docker compose up -d hub
```

`mfa-reset` removes MFA from the admin account and leaves a marker that is
emitted as an audit record (`mfa.reset_cli`) to the SIEM at next start.
Re-enrol immediately. Access to the Docker host is therefore equivalent to
admin access; restrict it accordingly.

## 9. Releasing (maintainers)

* Bump the version in code (`hub/cmd/truesignal-hub/main.go`,
  `cli/cmd/truesignal/main.go`, or `sensors/<name>/manifest.json` version and
  `image.tag`), merge to the default branch, then from that commit:
  `make tag-hub`, `make tag-cli`, `make tag-sensor NAME=<name>` or
  `make tag-sensors`. Each tag is pushed alone.
* Publish workflows refuse: a tag whose version differs from the code, a
  tagged commit not on the default branch, and any already published
  version (Hub image tag exists; CLI release has assets; sensor version in
  the registry or its image tag exists).
* Repository settings the workflows rely on (not expressible in code):
  - a **tag ruleset** on `hub/v*`, `cli/v*`, `sensor/**` blocking update and
    deletion (immutable tags) and restricting creation to maintainers;
  - a **branch ruleset** on `registry` allowing pushes only from GitHub
    Actions (the publish/rollback workflows);
  - GHCR packages `ts-hub` and `ts-sensor-*` linked to this repository with
    Actions write access; public visibility if nodes pull anonymously;
  - Actions → "Read and write permissions" are **not** needed: each job
    requests the minimum via `permissions:`.
