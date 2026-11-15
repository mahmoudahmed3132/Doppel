# Operations guide

Deploy, upgrade, roll back and recover a TrueSignal Hub, nodes and the sensor
registry. Image: `ghcr.io/mahmoudahmed3132/ts-hub`; sensors:
`ghcr.io/mahmoudahmed3132/ts-sensor-<name>` (Q60).

## 1. Verify before you run anything

Every Hub image, CLI binary and sensor manifest is signed keyless by the
workflow that built it, at the release tag. Verify the identity, not just
"a valid signature". The source repository is private: releases, the
installer and the sensor registry are served from the public repository
`mahmoudahmed3132/truesignal-releases`, but the signing identity is still the source repository's
workflow (it is public in every certificate and in the Rekor log):

```sh
# Hub image (digest from the release notes)
cosign verify ghcr.io/mahmoudahmed3132/ts-hub@sha256:<digest> \
  --certificate-identity https://github.com/mahmoudahmed3132/Doppel/.github/workflows/publish-hub.yml@refs/tags/hub/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# CLI binary (install.sh does this automatically when cosign is installed)
cosign verify-blob --bundle truesignal-linux-amd64.sigstore.json \
  --certificate-identity https://github.com/mahmoudahmed3132/Doppel/.github/workflows/publish-cli.yml@refs/tags/cli/v<version> \
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
curl -fsSLO https://raw.githubusercontent.com/mahmoudahmed3132/truesignal-releases/cli/v<version>/install.sh
sudo sh install.sh --version <version> --sha256 <hash from SHA256SUMS>
sudo TS_NODE_KEY=<key> truesignal link https://hub.example.com
sudo truesignal apply
```

The node key is shown once at node creation; rotate it from the node page if
it may have leaked (the old key stops working immediately). Upgrade the CLI by
re-running the installer with the new version.

## 5a. GeoIP database (DB-IP City Lite)

Locations on events, the geo-map projection and the SIEM output come from a
DB-IP IP to City Lite database (MMDB, CC BY 4.0: the UI credits DB-IP
wherever it shows a location).

* **Path:** `TS_GEOIP_DB`, default `geoip/dbip-city-lite.mmdb` next to the
  Hub database (`/data/geoip/dbip-city-lite.mmdb` in the shipped compose
  file). Without a file, events carry no location; nothing else changes.
* **Manual update (default):** download the current month's
  `dbip-city-lite-YYYY-MM.mmdb.gz` from <https://db-ip.com/db/download/ip-to-city-lite>,
  `gunzip` it and copy it to the path. The Hub re-reads the file within an
  hour, from a private copy, so it is safe to overwrite in place. A file
  that is not a City database is refused and the loaded one stays.
* **Automatic update (Q70, off by default):** `TS_GEOIP_AUTO_UPDATE=true`
  makes the Hub fetch `https://download.db-ip.com/free/dbip-city-lite-YYYY-MM.mmdb.gz`
  at start and daily when the loaded file is from an earlier month: HTTPS
  only, redirects followed only to the same host (at most 3), at most
  256 MiB compressed and 1 GiB uncompressed, validated before it replaces the
  current file. This is an outbound call in addition to Q55's list; allow
  `download.db-ip.com` in egress filtering only if you turn it on. DB-IP
  publishes no signature, so integrity rests on HTTPS.

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
(default repository `mahmoudahmed3132/Doppel`). Artefacts signed before the move
name `mahmoudahmed3132/TrueSignal-Rewrite` and verify only under that identity (§9.2).

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
* Releases, `install.sh` and the `registry` branch are published to the
  public repository `<owner>/truesignal-releases` (§9.1); the source
  repository is private. Tags, signing and `:latest` stay here.
* Repository settings the workflows rely on (not expressible in code):
  - a **tag ruleset** on `hub/v*`, `cli/v*`, `sensor/**` blocking update and
    deletion (immutable tags) and restricting creation to maintainers;
  - the `registry` branch and its ruleset now live in the releases
    repository (§9.1); the old `registry` branch here, its ruleset and the
    `REGISTRY_DEPLOY_KEY` secret and deploy key can be removed once the
    migration has been verified;
  - GHCR packages `ts-hub` and `ts-sensor-*` linked to this repository with
    Actions write access; public visibility if nodes pull anonymously;
  - Actions → "Read and write permissions" are **not** needed: each job
    requests the minimum via `permissions:`.

### 9.1 Public releases repository (`mahmoudahmed3132/truesignal-releases`)

The source repository is private, so anonymous clients (Hubs, `install.sh`,
the update check) read only from this public repository. It holds no source:
`main` carries `README.md` and `install.sh`; the `registry` branch carries the
signed manifests and `index.json`; releases carry the CLI assets and the Hub
release notes. Everything is built and signed here, in the private repository.

| Consumer | Reads |
|---|---|
| Hub catalogue (default `TS_REGISTRY_URL`) | `https://raw.githubusercontent.com/mahmoudahmed3132/truesignal-releases/registry/` |
| Hub update check (default `TS_UPDATE_CHECK_URL`) | `https://api.github.com/repos/mahmoudahmed3132/truesignal-releases/releases?per_page=100` |
| `install.sh` | releases API and `https://github.com/mahmoudahmed3132/truesignal-releases/releases/download/cli/v<version>/` |
| Signature checks (Hub, `install.sh`, cosign) | identity `https://github.com/mahmoudahmed3132/Doppel/.github/workflows/<workflow>@refs/tags/...` (releases before the move: `…/TrueSignal-Rewrite/…`, §9.2) |

`raw.githubusercontent.com` may serve a branch up to about five minutes stale
after a push. That is harmless: every manifest is versioned and signed, and
Hubs refresh periodically.

**One-time setup (owner):**

1. Create `mahmoudahmed3132/truesignal-releases` as a **public** repository with an initial commit on
   `main` (a README stating that it holds release artefacts only, and that
   the source is private).
2. Create a **GitHub App** (owner account → Settings → Developer settings →
   GitHub Apps) with no webhook and one repository permission, **Contents:
   Read and write**. Install it on `mahmoudahmed3132/truesignal-releases` **only**. Generate a private key.
3. In this repository: Actions **variable** `RELEASES_APP_CLIENT_ID` (the
   App's client ID) and Actions **secret** `RELEASES_APP_PRIVATE_KEY` (the
   PEM). Workflows mint an installation token per job, scoped to
   `truesignal-releases` with `contents: write`, valid for one hour.
4. Migrate the existing artefacts from a clone of this repository:
   `gh auth login && gh auth setup-git`, then
   `scripts/release/migrate-releases-repo.sh`. It copies the `registry`
   branch unchanged, recreates every `cli/v*` and `hub/v*` release with
   byte-identical assets, puts `install.sh` on `main`, and reads everything
   back anonymously. It is idempotent and stops on any difference.
5. Rulesets on `mahmoudahmed3132/truesignal-releases`, after the migration:
   - branches `main` and `registry`: block deletion and force pushes;
     restrict updates, with the App as the only bypass actor;
   - tags `hub/v*`, `cli/v*`: block update and deletion; restrict creation,
     with the App as the only bypass actor.
6. Remove the old `registry` branch ruleset, the `REGISTRY_DEPLOY_KEY` secret
   and the deploy key here. Keep the old releases here until existing Hubs
   have been upgraded (they still point at this repository's URLs and fail
   closed with `catalogue refresh failed` until they are upgraded or have
   `TS_REGISTRY_URL` set to the new URL).

### 9.2 Moving the source repository to `mahmoudahmed3132/Doppel` (republish plan)

Signing identities embed the source repository name, so everything signed by
`mahmoudahmed3132/TrueSignal-Rewrite` (Hub `3.0.0-rc.1`, CLI `3.0.0`, the five
sensors at `1.0.0`) verifies only under the old identity. A Hub built from
Doppel (`TS_MANIFEST_SIGNER_REPO` default `mahmoudahmed3132/Doppel`) skips the
`1.0.0` manifests and shows an empty catalogue until the sensors are
republished. `TS_MANIFEST_SIGNER_REPO=mahmoudahmed3132/TrueSignal-Rewrite` is
a temporary escape hatch for a Hub that must keep the old catalogue; it
accepts only the old manifests.

Owner steps, in order (the owner pushes every tag):

1. Push `main` to `mahmoudahmed3132/Doppel` and wait for CI and CodeQL to be
   green. Set up the tag ruleset (§9), Dependabot, and the Actions variable
   `RELEASES_APP_CLIENT_ID` and secret `RELEASES_APP_PRIVATE_KEY` in Doppel.
2. Install the `truesignal-releases` GitHub App on `mahmoudahmed3132/Doppel`
   as well, or create the rebranded successor App with the same single
   permission and install it on `truesignal-releases` only. The App's
   installation on the releases repository is what grants write access; the
   Doppel repository only holds its client ID and key. Remove the variable,
   secret and App installation from `TrueSignal-Rewrite` once step 5 is done.
3. Republish the five sensors at `1.0.1` from Doppel: bump each
   `sensors/<name>/manifest.json` to `1.0.1` in one reviewed PR, merge it,
   then `make tag-sensors` (one tag per push). The publish workflow signs with
   the Doppel identity and commits each manifest to the `registry` branch of
   `truesignal-releases`.
4. Cut a new CLI release (for example `cli/v3.1.0`, with the `doppel` binary
   name, Q66): bump the CLI version, merge, `make tag-cli`. `install.sh` from
   Doppel verifies `publish-cli.yml` of Doppel; the `cli/v3.0.0` assets keep
   verifying only under the old identity.
5. Release the Hub as `3.0.0-rc.2` (or `3.0.0` once the release candidate is
   accepted): bump `Version` in `hub/cmd/truesignal-hub/main.go`, merge,
   `make tag-hub`. Verify it with the §1 commands (Doppel identity).
6. Upgrade existing Hubs to that release. Their catalogue now lists the
   `1.0.1` sensors; upgrade deployed sensors from the node page.
7. Archive `TrueSignal-Rewrite` (read-only) after the last old Hub is
   upgraded. Its tags and Rekor entries remain the record for the old
   artefacts.

**Why a GitHub App, not a token:** the installation token is minted per job,
expires within an hour, is limited to one repository and one permission, and
is not tied to a person's account. A fine-grained PAT would be long-lived and
belong to a user.
