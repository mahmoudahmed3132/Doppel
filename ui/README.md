# Admin UI

Preact + TypeScript single-page app, bundled by esbuild into
`hub/internal/webui/dist/` and embedded in the Hub binary (`//go:embed`).

```sh
npm ci --ignore-scripts   # pinned dependencies, no install scripts
npm run check             # tsc --noEmit, safety lint, build
```

Design constraints (§7, §13):

- **Strict CSP** (`default-src 'self'`): one hashed script and one hashed
  stylesheet referenced from a static `index.html`; no inline script, no inline
  style, no `style=` attributes (charts are SVG with presentation attributes
  and CSS classes). `scripts/lint-safety.mjs` fails the build on raw-HTML
  injection (`dangerouslySetInnerHTML`, `innerHTML`), `eval`, inline styles or
  external resource URLs.
- **Untrusted text**: event fields, node aliases and manifest documentation are
  attacker-influenced and are only ever rendered as text (Preact escapes it).
- **No external resources** at runtime: system font stack, no CDN, no
  analytics.
- Session cookie is HttpOnly; the UI never sees it. Non-GET requests carry
  `Origin`, which the Hub's CSRF check requires. Secrets (node keys, TOTP
  secret, recovery codes) are shown once and never stored by the UI.

## End-to-end smoke test

Not part of `make` (needs a browser). Start a fresh development Hub, then:

```sh
TS_ENV=development TS_SETUP_TOKEN=e2e-setup-token-0123456789abcdef \
TS_DEV_ALLOW_PLAINTEXT_SECRETS=1 TS_DB_PATH=/tmp/ts-e2e.db TS_LISTEN_PORT=18080 \
TS_REGISTRY_URL=http://127.0.0.1:18081/ TS_DEV_ALLOW_UNSIGNED_MANIFESTS=1 \
TS_DEV_ALLOW_UNPINNED_IMAGES=1 ./bin/truesignal-hub serve
node ui/e2e/smoke.cjs /tmp/shots
```

with a local registry on port 18081 holding the repository's sensor manifests
(see `docs/registry.md` for the layout). It covers setup, login errors, node
creation (key shown once), the manifest-generated sensor form with client-side
validation and compose preview, port-conflict reporting, event ingestion with
the node key, the live "new events" notice, the detail drawer (HTML payload
rendered as text), filters, dashboard charts, settings, module shells, the
light theme, keyboard navigation and logout, and fails on any CSP violation or
page error.
