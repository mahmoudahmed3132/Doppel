# Dedicated analytics pages (UI)

## Seam

The admin UI (`ui/`, Preact + TypeScript, strict CSP: no inline script or
style, enforced by `npm run check`). Today `ui/src/pages/modules.tsx` renders
every projection generically. Each page below replaces the generic rendering
for one projection when that projection is installed, and keeps "module not
installed" otherwise (Q56). Data comes only from
`GET /api/v3/analytics/projections/{name}?days=` and existing endpoints; no
API change.

## Pages

- **ATT&CK matrix** (`attack_matrix`): a grid with tactics as columns (the
  `tactics` order in the DTO) and techniques as cells; cell intensity from
  primary events, a marker for secondary-only; a cell opens a side panel with
  counts, sources, triggers and last seen. Keep the Navigator layer download.
- **Geo map** (`geo_map`): a world map with one marker per point (size by
  events, colour by highest severity), a country table, and the counts of
  located, internal and unlocated events. Country outlines may come from
  Natural Earth 1:110m via the `world-atlas` npm package (ISC; record it in
  `THIRD_PARTY.md`), rendered as inline SVG paths built at build time (no
  runtime fetch, no inline style). Show the DB-IP credit whenever the map is
  shown.
- **Attack path** (`attack_path`): a source picker (the top sources from the
  `sources` projection, plus free text), the steps in order as a horizontal
  path (node, sensor, first and last seen, triggers, techniques), the tactic
  progression, and the timeline table.
- **Scans / sources** (`sources`): a table with sort and filter by label
  (internal, external, whitelisted, known scanner, multi-decoy (more than one
  decoy), repeat (more than one event)), linking each source to its attack
  path.
- **Report** (`report`): a printable page (print stylesheet, no navigation)
  with the period picker (`from`, `to`), the severity summary, the daily
  chart, top sources, assets, techniques and honeytoken uses.
- **Assets** editor: a table editor (add, edit, delete rows, CSV import and
  export with formula-injection-safe export) over `GET`/`PUT /api/v3/assets`,
  keeping the JSON editor as an advanced view.

## Rules

Escape everything (Preact does). No new runtime dependencies beyond
`world-atlas`, unless a QUESTIONS entry approves one. Keyboard accessible;
works in light and dark themes. Tests: the UI type check and safety lint
pass; add rendering tests if the UI gets a test runner.
