# Insights projection (dashboard coverage and per-decoy-type activity)

## Seam

`ported.Projection` named `insights`, registered in
`hub/cmd/truesignal-hub/main.go` next to the other projections
(`hub/internal/projections`). It receives the Hub's window of enriched events
(`domain.EnrichedEvent`, at most the Hub's projection cap) and the bounded
query parameters. It may also be given read access to the fleet (nodes and
sensors from `store.DB`) and to the honeytoken list through a small
interface passed at construction.

## Output (JSON object)

- `window`: the number of days the Hub used.
- `coverage`: decoys deployed (sensor instances), nodes with at least one
  decoy, nodes without one, sensors online (from the liveness status),
  honeytokens planted, beacons active (if a beacon lister is provided).
- `by_type`: one row per catalogue sensor name: instances deployed,
  instances online, events in the window, distinct sources, the highest
  severity seen, and last event time.
- `touched`: decoy instances with at least one attacker event in the window,
  and the share of deployed instances that is.
- `top_triggers`: the ten most frequent triggers with counts.

"Attacker events" exclude Hub-raised liveness and apply-failure events, and
whitelisted or known-scanner events (count those separately as
`allowed_events`).

## Limits and errors

Unknown parameters are ignored. A fleet read error returns an error (the Hub
answers 400 with the message). Times are RFC 3339 UTC. The output must not
include event details, secrets or honeytoken secrets.

## UI

The dashboard shows `coverage` as tiles and `by_type` as a table or bar
chart, if `insights` is listed in `/system/status` `modules.projections`.
Otherwise the dashboard is unchanged.

## Tests

A table-driven test over a fixed event set and fleet, and one test through
the Hub's projection route (`hub/internal/httpapi`).
