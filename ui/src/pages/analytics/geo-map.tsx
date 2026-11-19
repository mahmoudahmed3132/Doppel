// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Geo map view (geo_map projection): offline Natural Earth 1:110m SVG world
// map compiled at build time from world-atlas, interactive severity-coded
// markers, located/internal/unlocated counters, sortable country breakdown,
// and mandatory DB-IP attribution.
import { useMemo, useState } from "preact/hooks";
import { enc } from "../../api";
import { systemStatus } from "../../app";
import { fmtNum, fmtTime } from "../../format";
import { WORLD_COUNTRIES, WORLD_HEIGHT, WORLD_VIEWBOX, WORLD_WIDTH } from "../../generated/world-paths";
import { Link } from "../../router";
import { useStore } from "../../store";
import { Alert, Card, Empty, ErrorBox, KV, Loading, Modal, PageHead, Pill, SeverityBadge } from "../../ui";
import { DaysSelect, ModuleMissing, useProjection } from "./common";

interface GeoIPStatus {
  enabled: boolean;
  path: string;
  databaseType?: string;
  buildDate?: string;
  autoUpdate: boolean;
  lastError?: string;
  attribution: string;
  attributionUrl: string;
}

interface GeoPoint {
  lat: number;
  lon: number;
  city: string;
  region: string;
  country: string;
  countryCode: string;
  events: number;
  beaconEvents: number;
  sourceCount: number;
  sources: string[];
  clientSubnets: string[];
  triggers: string[];
  maxSeverity: string;
  lastSeen: string;
}

interface GeoCountry {
  countryCode: string;
  country: string;
  events: number;
  sources: number;
}

interface GeoDTO {
  geoip: GeoIPStatus;
  events: number;
  locatedEvents: number;
  internalEvents: number;
  unlocatedEvents: number;
  points: GeoPoint[];
  countries: GeoCountry[];
}

type CountrySortKey = "country" | "events" | "sources";

function projectLon(lon: number): number {
  return Math.round(((lon + 180) * (WORLD_WIDTH / 360)) * 10) / 10;
}

function projectLat(lat: number): number {
  return Math.round(((90 - lat) * (WORLD_HEIGHT / 180)) * 10) / 10;
}

function markerRadius(events: number, maxEvents: number): number {
  if (maxEvents <= 1) return 5;
  const norm = Math.sqrt(Math.max(1, events) / maxEvents);
  return Math.round((4 + norm * 12) * 10) / 10;
}

function placeLabel(p: GeoPoint): string {
  const parts = [p.city, p.region, p.country || p.countryCode].filter(Boolean);
  return parts.length ? parts.join(", ") : `${p.lat}, ${p.lon}`;
}

export function GeoMapPage() {
  const st = useStore(systemStatus);
  const [days, setDays] = useState(30);
  const [selected, setSelected] = useState<GeoPoint | null>(null);
  const [sortKey, setSortKey] = useState<CountrySortKey>("events");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const installed = !!st?.modules.projections.includes("geo_map");
  const data = useProjection<GeoDTO>("geo_map", { days }, installed);

  const maxPointEvents = useMemo(
    () => Math.max(1, ...(data.data?.points ?? []).map((p) => p.events)),
    [data.data],
  );

  const sortedCountries = useMemo(() => {
    const list = [...(data.data?.countries ?? [])];
    list.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "country") cmp = (a.country || a.countryCode).localeCompare(b.country || b.countryCode);
      else if (sortKey === "sources") cmp = a.sources - b.sources;
      else cmp = a.events - b.events;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return list;
  }, [data.data, sortKey, sortDir]);

  const toggleSort = (key: CountrySortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir(key === "country" ? "asc" : "desc");
    }
  };

  if (!st) return <Loading />;
  if (!installed) {
    return (
      <div class="stack-lg">
        <PageHead title="Geo map" sub="Event sources by location." />
        <ModuleMissing name="Geo map" />
      </div>
    );
  }

  const dto = data.data;
  const creditText = dto?.geoip?.attribution || "IP Geolocation by DB-IP";
  const creditUrl = dto?.geoip?.attributionUrl || "https://db-ip.com";

  return (
    <div class="stack-lg">
      <PageHead
        title="Geo map"
        sub="Public event sources and beacon hits placed by IP geolocation."
        actions={<DaysSelect days={days} onChange={setDays} />}
      />
      <ErrorBox error={data.error} retry={data.reload} />
      {data.loading && !dto ? (
        <Loading />
      ) : dto ? (
        <>
          {!dto.geoip?.enabled ? (
            <Alert kind="info">
              <span>
                GeoIP database is not loaded{dto.geoip?.lastError ? ` (${dto.geoip.lastError})` : ""}. Provide a DB-IP City Lite MMDB file to plot public sources on the map.
              </span>
            </Alert>
          ) : null}

          <div class="counters counters-4">
            <div class="counter">
              <div class="counter-value">{fmtNum(dto.events)}</div>
              <div class="counter-label">Attacker events</div>
            </div>
            <div class="counter">
              <div class="counter-value">{fmtNum(dto.locatedEvents)}</div>
              <div class="counter-label">Located</div>
            </div>
            <div class="counter">
              <div class="counter-value">{fmtNum(dto.internalEvents)}</div>
              <div class="counter-label">Internal (private)</div>
            </div>
            <div class="counter">
              <div class="counter-value">{fmtNum(dto.unlocatedEvents)}</div>
              <div class="counter-label">Unlocated</div>
            </div>
          </div>

          <Card
            title="World activity map"
            actions={
              dto.geoip?.enabled && dto.geoip.buildDate ? (
                <span class="muted">DB build {dto.geoip.buildDate}</span>
              ) : undefined
            }
          >
            <div class="world-map-wrap">
              <svg
                class="world-map"
                viewBox={WORLD_VIEWBOX}
                role="img"
                aria-label={`World map showing ${dto.points.length} located activity points across ${dto.countries.length} countries`}
              >
                <rect class="world-ocean" x="0" y="0" width={WORLD_WIDTH} height={WORLD_HEIGHT} />
                <line class="world-grid" x1="0" y1={WORLD_HEIGHT / 2} x2={WORLD_WIDTH} y2={WORLD_HEIGHT / 2} />
                <line class="world-grid" x1={WORLD_WIDTH / 2} y1="0" x2={WORLD_WIDTH / 2} y2={WORLD_HEIGHT} />
                <g class="world-countries">
                  {WORLD_COUNTRIES.map((c) => (
                    <path key={`${c.id}-${c.name}`} class="world-land" d={c.d}>
                      <title>{c.name}</title>
                    </path>
                  ))}
                </g>
                <g class="world-markers">
                  {dto.points.map((p, idx) => {
                    const cx = projectLon(p.lon);
                    const cy = projectLat(p.lat);
                    const r = markerRadius(p.events, maxPointEvents);
                    const label = `${placeLabel(p)}: ${p.events} events (${p.maxSeverity})`;
                    return (
                      <circle
                        key={`${p.lat},${p.lon},${idx}`}
                        class={`geo-marker geo-sev-${p.maxSeverity}`}
                        cx={cx}
                        cy={cy}
                        r={r}
                        tabIndex={0}
                        role="button"
                        aria-label={label}
                        onClick={() => setSelected(p)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            setSelected(p);
                          }
                        }}
                      >
                        <title>{label}</title>
                      </circle>
                    );
                  })}
                </g>
              </svg>
            </div>
            <div class="row between geo-foot">
              <div class="row geo-legend" aria-hidden="true">
                <span class="muted">Severity:</span>
                {["critical", "high", "medium", "low", "info"].map((sev) => (
                  <span class="geo-legend-item" key={sev}>
                    <svg width="10" height="10" viewBox="0 0 10 10"><circle class={`geo-marker geo-sev-${sev}`} cx="5" cy="5" r="4" /></svg>
                    <span>{sev}</span>
                  </span>
                ))}
              </div>
              <p class="credit">
                <a href={creditUrl} rel="noopener noreferrer" target="_blank">{creditText}</a>
              </p>
            </div>
          </Card>

          <Card title="Countries">
            {sortedCountries.length ? (
              <div class="table-wrap">
                <table class="table">
                  <thead>
                    <tr>
                      <th aria-sort={sortKey === "country" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
                        <button type="button" class="sort-btn" onClick={() => toggleSort("country")}>
                          Country {sortKey === "country" ? (sortDir === "asc" ? "▲" : "▼") : ""}
                        </button>
                      </th>
                      <th aria-sort={sortKey === "events" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
                        <button type="button" class="sort-btn" onClick={() => toggleSort("events")}>
                          Events {sortKey === "events" ? (sortDir === "asc" ? "▲" : "▼") : ""}
                        </button>
                      </th>
                      <th aria-sort={sortKey === "sources" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
                        <button type="button" class="sort-btn" onClick={() => toggleSort("sources")}>
                          Distinct sources {sortKey === "sources" ? (sortDir === "asc" ? "▲" : "▼") : ""}
                        </button>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedCountries.map((c) => (
                      <tr key={c.countryCode}>
                        <td>
                          <span class="mono muted">{c.countryCode}</span>{" "}
                          <span>{c.country || "Unknown"}</span>
                        </td>
                        <td class="num strong">{fmtNum(c.events)}</td>
                        <td class="num">{fmtNum(c.sources)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty>No geolocated events in this window.</Empty>
            )}
          </Card>

          <Modal
            side
            open={!!selected}
            title={selected ? placeLabel(selected) : "Location"}
            onClose={() => setSelected(null)}
          >
            {selected ? (
              <div class="stack-lg">
                <KV
                  rows={[
                    ["Location", placeLabel(selected)],
                    ["Coordinates", <span class="mono">{selected.lat}, {selected.lon}</span>],
                    ["Max severity", <SeverityBadge sev={selected.maxSeverity} />],
                    ["Events", <span class="num strong">{fmtNum(selected.events)}</span>],
                    ["Beacon events", <span class="num">{fmtNum(selected.beaconEvents)}</span>],
                    ["Distinct sources", <span class="num">{fmtNum(selected.sourceCount)}</span>],
                    ["Last seen", fmtTime(selected.lastSeen)],
                  ]}
                />
                <div class="stack">
                  <h3>Sources ({selected.sources?.length ?? 0}{selected.sourceCount > (selected.sources?.length ?? 0) ? ` of ${selected.sourceCount}` : ""})</h3>
                  {selected.sources?.length ? (
                    <div class="row">
                      {selected.sources.map((src) => (
                        <Link key={src} href={`/attack-path?source=${enc(src)}`} class="tag mono">
                          {src}
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <p class="muted">None</p>
                  )}
                </div>
                {selected.clientSubnets?.length ? (
                  <div class="stack">
                    <h3>Client subnets</h3>
                    <div class="row">
                      {selected.clientSubnets.map((sub) => (
                        <Pill key={sub} kind="info">{sub}</Pill>
                      ))}
                    </div>
                  </div>
                ) : null}
                <div class="stack">
                  <h3>Triggers</h3>
                  {selected.triggers?.length ? (
                    <div class="row">
                      {selected.triggers.map((tr) => (
                        <span key={tr} class="tag mono">{tr}</span>
                      ))}
                    </div>
                  ) : (
                    <p class="muted">None</p>
                  )}
                </div>
              </div>
            ) : null}
          </Modal>
        </>
      ) : null}
    </div>
  );
}
