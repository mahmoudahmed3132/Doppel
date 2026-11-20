// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Scans / sources view (sources projection): sortable, filterable table of
// event sources with classification filter chips and direct deep links into
// the Attack path view.
import { useMemo, useState } from "preact/hooks";
import { enc } from "../../api";
import { fmtNum, fmtTime } from "../../format";
import { Link } from "../../router";
import { Card, Empty, ErrorBox, Loading, PageHead, Pill } from "../../ui";
import { criticalityKind, DaysSelect, useProjection } from "./common";
import type { SourceProfile } from "./common";

type FilterChip = "all" | "internal" | "external" | "multi-decoy" | "repeat" | "known-scanner" | "whitelisted";
type SortKey = "source" | "events" | "decoys" | "firstSeen" | "lastSeen";
type GroupBy = "ip" | "subnet24" | "subnet64" | "asn";

const FILTERS: [FilterChip, string][] = [
  ["all", "All"],
  ["internal", "Internal"],
  ["external", "External"],
  ["multi-decoy", "Multi-decoy"],
  ["repeat", "Repeat"],
  ["known-scanner", "Known scanner"],
  ["whitelisted", "Whitelisted"],
];

function isMultiDecoy(s: SourceProfile): boolean {
  return s.decoys > 1 || (s.labels ?? []).includes("multi-decoy");
}

function isRepeat(s: SourceProfile): boolean {
  return s.events > 1 || (s.labels ?? []).includes("repeat");
}

function isHostLocal(s: SourceProfile): boolean {
  return (s.labels ?? []).includes("host_local");
}

function matchesFilter(s: SourceProfile, filter: FilterChip): boolean {
  switch (filter) {
    case "all": return true;
    case "internal": return s.internal;
    case "external": return !s.internal;
    case "multi-decoy": return isMultiDecoy(s);
    case "repeat": return isRepeat(s);
    case "known-scanner": return s.knownScanner;
    case "whitelisted": return s.whitelisted;
  }
}

export function SourcesPage() {
  const [days, setDays] = useState(30);
  const [groupBy, setGroupBy] = useState<GroupBy>("ip");
  const [filter, setFilter] = useState<FilterChip>("all");
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("events");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const data = useProjection<{ sources: SourceProfile[] }>("sources", { days, group_by: groupBy });

  const allSources = data.data?.sources ?? [];

  const counts = useMemo(() => {
    const map: Record<FilterChip, number> = {
      all: allSources.length,
      internal: 0,
      external: 0,
      "multi-decoy": 0,
      repeat: 0,
      "known-scanner": 0,
      whitelisted: 0,
    };
    for (const s of allSources) {
      if (s.internal) map.internal++;
      else map.external++;
      if (isMultiDecoy(s)) map["multi-decoy"]++;
      if (isRepeat(s)) map.repeat++;
      if (s.knownScanner) map["known-scanner"]++;
      if (s.whitelisted) map.whitelisted++;
    }
    return map;
  }, [allSources]);

  const rows = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = allSources.filter((s) => {
      if (!matchesFilter(s, filter)) return false;
      if (!q) return true;
      return (
        s.source.toLowerCase().includes(q) ||
        (s.asset?.name ?? "").toLowerCase().includes(q)
      );
    });
    filtered.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "source") cmp = a.source.localeCompare(b.source);
      else if (sortKey === "decoys") cmp = a.decoys - b.decoys;
      else if (sortKey === "firstSeen") cmp = a.firstSeen.localeCompare(b.firstSeen);
      else if (sortKey === "lastSeen") cmp = a.lastSeen.localeCompare(b.lastSeen);
      else cmp = a.events - b.events;
      if (cmp === 0) cmp = a.source.localeCompare(b.source);
      return sortDir === "asc" ? cmp : -cmp;
    });
    return filtered;
  }, [allSources, filter, search, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir(key === "source" ? "asc" : "desc");
    }
  };

  return (
    <div class="stack-lg">
      <PageHead
        title="Scans"
        sub="Observed sources classified by scope, persistence, and asset inventory. Click any source to inspect its attack path."
        actions={
          <div class="row">
            <label class="inline-field">
              <span>Group by</span>
              <select class="input" value={groupBy} onChange={(e) => setGroupBy(e.currentTarget.value as GroupBy)}>
                <option value="ip">IP</option>
                <option value="subnet24">/24 subnet</option>
                <option value="subnet64">/64 subnet</option>
                <option value="asn">ASN</option>
              </select>
            </label>
            <DaysSelect days={days} onChange={setDays} />
          </div>
        }
      />
      <ErrorBox error={data.error} retry={data.reload} />
      {data.loading && !data.data ? (
        <Loading />
      ) : (
        <Card>
          <div class="stack">
            <div class="sources-toolbar">
              <div class="row" role="group" aria-label="Source filters">
                {FILTERS.map(([key, label]) => (
                  <button
                    type="button"
                    key={key}
                    aria-pressed={filter === key}
                    class={`chip filter-chip${filter === key ? " filter-chip-on" : ""}`}
                    onClick={() => setFilter(key)}
                  >
                    <span>{label}</span>
                    <span class="chip-count num">{fmtNum(counts[key])}</span>
                  </button>
                ))}
              </div>
              <input
                type="search"
                class="input sources-search"
                aria-label="Filter sources by address or asset name"
                placeholder="Search IP or asset…"
                value={search}
                onInput={(e) => setSearch(e.currentTarget.value)}
              />
            </div>

            {rows.length ? (
              <div class="table-wrap">
                <table class="table">
                  <thead>
                    <tr>
                      <th aria-sort={sortKey === "source" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
                        <button type="button" class="sort-btn" onClick={() => toggleSort("source")}>
                          Source {sortKey === "source" ? (sortDir === "asc" ? "▲" : "▼") : ""}
                        </button>
                      </th>
                      <th>Labels</th>
                      <th>Asset</th>
                      <th aria-sort={sortKey === "events" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
                        <button type="button" class="sort-btn" onClick={() => toggleSort("events")}>
                          Events {sortKey === "events" ? (sortDir === "asc" ? "▲" : "▼") : ""}
                        </button>
                      </th>
                      <th aria-sort={sortKey === "decoys" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
                        <button type="button" class="sort-btn" onClick={() => toggleSort("decoys")}>
                          Decoys {sortKey === "decoys" ? (sortDir === "asc" ? "▲" : "▼") : ""}
                        </button>
                      </th>
                      <th aria-sort={sortKey === "firstSeen" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
                        <button type="button" class="sort-btn" onClick={() => toggleSort("firstSeen")}>
                          First seen {sortKey === "firstSeen" ? (sortDir === "asc" ? "▲" : "▼") : ""}
                        </button>
                      </th>
                      <th aria-sort={sortKey === "lastSeen" ? (sortDir === "asc" ? "ascending" : "descending") : "none"}>
                        <button type="button" class="sort-btn" onClick={() => toggleSort("lastSeen")}>
                          Last seen {sortKey === "lastSeen" ? (sortDir === "asc" ? "▲" : "▼") : ""}
                        </button>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((s) => (
                      <tr key={s.source}>
                        <td class="mono">
                          <Link href={`/attack-path?source=${enc(s.source)}`}>{s.source}</Link>
                        </td>
                        <td>
                          <Pill kind={s.internal ? "warn" : "info"}>{s.internal ? "internal" : "external"}</Pill>
                          {isHostLocal(s) ? <Pill kind="warn">host_local</Pill> : null}
                          {isMultiDecoy(s) ? <Pill kind="bad">multi-decoy</Pill> : null}
                          {isRepeat(s) ? <Pill kind="neutral">repeat</Pill> : null}
                          {s.knownScanner ? <Pill kind="neutral">known scanner</Pill> : null}
                          {s.whitelisted ? <Pill kind="ok">whitelisted</Pill> : null}
                        </td>
                        <td>
                          {s.asset ? (
                            <span>
                              {s.asset.name}{" "}
                              <Pill kind={criticalityKind(s.asset.criticality)}>{s.asset.criticality}</Pill>
                            </span>
                          ) : (
                            <span class="muted">—</span>
                          )}
                        </td>
                        <td class="num strong">{fmtNum(s.events)}</td>
                        <td class="num">{fmtNum(s.decoys)}</td>
                        <td class="nowrap">{fmtTime(s.firstSeen)}</td>
                        <td class="nowrap">{fmtTime(s.lastSeen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty>No sources match the current filter.</Empty>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}
