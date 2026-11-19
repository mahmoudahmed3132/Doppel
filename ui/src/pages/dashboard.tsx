// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Dashboard: counters, severity distribution, velocity, live latest events,
// fleet health and the sensor uptime heatmap. Charts reload on the live
// feed's debounced "refresh" hint.
import { useEffect, useState } from "preact/hooks";
import { get } from "../api";
import { systemStatus } from "../app";
import { SeverityBars, UptimeHeatmap, VelocityChart } from "../charts";
import { fmtAgo, fmtNum, fmtTime } from "../format";
import { onLive } from "../live";
import { Link, navigate } from "../router";
import { useStore } from "../store";
import type { EventRecord, NodeSummary } from "../types";
import { Card, Empty, ErrorBox, Loading, PageHead, Pill, SeverityBadge, useAsync } from "../ui";

interface Summary {
  events_total: number; events_unread: number; events_24h: number; critical_24h: number;
  nodes_total: number; nodes_online: number; sensors_total: number; sensors_online: number;
}

interface InsightsCoverage {
  decoys_deployed: number;
  nodes_with_decoy: number;
  nodes_without_decoy: number;
  sensors_online: number;
  honeytokens_planted: number;
  beacons_active: number;
}

interface InsightsByType {
  sensor_type: string;
  instances_deployed: number;
  instances_online: number;
  events: number;
  distinct_sources: number;
  highest_severity: string;
  last_event_at: string;
}

interface InsightsDTO {
  window: number;
  coverage: InsightsCoverage;
  by_type: InsightsByType[];
  touched: { instances: number; total: number; ratio: number };
  top_triggers: { trigger: string; count: number }[];
  allowed_events: number;
}

export function Dashboard() {
  const st = useStore(systemStatus);
  const [tick, setTick] = useState(0);
  const hasInsights = !!st?.modules.projections.includes("insights");

  const summary = useAsync(() => get<{ summary: Summary }>("/analytics/summary").then((r) => r.summary), [tick]);
  const sev = useAsync(() => get<{ severity: Record<string, number> }>("/analytics/severity?days=7").then((r) => r.severity), [tick]);
  const vel = useAsync(() => get<{ bucket_seconds: number; series: { t: string; count: number }[] }>("/analytics/velocity?hours=24&bucket=3600"), [tick]);
  const nodes = useAsync(() => get<{ nodes: NodeSummary[] }>("/nodes").then((r) => r.nodes), [tick]);
  const uptime = useAsync(() => get<{ sensors: { node_id: string; sensor_id: string; days: string[]; percent: number[] }[] }>("/analytics/uptime?days=14"), [tick]);
  const latest = useAsync(() => get<{ events: EventRecord[] }>("/events?limit=12").then((r) => r.events), []);
  const insights = useAsync<InsightsDTO | undefined>(
    () => (hasInsights ? get<{ data: InsightsDTO }>("/analytics/projections/insights?days=7").then((r) => r.data) : Promise.resolve(undefined)),
    [hasInsights, tick],
  );

  useEffect(() => onLive((m) => {
    if (m.type === "refresh") setTick((t) => t + 1);
    if (m.type === "event" && latest.data) latest.setData([m.data, ...latest.data].slice(0, 12));
  }), [latest.data]);

  const s = summary.data;
  const ins = insights.data;
  const alias = new Map((nodes.data ?? []).map((n) => [n.id, n.alias]));
  const upRows = (uptime.data?.sensors ?? []).map((r) => ({ label: `${alias.get(r.node_id) || r.node_id} / ${r.sensor_id}`, percent: r.percent }));
  const upDays = uptime.data?.sensors[0]?.days ?? [];
  const totalNodesInCoverage = ins ? ins.coverage.nodes_with_decoy + ins.coverage.nodes_without_decoy : 0;
  const maxTypeEvents = Math.max(1, ...(ins?.by_type ?? []).map((r) => r.events));

  return (
    <div class="stack-lg">
      <PageHead title="Dashboard" />
      <ErrorBox error={summary.error} retry={summary.reload} />
      <div class="counters">
        <Counter label="Events (24 h)" value={s?.events_24h} />
        <Counter label="Critical (24 h)" value={s?.critical_24h} tone={s && s.critical_24h > 0 ? "bad" : undefined} />
        <Counter label="Unread" value={s?.events_unread} href="/events" />
        <Counter label="Nodes online" value={s ? `${s.nodes_online} / ${s.nodes_total}` : undefined} tone={s && s.nodes_online < s.nodes_total ? "warn" : undefined} href="/fleet" />
        <Counter label="Sensors online" value={s ? `${s.sensors_online} / ${s.sensors_total}` : undefined} tone={s && s.sensors_online < s.sensors_total ? "warn" : undefined} />
        <Counter label="Events (all time)" value={s?.events_total} />
      </div>

      {hasInsights ? (
        <div class="stack-lg">
          <ErrorBox error={insights.error} retry={insights.reload} />
          {ins ? (
            <>
              <div class="counters counters-5" aria-label="Deception coverage">
                <Counter label="Decoys deployed" value={ins.coverage.decoys_deployed} href="/fleet" />
                <Counter
                  label="Nodes covered"
                  value={`${ins.coverage.nodes_with_decoy} / ${totalNodesInCoverage}`}
                  tone={ins.coverage.nodes_without_decoy > 0 ? "warn" : undefined}
                  href="/fleet"
                />
                <Counter
                  label={`Touched decoys (${ins.touched.instances}/${ins.touched.total})`}
                  value={`${Math.round(ins.touched.ratio * 100)}%`}
                />
                <Counter label="Honeytokens planted" value={ins.coverage.honeytokens_planted} href="/honeytokens" />
                <Counter label="Active beacons" value={ins.coverage.beacons_active} href="/beacons" />
              </div>

              <Card
                title={`Per-decoy-type activity — last ${ins.window} days`}
                actions={
                  ins.allowed_events > 0 ? (
                    <span class="muted">{fmtNum(ins.allowed_events)} allowed/scanner events excluded</span>
                  ) : undefined
                }
              >
                {ins.by_type?.length ? (
                  <div class="table-wrap">
                    <table class="table table-compact">
                      <thead>
                        <tr>
                          <th>Decoy type</th>
                          <th>Online / Deployed</th>
                          <th>Activity</th>
                          <th>Events</th>
                          <th>Sources</th>
                          <th>Highest severity</th>
                          <th>Last seen</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ins.by_type.map((row) => (
                          <tr key={row.sensor_type}>
                            <td class="mono strong">{row.sensor_type}</td>
                            <td class="num">
                              {row.instances_online} / {row.instances_deployed}
                            </td>
                            <td class="type-bar-cell">
                              <svg class="sevbar-svg" viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true">
                                <rect class="sevbar-bg" x="0" y="0" width="100" height="10" rx="2" />
                                <rect
                                  class={`sevbar-fill fill-${row.highest_severity || "info"}`}
                                  x="0"
                                  y="0"
                                  width={row.events > 0 ? Math.max(3, (row.events / maxTypeEvents) * 100) : 0}
                                  height="10"
                                  rx="2"
                                />
                              </svg>
                            </td>
                            <td class="num strong">{fmtNum(row.events)}</td>
                            <td class="num">{fmtNum(row.distinct_sources)}</td>
                            <td>
                              {row.highest_severity ? <SeverityBadge sev={row.highest_severity} /> : <span class="muted">—</span>}
                            </td>
                            <td class="nowrap" title={fmtTime(row.last_event_at)}>{fmtAgo(row.last_event_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty>No decoys deployed yet.</Empty>
                )}
              </Card>
            </>
          ) : insights.loading ? (
            <Loading />
          ) : null}
        </div>
      ) : null}

      <div class="grid-2">
        <Card title="Event velocity — last 24 h">
          {vel.data ? <VelocityChart series={vel.data.series} bucketSeconds={vel.data.bucket_seconds} /> : vel.error ? <ErrorBox error={vel.error} /> : <Loading />}
        </Card>
        <Card title="Severity — last 7 days">
          {sev.data ? <SeverityBars counts={sev.data} /> : sev.error ? <ErrorBox error={sev.error} /> : <Loading />}
        </Card>
      </div>
      <div class="grid-2">
        <Card title="Latest events" actions={<Link href="/events" class="btn btn-ghost btn-sm">All events</Link>}>
          {latest.data ? (
            latest.data.length ? (
              <ul class="feed">
                {latest.data.map((e) => (
                  <li key={e.seq || e.event_id}>
                    <button type="button" class="feed-item" onClick={() => navigate(`/events?open=${e.seq}`)}>
                      <SeverityBadge sev={e.severity} />
                      <span class="feed-main">
                        <span class="mono">{e.trigger}</span>
                        <span class="muted"> from </span>
                        <span class="mono">{e.source || "—"}</span>
                      </span>
                      <span class="feed-meta muted">{e.node_alias || e.node_id} · {fmtAgo(e.received_at)}</span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : <Empty>No events yet. Deploy a sensor and run a fire drill (<code>doppel firedrill</code>).</Empty>
          ) : latest.error ? <ErrorBox error={latest.error} /> : <Loading />}
        </Card>
        <Card title="Fleet health" actions={<Link href="/fleet" class="btn btn-ghost btn-sm">Fleet</Link>}>
          {nodes.data ? (
            nodes.data.length ? (
              <table class="table table-compact">
                <thead><tr><th>Node</th><th>Status</th><th>Sensors</th><th>Last seen</th></tr></thead>
                <tbody>
                  {nodes.data.map((n) => (
                    <tr key={n.id}>
                      <td><Link href={`/fleet/${n.id}`}>{n.alias || n.id}</Link></td>
                      <td>
                        <Pill kind={n.health.online ? "ok" : "bad"}>{n.health.online ? "online" : "offline"}</Pill>{" "}
                        {!n.health.in_sync ? <Pill kind="warn" title="Desired configuration not applied yet">pending apply</Pill> : null}
                      </td>
                      <td>{n.health.sensors_online}/{n.health.sensors_total}{n.health.sensors_offline ? <span class="text-bad"> · {n.health.sensors_offline} offline</span> : null}</td>
                      <td title={fmtTime(n.last_seen_at)}>{fmtAgo(n.last_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <Empty>No nodes. <Link href="/fleet">Create one</Link>.</Empty>
          ) : nodes.error ? <ErrorBox error={nodes.error} /> : <Loading />}
        </Card>
      </div>
      <Card title="Sensor uptime — last 14 days">
        {uptime.data ? <UptimeHeatmap days={upDays} rows={upRows} /> : uptime.error ? <ErrorBox error={uptime.error} /> : <Loading />}
      </Card>
    </div>
  );
}

function Counter({ label, value, tone, href }: { label: string; value: number | string | undefined; tone?: "bad" | "warn"; href?: string }) {
  const body = (
    <>
      <div class="counter-value">{typeof value === "number" ? fmtNum(value) : value ?? "—"}</div>
      <div class="counter-label">{label}</div>
    </>
  );
  const cls = `counter${tone ? " counter-" + tone : ""}`;
  return href ? <Link href={href} class={cls + " counter-link"}>{body}</Link> : <div class={cls}>{body}</div>;
}
