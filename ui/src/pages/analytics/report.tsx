// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Executive report view (report projection): date range picker (from/to),
// Print / Save PDF button with @media print stylesheet, KPI summary,
// severity breakdown, daily activity chart, top sources, targeted assets,
// ATT&CK techniques, and honeytoken uses.
import { useState } from "preact/hooks";
import { enc } from "../../api";
import { can, me } from "../../app";
import { useStore } from "../../store";
import { SeverityBars } from "../../charts";
import { fmtNum, fmtTime } from "../../format";
import { Link } from "../../router";
import { Button, Card, Empty, ErrorBox, Loading, PageHead, Pill } from "../../ui";
import { criticalityKind, useProjection } from "./common";
import type { AssetMatch, TechniqueStat } from "./common";

interface ReportDay {
  date: string;
  events: number;
  critical: number;
}

interface ReportSource {
  source: string;
  events: number;
  critical: number;
  decoys: number;
  firstSeen: string;
  lastSeen: string;
  asset: AssetMatch | null;
}

interface AssetActivity {
  name: string;
  criticality: string;
  sources: number;
  events: number;
}

interface HoneytokenUse {
  timestamp: string;
  username: string;
  source: string;
  nodeId: string;
  sensorId: string;
}

interface ReportDTO {
  from: string;
  to: string;
  generatedAt: string;
  events: number;
  severity: { critical: number; high: number; medium: number; low: number; info: number };
  daily: ReportDay[];
  topSources: ReportSource[];
  sourcesTotal: number;
  assets: AssetActivity[];
  techniques: TechniqueStat[];
  honeytokenUses: HoneytokenUse[];
  archivedEvents: number;
}

function isoDateOffset(offsetDays: number): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + offsetDays);
  return d.toISOString().slice(0, 10);
}

function windowDaysForRange(from: string): number {
  if (!from) return 30;
  const start = Date.parse(from + "T00:00:00Z");
  if (isNaN(start)) return 30;
  const diff = Math.ceil((Date.now() - start) / 86400000) + 1;
  return Math.max(1, Math.min(365, diff));
}

function DailyChart({ daily }: { daily: ReportDay[] }) {
  if (!daily.length) return <Empty>No daily activity in this period.</Empty>;
  const W = 720, H = 170, padL = 38, padB = 22, padT = 10;
  const max = Math.max(1, ...daily.map((d) => d.events));
  const step = (W - padL) / Math.max(1, daily.length);
  const y = (v: number) => padT + (H - padT - padB) * (1 - v / max);
  const ticks = [0, Math.ceil(max / 2), max];
  const labelEvery = Math.max(1, Math.ceil(daily.length / 8));
  const total = daily.reduce((a, d) => a + d.events, 0);

  return (
    <svg
      class="chart"
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label={`Daily events: ${total} total across ${daily.length} days, peak ${max}`}
    >
      {ticks.map((t) => (
        <g key={t}>
          <line class="grid" x1={padL} x2={W} y1={y(t)} y2={y(t)} />
          <text class="axis" x={padL - 6} y={y(t) + 4} text-anchor="end">{t}</text>
        </g>
      ))}
      {daily.map((d, i) => {
        const bw = Math.max(2, step - 2);
        const x = padL + i * step + 1;
        const hAll = Math.max(0, H - padB - y(d.events));
        const hCrit = Math.max(0, H - padB - y(d.critical));
        return (
          <g key={d.date}>
            <rect class="vel-bar" x={x} y={y(d.events)} width={bw} height={hAll}>
              <title>{`${d.date}: ${d.events} events (${d.critical} critical)`}</title>
            </rect>
            {d.critical > 0 ? (
              <rect class="fill-critical" x={x} y={y(d.critical)} width={bw} height={hCrit}>
                <title>{`${d.date}: ${d.critical} critical`}</title>
              </rect>
            ) : null}
          </g>
        );
      })}
      {daily.map((d, i) =>
        i % labelEvery === 0 ? (
          <text key={`lbl-${d.date}`} class="axis" x={padL + i * step + step / 2} y={H - 5} text-anchor="middle">
            {d.date.slice(5)}
          </text>
        ) : null,
      )}
    </svg>
  );
}

export function ReportPage() {
  const [fromInput, setFromInput] = useState(() => isoDateOffset(-30));
  const [toInput, setToInput] = useState(() => isoDateOffset(1));
  const [applied, setApplied] = useState(() => ({ from: isoDateOffset(-30), to: isoDateOffset(1) }));
  // Fire drills are excluded by default (F-001); analysts and admins may add them back.
  const [drills, setDrills] = useState(false);
  const canDrills = can(useStore(me), "analyst");

  const days = windowDaysForRange(applied.from);
  const data = useProjection<ReportDTO>(
    "report",
    { days, from: applied.from || undefined, to: applied.to || undefined, include_drills: canDrills && drills ? true : undefined },
  );

  const applyPreset = (d: number) => {
    const f = isoDateOffset(-d);
    const t = isoDateOffset(1);
    setFromInput(f);
    setToInput(t);
    setApplied({ from: f, to: t });
  };

  const dto = data.data;

  return (
    <div class="stack-lg report-page">
      <PageHead
        title="Executive report"
        sub={dto ? `Period ${dto.from.slice(0, 10)} to ${dto.to.slice(0, 10)} · Generated ${fmtTime(dto.generatedAt)}` : "Periodic deception evidence summary for stakeholders."}
        actions={
          <div class="row no-print">
            <Button variant="primary" onClick={() => window.print()}>Print / Save PDF</Button>
          </div>
        }
      />

      <Card class="no-print">
        <form
          class="report-controls"
          onSubmit={(e) => {
            e.preventDefault();
            setApplied({ from: fromInput, to: toInput });
          }}
        >
          <label class="inline-field">
            <span>From</span>
            <input type="date" class="input" value={fromInput} onChange={(e) => setFromInput(e.currentTarget.value)} required />
          </label>
          <label class="inline-field">
            <span>To (exclusive)</span>
            <input type="date" class="input" value={toInput} onChange={(e) => setToInput(e.currentTarget.value)} required />
          </label>
          <Button type="submit" variant="primary" small>Apply</Button>
          {canDrills ? (
            <label class="inline-field">
              <input type="checkbox" checked={drills} onChange={(e) => setDrills(e.currentTarget.checked)} />
              <span>Include fire drills</span>
            </label>
          ) : null}
          <div class="row report-presets">
            <Button small variant="ghost" onClick={() => applyPreset(7)}>7 days</Button>
            <Button small variant="ghost" onClick={() => applyPreset(30)}>30 days</Button>
            <Button small variant="ghost" onClick={() => applyPreset(90)}>90 days</Button>
          </div>
        </form>
      </Card>

      <ErrorBox error={data.error} retry={data.reload} />

      {data.loading && !dto ? (
        <Loading />
      ) : dto ? (
        <>
          <div class="counters">
            <div class="counter">
              <div class="counter-value">{fmtNum(dto.events)}</div>
              <div class="counter-label">Active events</div>
            </div>
            <div class={`counter${dto.severity.critical > 0 ? " counter-bad" : ""}`}>
              <div class="counter-value">{fmtNum(dto.severity.critical)}</div>
              <div class="counter-label">Critical</div>
            </div>
            <div class={`counter${dto.severity.high > 0 ? " counter-warn" : ""}`}>
              <div class="counter-value">{fmtNum(dto.severity.high)}</div>
              <div class="counter-label">High</div>
            </div>
            <div class="counter">
              <div class="counter-value">{fmtNum(dto.sourcesTotal)}</div>
              <div class="counter-label">Distinct sources</div>
            </div>
            <div class="counter">
              <div class="counter-value">{fmtNum(dto.assets.length)}</div>
              <div class="counter-label">Targeted assets</div>
            </div>
            <div class={`counter${dto.honeytokenUses.length > 0 ? " counter-bad" : ""}`}>
              <div class="counter-value">{fmtNum(dto.honeytokenUses.length)}</div>
              <div class="counter-label">Honeytoken hits</div>
            </div>
          </div>

          {canDrills && drills ? <p class="muted">Fire drills are included in these figures.</p> : null}
          {dto.archivedEvents > 0 ? (
            <p class="muted">
              {fmtNum(dto.archivedEvents)} archived, whitelisted, or known-scanner events in this period are excluded from the figures below.
            </p>
          ) : null}

          <div class="grid-2">
            <Card title="Severity breakdown" class="print-avoid-break">
              <SeverityBars counts={dto.severity} />
            </Card>
            <Card title="Daily activity" class="print-avoid-break">
              <DailyChart daily={dto.daily} />
            </Card>
          </div>

          <Card title={`Top sources (${dto.topSources.length} of ${fmtNum(dto.sourcesTotal)})`} class="print-avoid-break">
            {dto.topSources.length ? (
              <div class="table-wrap">
                <table class="table table-compact">
                  <thead>
                    <tr>
                      <th>Source</th>
                      <th>Asset</th>
                      <th>Events</th>
                      <th>Critical</th>
                      <th>Decoys</th>
                      <th>First seen</th>
                      <th>Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dto.topSources.map((s) => (
                      <tr key={s.source}>
                        <td class="mono"><Link href={`/attack-path?source=${enc(s.source)}`}>{s.source}</Link></td>
                        <td>
                          {s.asset ? (
                            <span>
                              {s.asset.name} <Pill kind={criticalityKind(s.asset.criticality)}>{s.asset.criticality}</Pill>
                            </span>
                          ) : <span class="muted">—</span>}
                        </td>
                        <td class="num strong">{fmtNum(s.events)}</td>
                        <td class={s.critical > 0 ? "num text-bad strong" : "num"}>{fmtNum(s.critical)}</td>
                        <td class="num">{fmtNum(s.decoys)}</td>
                        <td class="nowrap">{fmtTime(s.firstSeen)}</td>
                        <td class="nowrap">{fmtTime(s.lastSeen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty>No active sources in this period.</Empty>
            )}
          </Card>

          <div class="grid-2">
            <Card title="Targeted assets" class="print-avoid-break">
              {dto.assets.length ? (
                <div class="table-wrap">
                  <table class="table table-compact">
                    <thead>
                      <tr><th>Asset</th><th>Criticality</th><th>Sources</th><th>Events</th></tr>
                    </thead>
                    <tbody>
                      {dto.assets.map((a) => (
                        <tr key={`${a.name}-${a.criticality}`}>
                          <td class="strong">{a.name}</td>
                          <td><Pill kind={criticalityKind(a.criticality)}>{a.criticality}</Pill></td>
                          <td class="num">{fmtNum(a.sources)}</td>
                          <td class="num strong">{fmtNum(a.events)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty>No inventoried assets matched event sources in this period.</Empty>
              )}
            </Card>

            <Card title="Honeytoken uses" class="print-avoid-break">
              {dto.honeytokenUses.length ? (
                <div class="table-wrap">
                  <table class="table table-compact">
                    <thead>
                      <tr><th>Time</th><th>Username</th><th>Source</th><th>Decoy</th></tr>
                    </thead>
                    <tbody>
                      {dto.honeytokenUses.map((h, i) => (
                        <tr key={`${h.timestamp}-${i}`} class="row-alert">
                          <td class="nowrap">{fmtTime(h.timestamp)}</td>
                          <td class="mono strong">{h.username || "—"}</td>
                          <td class="mono">{h.source}</td>
                          <td class="mono">{h.nodeId} / {h.sensorId}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty>No honeytoken credential uses in this period.</Empty>
              )}
            </Card>
          </div>

          <Card title="MITRE ATT&CK techniques observed" class="print-avoid-break">
            {dto.techniques.length ? (
              <div class="table-wrap">
                <table class="table table-compact">
                  <thead>
                    <tr>
                      <th>Technique</th>
                      <th>Name</th>
                      <th>Primary</th>
                      <th>Secondary</th>
                      <th>Sources</th>
                      <th>Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dto.techniques.map((t) => (
                      <tr key={t.id}>
                        <td class="mono strong">{t.id}</td>
                        <td>{t.name}</td>
                        <td class="num strong">{fmtNum(t.primaryEvents)}</td>
                        <td class="num">{fmtNum(t.secondaryEvents)}</td>
                        <td class="num">{fmtNum(t.sources)}</td>
                        <td class="nowrap">{fmtTime(t.lastSeen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty>No mapped ATT&amp;CK techniques observed in this period.</Empty>
            )}
          </Card>
        </>
      ) : null}
    </div>
  );
}
