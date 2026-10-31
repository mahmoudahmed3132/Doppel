// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Hand-written SVG charts. Geometry uses SVG presentation attributes and
// colours come from CSS classes, so nothing needs inline style (CSP).
import { SEVERITIES } from "./types";

export function SeverityBars({ counts }: { counts: Record<string, number> }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s] ?? 0));
  const total = SEVERITIES.reduce((a, s) => a + (counts[s] ?? 0), 0);
  return (
    <div class="sevbars" role="img" aria-label={SEVERITIES.map((s) => `${s} ${counts[s] ?? 0}`).join(", ")}>
      {SEVERITIES.map((s) => {
        const n = counts[s] ?? 0;
        return (
          <div class="sevbar-row" key={s}>
            <span class="sevbar-label">{s}</span>
            <svg class="sevbar-svg" viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true">
              <rect class="sevbar-bg" x="0" y="0" width="100" height="10" rx="2" />
              <rect class={`sevbar-fill fill-${s}`} x="0" y="0" width={(n / max) * 100} height="10" rx="2" />
            </svg>
            <span class="sevbar-num">{n.toLocaleString()}</span>
            <span class="sevbar-pct muted">{total ? Math.round((n / total) * 100) : 0}%</span>
          </div>
        );
      })}
    </div>
  );
}

export function VelocityChart({ series, bucketSeconds }: { series: { t: string; count: number }[]; bucketSeconds: number }) {
  const W = 600, H = 160, padL = 34, padB = 20, padT = 8;
  if (!series.length) return <div class="empty">No data</div>;
  const max = Math.max(1, ...series.map((p) => p.count));
  const step = (W - padL) / Math.max(1, series.length);
  const y = (v: number) => padT + (H - padT - padB) * (1 - v / max);
  const bars = series.map((p, i) => {
    const h = H - padB - y(p.count);
    const d = new Date(p.t);
    const label = `${d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" })}: ${p.count}`;
    return (
      <rect key={p.t} class="vel-bar" x={padL + i * step + 1} y={y(p.count)} width={Math.max(1, step - 2)} height={Math.max(0, h)}>
        <title>{label}</title>
      </rect>
    );
  });
  const ticks = [0, Math.ceil(max / 2), max];
  const labelEvery = Math.max(1, Math.ceil(series.length / 6));
  const total = series.reduce((a, p) => a + p.count, 0);
  return (
    <svg class="chart" viewBox={`0 0 ${W} ${H}`} role="img"
      aria-label={`Event velocity: ${total} events in ${series.length} buckets of ${Math.round(bucketSeconds / 60)} minutes, peak ${max}`}>
      {ticks.map((t) => (
        <g key={t}>
          <line class="grid" x1={padL} x2={W} y1={y(t)} y2={y(t)} />
          <text class="axis" x={padL - 6} y={y(t) + 4} text-anchor="end">{t}</text>
        </g>
      ))}
      {bars}
      {series.map((p, i) =>
        i % labelEvery === 0 ? (
          <text key={"l" + p.t} class="axis" x={padL + i * step + step / 2} y={H - 5} text-anchor="middle">
            {new Date(p.t).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
          </text>
        ) : null,
      )}
    </svg>
  );
}

function heatClass(p: number): string {
  if (p < 0) return "heat-none";
  if (p >= 99.5) return "heat-5";
  if (p >= 95) return "heat-4";
  if (p >= 75) return "heat-3";
  if (p >= 25) return "heat-2";
  if (p > 0) return "heat-1";
  return "heat-0";
}

export function UptimeHeatmap({ days, rows }: { days: string[]; rows: { label: string; percent: number[] }[] }) {
  if (!rows.length) return <div class="empty">No sensors yet</div>;
  const cell = 16, gap = 3, labelW = 220;
  const W = labelW + days.length * (cell + gap), H = rows.length * (cell + gap) + 20;
  return (
    <div class="heatmap-wrap">
      <svg class="heatmap" viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="img" aria-label="Sensor uptime per day">
        {rows.map((r, ri) => (
          <g key={r.label}>
            <text class="axis heat-label" x={labelW - 8} y={ri * (cell + gap) + cell - 3} text-anchor="end">{r.label}</text>
            {r.percent.map((p, di) => (
              <rect key={di} class={`heat ${heatClass(p)}`} x={labelW + di * (cell + gap)} y={ri * (cell + gap)} width={cell} height={cell} rx="3">
                <title>{`${r.label} — ${days[di] ?? ""}: ${p < 0 ? "not deployed" : p.toFixed(1) + "% online"}`}</title>
              </rect>
            ))}
          </g>
        ))}
        {days.map((d, di) =>
          di % Math.max(1, Math.ceil(days.length / 7)) === 0 ? (
            <text key={d} class="axis" x={labelW + di * (cell + gap) + cell / 2} y={H - 4} text-anchor="middle">{d.slice(5)}</text>
          ) : null,
        )}
      </svg>
      <div class="heat-legend" aria-hidden="true">
        <span class="muted">less</span>
        {["heat-0", "heat-1", "heat-2", "heat-3", "heat-4", "heat-5"].map((c) => (
          <svg key={c} width="12" height="12" viewBox="0 0 12 12"><rect class={`heat ${c}`} width="12" height="12" rx="2" /></svg>
        ))}
        <span class="muted">100% online</span>
        <svg width="12" height="12" viewBox="0 0 12 12"><rect class="heat heat-none" width="12" height="12" rx="2" /></svg>
        <span class="muted">not deployed</span>
      </div>
    </div>
  );
}
