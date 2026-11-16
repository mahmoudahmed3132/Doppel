// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Honeytokens, beacons, assets, ATT&CK and the analytics projections. The
// projection DTOs are rendered generically as text; each module owns its
// data contract.
import { useState } from "preact/hooks";
import { enc, get, del, post, put, qs } from "../api";
import { fmtTime, pretty } from "../format";
import { Alert, Button, Card, Confirm, Empty, ErrorBox, Field, Loading, PageHead, Pill, useAction, useAsync } from "../ui";

// ---- generic DTO rendering --------------------------------------------------

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

export function DataView({ value, depth = 0 }: { value: unknown; depth?: number }) {
  if (value === null || value === undefined) return <span class="muted">—</span>;
  if (typeof value !== "object") return <span class={typeof value === "number" ? "num" : ""}>{String(value)}</span>;
  if (depth > 3) return <pre class="code small">{pretty(value)}</pre>;
  if (Array.isArray(value)) {
    if (!value.length) return <span class="muted">none</span>;
    if (value.every(isObj)) {
      const cols = Array.from(new Set(value.slice(0, 200).flatMap((r) => Object.keys(r)))).slice(0, 12);
      return (
        <div class="table-wrap">
          <table class="table table-compact">
            <thead><tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
            <tbody>
              {value.slice(0, 500).map((r, i) => (
                <tr key={i}>{cols.map((c) => <td key={c}><DataView value={(r as Record<string, unknown>)[c]} depth={depth + 1} /></td>)}</tr>
              ))}
            </tbody>
          </table>
          {value.length > 500 ? <p class="muted">{value.length - 500} more rows not shown.</p> : null}
        </div>
      );
    }
    return <span>{value.map((v) => (typeof v === "object" ? pretty(v) : String(v))).join(", ")}</span>;
  }
  return (
    <dl class="kv">
      {Object.entries(value).map(([k, v]) => (
        <div class="kv-row" key={k}><dt>{k}</dt><dd><DataView value={v} depth={depth + 1} /></dd></div>
      ))}
    </dl>
  );
}

// ---- honeytokens ------------------------------------------------------------

interface Honeytoken { id: string; username: string; planted_node_id: string; planted_sensor_id: string; status: string; created_at: string; use_count: number; last_used_at: string | null }

export function Honeytokens() {
  const list = useAsync(() => get<{ honeytokens: Honeytoken[] | null }>("/honeytokens").then((r) => r.honeytokens ?? []), []);
  return (
    <div class="stack-lg">
      <PageHead title="Honeytokens" sub="Decoy credentials planted in lures. Any use raises a critical honeytoken_used event."
        actions={<a class="btn btn-sm" href="/api/v3/honeytokens/export" download>Export inventory (CSV)</a>} />
      <ErrorBox error={list.error} retry={list.reload} />
      {list.data ? (
        list.data.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>ID</th><th>Username</th><th>Planted on</th><th>Status</th><th>Created</th><th>Uses</th><th>Last used</th></tr></thead>
              <tbody>
                {list.data.map((h) => (
                  <tr key={h.id} class={h.use_count ? "row-alert" : ""}>
                    <td class="mono">{h.id}</td>
                    <td class="mono">{h.username}</td>
                    <td class="mono">{h.planted_node_id} / {h.planted_sensor_id}</td>
                    <td><Pill kind={h.status === "active" ? "ok" : "neutral"}>{h.status}</Pill></td>
                    <td>{fmtTime(h.created_at)}</td>
                    <td class={h.use_count ? "text-bad strong" : ""}>{h.use_count}</td>
                    <td>{fmtTime(h.last_used_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty>No honeytokens. They are generated when a sensor that plants credential lures is deployed (requires the honeytoken module).</Empty>
      ) : list.loading ? <Loading /> : null}
    </div>
  );
}

// ---- beacons ------------------------------------------------------------------

interface Beacon { id: string; type: string; name: string; memo: string; domain: string; created_at: string; use_count: number; last_used_at: string | null }

export function Beacons() {
  const list = useAsync(() => get<{ beacons: Beacon[] | null }>("/beacons"), []);
  const [type, setType] = useState("");
  const [name, setName] = useState("");
  const [memo, setMemo] = useState("");
  const [remove, setRemove] = useState<Beacon | null>(null);
  const act = useAction();
  if (list.error) return <div class="stack-lg"><PageHead title="Beacons" /><ErrorBox error={list.error} retry={list.reload} /></div>;
  if (!list.data) return <Loading />;
  const beacons = list.data.beacons ?? [];
  return (
    <div class="stack-lg">
      <PageHead title="Beacons" sub="Tracking artefacts that call home when opened. A hit raises an event." />
      <Card title="Create beacon">
        <form class="form-row" onSubmit={async (e) => {
          e.preventDefault();
          if (await act.run(() => post("/beacons", { type: type.trim(), name: name.trim(), memo: memo.trim() }), "Beacon created")) {
            setName(""); setMemo(""); list.reload();
          }
        }}>
          <Field label="Type" hint="DNS name, web bug (1x1 image) or kubeconfig file; the zone is the deployed Token Receiver's">{(id) => (
            <select id={id} class="input" value={type} onChange={(e) => setType(e.currentTarget.value)} required>
              <option value="" disabled>Choose…</option>
              <option value="dns">DNS name</option>
              <option value="web-bug">Web bug</option>
              <option value="kubeconfig">Kubeconfig</option>
            </select>
          )}</Field>
          <Field label="Name">{(id) => <input id={id} class="input" maxLength={100} value={name} onInput={(e) => setName(e.currentTarget.value)} required />}</Field>
          <Field label="Memo" hint="Where you will place it">{(id) => <input id={id} class="input" maxLength={500} value={memo} onInput={(e) => setMemo(e.currentTarget.value)} />}</Field>
          <div class="form-row-end"><Button type="submit" variant="primary" busy={act.busy}>Create</Button></div>
        </form>
      </Card>
      {beacons.length ? (
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th>Name</th><th>Type</th><th>Memo</th><th>Created</th><th>Hits</th><th>Last hit</th><th><span class="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {beacons.map((b) => (
                <tr key={b.id} class={b.use_count ? "row-alert" : ""}>
                  <td>{b.name}</td><td class="mono">{b.type}</td><td>{b.memo}</td><td>{fmtTime(b.created_at)}</td>
                  <td class={b.use_count ? "text-bad strong" : ""}>{b.use_count}</td><td>{fmtTime(b.last_used_at)}</td>
                  <td class="nowrap actions">
                    <a class="btn btn-sm btn-ghost" href={`/api/v3/beacons/${enc(b.id)}/artefact`} download>Download</a>
                    <Button small variant="ghost" onClick={() => setRemove(b)}>Delete</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <Empty>No beacons yet.</Empty>}
      <Confirm open={!!remove} title="Delete beacon?" confirmLabel="Delete" danger busy={act.busy}
        body={remove ? `"${remove.name}" stops reporting. Copies already placed become inert.` : ""}
        onClose={() => setRemove(null)}
        onConfirm={async () => {
          if (remove && (await act.run(() => del(`/beacons/${enc(remove.id)}`), "Beacon deleted"))) list.reload();
          setRemove(null);
        }} />
    </div>
  );
}

// ---- assets -------------------------------------------------------------------

export function Assets() {
  const data = useAsync(() => get<{ assets: unknown }>("/assets"), []);
  const [text, setText] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const act = useAction();
  if (data.error) return <div class="stack-lg"><PageHead title="Assets" /><ErrorBox error={data.error} retry={data.reload} /></div>;
  if (!data.data) return <Loading />;
  const current = text ?? pretty(data.data.assets);
  return (
    <div class="stack-lg">
      <PageHead title="Assets" sub="Inventory used to tag event sources with an asset name and criticality." />
      <Card title="Inventory (JSON)" actions={<Button small variant="primary" busy={act.busy} onClick={async () => {
          let parsed: unknown;
          try { parsed = JSON.parse(current); } catch (e) { setErr(`Invalid JSON: ${(e as Error).message}`); return; }
          setErr("");
          const r = await act.run(() => put<{ assets: unknown }>("/assets", { assets: parsed }), "Inventory saved");
          if (r) { setText(pretty(r.assets)); data.reload(); }
        }}>Save</Button>}>
          {err ? <Alert kind="error">{err}</Alert> : null}
          <textarea class="input mono editor" spellcheck={false} aria-label="Asset inventory JSON" value={current}
            onInput={(e) => setText(e.currentTarget.value)} />
          <p class="muted">
            A JSON array of <code>{"{"}"name", "address", "criticality", "owner", "tags"{"}"}</code>. <code>address</code> is an IP
            or a CIDR range; <code>criticality</code> is low, medium (default), high or critical. At most 5000 assets; the most
            specific range wins. Validated by the Hub on save.
          </p>
        </Card>
    </div>
  );
}

// ---- ATT&CK and projections ------------------------------------------------------

/** Page → PORTED projection name (see QUESTIONS.md Q56). */
export const PROJECTIONS: Record<string, { name: string; title: string; sub: string; geo?: boolean }> = {
  "attack-path": { name: "attack_path", title: "Attack path", sub: "Per-source progression across nodes and techniques." },
  scans: { name: "sources", title: "Scans", sub: "Sources, scan patterns and their activity." },
  geo: { name: "geo_map", title: "Geo map", sub: "Event sources by location.", geo: true },
  report: { name: "report", title: "Report", sub: "Periodic summary for stakeholders." },
};

function useProjection(name: string, days: number) {
  return useAsync(() => get<{ data: unknown }>(`/analytics/projections/${enc(name)}${qs({ days })}`).then((r) => r.data), [name, days]);
}

function DaysSelect({ days, onChange }: { days: number; onChange: (d: number) => void }) {
  return (
    <label class="inline-field">
      <span>Window</span>
      <select class="input" value={String(days)} onChange={(e) => onChange(Number(e.currentTarget.value))}>
        {[1, 7, 30, 90, 365].map((d) => <option key={d} value={d}>{d === 1 ? "24 hours" : `${d} days`}</option>)}
      </select>
    </label>
  );
}

export function Projection({ page }: { page: keyof typeof PROJECTIONS }) {
  const p = PROJECTIONS[page];
  const [days, setDays] = useState(30);
  const data = useProjection(p.name, days);
  return (
    <div class="stack-lg">
      <PageHead title={p.title} sub={p.sub} actions={<DaysSelect days={days} onChange={setDays} />} />
      <Card>
        {data.error ? <ErrorBox error={data.error} retry={data.reload} /> : data.loading ? <Loading /> : <DataView value={data.data} />}
        {p.geo ? <p class="credit"><a href="https://db-ip.com" rel="noopener noreferrer" target="_blank">IP Geolocation by DB-IP</a></p> : null}
      </Card>
    </div>
  );
}

export function Attack() {
  const [days, setDays] = useState(30);
  const matrix = useProjection("attack_matrix", days);
  return (
    <div class="stack-lg">
      <PageHead title="ATT&CK" sub="Techniques observed across the fleet."
        actions={<>
          <DaysSelect days={days} onChange={setDays} />
          <a class="btn btn-sm" href={`/api/v3/analytics/attack/navigator${qs({ days })}`} download>Navigator layer</a>
        </>} />
      <Card title="Matrix">
        {matrix.error ? <ErrorBox error={matrix.error} /> : matrix.loading ? <Loading /> : <DataView value={matrix.data} />}
      </Card>
    </div>
  );
}

