// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Honeytokens and Beacons pages, plus re-exports for the dedicated Assets
// and Analytics pages under ui/src/pages/analytics/.
import { useState } from "preact/hooks";
import { enc, get, del, post } from "../api";
import { fmtTime } from "../format";
import { Button, Card, Confirm, Empty, ErrorBox, Field, Loading, PageHead, Pill, useAction, useAsync } from "../ui";
import { ModuleMissing } from "./analytics/common";

export { Assets } from "./assets";
export { AttackMatrixPage as Attack } from "./analytics/attack-matrix";
export { AttackPathPage } from "./analytics/attack-path";
export { GeoMapPage } from "./analytics/geo-map";
export { ReportPage } from "./analytics/report";
export { SourcesPage } from "./analytics/sources";

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
  const list = useAsync(() => get<{ beacons: Beacon[] | null; available: boolean }>("/beacons"), []);
  const [type, setType] = useState("");
  const [name, setName] = useState("");
  const [memo, setMemo] = useState("");
  const [remove, setRemove] = useState<Beacon | null>(null);
  const act = useAction();
  if (list.error) return <div class="stack-lg"><PageHead title="Beacons" /><ErrorBox error={list.error} retry={list.reload} /></div>;
  if (!list.data) return <Loading />;
  if (!list.data.available) return <div class="stack-lg"><PageHead title="Beacons" /><ModuleMissing name="Beacon" /></div>;
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
