// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
//
// Fleet: node list with health, create node (key shown once), node details
// with sensors, compose preview, key rotation and deletion.
import { useEffect, useState } from "preact/hooks";
import { enc, get, del, patch, post } from "../api";
import { fmtAgo, fmtTime } from "../format";
import { onLive } from "../live";
import { Link, navigate } from "../router";
import type { NodeDetail, NodeSummary, SensorView } from "../types";
import { Alert, Button, Card, Confirm, Empty, ErrorBox, Field, KV, Loading, Modal, PageHead, Pill, Secret, Toggle, toast, useAction, useAsync } from "../ui";
import { SensorDialog, UpgradeDialog, prettyCompose } from "./sensorform";

interface KeyResult { node: { id: string }; node_key: string; link: { key_env: string; hub_url: string; command?: string }; warning: string }

const tagsOf = (s: string) => s.split(",").map((t) => t.trim()).filter(Boolean);

/** Shows a freshly issued node key exactly once. */
function KeyOnce({ result, onClose }: { result: KeyResult | null; onClose: () => void }) {
  const [ack, setAck] = useState(false);
  useEffect(() => setAck(false), [result?.node_key]);
  return (
    <Modal title="Node key" open={!!result} onClose={onClose} dismissable={false} wide
      footer={<Button variant="primary" disabled={!ack} onClick={onClose}>Done</Button>}>
      {result ? (
        <div class="stack">
          <Alert kind="warn">{result.warning}</Alert>
          <Secret label="Node key" value={result.node_key} />
          {result.link.command ? (
            <Secret label="Link the node (run as root on the node; the key is passed in the environment, not argv)" value={result.link.command} />
          ) : (
            <Alert kind="info">No Hub endpoint is configured. Set it in Settings, then link with {result.link.key_env}=&lt;key&gt; truesignal link &lt;hub-url&gt;.</Alert>
          )}
          <p class="muted">Install the CLI first with the verified installer (see the operations guide); it checks SHA256SUMS and the release signature.</p>
          <label class="check"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.currentTarget.checked)} /> I have stored the key</label>
        </div>
      ) : null}
    </Modal>
  );
}

export function FleetList() {
  const nodes = useAsync(() => get<{ nodes: NodeSummary[] }>("/nodes").then((r) => r.nodes), []);
  const [creating, setCreating] = useState(false);
  const [alias, setAlias] = useState("");
  const [tags, setTags] = useState("");
  const [key, setKey] = useState<KeyResult | null>(null);
  const act = useAction();

  useEffect(() => onLive((m) => { if (m.type === "status" || m.type === "refresh") nodes.reload(); }), []);

  return (
    <div class="stack-lg">
      <PageHead title="Fleet" sub="Nodes run the truesignal CLI and the sensors deployed to them."
        actions={<Button variant="primary" onClick={() => { setAlias(""); setTags(""); setCreating(true); }}>Create node</Button>} />
      <ErrorBox error={nodes.error} retry={nodes.reload} />
      {nodes.data ? (
        nodes.data.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Node</th><th>ID</th><th>Tags</th><th>Status</th><th>Configuration</th><th>Sensors</th><th>Last seen</th></tr></thead>
              <tbody>
                {nodes.data.map((n) => (
                  <tr key={n.id} class="row-click" tabIndex={0} onClick={() => navigate(`/fleet/${n.id}`)}
                    onKeyDown={(k) => { if (k.key === "Enter") navigate(`/fleet/${n.id}`); }}>
                    <td><Link href={`/fleet/${n.id}`}>{n.alias || n.id}</Link></td>
                    <td class="mono muted">{n.id}</td>
                    <td>{(n.tags ?? []).map((t) => <span key={t} class="tag">{t}</span>)}</td>
                    <td><Pill kind={n.health.online ? "ok" : "bad"}>{n.health.online ? "online" : "offline"}</Pill></td>
                    <td>{n.health.in_sync ? <Pill kind="ok">applied</Pill> : <Pill kind="warn" title={`desired ${n.desired_revision || "—"}, applied ${n.applied_revision || "—"}`}>pending apply</Pill>}</td>
                    <td>
                      {n.health.sensors_online}/{n.health.sensors_total} online
                      {n.health.sensors_offline ? <span class="text-bad"> · {n.health.sensors_offline} offline</span> : null}
                      {n.health.sensors_pending ? <span class="muted"> · {n.health.sensors_pending} pending</span> : null}
                    </td>
                    <td title={fmtTime(n.last_seen_at)}>{fmtAgo(n.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty>No nodes yet. Create one, then link it with the truesignal CLI.</Empty>
      ) : nodes.loading ? <Loading /> : null}

      <Modal title="Create node" open={creating} onClose={() => setCreating(false)}
        footer={<>
          <Button variant="ghost" onClick={() => setCreating(false)}>Cancel</Button>
          <Button variant="primary" busy={act.busy} disabled={!alias.trim()} onClick={async () => {
            const r = await act.run(() => post<KeyResult>("/nodes", { alias: alias.trim(), tags: tagsOf(tags) }));
            if (r) { setCreating(false); setKey(r); nodes.reload(); }
          }}>Create</Button>
        </>}>
        <div class="stack">
          <Field label="Alias">{(id) => <input id={id} class="input" maxLength={64} value={alias} onInput={(e) => setAlias(e.currentTarget.value)} autoFocus />}</Field>
          <Field label="Tags" hint="Comma-separated, e.g. dmz, cairo-dc1">{(id) => <input id={id} class="input" value={tags} onInput={(e) => setTags(e.currentTarget.value)} />}</Field>
        </div>
      </Modal>
      <KeyOnce result={key} onClose={() => setKey(null)} />
    </div>
  );
}

function statusPill(s: SensorView) {
  const kind = s.status === "online" ? "ok" : s.status === "offline" || s.status === "stopped" ? "bad" : "warn";
  return <Pill kind={kind}>{s.status || "pending"}</Pill>;
}

export function NodePage({ id }: { id: string }) {
  const node = useAsync(() => get<{ node: NodeDetail }>(`/nodes/${enc(id)}`).then((r) => r.node), [id]);
  const [edit, setEdit] = useState(false);
  const [alias, setAlias] = useState("");
  const [tags, setTags] = useState("");
  const [sensorDlg, setSensorDlg] = useState<{ open: boolean; editing?: SensorView }>({ open: false });
  const [upgrade, setUpgrade] = useState<SensorView | null>(null);
  const [confirm, setConfirm] = useState<"" | "rotate" | "delete" | "upgradeAll" | { removeSensor: SensorView }>("");
  const [key, setKey] = useState<KeyResult | null>(null);
  const [compose, setCompose] = useState<string | null>(null);
  const act = useAction();

  useEffect(() => onLive((m) => {
    if ((m.type === "status" && m.data.node_id === id) || m.type === "refresh") node.reload();
  }), [id]);

  const n = node.data;
  if (node.error) return <div class="stack-lg"><PageHead title="Node" /><ErrorBox error={node.error} retry={node.reload} /></div>;
  if (!n) return <Loading />;
  const updatable = n.sensors.filter((s) => s.update_available).length;

  return (
    <div class="stack-lg">
      <div class="crumbs"><Link href="/fleet">Fleet</Link> / <span>{n.alias || n.id}</span></div>
      <PageHead
        title={n.alias || n.id}
        sub={<span class="mono">{n.id}</span>}
        actions={<>
          <Button small onClick={() => { setAlias(n.alias); setTags((n.tags ?? []).join(", ")); setEdit(true); }}>Edit</Button>
          <Button small onClick={async () => {
            const r = await act.run(() => get<{ compose: string }>(`/nodes/${enc(id)}/compose`));
            if (r) setCompose(r.compose);
          }}>Compose</Button>
          <Button small onClick={() => setConfirm("rotate")}>Rotate key</Button>
          <Button small variant="danger" onClick={() => setConfirm("delete")}>Delete node</Button>
        </>}
      />
      <div class="grid-2">
        <Card title="Node">
          <KV rows={[
            ["Status", <Pill kind={n.health.online ? "ok" : "bad"}>{n.health.online ? "online" : "offline"}</Pill>],
            ["Last seen", <span title={fmtTime(n.last_seen_at)}>{fmtAgo(n.last_seen_at)}</span>],
            ["Tags", (n.tags ?? []).length ? (n.tags ?? []).map((t) => <span key={t} class="tag">{t}</span>) : ""],
            ["Created", fmtTime(n.created_at)],
          ]} />
        </Card>
        <Card title="Configuration">
          <KV rows={[
            ["State", n.health.in_sync ? <Pill kind="ok">applied</Pill> : <Pill kind="warn">pending apply</Pill>],
            ["Desired revision", <span class="mono">{n.desired_revision}</span>],
            ["Applied revision", <span class="mono">{n.applied_revision}</span>],
          ]} />
          {!n.health.in_sync ? <p class="muted">Run <code>truesignal apply</code> on the node (or wait for its timer) to apply the change.</p> : null}
        </Card>
      </div>

      <Card title="Sensors" actions={<>
        {updatable ? <Button small onClick={() => setConfirm("upgradeAll")}>Upgrade all ({updatable})</Button> : null}
        <Button small variant="primary" onClick={() => setSensorDlg({ open: true })}>Add sensor</Button>
      </>}>
        {n.sensors.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>Sensor</th><th>Type</th><th>Version</th><th>Status</th><th>Last heartbeat</th><th>Last activity</th><th title="Silenced sensors still record events but send no webhook notifications">Silenced</th><th><span class="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {n.sensors.map((s) => (
                  <tr key={s.id}>
                    <td class="mono">{s.id}</td>
                    <td>{s.catalogue_name}</td>
                    <td class="nowrap">
                      <span class="mono">{s.version}</span>
                      {s.update_available ? <> <Pill kind="info" title={`latest ${s.latest_version}`}>update {s.latest_version}</Pill></> : null}
                    </td>
                    <td>{statusPill(s)}</td>
                    <td title={fmtTime(s.last_heartbeat_at)}>{fmtAgo(s.last_heartbeat_at)}</td>
                    <td title={fmtTime(s.last_activity_at)}>{fmtAgo(s.last_activity_at)}</td>
                    <td>
                      <Toggle label={s.silenced ? "on" : "off"} checked={s.silenced} disabled={act.busy} onChange={async (v) => {
                        if (await act.run(() => post(`/nodes/${enc(id)}/sensors/${enc(s.id)}/${v ? "silence" : "unsilence"}`), v ? "Sensor silenced" : "Sensor unsilenced")) node.reload();
                      }} />
                    </td>
                    <td class="nowrap actions">
                      <Button small variant="ghost" onClick={() => setSensorDlg({ open: true, editing: s })}>Edit</Button>
                      <Button small variant="ghost" onClick={() => setUpgrade(s)}>Upgrade</Button>
                      <Button small variant="ghost" onClick={() => setConfirm({ removeSensor: s })}>Delete</Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <Empty>No sensors on this node. Add one from the catalogue.</Empty>}
      </Card>

      <Modal title="Edit node" open={edit} onClose={() => setEdit(false)}
        footer={<>
          <Button variant="ghost" onClick={() => setEdit(false)}>Cancel</Button>
          <Button variant="primary" busy={act.busy} disabled={!alias.trim()} onClick={async () => {
            if (await act.run(() => patch(`/nodes/${enc(id)}`, { alias: alias.trim(), tags: tagsOf(tags) }), "Node updated")) { setEdit(false); node.reload(); }
          }}>Save</Button>
        </>}>
        <div class="stack">
          <Field label="Alias">{(fid) => <input id={fid} class="input" maxLength={64} value={alias} onInput={(e) => setAlias(e.currentTarget.value)} />}</Field>
          <Field label="Tags" hint="Comma-separated">{(fid) => <input id={fid} class="input" value={tags} onInput={(e) => setTags(e.currentTarget.value)} />}</Field>
        </div>
      </Modal>

      <Modal title="Rendered compose (secrets redacted)" open={compose !== null} onClose={() => setCompose(null)} wide>
        <p class="muted">The node key is not part of the file; the CLI injects it at apply time.</p>
        <pre class="code">{compose !== null ? prettyCompose(compose) : ""}</pre>
      </Modal>

      <SensorDialog nodeId={id} open={sensorDlg.open} editing={sensorDlg.editing}
        onClose={() => setSensorDlg({ open: false })} onSaved={() => { setSensorDlg({ open: false }); node.reload(); }} />
      <UpgradeDialog nodeId={id} sensor={upgrade} onClose={() => setUpgrade(null)} onDone={() => { setUpgrade(null); node.reload(); }} />
      <KeyOnce result={key} onClose={() => setKey(null)} />

      <Confirm open={confirm === "rotate"} title="Rotate node key?" confirmLabel="Rotate key" danger busy={act.busy}
        body="The current key stops working immediately. The node stays offline until you re-link it with the new key."
        onClose={() => setConfirm("")}
        onConfirm={async () => {
          const r = await act.run(() => post<KeyResult>(`/nodes/${enc(id)}/key`));
          setConfirm("");
          if (r) setKey(r);
        }} />
      <Confirm open={confirm === "upgradeAll"} title="Upgrade all sensors?" confirmLabel="Upgrade all" busy={act.busy}
        body={`${updatable} sensor(s) move to the latest catalogue version in one change.`}
        onClose={() => setConfirm("")}
        onConfirm={async () => {
          const r = await act.run(() => post<{ upgraded: string[] }>(`/nodes/${enc(id)}/upgrade`));
          setConfirm("");
          if (r) { toast(`${r.upgraded.length} sensor(s) upgraded; the node applies it on its next apply.`, "ok"); node.reload(); }
        }} />
      <Confirm open={confirm === "delete"} title="Delete node?" confirmLabel="Delete node" danger busy={act.busy} phrase={n.id}
        body={<>The node, its sensors and its key are removed; the key stops working immediately. Events already received are kept. Run <code>truesignal uninstall</code> on the host to remove the containers.</>}
        onClose={() => setConfirm("")}
        onConfirm={async () => {
          if (await act.run(() => del(`/nodes/${enc(id)}`), "Node deleted")) navigate("/fleet");
          setConfirm("");
        }} />
      <Confirm open={typeof confirm === "object"} title="Delete sensor?" confirmLabel="Delete sensor" danger busy={act.busy}
        body={typeof confirm === "object" ? <>Sensor <span class="mono">{confirm.removeSensor.id}</span> is removed on the node's next apply. Its events are kept.</> : null}
        onClose={() => setConfirm("")}
        onConfirm={async () => {
          if (typeof confirm !== "object") return;
          const ok = await act.run(() => del(`/nodes/${enc(id)}/sensors/${enc(confirm.removeSensor.id)}`), "Sensor deleted");
          setConfirm("");
          if (ok) node.reload();
        }} />
    </div>
  );
}

