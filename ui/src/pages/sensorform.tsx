// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
//
// Sensor configuration form generated from the manifest's config[]:
// input per type, defaults, descriptions, client-side checks mirroring the
// manifest validation (the Hub re-validates), secrets masked. Manifest text
// (documentation, descriptions) is untrusted and rendered as plain text.
import { useEffect, useState } from "preact/hooks";
import { ApiError, enc, errorText, get, patch, post } from "../api";
import { pretty } from "../format";
import type { CatalogueSensor, ConfigItem, Manifest, SensorView } from "../types";
import { Alert, Button, Field, Loading, Modal, toast } from "../ui";

export function validate(item: ConfigItem, v: string): string | undefined {
  const val = item.validation ?? {};
  if (v === "") return item.required ? "Required" : undefined;
  const intOK = (s: string) => /^-?\d+$/.test(s);
  const checkScalar = (t: string, s: string): string | undefined => {
    if (t === "int" || t === "port") {
      if (!intOK(s)) return `"${s}" is not an integer`;
      const n = Number(s);
      if (t === "port" && (n < 1 || n > 65535)) return "Port must be 1–65535";
      if (val.min !== undefined && n < val.min) return `Minimum ${val.min}`;
      if (val.max !== undefined && n > val.max) return `Maximum ${val.max}`;
    }
    if (t === "enum" && val.enum && !val.enum.includes(s)) return `One of: ${val.enum.join(", ")}`;
    if (t === "bool" && s !== "true" && s !== "false") return "true or false";
    if (val.pattern) {
      try {
        if (!new RegExp(`^(?:${val.pattern})$`, "u").test(s)) return `Must match ${val.pattern}`;
      } catch {
        /* RE2-only syntax: leave it to the Hub */
      }
    }
    return undefined;
  };
  if (val.max_length !== undefined && v.length > val.max_length) return `At most ${val.max_length} characters`;
  if (item.type === "list") {
    const items = v.split(",").map((s) => s.trim()).filter(Boolean);
    if (item.required && !items.length) return "Required";
    if (val.max_items !== undefined && items.length > val.max_items) return `At most ${val.max_items} items`;
    for (const it of items) {
      const e = checkScalar(item.item_type ?? "string", it);
      if (e) return e;
    }
    return undefined;
  }
  return checkScalar(item.type, v);
}

function ConfigInput({ item, value, masked, onChange, id }: { item: ConfigItem; value: string; masked: boolean; onChange: (v: string) => void; id: string }) {
  const v = item.validation ?? {};
  if (item.type === "bool") {
    return (
      <select id={id} class="input" value={value} onChange={(e) => onChange(e.currentTarget.value)}>
        {!item.required ? <option value="">(default)</option> : null}
        <option value="true">true</option>
        <option value="false">false</option>
      </select>
    );
  }
  if (item.type === "enum" && v.enum) {
    return (
      <select id={id} class="input" value={value} onChange={(e) => onChange(e.currentTarget.value)}>
        {!item.required || value === "" ? <option value="">(choose)</option> : null}
        {v.enum.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    );
  }
  const numeric = item.type === "int" || item.type === "port";
  const common = {
    id,
    class: `input${item.type === "path" || item.type === "list" || numeric ? " mono" : ""}`,
    spellcheck: false,
    maxLength: v.max_length,
    placeholder: masked ? "unchanged — type to replace" : item.type === "list" ? "comma-separated" : item.default ? `default: ${item.default}` : "",
    value,
    onInput: (e: { currentTarget: HTMLInputElement }) => onChange(e.currentTarget.value),
  };
  // One element per input type: Preact 11 types <input> attributes by a literal `type`.
  if (item.secret) return <input {...common} type="password" autoComplete="new-password" />;
  if (numeric) {
    const min = item.type === "port" ? Math.max(1, v.min ?? 1) : v.min;
    const max = item.type === "port" ? Math.min(65535, v.max ?? 65535) : v.max;
    return <input {...common} type="number" autoComplete="off" min={min} max={max} />;
  }
  return <input {...common} type="text" autoComplete="off" />;
}

export function ConfigForm({ manifest, values, masked, onChange, errors }: {
  manifest: Manifest; values: Record<string, string>; masked: Set<string>; onChange: (k: string, v: string) => void; errors: Record<string, string | undefined>;
}) {
  const items = manifest.config.filter((c) => !c.hub_reserved);
  if (!items.length) return <p class="muted">This sensor has no configurable settings.</p>;
  return (
    <div class="config-grid">
      {items.map((c) => (
        <Field
          key={c.name}
          label={`${c.name}${c.required ? " *" : ""}`}
          error={errors[c.name]}
          hint={
            <>
              <span>{c.description}</span>
              <span class="muted"> · {c.type}{c.item_type ? ` of ${c.item_type}` : ""}{c.secret ? " · secret" : ""}{c.default ? ` · default ${c.default}` : ""}</span>
            </>
          }
        >
          {(id) => <ConfigInput id={id} item={c} value={values[c.name] ?? ""} masked={masked.has(c.name)} onChange={(v) => onChange(c.name, v)} />}
        </Field>
      ))}
    </div>
  );
}

function initialValues(m: Manifest, current?: SensorView): { values: Record<string, string>; masked: Set<string> } {
  const values: Record<string, string> = {};
  const masked = new Set<string>();
  for (const c of m.config) {
    if (c.hub_reserved) continue;
    if (current) {
      const isMasked = current.config_masked.includes(c.name) || c.secret;
      if (isMasked && current.config && c.name in current.config) {
        masked.add(c.name);
        values[c.name] = "";
      } else values[c.name] = current.config?.[c.name] ?? "";
    } else values[c.name] = c.default ?? "";
  }
  return { values, masked };
}

/** Add (catalogue pick + config) or edit a sensor on a node. */
export function SensorDialog({ nodeId, open, editing, onClose, onSaved }: {
  nodeId: string; open: boolean; editing?: SensorView; onClose: () => void; onSaved: () => void;
}) {
  const [cat, setCat] = useState<CatalogueSensor[] | null>(null);
  const [catErr, setCatErr] = useState<unknown>(null);
  const [pick, setPick] = useState<{ name: string; version: string } | null>(null);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [mErr, setMErr] = useState<unknown>(null);
  const [instance, setInstance] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [masked, setMasked] = useState<Set<string>>(new Set());
  const [errors, setErrors] = useState<Record<string, string | undefined>>({});
  const [serverErr, setServerErr] = useState("");
  const [preview, setPreview] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setManifest(null); setMErr(null); setServerErr(""); setPreview(null); setErrors({}); setInstance("");
    if (editing) setPick({ name: editing.catalogue_name, version: editing.version });
    else {
      setPick(null);
      get<{ sensors: CatalogueSensor[] }>("/catalogue").then((r) => setCat(r.sensors), setCatErr);
    }
  }, [open, editing?.id]);

  useEffect(() => {
    if (!pick) return;
    setManifest(null);
    get<{ manifest: Manifest }>(`/catalogue/${enc(pick.name)}/${enc(pick.version)}`).then((r) => {
      setManifest(r.manifest);
      const iv = initialValues(r.manifest, editing);
      setValues(iv.values);
      setMasked(iv.masked);
    }, setMErr);
  }, [pick?.name, pick?.version]);

  const setVal = (k: string, v: string) => {
    setValues((x) => ({ ...x, [k]: v }));
    setErrors((x) => ({ ...x, [k]: undefined }));
    setPreview(null);
  };

  function check(): boolean {
    if (!manifest) return false;
    const errs: Record<string, string | undefined> = {};
    let ok = true;
    for (const c of manifest.config) {
      if (c.hub_reserved) continue;
      if (masked.has(c.name) && values[c.name] === "") continue; // keep current secret
      const e = validate(c, values[c.name] ?? "");
      if (e) { errs[c.name] = e; ok = false; }
    }
    setErrors(errs);
    return ok;
  }

  // Only explicit values are sent on add; on edit, null keeps the current value.
  const addConfig = () => Object.fromEntries(Object.entries(values).filter(([, v]) => v !== ""));
  const patchConfig = () => {
    const out: Record<string, string | null> = {};
    for (const [k, v] of Object.entries(values)) out[k] = masked.has(k) && v === "" ? null : v;
    return out;
  };

  function handle(e: unknown) {
    if (e instanceof ApiError) {
      if (e.code === "port_conflict") setServerErr(`Port conflict${e.body.sensor_id ? ` with sensor ${String(e.body.sensor_id)}` : ""}: ${e.message}`);
      else if (e.code === "sensor_exists") setServerErr("A sensor with this instance name already exists on this node. Choose another instance name.");
      else setServerErr(errorText(e));
    } else setServerErr(errorText(e));
  }

  async function doPreview() {
    if (!check() || !pick) return;
    setBusy(true); setServerErr("");
    try {
      const body = editing
        ? { sensor_id: editing.id, config: patchConfig() }
        : { add: { name: instance.trim(), catalogue_name: pick.name, version: pick.version, config: addConfig() } };
      const r = await post<{ compose: string }>(`/nodes/${enc(nodeId)}/compose/preview`, body);
      setPreview(r.compose);
    } catch (e) { handle(e); } finally { setBusy(false); }
  }

  async function save() {
    if (!check() || !pick) return;
    setBusy(true); setServerErr("");
    try {
      const r = editing
        ? await patch<{ render: { warnings: string[] } }>(`/nodes/${enc(nodeId)}/sensors/${enc(editing.id)}`, { config: patchConfig() })
        : await post<{ render: { warnings: string[] } }>(`/nodes/${enc(nodeId)}/sensors`, { name: instance.trim() || undefined, catalogue_name: pick.name, version: pick.version, config: addConfig() });
      toast(editing ? "Sensor updated. The node applies it on its next apply." : "Sensor added. The node applies it on its next apply.", "ok");
      for (const w of r.render?.warnings ?? []) toast(w, "info");
      onSaved();
    } catch (e) { handle(e); } finally { setBusy(false); }
  }

  const title = editing ? `Edit ${editing.id}` : "Add sensor";
  return (
    <Modal title={title} open={open} onClose={onClose} wide
      footer={manifest ? (
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button busy={busy} onClick={doPreview}>Preview compose</Button>
          <Button variant="primary" busy={busy} onClick={save}>{editing ? "Save" : "Add sensor"}</Button>
        </>
      ) : undefined}>
      <div class="stack">
        {!editing && !pick ? <CataloguePicker cat={cat} err={catErr} onPick={setPick} /> : null}
        {pick && !manifest && !mErr ? <Loading label="Verifying manifest…" /> : null}
        {mErr ? <Alert kind="error">{errorText(mErr)}</Alert> : null}
        {manifest ? (
          <>
            <div class="row between">
              <div>
                <div class="strong">{manifest.display_name} <span class="muted mono">{manifest.name}@{manifest.version}</span></div>
                <div class="muted">{manifest.description}</div>
              </div>
              {!editing ? <Button small variant="ghost" onClick={() => { setPick(null); setManifest(null); }}>Change</Button> : null}
            </div>
            {manifest.documentation ? (
              <details>
                <summary>Documentation</summary>
                <pre class="doc">{manifest.documentation}</pre>
              </details>
            ) : null}
            {!editing ? (
              <Field label="Instance name (optional)" hint="Lowercase letters, digits and hyphens. Defaults to the catalogue name; needed to run two instances of one sensor.">
                {(id) => <input id={id} class="input mono" value={instance} maxLength={40} pattern="[a-z0-9][a-z0-9-]*" onInput={(e) => setInstance(e.currentTarget.value)} />}
              </Field>
            ) : null}
            <ConfigForm manifest={manifest} values={values} masked={masked} onChange={setVal} errors={errors} />
            {serverErr ? <Alert kind="error">{serverErr}</Alert> : null}
            {preview !== null ? (
              <details open>
                <summary>Compose preview (secrets redacted)</summary>
                <pre class="code">{prettyCompose(preview)}</pre>
              </details>
            ) : null}
          </>
        ) : null}
      </div>
    </Modal>
  );
}

export function prettyCompose(s: string): string {
  try { return pretty(JSON.parse(s)); } catch { return s; }
}

function CataloguePicker({ cat, err, onPick }: { cat: CatalogueSensor[] | null; err: unknown; onPick: (p: { name: string; version: string }) => void }) {
  const [sel, setSel] = useState<Record<string, string>>({});
  if (err) return <Alert kind="error">{errorText(err)}</Alert>;
  if (!cat) return <Loading label="Loading catalogue…" />;
  if (!cat.length) return <Alert kind="warn">The catalogue is empty. Check the registry URL in Settings and refresh the catalogue.</Alert>;
  return (
    <div class="catalogue">
      {cat.map((s) => {
        const avail = s.versions.filter((v) => v.available && !v.deprecated);
        const chosen = sel[s.name] ?? (avail.find((v) => v.version === s.latest)?.version || avail[0]?.version || "");
        const reason = s.versions.find((v) => !v.available)?.reason;
        return (
          <div class="cat-item" key={s.name}>
            <div class="cat-main">
              <div class="strong">{s.display_name || s.name} <span class="muted">· {s.category}</span></div>
              <div class="muted">{s.description}</div>
              {!avail.length ? <div class="text-warn">No usable version{reason ? `: ${reason}` : ""}</div> : null}
            </div>
            <div class="cat-actions">
              <select class="input" aria-label={`Version of ${s.name}`} value={chosen} disabled={!avail.length}
                onChange={(e) => setSel({ ...sel, [s.name]: e.currentTarget.value })}>
                {avail.map((v) => <option key={v.version} value={v.version}>{v.version}{v.version === s.latest ? " (latest)" : ""}{v.verified ? "" : " — unsigned"}</option>)}
              </select>
              <Button small variant="primary" disabled={!chosen} onClick={() => onPick({ name: s.name, version: chosen })}>Configure</Button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/** Upgrade one sensor to a chosen version (default: latest). */
export function UpgradeDialog({ nodeId, sensor, onClose, onDone }: { nodeId: string; sensor: SensorView | null; onClose: () => void; onDone: () => void }) {
  const [versions, setVersions] = useState<string[]>([]);
  const [v, setV] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => {
    if (!sensor) return;
    setErr("");
    get<{ sensors: CatalogueSensor[] }>("/catalogue").then((r) => {
      const c = r.sensors.find((s) => s.name === sensor.catalogue_name);
      const list = (c?.versions ?? []).filter((x) => x.available && !x.deprecated && x.version !== sensor.version).map((x) => x.version);
      setVersions(list);
      setV(sensor.latest_version && list.includes(sensor.latest_version) ? sensor.latest_version : list[0] ?? "");
    }, (e) => setErr(errorText(e)));
  }, [sensor?.id]);
  return (
    <Modal title={sensor ? `Upgrade ${sensor.id}` : "Upgrade"} open={!!sensor} onClose={onClose}
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" busy={busy} disabled={!v} onClick={async () => {
          setBusy(true); setErr("");
          try {
            await post(`/nodes/${enc(nodeId)}/sensors/${enc(sensor!.id)}/upgrade`, { version: v });
            toast(`Upgrade to ${v} queued; the node applies it on its next apply.`, "ok");
            onDone();
          } catch (e) { setErr(errorText(e)); } finally { setBusy(false); }
        }}>Upgrade</Button>
      </>}>
      {sensor ? (
        <div class="stack">
          <p>Current version <span class="mono">{sensor.version}</span>. The configuration is kept and re-validated against the new version's manifest; the upgrade is refused if it no longer validates.</p>
          {err ? <Alert kind="error">{err}</Alert> : null}
          {versions.length ? (
            <Field label="Target version">
              {(id) => <select id={id} class="input" value={v} onChange={(e) => setV(e.currentTarget.value)}>{versions.map((x) => <option key={x} value={x}>{x}</option>)}</select>}
            </Field>
          ) : <p class="muted">No other usable version in the catalogue.</p>}
        </div>
      ) : null}
    </Modal>
  );
}
