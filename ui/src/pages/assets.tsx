// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Asset inventory editor: structured CRUD table over GET/PUT /api/v3/assets,
// client-side CSV import with validation preview, formula-injection-safe CSV
// export, and a Raw JSON tab for power users.
import { useEffect, useMemo, useState } from "preact/hooks";
import { get, put } from "../api";
import { pretty } from "../format";
import { Alert, Button, Card, Empty, ErrorBox, Field, Loading, Modal, PageHead, Pill, Tabs, toast, useAction, useAsync } from "../ui";
import { criticalityKind, ModuleMissing } from "./analytics/common";

export interface AssetRow {
  name: string;
  address: string;
  criticality: "low" | "medium" | "high" | "critical";
  owner: string;
  tags: string[];
}

const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
const MAX_ASSETS = 5000;
const MAX_FIELD = 256;
const MAX_TAGS = 20;

function isCriticality(v: string): v is AssetRow["criticality"] {
  return (CRITICALITIES as readonly string[]).includes(v);
}

function normalizeAssets(raw: unknown): AssetRow[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((item): item is Record<string, unknown> => typeof item === "object" && item !== null)
    .map((item) => {
      const crit = String(item.criticality ?? "medium").trim().toLowerCase();
      return {
        name: String(item.name ?? ""),
        address: String(item.address ?? ""),
        criticality: isCriticality(crit) ? crit : "medium",
        owner: String(item.owner ?? ""),
        tags: Array.isArray(item.tags) ? item.tags.map((t) => String(t).trim()).filter(Boolean) : [],
      };
    });
}

// ---- Formula-safe CSV export ------------------------------------------------

const FORMULA_PREFIX = /^[=+\-@\t\r]/;

function csvCell(value: string): string {
  const safe = FORMULA_PREFIX.test(value) ? `'${value}` : value;
  if (/[",\r\n]/.test(safe)) return `"${safe.replace(/"/g, '""')}"`;
  return safe;
}

function serializeCSV(rows: AssetRow[]): string {
  const header = "name,address,criticality,owner,tags";
  const body = rows.map((r) => [
    csvCell(r.name),
    csvCell(r.address),
    csvCell(r.criticality),
    csvCell(r.owner),
    csvCell(r.tags.join(";")),
  ].join(","));
  return [header, ...body].join("\r\n") + "\r\n";
}

function downloadCSV(rows: AssetRow[]) {
  const blob = new Blob([serializeCSV(rows)], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "doppel-assets.csv";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---- Client-side RFC 4180 CSV parser & validator ----------------------------

function parseCSV(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\r" || ch === "\n") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      if (row.some((c) => c.trim() !== "")) rows.push(row);
      row = [];
      field = "";
    } else {
      field += ch;
    }
  }
  row.push(field);
  if (row.some((c) => c.trim() !== "")) rows.push(row);
  return rows;
}

interface ParsedImport {
  valid: AssetRow[];
  errors: string[];
}

function parseAssetCSV(text: string): ParsedImport {
  const grid = parseCSV(text);
  if (!grid.length) return { valid: [], errors: [] };
  const first = grid[0].map((c) => c.trim().toLowerCase());
  const hasHeader = first[0] === "name" && first[1] === "address";
  const start = hasHeader ? 1 : 0;
  const valid: AssetRow[] = [];
  const errors: string[] = [];
  const seenAddr = new Set<string>();

  for (let i = start; i < grid.length; i++) {
    const lineNo = i + 1;
    const cols = grid[i];
    const name = (cols[0] ?? "").trim();
    const address = (cols[1] ?? "").trim();
    const rawCrit = (cols[2] ?? "").trim().toLowerCase();
    const crit = rawCrit || "medium";
    const owner = (cols[3] ?? "").trim();
    const rawTags = (cols[4] ?? "").trim();
    const tags = rawTags ? rawTags.split(/[;|]/).map((t) => t.trim()).filter(Boolean) : [];

    if (!name) {
      errors.push(`Row ${lineNo}: name is required`);
      continue;
    }
    if (!address) {
      errors.push(`Row ${lineNo} (${name}): address is required`);
      continue;
    }
    if (name.length > MAX_FIELD || address.length > MAX_FIELD || owner.length > MAX_FIELD) {
      errors.push(`Row ${lineNo} (${name}): field exceeds ${MAX_FIELD} characters`);
      continue;
    }
    if (!isCriticality(crit)) {
      errors.push(`Row ${lineNo} (${name}): criticality must be low, medium, high, or critical`);
      continue;
    }
    if (tags.length > MAX_TAGS) {
      errors.push(`Row ${lineNo} (${name}): more than ${MAX_TAGS} tags`);
      continue;
    }
    const addrKey = address.toLowerCase();
    if (seenAddr.has(addrKey)) {
      errors.push(`Row ${lineNo} (${name}): duplicate address "${address}" in CSV`);
      continue;
    }
    seenAddr.add(addrKey);
    valid.push({ name, address, criticality: crit, owner, tags });
  }
  return { valid, errors };
}

// ---- Component --------------------------------------------------------------

type TabMode = "table" | "json";

export function Assets() {
  const data = useAsync(() => get<{ assets: unknown; editable: boolean }>("/assets"), []);
  const act = useAction();

  const [tab, setTab] = useState<TabMode>("table");
  const [rows, setRows] = useState<AssetRow[]>([]);
  const [jsonText, setJsonText] = useState("[]");
  const [dirty, setDirty] = useState(false);
  const [err, setErr] = useState("");
  const [search, setSearch] = useState("");

  // Add / Edit modal state
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [fName, setFName] = useState("");
  const [fAddress, setFAddress] = useState("");
  const [fCrit, setFCrit] = useState<AssetRow["criticality"]>("medium");
  const [fOwner, setFOwner] = useState("");
  const [fTags, setFTags] = useState("");
  const [fErr, setFErr] = useState("");

  // CSV import modal state
  const [importOpen, setImportOpen] = useState(false);
  const [csvText, setCsvText] = useState("");
  const [importMode, setImportMode] = useState<"merge" | "replace">("merge");

  useEffect(() => {
    if (!data.data) return;
    const norm = normalizeAssets(data.data.assets);
    setRows(norm);
    setJsonText(pretty(data.data.assets ?? []));
    setDirty(false);
    setErr("");
  }, [data.data]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rows
      .map((row, idx) => ({ row, idx }))
      .filter(({ row }) => {
        if (!q) return true;
        return (
          row.name.toLowerCase().includes(q) ||
          row.address.toLowerCase().includes(q) ||
          row.owner.toLowerCase().includes(q) ||
          row.criticality.includes(q) ||
          row.tags.some((t) => t.toLowerCase().includes(q))
        );
      });
  }, [rows, search]);

  const parsedImport = useMemo(() => parseAssetCSV(csvText), [csvText]);

  const syncRows = (next: AssetRow[]) => {
    setRows(next);
    setJsonText(pretty(next));
    setDirty(true);
    setErr("");
  };

  const switchTab = (next: TabMode) => {
    if (next === tab) return;
    if (tab === "json" && next === "table") {
      try {
        const parsed = JSON.parse(jsonText);
        if (!Array.isArray(parsed)) {
          setErr("JSON must be an array of assets before switching to the table editor.");
          return;
        }
        setRows(normalizeAssets(parsed));
        setErr("");
      } catch (e) {
        setErr(`Invalid JSON: ${(e as Error).message}`);
        return;
      }
    } else if (tab === "table" && next === "json") {
      setJsonText(pretty(rows));
      setErr("");
    }
    setTab(next);
  };

  const openAdd = () => {
    setEditingIndex(null);
    setFName("");
    setFAddress("");
    setFCrit("medium");
    setFOwner("");
    setFTags("");
    setFErr("");
    setFormOpen(true);
  };

  const openEdit = (idx: number) => {
    const r = rows[idx];
    setEditingIndex(idx);
    setFName(r.name);
    setFAddress(r.address);
    setFCrit(r.criticality);
    setFOwner(r.owner);
    setFTags(r.tags.join(", "));
    setFErr("");
    setFormOpen(true);
  };

  const submitRow = (e: Event) => {
    e.preventDefault();
    const name = fName.trim();
    const address = fAddress.trim();
    const owner = fOwner.trim();
    const tags = fTags.split(",").map((t) => t.trim()).filter(Boolean);
    if (!name) { setFErr("Name is required."); return; }
    if (!address) { setFErr("Address (IP or CIDR) is required."); return; }
    if (tags.length > MAX_TAGS) { setFErr(`At most ${MAX_TAGS} tags are allowed.`); return; }
    const dup = rows.findIndex((r, i) => i !== editingIndex && r.address.trim().toLowerCase() === address.toLowerCase());
    if (dup >= 0) { setFErr(`Address "${address}" is already used by ${rows[dup].name}.`); return; }

    const item: AssetRow = { name, address, criticality: fCrit, owner, tags };
    if (editingIndex === null) {
      if (rows.length >= MAX_ASSETS) { setFErr(`At most ${MAX_ASSETS} assets are allowed.`); return; }
      syncRows([...rows, item]);
    } else {
      syncRows(rows.map((r, i) => (i === editingIndex ? item : r)));
    }
    setFormOpen(false);
  };

  const deleteRow = (idx: number) => {
    syncRows(rows.filter((_, i) => i !== idx));
  };

  const applyImport = () => {
    if (!parsedImport.valid.length) return;
    let next: AssetRow[];
    if (importMode === "replace") {
      next = parsedImport.valid.slice(0, MAX_ASSETS);
    } else {
      const byAddr = new Map<string, AssetRow>();
      for (const r of rows) byAddr.set(r.address.trim().toLowerCase(), r);
      for (const r of parsedImport.valid) byAddr.set(r.address.trim().toLowerCase(), r);
      next = Array.from(byAddr.values()).slice(0, MAX_ASSETS);
    }
    syncRows(next);
    setImportOpen(false);
    setCsvText("");
    toast(`Staged ${parsedImport.valid.length} assets. Click Save changes to persist.`, "info");
  };

  const saveInventory = async () => {
    let payload: unknown;
    if (tab === "json") {
      try {
        payload = JSON.parse(jsonText);
      } catch (e) {
        setErr(`Invalid JSON: ${(e as Error).message}`);
        return;
      }
    } else {
      payload = rows;
    }
    setErr("");
    const r = await act.run(() => put<{ assets: unknown }>("/assets", { assets: payload }), "Inventory saved");
    if (r) {
      const norm = normalizeAssets(r.assets);
      setRows(norm);
      setJsonText(pretty(r.assets ?? []));
      setDirty(false);
      data.reload();
    }
  };

  if (data.error) return <div class="stack-lg"><PageHead title="Assets" /><ErrorBox error={data.error} retry={data.reload} /></div>;
  if (!data.data) return <Loading />;

  if (!data.data.editable) {
    return (
      <div class="stack-lg">
        <PageHead title="Assets" sub="Inventory used to tag event sources with an asset name and criticality." />
        <ModuleMissing name="Asset inventory">
          <p class="muted">The stored inventory is shown read-only.</p>
          <pre class="code">{pretty(data.data.assets)}</pre>
        </ModuleMissing>
      </div>
    );
  }

  return (
    <div class="stack-lg">
      <PageHead
        title="Assets"
        sub="Protected hosts and CIDR ranges used to tag event sources with asset name and criticality."
        actions={
          <div class="row">
            {dirty ? <Pill kind="warn">Unsaved changes</Pill> : null}
            <Button variant="primary" busy={act.busy} onClick={saveInventory}>Save changes</Button>
          </div>
        }
      />

      <Tabs
        tabs={[["table", `Table editor (${rows.length})`], ["json", "Raw JSON"]]}
        value={tab}
        onChange={switchTab}
      />

      {err ? <Alert kind="error">{err}</Alert> : null}

      {tab === "table" ? (
        <Card
          title="Asset inventory"
          actions={
            <div class="row">
              <Button small onClick={openAdd}>Add asset</Button>
              <Button small onClick={() => { setCsvText(""); setImportOpen(true); }}>Import CSV</Button>
              <Button small onClick={() => downloadCSV(rows)} disabled={!rows.length}>Export CSV</Button>
            </div>
          }
        >
          <div class="stack">
            <div class="row between">
              <input
                type="search"
                class="input sources-search"
                aria-label="Filter assets"
                placeholder="Filter by name, IP/CIDR, owner, or tag…"
                value={search}
                onInput={(e) => setSearch(e.currentTarget.value)}
              />
              <span class="muted">
                Showing {filtered.length} of {rows.length} (max {MAX_ASSETS})
              </span>
            </div>

            {filtered.length ? (
              <div class="table-wrap">
                <table class="table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Address (IP / CIDR)</th>
                      <th>Criticality</th>
                      <th>Owner</th>
                      <th>Tags</th>
                      <th><span class="sr-only">Actions</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map(({ row, idx }) => (
                      <tr key={`${row.address}-${idx}`}>
                        <td class="strong">{row.name}</td>
                        <td class="mono">{row.address}</td>
                        <td><Pill kind={criticalityKind(row.criticality)}>{row.criticality}</Pill></td>
                        <td>{row.owner || <span class="muted">—</span>}</td>
                        <td>
                          {row.tags.length ? (
                            row.tags.map((t) => <span key={t} class="tag">{t}</span>)
                          ) : (
                            <span class="muted">—</span>
                          )}
                        </td>
                        <td class="nowrap actions">
                          <Button small variant="ghost" onClick={() => openEdit(idx)}>Edit</Button>
                          <Button small variant="ghost" onClick={() => deleteRow(idx)}>Delete</Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty>
                {rows.length
                  ? "No assets match your filter."
                  : "No assets configured. Add an asset or import a CSV to tag event sources."}
              </Empty>
            )}
          </div>
        </Card>
      ) : (
        <Card
          title="Inventory (JSON)"
          actions={<Button small variant="primary" busy={act.busy} onClick={saveInventory}>Save</Button>}
        >
          <div class="stack">
            <textarea
              class="input mono editor"
              spellcheck={false}
              aria-label="Asset inventory JSON"
              value={jsonText}
              onInput={(e) => { setJsonText(e.currentTarget.value); setDirty(true); }}
            />
            <p class="muted">
              A JSON array of <code>{"{"}"name", "address", "criticality", "owner", "tags"{"}"}</code>. <code>address</code> is an IP
              or a CIDR range; <code>criticality</code> is low, medium (default), high or critical. At most {MAX_ASSETS} assets; the most
              specific range wins. Validated by the Hub on save.
            </p>
          </div>
        </Card>
      )}

      <Modal
        open={formOpen}
        title={editingIndex === null ? "Add asset" : "Edit asset"}
        onClose={() => setFormOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setFormOpen(false)}>Cancel</Button>
            <Button type="submit" form="asset-row-form" variant="primary">
              {editingIndex === null ? "Add" : "Update"}
            </Button>
          </>
        }
      >
        <form id="asset-row-form" class="stack" onSubmit={submitRow}>
          {fErr ? <Alert kind="error">{fErr}</Alert> : null}
          <Field label="Name">
            {(id) => (
              <input id={id} class="input" maxLength={MAX_FIELD} value={fName} onInput={(e) => setFName(e.currentTarget.value)} required />
            )}
          </Field>
          <Field label="Address (IP or CIDR)" hint="e.g. 10.20.1.5 or 10.20.0.0/16">
            {(id) => (
              <input id={id} class="input mono" maxLength={MAX_FIELD} value={fAddress} onInput={(e) => setFAddress(e.currentTarget.value)} required />
            )}
          </Field>
          <Field label="Criticality">
            {(id) => (
              <select id={id} class="input" value={fCrit} onChange={(e) => setFCrit(e.currentTarget.value as AssetRow["criticality"])}>
                {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            )}
          </Field>
          <Field label="Owner" hint="Optional team or contact">
            {(id) => (
              <input id={id} class="input" maxLength={MAX_FIELD} value={fOwner} onInput={(e) => setFOwner(e.currentTarget.value)} />
            )}
          </Field>
          <Field label="Tags" hint="Comma-separated (e.g. pci, prod, dc-1)">
            {(id) => (
              <input id={id} class="input" value={fTags} onInput={(e) => setFTags(e.currentTarget.value)} />
            )}
          </Field>
        </form>
      </Modal>

      <Modal
        wide
        open={importOpen}
        title="Import assets from CSV"
        onClose={() => setImportOpen(false)}
        footer={
          <>
            <Button variant="ghost" onClick={() => setImportOpen(false)}>Cancel</Button>
            <Button
              variant="primary"
              disabled={!parsedImport.valid.length}
              onClick={applyImport}
            >
              Stage {parsedImport.valid.length} {parsedImport.valid.length === 1 ? "asset" : "assets"}
            </Button>
          </>
        }
      >
        <div class="stack">
          <p class="muted">
            Columns: <code>name,address,criticality,owner,tags</code> (separate multiple tags with <code>;</code>). Header row is optional.
          </p>
          <div class="row between">
            <label class="btn btn-sm">
              Choose CSV file
              <input
                type="file"
                class="sr-only"
                accept=".csv,text/csv"
                onChange={async (e) => {
                  const file = e.currentTarget.files?.[0];
                  if (file) setCsvText(await file.text());
                }}
              />
            </label>
            <div class="row">
              <label class="check">
                <input type="radio" name="import-mode" checked={importMode === "merge"} onChange={() => setImportMode("merge")} />
                <span>Merge by address</span>
              </label>
              <label class="check">
                <input type="radio" name="import-mode" checked={importMode === "replace"} onChange={() => setImportMode("replace")} />
                <span>Replace all</span>
              </label>
            </div>
          </div>
          <textarea
            class="input mono list-editor"
            spellcheck={false}
            aria-label="CSV content"
            placeholder={"name,address,criticality,owner,tags\ndc-01,10.0.1.10,critical,identity-team,ad;tier0"}
            value={csvText}
            onInput={(e) => setCsvText(e.currentTarget.value)}
          />
          {parsedImport.errors.length ? (
            <Alert kind="warn">
              <div class="stack">
                <strong>{parsedImport.errors.length} row(s) skipped due to validation errors:</strong>
                <ul class="plain">
                  {parsedImport.errors.slice(0, 10).map((msg, i) => <li key={i} class="mono">{msg}</li>)}
                  {parsedImport.errors.length > 10 ? <li class="muted">…and {parsedImport.errors.length - 10} more</li> : null}
                </ul>
              </div>
            </Alert>
          ) : null}
          {parsedImport.valid.length ? (
            <div class="stack">
              <h3>Preview ({parsedImport.valid.length} valid)</h3>
              <div class="table-wrap">
                <table class="table table-compact">
                  <thead><tr><th>Name</th><th>Address</th><th>Criticality</th><th>Owner</th><th>Tags</th></tr></thead>
                  <tbody>
                    {parsedImport.valid.slice(0, 8).map((r, i) => (
                      <tr key={i}>
                        <td>{r.name}</td>
                        <td class="mono">{r.address}</td>
                        <td><Pill kind={criticalityKind(r.criticality)}>{r.criticality}</Pill></td>
                        <td>{r.owner || "—"}</td>
                        <td>{r.tags.join(", ") || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {parsedImport.valid.length > 8 ? <p class="muted">Showing first 8 of {parsedImport.valid.length} valid rows.</p> : null}
            </div>
          ) : null}
        </div>
      </Modal>
    </div>
  );
}
