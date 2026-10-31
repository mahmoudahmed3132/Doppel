// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Events: filters (§6.4), keyset pagination, detail drawer, read/archive,
// export. Every field is attacker-influenced and rendered as text only.
import { useEffect, useMemo, useState } from "preact/hooks";
import { enc, errorText, get, post, qs } from "../api";
import { refreshUnread } from "../app";
import { fmtTime, localToRFC3339, pretty } from "../format";
import { onLive } from "../live";
import { Link, navigate, useLocation } from "../router";
import { type EventRecord, type NodeSummary, SEVERITIES, type Severity } from "../types";
import { Alert, Button, Card, Confirm, Empty, ErrorBox, KV, Loading, Modal, PageHead, Pill, SeverityBadge, toast, useAction, useAsync } from "../ui";

interface Filter { archived: "false" | "true" | "any"; severity: Severity[]; node: string; sensor: string; trigger: string; from: string; to: string; q: string }
const emptyFilter: Filter = { archived: "false", severity: [], node: "", sensor: "", trigger: "", from: "", to: "", q: "" };

function filterQuery(f: Filter): Record<string, string> {
  return {
    archived: f.archived, severity: f.severity.join(","), node: f.node, sensor: f.sensor.trim(), trigger: f.trigger.trim(),
    from: localToRFC3339(f.from), to: localToRFC3339(f.to), q: f.q.trim(),
  };
}

export function Events() {
  const { query } = useLocation();
  const [draft, setDraft] = useState<Filter>(emptyFilter);
  const [filter, setFilter] = useState<Filter>(emptyFilter);
  const [events, setEvents] = useState<EventRecord[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [fresh, setFresh] = useState(0);
  const [confirm, setConfirm] = useState<"" | "read" | "archive">("");
  const act = useAction();
  const nodes = useAsync(() => get<{ nodes: NodeSummary[] }>("/nodes").then((r) => r.nodes), []);
  const openSeq = Number(query.get("open")) || 0;

  async function load(f: Filter, before?: number) {
    setLoading(true);
    setError(null);
    try {
      const r = await get<{ events: EventRecord[]; next_cursor: number | null }>("/events" + qs({ ...filterQuery(f), before, limit: 100 }));
      setEvents((prev) => (before ? [...prev, ...r.events] : r.events));
      setCursor(r.next_cursor ?? null);
      if (!before) setFresh(0);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(filter); }, [filter]);
  useEffect(() => onLive((m) => { if (m.type === "event") setFresh((n) => n + 1); }), []);

  const apply = (e?: Event) => {
    e?.preventDefault();
    setFilter({ ...draft });
  };
  const toggleSev = (s: Severity) =>
    setDraft((d) => ({ ...d, severity: d.severity.includes(s) ? d.severity.filter((x) => x !== s) : [...d.severity, s] }));

  const exportURL = (format: "json" | "csv") => "/api/v3/events/export" + qs({ ...filterQuery(filter), format });
  const setOpen = (seq: number | null) => navigate(seq ? `/events?open=${seq}` : "/events", true);

  const update = (seq: number, patch: Partial<EventRecord>) =>
    setEvents((list) => list.map((e) => (e.seq === seq ? { ...e, ...patch } : e)));

  return (
    <div class="stack-lg">
      <PageHead
        title="Events"
        actions={
          <>
            <a class="btn btn-sm" href={exportURL("csv")} download>Export CSV</a>
            <a class="btn btn-sm" href={exportURL("json")} download>Export JSON</a>
            <Button small onClick={() => setConfirm("read")}>Mark all read</Button>
            <Button small onClick={() => setConfirm("archive")}>Archive all</Button>
          </>
        }
      />
      <Card>
        <form class="filters" onSubmit={apply}>
          <label class="filter">
            <span>View</span>
            <select class="input" value={draft.archived} onChange={(e) => setDraft({ ...draft, archived: e.currentTarget.value as Filter["archived"] })}>
              <option value="false">Active</option>
              <option value="true">Archived</option>
              <option value="any">All</option>
            </select>
          </label>
          <label class="filter">
            <span>Node</span>
            <select class="input" value={draft.node} onChange={(e) => setDraft({ ...draft, node: e.currentTarget.value })}>
              <option value="">Any</option>
              {(nodes.data ?? []).map((n) => <option key={n.id} value={n.id}>{n.alias || n.id}</option>)}
            </select>
          </label>
          <label class="filter"><span>Sensor</span><input class="input mono" placeholder="ts-…" value={draft.sensor} onInput={(e) => setDraft({ ...draft, sensor: e.currentTarget.value })} /></label>
          <label class="filter"><span>Trigger</span><input class="input mono" value={draft.trigger} onInput={(e) => setDraft({ ...draft, trigger: e.currentTarget.value })} /></label>
          <label class="filter"><span>From</span><input class="input" type="datetime-local" value={draft.from} onInput={(e) => setDraft({ ...draft, from: e.currentTarget.value })} /></label>
          <label class="filter"><span>To</span><input class="input" type="datetime-local" value={draft.to} onInput={(e) => setDraft({ ...draft, to: e.currentTarget.value })} /></label>
          <label class="filter filter-grow"><span>Search</span><input class="input" type="search" maxLength={200} placeholder="source, target, details…" value={draft.q} onInput={(e) => setDraft({ ...draft, q: e.currentTarget.value })} /></label>
          <fieldset class="sev-filter">
            <legend>Severity</legend>
            {SEVERITIES.map((s) => (
              <label key={s} class={`chip chip-${s}${draft.severity.includes(s) ? " chip-on" : ""}`}>
                <input type="checkbox" class="sr-only" checked={draft.severity.includes(s)} onChange={() => toggleSev(s)} />
                {s}
              </label>
            ))}
          </fieldset>
          <div class="filter-actions">
            <Button type="submit" variant="primary" small>Apply</Button>
            <Button small variant="ghost" onClick={() => { setDraft(emptyFilter); setFilter(emptyFilter); }}>Reset</Button>
          </div>
        </form>
      </Card>

      {fresh > 0 ? (
        <div class="notice notice-inline" role="status">
          <span>{fresh} new event{fresh === 1 ? "" : "s"} since this list was loaded.</span>
          <Button small variant="primary" onClick={() => load(filter)}>Show</Button>
        </div>
      ) : null}

      <ErrorBox error={error} retry={() => load(filter)} />
      <div class="table-wrap">
        <table class="table events-table">
          <thead>
            <tr>
              <th class="col-dot"><span class="sr-only">Unread</span></th>
              <th>Received</th><th>Severity</th><th>Trigger</th><th>Node</th><th>Sensor</th><th>Source</th><th>Target</th><th>Flags</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.seq} class={`row-click${e.read ? "" : " unread"}`} tabIndex={0}
                onClick={() => setOpen(e.seq)} onKeyDown={(k) => { if (k.key === "Enter" || k.key === " ") { k.preventDefault(); setOpen(e.seq); } }}
                aria-label={`${e.severity} ${e.trigger} from ${e.source}`}>
                <td class="col-dot">{e.read ? null : <span class="dot" title="Unread" />}</td>
                <td class="nowrap" title={`occurred ${fmtTime(e.occurred_at)}`}>{fmtTime(e.received_at)}</td>
                <td><SeverityBadge sev={e.severity} /></td>
                <td class="mono">{e.trigger}</td>
                <td>{e.node_alias || e.node_id}</td>
                <td class="mono">{e.sensor_id}</td>
                <td class="mono trunc">{e.source}</td>
                <td class="mono trunc">{e.target}</td>
                <td class="nowrap">
                  {e.whitelisted ? <Pill kind="info">whitelisted</Pill> : null}
                  {e.known_scanner ? <Pill kind="neutral">scanner</Pill> : null}
                  {e.archived ? <Pill kind="neutral">archived</Pill> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && !events.length && !error ? <Empty>No events match these filters.</Empty> : null}
        {loading ? <Loading /> : null}
      </div>
      {cursor && !loading ? <div class="center"><Button onClick={() => load(filter, cursor)}>Load older events</Button></div> : null}

      <EventDrawer seq={openSeq} known={events.find((e) => e.seq === openSeq)} onClose={() => setOpen(null)} onChange={update} />

      <Confirm
        open={confirm !== ""}
        title={confirm === "read" ? "Mark all events read?" : "Archive all events?"}
        body={confirm === "read" ? "Every unread event is marked read." : "Every active event moves to the archive. Archived events remain searchable and exportable."}
        confirmLabel={confirm === "read" ? "Mark all read" : "Archive all"}
        busy={act.busy}
        onClose={() => setConfirm("")}
        onConfirm={async () => {
          const r = await act.run(() => post<{ updated: number }>(confirm === "read" ? "/events/read-all" : "/events/archive-all"));
          if (r) toast(`${r.updated} event${r.updated === 1 ? "" : "s"} updated`, "ok");
          setConfirm("");
          refreshUnread();
          load(filter);
        }}
      />
    </div>
  );
}

function EventDrawer({ seq, known, onClose, onChange }: { seq: number; known?: EventRecord; onClose: () => void; onChange: (seq: number, p: Partial<EventRecord>) => void }) {
  const [ev, setEv] = useState<EventRecord | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const act = useAction();

  useEffect(() => {
    setErr(null);
    if (!seq) { setEv(null); return; }
    if (known) setEv(known);
    else get<{ event: EventRecord }>(`/events/${seq}`).then((r) => setEv(r.event), setErr);
  }, [seq]);

  useEffect(() => {
    if (!ev || ev.read) return;
    post(`/events/${ev.seq}/read`).then(() => {
      setEv((x) => (x ? { ...x, read: true } : x));
      onChange(ev.seq, { read: true });
      refreshUnread();
    }, () => {});
  }, [ev?.seq]);

  const details = useMemo(() => (ev ? pretty(ev.details) : ""), [ev]);
  const loc = ev?.enrichment.location;
  const attack = ev?.enrichment.attack;
  const asset = ev?.enrichment.source_asset;

  return (
    <Modal title={ev ? `Event #${ev.seq}` : "Event"} open={seq > 0} onClose={onClose} side
      footer={ev ? (
        <>
          {!ev.archived ? (
            <Button busy={act.busy} onClick={async () => {
              if (await act.run(() => post(`/events/${ev.seq}/archive`), "Event archived")) {
                setEv({ ...ev, archived: true });
                onChange(ev.seq, { archived: true });
              }
            }}>Archive</Button>
          ) : null}
          <Button variant="ghost" onClick={onClose}>Close</Button>
        </>
      ) : undefined}>
      {err ? <Alert kind="error">{errorText(err)}</Alert> : !ev ? <Loading /> : (
        <div class="stack">
          <div class="row"><SeverityBadge sev={ev.severity} /><span class="mono strong">{ev.trigger}</span></div>
          <KV rows={[
            ["Event ID", <span class="mono">{ev.event_id}</span>],
            ["Received", fmtTime(ev.received_at)],
            ["Occurred", fmtTime(ev.occurred_at)],
            ["Node", <><Link href={`/fleet/${enc(ev.node_id)}`}>{ev.node_alias || ev.node_id}</Link> <span class="muted mono">{ev.node_id}</span></>],
            ["Sensor", <span class="mono">{ev.sensor_id}</span>],
            ["Source", <span class="mono break">{ev.source}</span>],
            ["Target", <span class="mono break">{ev.target}</span>],
            ["State", <>{ev.read ? "read" : "unread"}{ev.archived ? ", archived" : ""}{ev.whitelisted ? ", whitelisted source" : ""}{ev.known_scanner ? ", known scanner" : ""}</>],
          ]} />
          <h3>ATT&amp;CK</h3>
          {attack ? (
            <ul class="plain">
              {[attack.primary, ...(attack.secondary ?? [])].map((t, i) => (
                <li key={t.id + i}><span class="mono">{t.id}</span> {t.name} <span class="muted">({(t.tactics ?? []).join(", ")})</span>{i === 0 ? <Pill kind="info">primary</Pill> : null}</li>
              ))}
            </ul>
          ) : <p class="muted">No mapping (the ATT&amp;CK module is not installed or has no mapping for this trigger).</p>}
          <h3>Source asset</h3>
          {asset ? <KV rows={[["Name", asset.name], ["Criticality", asset.criticality]]} /> : <p class="muted">Not in the asset inventory.</p>}
          <h3>Location</h3>
          {loc ? (
            <>
              <KV rows={[
                ["Country", `${loc.country}${loc.country_code ? ` (${loc.country_code})` : ""}`],
                ["Region / city", [loc.region, loc.city].filter(Boolean).join(" / ")],
                ["Coordinates", `${loc.lat.toFixed(3)}, ${loc.lon.toFixed(3)}`],
                ["Basis", `${loc.basis}${loc.address ? ` — ${loc.address}` : ""}`],
              ]} />
              <p class="credit"><a href="https://db-ip.com" rel="noopener noreferrer" target="_blank">IP Geolocation by DB-IP</a></p>
            </>
          ) : <p class="muted">No location (private address or geolocation not installed).</p>}
          <h3>Details</h3>
          <pre class="code">{details}</pre>
        </div>
      )}
    </Modal>
  );
}
