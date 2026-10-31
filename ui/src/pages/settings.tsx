// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
//
// Settings: general, source lists, retention, SIEM, webhook, security
// (MFA, password), danger zone. Secrets are write-only: the API reports only
// whether they are set.
import { useEffect, useState } from "preact/hooks";
import { ApiError, errorText, get, patch, post, put } from "../api";
import { logout, refreshStatus, refreshUnread, resolvePhase, systemStatus } from "../app";
import { fmtDuration, fmtTime, lines } from "../format";
import { navigate, useLocation } from "../router";
import { useStore } from "../store";
import { type CatalogueStatus, type MFAState, SEVERITIES, type Settings, type Severity } from "../types";
import { Alert, Button, Card, Confirm, ErrorBox, Field, KV, Loading, PageHead, Pill, Tabs, Toggle, toast, useAction, useAsync } from "../ui";
import { MfaEnrol, RecoveryCodes } from "./mfa";
import { MIN_PASSWORD, StrengthMeter } from "./setup";

type Tab = "general" | "sources" | "retention" | "siem" | "webhook" | "security" | "danger";
const TABS: [Tab, string][] = [
  ["general", "General"], ["sources", "Source lists"], ["retention", "Retention"], ["siem", "SIEM output"],
  ["webhook", "Webhook"], ["security", "Security"], ["danger", "Danger zone"],
];

export function SettingsPage() {
  const { query } = useLocation();
  const tab = (TABS.find(([k]) => k === query.get("tab"))?.[0] ?? "general") as Tab;
  const settings = useAsync(() => get<{ settings: Settings }>("/settings").then((r) => r.settings), []);
  const save = async (p: Record<string, unknown>, ok = "Settings saved") => {
    try {
      const r = await patch<{ settings: Settings }>("/settings", p);
      settings.setData(r.settings);
      toast(ok, "ok");
      return true;
    } catch (e) {
      toast(errorText(e), "error");
      return false;
    }
  };
  return (
    <div class="stack-lg">
      <PageHead title="Settings" />
      <Tabs tabs={TABS} value={tab} onChange={(t) => navigate(`/settings?tab=${t}`, true)} />
      <ErrorBox error={settings.error} retry={settings.reload} />
      {tab === "siem" ? <SIEM /> : tab === "webhook" ? <Webhook /> : tab === "security" ? <Security /> : tab === "danger" ? <Danger /> :
        !settings.data ? <Loading /> :
        tab === "general" ? <General s={settings.data} save={save} /> :
        tab === "sources" ? <Sources s={settings.data} save={save} /> :
        <Retention s={settings.data} save={save} />}
    </div>
  );
}

type Save = (p: Record<string, unknown>, ok?: string) => Promise<boolean>;

function General({ s, save }: { s: Settings; save: Save }) {
  const st = useStore(systemStatus);
  const [endpoint, setEndpoint] = useState(s.public_endpoint);
  const [registry, setRegistry] = useState(s.registry_url);
  const [refresh, setRefresh] = useState(String(s.catalogue_refresh_hours));
  const [updates, setUpdates] = useState(String(s.update_check_hours));
  const cat = useAsync(() => get<{ status: CatalogueStatus }>("/catalogue").then((r) => r.status), []);
  const act = useAction();
  return (
    <div class="grid-2">
      <Card title="Hub">
        <form class="stack" onSubmit={(e) => {
          e.preventDefault();
          save({ public_endpoint: endpoint.trim(), registry_url: registry.trim(), catalogue_refresh_hours: Number(refresh), update_check_hours: Number(updates) });
        }}>
          <Field label="Hub endpoint" hint="URL nodes use to reach this Hub. Shown in node link commands.">
            {(id) => <input id={id} class="input mono" type="url" value={endpoint} onInput={(e) => setEndpoint(e.currentTarget.value)} />}
          </Field>
          <Field label="Sensor registry URL" hint="Signed sensor catalogue. Changing it re-verifies every manifest against the new source.">
            {(id) => <input id={id} class="input mono" type="url" value={registry} onInput={(e) => setRegistry(e.currentTarget.value)} />}
          </Field>
          <div class="grid-2 tight">
            <Field label="Catalogue refresh (hours)">{(id) => <input id={id} class="input" type="number" min={1} max={168} value={refresh} onInput={(e) => setRefresh(e.currentTarget.value)} />}</Field>
            <Field label="Update check (hours)" hint="0 disables">{(id) => <input id={id} class="input" type="number" min={0} max={720} value={updates} onInput={(e) => setUpdates(e.currentTarget.value)} />}</Field>
          </div>
          <div><Button type="submit" variant="primary">Save</Button></div>
        </form>
      </Card>
      <div class="stack-lg">
        <Card title="Catalogue" actions={<Button small busy={act.busy} onClick={async () => {
          const r = await act.run(() => post<{ status: CatalogueStatus }>("/catalogue/refresh"), "Catalogue refreshed");
          if (r) cat.setData(r.status);
        }}>Refresh now</Button>}>
          {cat.data ? (
            <>
              <KV rows={[["Registry", <span class="mono break">{cat.data.registry_url}</span>], ["Last refresh", fmtTime(cat.data.last_refresh)]]} />
              {cat.data.last_error ? <Alert kind="warn">Last refresh failed: {cat.data.last_error}</Alert> : null}
            </>
          ) : cat.error ? <ErrorBox error={cat.error} /> : <Loading />}
        </Card>
        <Card title="System" actions={<Button small busy={act.busy} onClick={async () => {
          const r = await act.run(() => post("/system/update-check"), "Update check complete");
          if (r) refreshStatus();
        }}>Check for updates</Button>}>
          {st ? (
            <>
              <KV rows={[
                ["Hub version", st.version], ["Schema", String(st.schema)], ["Uptime", fmtDuration(st.uptime_seconds)],
                ["Latest Hub", st.updates.latest_hub ? <>{st.updates.latest_hub} {st.hub_update_available ? <Pill kind="info">update available</Pill> : null}</> : ""],
                ["Latest CLI", st.updates.latest_cli], ["Last check", fmtTime(st.updates.last_check)],
                ["SIEM queue", `${st.siem_queue.depth} queued, ${st.siem_queue.dropped} dropped`], ["Live clients", String(st.live_clients)],
              ]} />
              {st.updates.last_error ? <Alert kind="warn">Last update check failed: {st.updates.last_error}</Alert> : null}
            </>
          ) : <Loading />}
        </Card>
        <Armed />
      </div>
    </div>
  );
}

function Armed() {
  const st = useStore(systemStatus);
  const act = useAction();
  if (!st) return null;
  return (
    <Card title="Notifications">
      <div class="stack">
        <Toggle label={st.armed ? "Armed — webhook notifications are sent" : "Disarmed — webhook notifications are suppressed"} checked={st.armed} disabled={act.busy}
          onChange={async (v) => { if (await act.run(() => put("/system/armed", { armed: v }), v ? "Armed" : "Disarmed")) refreshStatus(); }} />
        <p class="muted">Disarming (e.g. during maintenance or a pentest) only stops webhook notifications; events are still recorded and sent to the SIEM.</p>
      </div>
    </Card>
  );
}

function Sources({ s, save }: { s: Settings; save: Save }) {
  const [wl, setWl] = useState((s.whitelist ?? []).join("\n"));
  const [ks, setKs] = useState((s.known_scanners ?? []).join("\n"));
  return (
    <Card title="Source lists">
      <form class="stack" onSubmit={(e) => { e.preventDefault(); save({ whitelist: lines(wl), known_scanners: lines(ks) }); }}>
        {!s.source_lists_active ? <Alert kind="warn">The source-list matcher module is not installed: lists are stored but events are not tagged.</Alert> : null}
        <div class="grid-2">
          <Field label="Whitelist" hint="One entry per line (address, CIDR). Matching events are tagged whitelisted and skip webhooks.">
            {(id) => <textarea id={id} class="input mono list-editor" spellcheck={false} value={wl} onInput={(e) => setWl(e.currentTarget.value)} />}
          </Field>
          <Field label="Known scanners" hint="One entry per line. Matching events are tagged known_scanner.">
            {(id) => <textarea id={id} class="input mono list-editor" spellcheck={false} value={ks} onInput={(e) => setKs(e.currentTarget.value)} />}
          </Field>
        </div>
        <div><Button type="submit" variant="primary">Save lists</Button></div>
      </form>
    </Card>
  );
}

function Retention({ s, save }: { s: Settings; save: Save }) {
  const [a, setA] = useState(String(s.retention.archive_after_days));
  const [p, setP] = useState(String(s.retention.purge_archived_after_days));
  const [h, setH] = useState(String(s.retention.history_days));
  return (
    <Card title="Retention">
      <form class="stack" onSubmit={(e) => {
        e.preventDefault();
        save({ retention: { archive_after_days: Number(a), purge_archived_after_days: Number(p), history_days: Number(h) } });
      }}>
        <div class="grid-3">
          <Field label="Archive events after (days)" hint="0 = never">{(id) => <input id={id} class="input" type="number" min={0} max={3650} value={a} onInput={(e) => setA(e.currentTarget.value)} />}</Field>
          <Field label="Delete archived events after (days)" hint="0 = never. Deletion is permanent.">{(id) => <input id={id} class="input" type="number" min={0} max={3650} value={p} onInput={(e) => setP(e.currentTarget.value)} />}</Field>
          <Field label="Sensor status history (days)">{(id) => <input id={id} class="input" type="number" min={1} max={3650} value={h} onInput={(e) => setH(e.currentTarget.value)} />}</Field>
        </div>
        <p class="muted">Check these against your log-retention obligations (e.g. PCI DSS 10.5.1: one year, three months immediately available). The SIEM copy is normally the retained record.</p>
        <div><Button type="submit" variant="primary">Save retention</Button></div>
      </form>
    </Card>
  );
}

interface SIEMState { siem: { protocol: string; address: string; format: string; token_set: boolean }; capabilities: { ecs: boolean; http_transports: boolean }; queue: { depth: number; dropped: number } }

function SIEM() {
  const data = useAsync(() => get<SIEMState>("/settings/siem"), []);
  const [proto, setProto] = useState("none");
  const [addr, setAddr] = useState("");
  const [format, setFormat] = useState("rfc5424");
  const [token, setToken] = useState("");
  const [clearToken, setClearToken] = useState(false);
  const act = useAction();
  useEffect(() => {
    if (!data.data) return;
    setProto(data.data.siem.protocol || "none");
    setAddr(data.data.siem.address);
    setFormat(data.data.siem.format || "rfc5424");
    setToken("");
    setClearToken(false);
  }, [data.data]);
  if (data.error) return <ErrorBox error={data.error} retry={data.reload} />;
  if (!data.data) return <Loading />;
  const caps = data.data.capabilities;
  const http = proto === "elastic" || proto === "logscale";
  const stream = proto === "tcp" || proto === "udp" || proto === "tls";
  return (
    <div class="grid-2">
      <Card title="SIEM output">
        <form class="stack" onSubmit={async (e) => {
          e.preventDefault();
          const body: Record<string, unknown> = { protocol: proto, address: proto === "none" ? "" : addr.trim(), format: stream ? format : "" };
          if (http && token) body.token = token;
          if (http && clearToken) body.token = "";
          const r = await act.run(() => put<SIEMState>("/settings/siem", body), "SIEM output saved");
          if (r) data.reload();
        }}>
          <Field label="Protocol">
            {(id) => (
              <select id={id} class="input" value={proto} onChange={(e) => setProto(e.currentTarget.value)}>
                <option value="none">Disabled</option>
                <option value="tls">Syslog over TLS (recommended)</option>
                <option value="tcp">Syslog over TCP</option>
                <option value="udp">Syslog over UDP</option>
                <option value="elastic" disabled={!caps.http_transports}>Elastic (HTTPS){caps.http_transports ? "" : " — module not installed"}</option>
                <option value="logscale" disabled={!caps.http_transports}>Falcon LogScale (HTTPS){caps.http_transports ? "" : " — module not installed"}</option>
              </select>
            )}
          </Field>
          {proto !== "none" ? (
            <Field label={http ? "URL" : "Address"} hint={http ? "https:// only; redirects are not followed." : "host:port"}>
              {(id) => <input id={id} class="input mono" value={addr} onInput={(e) => setAddr(e.currentTarget.value)} required />}
            </Field>
          ) : null}
          {stream ? (
            <Field label="Format">
              {(id) => (
                <select id={id} class="input" value={format} onChange={(e) => setFormat(e.currentTarget.value)}>
                  <option value="rfc5424">RFC 5424 syslog</option>
                  <option value="ecs" disabled={!caps.ecs}>ECS JSON{caps.ecs ? "" : " — module not installed"}</option>
                </select>
              )}
            </Field>
          ) : null}
          {http ? (
            <>
              <Field label="Ingest token" hint={data.data.siem.token_set ? "A token is set. Leave blank to keep it." : "No token set."}>
                {(id) => <input id={id} class="input mono" type="password" autoComplete="new-password" value={token} disabled={clearToken} onInput={(e) => setToken(e.currentTarget.value)} />}
              </Field>
              {data.data.siem.token_set ? <label class="check"><input type="checkbox" checked={clearToken} onChange={(e) => setClearToken(e.currentTarget.checked)} /> Clear the stored token</label> : null}
            </>
          ) : null}
          {proto === "udp" ? <Alert kind="warn">UDP syslog is unauthenticated, unencrypted and lossy. Use TLS for audit records you rely on.</Alert> : null}
          {proto === "tcp" ? <Alert kind="warn">Plain TCP is unencrypted. Prefer TLS outside an isolated management network.</Alert> : null}
          <p class="muted">Switching output sends an audit record of the change to the previous destination first.</p>
          <div class="row">
            <Button type="submit" variant="primary" busy={act.busy}>Save</Button>
            <Button busy={act.busy} disabled={data.data.siem.protocol === "none"} onClick={() => act.run(() => post("/settings/siem/test"), "Test record delivered")}>Send test record</Button>
          </div>
        </form>
      </Card>
      <Card title="Delivery">
        <KV rows={[["Configured", `${data.data.siem.protocol}${data.data.siem.address ? " → " + data.data.siem.address : ""}`], ["Queue depth", String(data.data.queue.depth)], ["Dropped records", String(data.data.queue.dropped)]]} />
        {data.data.queue.dropped > 0 ? <Alert kind="warn">Records have been dropped because the queue was full. Check the collector's reachability.</Alert> : null}
      </Card>
    </div>
  );
}

interface WebhookState { webhook: { type: string; severities: Severity[] | null; url_set: boolean }; dropped: number; armed: boolean }

function Webhook() {
  const data = useAsync(() => get<WebhookState>("/settings/webhook"), []);
  const [type, setType] = useState("none");
  const [url, setUrl] = useState("");
  const [sev, setSev] = useState<Severity[]>([]);
  const act = useAction();
  useEffect(() => {
    if (!data.data) return;
    setType(data.data.webhook.type || "none");
    setSev(data.data.webhook.severities ?? []);
    setUrl("");
  }, [data.data]);
  if (data.error) return <ErrorBox error={data.error} retry={data.reload} />;
  if (!data.data) return <Loading />;
  return (
    <div class="grid-2">
      <Card title="Webhook">
        <form class="stack" onSubmit={async (e) => {
          e.preventDefault();
          const body: Record<string, unknown> = { type, severities: sev };
          if (url.trim()) body.url = url.trim();
          if (type === "none") body.url = "";
          if (await act.run(() => put("/settings/webhook", body), "Webhook saved")) data.reload();
        }}>
          <Field label="Type">
            {(id) => (
              <select id={id} class="input" value={type} onChange={(e) => setType(e.currentTarget.value)}>
                <option value="none">Disabled</option>
                <option value="slack">Slack</option>
                <option value="discord">Discord</option>
                <option value="ntfy">ntfy</option>
                <option value="gotify">Gotify</option>
              </select>
            )}
          </Field>
          {type !== "none" ? (
            <Field label="URL" hint={data.data.webhook.url_set ? "A URL is set (it contains a secret and is never shown). Leave blank to keep it." : "https:// URL including its token."}>
              {(id) => <input id={id} class="input mono" type="password" autoComplete="off" value={url} onInput={(e) => setUrl(e.currentTarget.value)} required={!data.data!.webhook.url_set} />}
            </Field>
          ) : null}
          {type !== "none" ? (
            <fieldset class="sev-filter">
              <legend>Notify for severities</legend>
              {SEVERITIES.map((s) => (
                <label key={s} class={`chip chip-${s}${sev.includes(s) ? " chip-on" : ""}`}>
                  <input type="checkbox" class="sr-only" checked={sev.includes(s)} onChange={() => setSev(sev.includes(s) ? sev.filter((x) => x !== s) : [...sev, s])} />
                  {s}
                </label>
              ))}
            </fieldset>
          ) : null}
          <div class="row">
            <Button type="submit" variant="primary" busy={act.busy}>Save</Button>
            <Button busy={act.busy} disabled={data.data.webhook.type === "none"} onClick={() => act.run(() => post("/settings/webhook/test"), "Test notification delivered")}>Send test</Button>
          </div>
        </form>
      </Card>
      <div class="stack-lg">
        <Card title="Delivery">
          <KV rows={[["State", data.data.armed ? <Pill kind="ok">armed</Pill> : <Pill kind="warn">disarmed</Pill>], ["Dropped notifications", String(data.data.dropped)]]} />
        </Card>
        <Armed />
      </div>
    </div>
  );
}

function Security() {
  const mfa = useAsync(() => get<{ mfa: MFAState }>("/mfa").then((r) => r.mfa), []);
  const managed = useAsync(() => get<{ password_managed: boolean }>("/session").then((r) => r.password_managed), []);
  return (
    <div class="grid-2">
      <MfaCard mfa={mfa.data} error={mfa.error} reload={mfa.reload} />
      <PasswordCard managed={managed.data} />
    </div>
  );
}

function MfaCard({ mfa, error, reload }: { mfa?: MFAState; error: unknown; reload: () => void }) {
  const [mode, setMode] = useState<"" | "enrol" | "disable" | "regen">("");
  const [pw, setPw] = useState("");
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const act = useAction();
  const reset = () => { setMode(""); setPw(""); setCode(""); };
  if (error) return <Card title="Two-factor authentication"><ErrorBox error={error} retry={reload} /></Card>;
  if (!mfa) return <Card title="Two-factor authentication"><Loading /></Card>;
  return (
    <Card title="Two-factor authentication">
      <div class="stack">
        {!mfa.available ? <Alert kind="warn">The TOTP module is not installed on this Hub; MFA cannot be enabled.</Alert> : null}
        <KV rows={[
          ["Status", mfa.enabled ? <Pill kind="ok">enabled</Pill> : <Pill kind="warn">disabled</Pill>],
          ["Required by policy", mfa.required ? "yes" : "no"],
          ["Recovery codes left", mfa.enabled ? String(mfa.recovery_codes_remaining) : ""],
        ]} />
        {mfa.enabled && mfa.recovery_codes_remaining <= 3 ? <Alert kind="warn">Few recovery codes remain. Generate a new set.</Alert> : null}
        {codes ? <><RecoveryCodes codes={codes} /><div><Button onClick={() => setCodes(null)}>Done</Button></div></> : null}
        {mode === "enrol" ? (
          <MfaEnrol onDone={() => { toast("MFA enabled. Sign in again.", "ok"); logout().then(resolvePhase); }} />
        ) : mode === "disable" || mode === "regen" ? (
          <form class="stack" onSubmit={async (e) => {
            e.preventDefault();
            if (mode === "disable") {
              if (await act.run(() => post("/mfa/disable", { password: pw, code: code.trim() }), "MFA disabled. Sign in again.")) { await logout(); resolvePhase(); }
            } else {
              const r = await act.run(() => post<{ recovery_codes: string[] }>("/mfa/recovery-codes", { password: pw, code: code.trim() }));
              if (r) { setCodes(r.recovery_codes); reset(); reload(); }
            }
          }}>
            <Field label="Password">{(id) => <input id={id} class="input" type="password" autoComplete="current-password" value={pw} onInput={(e) => setPw(e.currentTarget.value)} required />}</Field>
            <Field label="Authenticator code">{(id) => <input id={id} class="input mono" autoComplete="one-time-code" value={code} onInput={(e) => setCode(e.currentTarget.value)} required />}</Field>
            {mode === "disable" && mfa.required ? <Alert kind="warn">MFA is required by policy; after disabling, you must enrol again at next sign-in.</Alert> : null}
            <div class="row">
              <Button type="submit" variant={mode === "disable" ? "danger" : "primary"} busy={act.busy}>{mode === "disable" ? "Disable MFA" : "Generate new codes"}</Button>
              <Button variant="ghost" onClick={reset}>Cancel</Button>
            </div>
          </form>
        ) : mfa.available && !codes ? (
          <div class="row">
            {!mfa.enabled ? <Button variant="primary" onClick={() => setMode("enrol")}>Enable MFA</Button> : (
              <>
                <Button onClick={() => setMode("regen")}>Regenerate recovery codes</Button>
                <Button variant="danger" onClick={() => setMode("disable")}>Disable MFA</Button>
              </>
            )}
          </div>
        ) : null}
        <p class="muted">Lost every factor? Use the break-glass command <code>truesignal-hub mfa-reset</code> on the Hub host (see the operations guide).</p>
      </div>
    </Card>
  );
}

function PasswordCard({ managed }: { managed?: boolean }) {
  const [cur, setCur] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const act = useAction();
  const ok = cur && pw.length >= MIN_PASSWORD && pw === pw2;
  return (
    <Card title="Admin password">
      {managed === undefined ? <Loading /> : managed ? (
        <Alert kind="info">The admin password is set by the Hub's environment (the password override variable), so it cannot be changed here. Change it in the deployment configuration and restart the Hub.</Alert>
      ) : (
        <form class="stack" onSubmit={async (e) => {
          e.preventDefault();
          if (await act.run(() => post("/system/password", { current_password: cur, new_password: pw }), "Password changed. Sign in again.")) {
            await logout();
            resolvePhase();
          }
        }}>
          <Field label="Current password">{(id) => <input id={id} class="input" type="password" autoComplete="current-password" value={cur} onInput={(e) => setCur(e.currentTarget.value)} required />}</Field>
          <Field label="New password">{(id) => <input id={id} class="input" type="password" autoComplete="new-password" value={pw} onInput={(e) => setPw(e.currentTarget.value)} required />}</Field>
          <StrengthMeter pw={pw} />
          <Field label="Confirm new password" error={pw2 && pw !== pw2 ? "Passwords do not match" : undefined}>{(id) => <input id={id} class="input" type="password" autoComplete="new-password" value={pw2} onInput={(e) => setPw2(e.currentTarget.value)} required />}</Field>
          <p class="muted">Every session, including this one, is signed out.</p>
          <div><Button type="submit" variant="primary" busy={act.busy} disabled={!ok}>Change password</Button></div>
        </form>
      )}
    </Card>
  );
}

function Danger() {
  const [which, setWhich] = useState<"" | "events" | "reset">("");
  const [pw, setPw] = useState("");
  const [purge, setPurge] = useState(false);
  const [err, setErr] = useState("");
  const act = useAction();
  const close = () => { setWhich(""); setPw(""); setPurge(false); setErr(""); };
  return (
    <div class="stack-lg">
      <Card title="Delete all events" class="card-danger">
        <div class="row between">
          <p>Permanently deletes every event, active and archived. SIEM copies are unaffected. This is audited.</p>
          <Button variant="danger" onClick={() => setWhich("events")}>Delete all events</Button>
        </div>
      </Card>
      <Card title="Factory reset" class="card-danger">
        <div class="row between">
          <p>Deletes the admin account, sessions, MFA, nodes, sensors, events, settings and beacons. Every node key is revoked. Audited to the current SIEM output before execution; refused if that record cannot be delivered.</p>
          <Button variant="danger" onClick={() => setWhich("reset")}>Factory reset</Button>
        </div>
      </Card>
      <Confirm open={which === "events"} title="Delete all events?" danger confirmLabel="Delete all events" phrase="DELETE ALL EVENTS" busy={act.busy}
        body="This cannot be undone." onClose={close}
        onConfirm={async () => {
          const r = await act.run(() => post<{ deleted: number }>("/events/delete-all", { confirm: "DELETE ALL EVENTS" }));
          if (r) { toast(`${r.deleted} events deleted`, "ok"); refreshUnread(); close(); }
        }} />
      <Confirm open={which === "reset"} title="Factory reset?" danger confirmLabel="Reset the Hub" phrase="FACTORY RESET" busy={act.busy} ready={!!pw}
        body="The Hub returns to first-run setup. A new one-time setup token is written to the Hub log."
        extra={
          <div class="stack">
            {err ? <Alert kind="error">{err}</Alert> : null}
            <Field label="Admin password">{(id) => <input id={id} class="input" type="password" autoComplete="current-password" value={pw} onInput={(e) => setPw(e.currentTarget.value)} />}</Field>
            <label class="check"><input type="checkbox" checked={purge} onChange={(e) => setPurge(e.currentTarget.checked)} /> Also delete honeytokens (they may still be planted in lures; deleting them means their use is no longer recognised)</label>
          </div>
        }
        onClose={close}
        onConfirm={async () => {
          setErr("");
          try {
            await post("/system/factory-reset", { password: pw, confirm: "FACTORY RESET", purge_honeytokens: purge });
            close();
            toast("Factory reset complete", "ok");
            resolvePhase();
          } catch (e) {
            setErr(e instanceof ApiError && e.code === "audit_undeliverable"
              ? "Refused: the audit record could not be delivered to the SIEM output. Fix or disable the output first."
              : e instanceof ApiError && e.code === "invalid_credentials" ? "Incorrect password." : errorText(e));
          }
        }} />
    </div>
  );
}
