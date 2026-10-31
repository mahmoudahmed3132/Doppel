// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
//
// Application shell: decides between setup, login, MFA enrolment and the
// authenticated layout; owns the live feed, unread badge and release notice.
import { Fragment } from "preact";
import { useCallback, useEffect, useState } from "preact/hooks";
import { ENROL_EVENT, UNAUTH_EVENT, get, post } from "./api";
import { liveState, onLive, startLive, stopLive } from "./live";
import { Link, match, navigate, useLocation } from "./router";
import { store, useStore } from "./store";
import type { SystemStatus } from "./types";
import { Button, Loading, Toasts, toast } from "./ui";
import { Setup } from "./pages/setup";
import { Login, EnrolOnly } from "./pages/login";
import { Dashboard } from "./pages/dashboard";
import { Events } from "./pages/events";
import { FleetList, NodePage } from "./pages/fleet";
import { Honeytokens, Beacons, Assets, Attack, Projection } from "./pages/modules";
import { SettingsPage } from "./pages/settings";
import { theme, toggleTheme } from "./theme";

type Phase = "loading" | "setup" | "login" | "enrol" | "ready" | "down";
export const phase = store<Phase>("loading");
export const unread = store<number>(0);
export const systemStatus = store<SystemStatus | null>(null);

export async function refreshStatus() {
  try {
    const r = await get<{ status: SystemStatus }>("/system/status");
    systemStatus.set(r.status);
  } catch {
    /* shown elsewhere */
  }
}

export async function refreshUnread() {
  try {
    const r = await get<{ unread: number }>("/events/unread-count");
    unread.set(r.unread);
  } catch {
    /* ignore */
  }
}

/** Re-evaluates which screen to show. */
export async function resolvePhase() {
  try {
    const s = await get<{ setup_completed: boolean }>("/setup");
    if (!s.setup_completed) return phase.set("setup");
  } catch {
    return phase.set("down");
  }
  try {
    const r = await get<{ session: { enrol_only: boolean } }>("/session");
    phase.set(r.session.enrol_only ? "enrol" : "ready");
  } catch (e: any) {
    phase.set(e?.code === "mfa_enrolment_required" ? "enrol" : "login");
  }
}

export async function logout() {
  try {
    await post("/session/logout");
  } catch {
    /* session may already be gone */
  }
  stopLive();
  phase.set("login");
}

export function App() {
  const p = useStore(phase);
  useEffect(() => {
    resolvePhase();
    const unauth = () => {
      if (phase.get() === "ready" || phase.get() === "enrol") {
        stopLive();
        phase.set("login");
        toast("Your session has ended. Sign in again.", "info");
      }
    };
    const enrol = () => phase.set("enrol");
    window.addEventListener(UNAUTH_EVENT, unauth);
    window.addEventListener(ENROL_EVENT, enrol);
    return () => {
      window.removeEventListener(UNAUTH_EVENT, unauth);
      window.removeEventListener(ENROL_EVENT, enrol);
    };
  }, []);

  let body;
  switch (p) {
    case "loading": body = <div class="center-screen"><Loading /></div>; break;
    case "down": body = <HubDown />; break;
    case "setup": body = <Setup onDone={() => phase.set("login")} />; break;
    case "login": body = <Login onDone={resolvePhase} onSetup={() => phase.set("setup")} />; break;
    case "enrol": body = <EnrolOnly onDone={() => phase.set("login")} />; break;
    case "ready": body = <Shell />; break;
  }
  return (
    <>
      {body}
      <Toasts />
    </>
  );
}

function HubDown() {
  return (
    <div class="center-screen">
      <div class="auth-card">
        <h1>Hub unreachable</h1>
        <p class="muted">The admin API did not answer. Check that the Hub is running.</p>
        <Button variant="primary" onClick={resolvePhase}>Retry</Button>
      </div>
    </div>
  );
}

const NAV: [string, string, string][] = [
  ["/", "Dashboard", "monitor"],
  ["/events", "Events", "events"],
  ["/fleet", "Fleet", "monitor"],
  ["/honeytokens", "Honeytokens", "deception"],
  ["/beacons", "Beacons", "deception"],
  ["/assets", "Assets", "context"],
  ["/attack", "ATT&CK", "analysis"],
  ["/attack-path", "Attack path", "analysis"],
  ["/scans", "Scans", "analysis"],
  ["/geo", "Geo map", "analysis"],
  ["/report", "Report", "analysis"],
  ["/settings", "Settings", "system"],
];

function Shell() {
  const { path } = useLocation();
  const n = useStore(unread);
  const ls = useStore(liveState);
  const st = useStore(systemStatus);
  const th = useStore(theme);

  const sessionEnded = useCallback(() => {
    // The feed closes with 1008 when the session expires or is revoked.
    get("/session").then(
      () => startLive(sessionEnded),
      () => window.dispatchEvent(new Event(UNAUTH_EVENT)),
    );
  }, []);

  useEffect(() => {
    startLive(sessionEnded);
    refreshStatus();
    refreshUnread();
    const off = onLive((m) => {
      if (m.type === "event") unread.set(unread.get() + 1);
      if (m.type === "refresh") refreshUnread();
    });
    const t = window.setInterval(refreshStatus, 60000);
    return () => {
      off();
      window.clearInterval(t);
      stopLive();
    };
  }, []);

  let page;
  let m: Record<string, string> | null;
  if (path === "/") page = <Dashboard />;
  else if (path === "/events") page = <Events />;
  else if (path === "/fleet") page = <FleetList />;
  else if ((m = match("/fleet/:node", path))) page = <NodePage id={m.node} />;
  else if (path === "/honeytokens") page = <Honeytokens />;
  else if (path === "/beacons") page = <Beacons />;
  else if (path === "/assets") page = <Assets />;
  else if (path === "/attack") page = <Attack />;
  else if (path === "/attack-path") page = <Projection page="attack-path" />;
  else if (path === "/scans") page = <Projection page="scans" />;
  else if (path === "/geo") page = <Projection page="geo" />;
  else if (path === "/report") page = <Projection page="report" />;
  else if (path === "/settings") page = <SettingsPage />;
  else page = <NotFound />;

  const active = (href: string) => (href === "/" ? path === "/" : path === href || path.startsWith(href + "/"));
  const liveLabel = ls === "open" ? "Live" : ls === "connecting" ? "Connecting" : "Offline";

  return (
    <div class="layout">
      <a class="skip" href="#main">Skip to content</a>
      <aside class="sidebar">
        <div class="brand">
          <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><path d="M6 20h5l3-9 4 14 3-9h5" class="brand-mark" /></svg>
          <span>TrueSignal</span>
        </div>
        <nav aria-label="Main">
          {NAV.map(([href, label], i) => (
            <Fragment key={href}>
              {i > 0 && NAV[i - 1][2] !== NAV[i][2] ? <div class="nav-sep" /> : null}
              <Link href={href} class={`nav-item${active(href) ? " nav-active" : ""}`} aria-current={active(href) ? "page" : undefined}>
                <span>{label}</span>
                {href === "/events" && n > 0 ? <span class="badge" aria-label={`${n} unread`}>{n > 999 ? "999+" : n}</span> : null}
              </Link>
            </Fragment>
          ))}
        </nav>
        <div class="sidebar-foot muted">{st ? `Hub ${st.version}` : ""}</div>
      </aside>
      <div class="main-col">
        <header class="topbar">
          <div class="topbar-left">
            <span class={`live live-${ls}`} role="status" title={`Live feed: ${liveLabel}`}>
              <span class="live-dot" aria-hidden="true" />
              {liveLabel}
            </span>
            {st && !st.armed ? <span class="pill pill-warn" title="Webhook notifications are disarmed">Disarmed</span> : null}
          </div>
          <div class="topbar-right">
            <Button small variant="ghost" onClick={toggleTheme} aria-label={`Switch to ${th === "dark" ? "light" : "dark"} theme`}>
              {th === "dark" ? "Light theme" : "Dark theme"}
            </Button>
            <Button small variant="ghost" onClick={logout}>Sign out</Button>
          </div>
        </header>
        <ReleaseNotice />
        <main id="main" class="content" tabIndex={-1}>{page}</main>
      </div>
    </div>
  );
}

function ReleaseNotice() {
  const st = useStore(systemStatus);
  const [hideHub, setHideHub] = useState(false);
  if (!st) return null;
  const items = [];
  if (st.hub_update_available && !hideHub) {
    items.push(
      <div class="notice" key="hub">
        <span>Hub {st.updates.latest_hub} is available (running {st.version}). See the operations guide for the upgrade procedure.</span>
        <Button small variant="ghost" onClick={() => setHideHub(true)}>Dismiss</Button>
      </div>,
    );
  }
  if (st.cli_release_notice) {
    items.push(
      <div class="notice" key="cli">
        <span>Node CLI {st.updates.latest_cli} has been released. Update the CLI on your nodes (verify the release signature first).</span>
        <Button small variant="ghost" onClick={async () => {
          try {
            await post("/system/cli-notice/ack", { version: st.updates.latest_cli });
            refreshStatus();
          } catch {
            toast("Could not acknowledge the notice", "error");
          }
        }}>Acknowledge</Button>
      </div>,
    );
  }
  return items.length ? <div class="notices" role="status">{items}</div> : null;
}

function NotFound() {
  return (
    <div class="stack">
      <h1>Not found</h1>
      <p class="muted">This page does not exist.</p>
      <div><Button onClick={() => navigate("/")}>Go to the dashboard</Button></div>
    </div>
  );
}
