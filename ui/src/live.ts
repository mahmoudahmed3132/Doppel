// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Live feed client for /api/v3/live (WebSocket, server push only). Reconnects
// with capped exponential backoff; a 1008 close means the session ended.
import { store } from "./store";
import type { EventRecord } from "./types";

export type LiveState = "connecting" | "open" | "closed";
export type LiveMessage =
  | { type: "event"; data: EventRecord }
  | { type: "status"; data: { node_id: string; sensor_id: string; status: string; at: string } }
  | { type: "tick"; data: { time: string } }
  | { type: "refresh"; data: { charts: boolean } };

export const liveState = store<LiveState>("closed");
const listeners = new Set<(m: LiveMessage) => void>();

export function onLive(fn: (m: LiveMessage) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

let ws: WebSocket | null = null;
let wanted = false;
let backoff = 1000;
let timer: number | undefined;
let onSessionEnd: () => void = () => {};

export function startLive(sessionEnded: () => void) {
  onSessionEnd = sessionEnded;
  wanted = true;
  connect();
}

export function stopLive() {
  wanted = false;
  window.clearTimeout(timer);
  ws?.close(1000);
  ws = null;
  liveState.set("closed");
}

function connect() {
  if (!wanted || ws) return;
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  liveState.set("connecting");
  const sock = new WebSocket(`${proto}//${location.host}/api/v3/live`);
  ws = sock;
  sock.onopen = () => {
    backoff = 1000;
    liveState.set("open");
  };
  sock.onmessage = (e) => {
    if (typeof e.data !== "string" || e.data.length > 1 << 20) return;
    let m: LiveMessage;
    try {
      m = JSON.parse(e.data);
    } catch {
      return;
    }
    if (!m || typeof m.type !== "string") return;
    listeners.forEach((fn) => fn(m));
  };
  sock.onclose = (e) => {
    if (ws === sock) ws = null;
    liveState.set("closed");
    if (!wanted) return;
    if (e.code === 1008) {
      onSessionEnd();
      return;
    }
    timer = window.setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 30000);
  };
}
