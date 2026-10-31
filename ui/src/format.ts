// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

export function fmtTime(s: string | null | undefined): string {
  if (!s) return "—";
  const d = new Date(s);
  if (isNaN(d.getTime()) || d.getUTCFullYear() < 1971) return "—";
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function fmtAgo(s: string | null | undefined, now = Date.now()): string {
  if (!s) return "never";
  const t = new Date(s).getTime();
  if (isNaN(t) || t < 31536000000) return "never";
  const sec = Math.round((now - t) / 1000);
  if (sec < 5) return "just now";
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

export function fmtDuration(sec: number): string {
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

export function fmtNum(n: number | undefined): string {
  return n === undefined ? "—" : n.toLocaleString();
}

/** Lines of a textarea → trimmed, non-empty entries. */
export function lines(s: string): string[] {
  return s.split("\n").map((l) => l.trim()).filter(Boolean);
}

/** Pretty JSON for display only (rendered as escaped text). */
export function pretty(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2) ?? "null";
  } catch {
    return String(v);
  }
}

/** datetime-local value → RFC 3339 (UTC). */
export function localToRFC3339(v: string): string {
  if (!v) return "";
  const d = new Date(v);
  return isNaN(d.getTime()) ? "" : d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
