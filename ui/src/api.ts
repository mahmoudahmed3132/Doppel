// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Thin client for the admin API (/api/v3). Same-origin fetches carry the
// session cookie; the browser adds Origin on non-GET requests, which the
// Hub's CSRF check requires.

export class ApiError extends Error {
  status: number;
  code: string;
  retryAfter?: number;
  body: Record<string, unknown>;
  constructor(status: number, code: string, message: string, body: Record<string, unknown>, retryAfter?: number) {
    super(message);
    this.status = status;
    this.code = code;
    this.body = body;
    this.retryAfter = retryAfter;
  }
}

/** Fired when a request finds no valid session (but not on login errors). */
export const UNAUTH_EVENT = "ts:unauthenticated";
/** Fired when the session may only finish MFA enrolment. */
export const ENROL_EVENT = "ts:enrolment-required";

const loginCodes = new Set(["invalid_credentials", "mfa_required", "invalid_code", "locked"]);

export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, credentials: "same-origin", headers: { Accept: "application/json" } };
  if (body !== undefined) {
    (init.headers as Record<string, string>)["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let res: Response;
  try {
    res = await fetch("/api/v3" + path, init);
  } catch {
    throw new ApiError(0, "network", "The Hub is unreachable", {});
  }
  let data: any = {};
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = {};
    }
  }
  if (!res.ok || data.ok === false) {
    const code = typeof data.error === "string" ? data.error : "http_" + res.status;
    const msg = typeof data.message === "string" ? data.message : res.statusText || "Request failed";
    const ra = Number(res.headers.get("Retry-After"));
    if (res.status === 401 && !loginCodes.has(code)) window.dispatchEvent(new Event(UNAUTH_EVENT));
    if (res.status === 403 && code === "mfa_enrolment_required") window.dispatchEvent(new Event(ENROL_EVENT));
    throw new ApiError(res.status, code, msg, data, Number.isFinite(ra) && ra > 0 ? ra : undefined);
  }
  return data as T;
}

export const get = <T = any>(p: string) => api<T>("GET", p);
export const post = <T = any>(p: string, b: unknown = {}) => api<T>("POST", p, b);
export const put = <T = any>(p: string, b: unknown) => api<T>("PUT", p, b);
export const patch = <T = any>(p: string, b: unknown) => api<T>("PATCH", p, b);
export const del = <T = any>(p: string) => api<T>("DELETE", p);

export function errorText(e: unknown): string {
  if (e instanceof ApiError) return e.message + (e.code && e.status ? ` (${e.code})` : "");
  if (e instanceof Error) return e.message;
  return String(e);
}

/** Builds a query string, skipping empty values. */
export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    u.set(k, String(v));
  }
  const s = u.toString();
  return s ? "?" + s : "";
}

export const enc = encodeURIComponent;
