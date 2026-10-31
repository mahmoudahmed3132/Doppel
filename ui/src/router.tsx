// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
//
// History-API router. The Hub serves index.html for every non-API path.
import type { ComponentChildren } from "preact";
import { store, useStore } from "./store";

const loc = store(location.pathname + location.search);
window.addEventListener("popstate", () => loc.set(location.pathname + location.search));

export function navigate(to: string, replace = false) {
  if (to === location.pathname + location.search) return;
  if (replace) history.replaceState(null, "", to);
  else history.pushState(null, "", to);
  loc.set(to);
  window.scrollTo(0, 0);
}

export function useLocation(): { path: string; query: URLSearchParams } {
  const full = useStore(loc);
  const i = full.indexOf("?");
  return { path: i < 0 ? full : full.slice(0, i), query: new URLSearchParams(i < 0 ? "" : full.slice(i + 1)) };
}

/** Matches "/fleet/:node" style patterns. */
export function match(pattern: string, path: string): Record<string, string> | null {
  const p = pattern.split("/"), a = path.split("/");
  if (p.length !== a.length) return null;
  const out: Record<string, string> = {};
  for (let i = 0; i < p.length; i++) {
    if (p[i].startsWith(":")) {
      if (!a[i]) return null;
      out[p[i].slice(1)] = decodeURIComponent(a[i]);
    } else if (p[i] !== a[i]) return null;
  }
  return out;
}

export function Link(props: { href: string; class?: string; children: ComponentChildren; title?: string; "aria-current"?: "page" | undefined }) {
  return (
    <a
      href={props.href}
      class={props.class}
      title={props.title}
      aria-current={props["aria-current"]}
      onClick={(e) => {
        if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        e.preventDefault();
        navigate(props.href);
      }}
    >
      {props.children}
    </a>
  );
}
