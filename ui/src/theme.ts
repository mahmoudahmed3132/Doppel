// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Dark theme by default; the choice is kept per browser.
import { store } from "./store";

type Theme = "dark" | "light";
function initial(): Theme {
  try {
    const v = localStorage.getItem("ts-theme");
    if (v === "light" || v === "dark") return v;
  } catch {
    /* storage may be blocked */
  }
  return "dark";
}

export const theme = store<Theme>(initial());

function apply(t: Theme) {
  document.documentElement.dataset.theme = t;
}
apply(theme.get());
theme.subscribe(apply);

export function toggleTheme() {
  const t: Theme = theme.get() === "dark" ? "light" : "dark";
  theme.set(t);
  try {
    localStorage.setItem("ts-theme", t);
  } catch {
    /* ignore */
  }
}
