// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
//
// Shared components. Everything renders data as text (Preact escapes it);
// nothing here builds HTML from strings.
import type { ComponentChildren, ComponentProps } from "preact";
import { useCallback, useEffect, useId, useRef, useState } from "preact/hooks";
import { errorText } from "./api";
import { store, useStore } from "./store";
import type { Severity } from "./types";

// ---- async data -----------------------------------------------------------

export interface Async<T> { data: T | undefined; error: unknown; loading: boolean; reload: () => void; setData: (v: T) => void }

export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): Async<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<unknown>(undefined);
  const [loading, setLoading] = useState(true);
  const [n, setN] = useState(0);
  useEffect(() => {
    let live = true;
    setLoading(true);
    fn().then(
      (v) => { if (live) { setData(v); setError(undefined); setLoading(false); } },
      (e) => { if (live) { setError(e); setLoading(false); } },
    );
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, n]);
  const reload = useCallback(() => setN((x) => x + 1), []);
  return { data, error, loading, reload, setData };
}

/** Runs an action, tracking busy state and surfacing errors as toasts. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const run = useCallback(async <T,>(fn: () => Promise<T>, ok?: string): Promise<T | undefined> => {
    setBusy(true);
    try {
      const v = await fn();
      if (ok) toast(ok, "ok");
      return v;
    } catch (e) {
      toast(errorText(e), "error");
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);
  return { busy, run };
}

// ---- toasts ---------------------------------------------------------------

interface Toast { id: number; text: string; kind: "ok" | "error" | "info" }
const toasts = store<Toast[]>([]);
let toastSeq = 0;

export function toast(text: string, kind: Toast["kind"] = "info") {
  const id = ++toastSeq;
  toasts.set([...toasts.get(), { id, text, kind }].slice(-4));
  window.setTimeout(() => toasts.set(toasts.get().filter((t) => t.id !== id)), kind === "error" ? 8000 : 4000);
}

export function Toasts() {
  const list = useStore(toasts);
  return (
    <div class="toasts" role="status" aria-live="polite">
      {list.map((t) => (
        <div key={t.id} class={`toast toast-${t.kind}`}>{t.text}</div>
      ))}
    </div>
  );
}

// ---- basic elements --------------------------------------------------------

type BtnProps = ComponentProps<"button"> & { variant?: "primary" | "danger" | "ghost" | "default"; busy?: boolean; small?: boolean };

export function Button({ variant = "default", busy, small, children, disabled, class: cls, type, ...rest }: BtnProps) {
  return (
    <button
      type={(type as "button" | "submit" | undefined) ?? "button"}
      class={`btn btn-${variant}${small ? " btn-sm" : ""}${cls ? " " + cls : ""}`}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {busy ? <span class="spinner" aria-hidden="true" /> : null}
      {children}
    </button>
  );
}

export function Field(props: { label: string; hint?: ComponentChildren; error?: string; children: (id: string) => ComponentChildren; inline?: boolean }) {
  const id = useId();
  return (
    <div class={`field${props.inline ? " field-inline" : ""}${props.error ? " field-error" : ""}`}>
      <label for={id}>{props.label}</label>
      {props.children(id)}
      {props.hint ? <div class="hint">{props.hint}</div> : null}
      {props.error ? <div class="error-text" role="alert">{props.error}</div> : null}
    </div>
  );
}

export function ErrorBox({ error, retry }: { error: unknown; retry?: () => void }) {
  if (!error) return null;
  return (
    <div class="alert alert-error" role="alert">
      <span>{errorText(error)}</span>
      {retry ? <Button small variant="ghost" onClick={retry}>Retry</Button> : null}
    </div>
  );
}

export function Alert({ kind = "info", children }: { kind?: "info" | "warn" | "error" | "ok"; children: ComponentChildren }) {
  return <div class={`alert alert-${kind}`} role={kind === "error" ? "alert" : undefined}>{children}</div>;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return <div class="loading"><span class="spinner" aria-hidden="true" />{label}</div>;
}

export function Empty({ children }: { children: ComponentChildren }) {
  return <div class="empty">{children}</div>;
}

export function Card({ title, actions, children, class: cls }: { title?: ComponentChildren; actions?: ComponentChildren; children: ComponentChildren; class?: string }) {
  return (
    <section class={`card${cls ? " " + cls : ""}`}>
      {title || actions ? (
        <header class="card-head">
          {title ? <h2>{title}</h2> : <span />}
          {actions ? <div class="card-actions">{actions}</div> : null}
        </header>
      ) : null}
      <div class="card-body">{children}</div>
    </section>
  );
}

export function PageHead({ title, sub, actions }: { title: string; sub?: ComponentChildren; actions?: ComponentChildren }) {
  return (
    <div class="page-head">
      <div>
        <h1>{title}</h1>
        {sub ? <p class="muted">{sub}</p> : null}
      </div>
      {actions ? <div class="page-actions">{actions}</div> : null}
    </div>
  );
}

export function SeverityBadge({ sev }: { sev: Severity | string }) {
  return <span class={`sev sev-${sev}`}>{sev}</span>;
}

export function Pill({ kind = "neutral", children, title }: { kind?: "ok" | "warn" | "bad" | "neutral" | "info"; children: ComponentChildren; title?: string }) {
  return <span class={`pill pill-${kind}`} title={title}>{children}</span>;
}

export function KV({ rows }: { rows: [string, ComponentChildren][] }) {
  return (
    <dl class="kv">
      {rows.map(([k, v]) => (
        <div class="kv-row" key={k}>
          <dt>{k}</dt>
          <dd>{v === "" || v === null || v === undefined ? <span class="muted">—</span> : v}</dd>
        </div>
      ))}
    </dl>
  );
}

// ---- clipboard ------------------------------------------------------------

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      small
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          window.setTimeout(() => setDone(false), 2000);
        } catch {
          toast("Copy failed: select the text and copy it manually", "error");
        }
      }}
    >
      {done ? "Copied" : label}
    </Button>
  );
}

export function Secret({ value, label }: { value: string; label?: string }) {
  return (
    <div class="secret">
      {label ? <div class="secret-label">{label}</div> : null}
      <div class="secret-row">
        <code class="secret-value">{value}</code>
        <CopyButton text={value} />
      </div>
    </div>
  );
}

// ---- dialogs --------------------------------------------------------------

/** Native <dialog>: focus trapping, Escape and inert background for free. */
export function Modal(props: { title: string; open: boolean; onClose: () => void; children: ComponentChildren; footer?: ComponentChildren; wide?: boolean; side?: boolean; dismissable?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  const dismissable = props.dismissable !== false;
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (props.open && !d.open) d.showModal();
    if (!props.open && d.open) d.close();
  }, [props.open]);
  return (
    <dialog
      ref={ref}
      class={`modal${props.wide ? " modal-wide" : ""}${props.side ? " modal-side" : ""}`}
      aria-label={props.title}
      onCancel={(e) => {
        e.preventDefault();
        if (dismissable) props.onClose();
      }}
      onClick={(e) => {
        if (dismissable && e.target === ref.current) props.onClose();
      }}
    >
      {props.open ? (
        <div class="modal-inner">
          <header class="modal-head">
            <h2>{props.title}</h2>
            {dismissable ? (
              <button type="button" class="icon-btn" aria-label="Close" onClick={props.onClose}>×</button>
            ) : null}
          </header>
          <div class="modal-body">{props.children}</div>
          {props.footer ? <footer class="modal-foot">{props.footer}</footer> : null}
        </div>
      ) : null}
    </dialog>
  );
}

/** Confirmation dialog; with `phrase`, the user must type it exactly. */
export function Confirm(props: {
  open: boolean; title: string; body: ComponentChildren; confirmLabel: string; danger?: boolean;
  phrase?: string; busy?: boolean; onConfirm: () => void; onClose: () => void; extra?: ComponentChildren; ready?: boolean;
}) {
  const [typed, setTyped] = useState("");
  useEffect(() => { if (!props.open) setTyped(""); }, [props.open]);
  const ok = (!props.phrase || typed === props.phrase) && props.ready !== false;
  return (
    <Modal
      title={props.title}
      open={props.open}
      onClose={props.onClose}
      footer={
        <>
          <Button variant="ghost" onClick={props.onClose}>Cancel</Button>
          <Button variant={props.danger ? "danger" : "primary"} disabled={!ok} busy={props.busy} onClick={props.onConfirm}>
            {props.confirmLabel}
          </Button>
        </>
      }
    >
      <div class="stack">
        <div>{props.body}</div>
        {props.extra}
        {props.phrase ? (
          <Field label={`Type ${props.phrase} to confirm`}>
            {(id) => (
              <input id={id} class="input mono" value={typed} autoComplete="off" spellcheck={false}
                onInput={(e) => setTyped(e.currentTarget.value)} />
            )}
          </Field>
        ) : null}
      </div>
    </Modal>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: [T, string][]; value: T; onChange: (t: T) => void }) {
  return (
    <div class="tabs" role="tablist">
      {tabs.map(([k, label]) => (
        <button
          type="button"
          key={k}
          role="tab"
          aria-selected={value === k}
          class={`tab${value === k ? " tab-active" : ""}`}
          onClick={() => onChange(k)}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <label class={`toggle${disabled ? " toggle-disabled" : ""}`}>
      <input type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => onChange(e.currentTarget.checked)} />
      <span class="toggle-track" aria-hidden="true"><span class="toggle-thumb" /></span>
      <span>{label}</span>
    </label>
  );
}
