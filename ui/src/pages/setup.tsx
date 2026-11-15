// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// First-run setup: one-time setup token (printed in the Hub log), admin
// password, public Hub endpoint.
import { useState } from "preact/hooks";
import { ApiError, errorText, post } from "../api";
import { Alert, Button, Field } from "../ui";

export const MIN_PASSWORD = 12;

/** Rough strength estimate for the meter; the Hub enforces the minimum. */
export function strength(pw: string): { score: number; label: string } {
  if (pw.length < MIN_PASSWORD) return { score: 0, label: `Too short (${pw.length}/${MIN_PASSWORD})` };
  let classes = 0;
  for (const re of [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/]) if (re.test(pw)) classes++;
  const unique = new Set(pw).size;
  let score = 1;
  if (pw.length >= 16) score++;
  if (pw.length >= 20) score++;
  if (classes >= 3) score++;
  if (unique < 6) score = 1;
  score = Math.min(4, score);
  return { score, label: ["Too short", "Weak", "Fair", "Good", "Strong"][score] };
}

export function StrengthMeter({ pw }: { pw: string }) {
  const s = strength(pw);
  return (
    <div class="meter" aria-live="polite">
      <div class={`meter-bar meter-${s.score}`} role="meter" aria-valuemin={0} aria-valuemax={4} aria-valuenow={s.score} aria-label="Password strength">
        {[1, 2, 3, 4].map((i) => <span key={i} class={i <= s.score ? "on" : ""} />)}
      </div>
      <span class="meter-label">{pw ? s.label : `At least ${MIN_PASSWORD} characters`}</span>
    </div>
  );
}

export function Setup({ onDone }: { onDone: () => void }) {
  const [token, setToken] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [endpoint, setEndpoint] = useState(location.origin);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const mismatch = pw2 !== "" && pw !== pw2;
  const valid = token.trim() !== "" && pw.length >= MIN_PASSWORD && pw === pw2 && endpoint.trim() !== "";

  async function submit(e: Event) {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    setErr("");
    try {
      await post("/setup", { setup_token: token.trim(), password: pw, public_endpoint: endpoint.trim() });
      onDone();
    } catch (e) {
      setErr(e instanceof ApiError && e.code === "invalid_setup_token" ? "The setup token is not valid. Copy it again from the Hub log." : errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="center-screen">
      <form class="auth-card" onSubmit={submit}>
        <h1>Set up Doppel</h1>
        <p class="muted">The one-time setup token is printed in the Hub log at first start.</p>
        {err ? <Alert kind="error">{err}</Alert> : null}
        <Field label="Setup token">
          {(id) => <input id={id} class="input mono" autoComplete="off" spellcheck={false} value={token} onInput={(e) => setToken(e.currentTarget.value)} required />}
        </Field>
        <Field label="Admin password">
          {(id) => <input id={id} class="input" type="password" autoComplete="new-password" value={pw} onInput={(e) => setPw(e.currentTarget.value)} required minLength={MIN_PASSWORD} />}
        </Field>
        <StrengthMeter pw={pw} />
        <Field label="Confirm password" error={mismatch ? "Passwords do not match" : undefined}>
          {(id) => <input id={id} class="input" type="password" autoComplete="new-password" value={pw2} onInput={(e) => setPw2(e.currentTarget.value)} required />}
        </Field>
        <Field label="Hub endpoint" hint="The URL nodes use to reach this Hub (https in production).">
          {(id) => <input id={id} class="input mono" type="url" value={endpoint} onInput={(e) => setEndpoint(e.currentTarget.value)} required />}
        </Field>
        <Button type="submit" variant="primary" busy={busy} disabled={!valid}>Complete setup</Button>
      </form>
    </div>
  );
}
