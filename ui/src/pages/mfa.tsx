// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
//
// MFA enrolment, recovery codes display. The TOTP secret and recovery codes
// are shown once and never stored by the UI.
import { useState } from "preact/hooks";
import { errorText, post } from "../api";
import { Alert, Button, CopyButton, Field, Secret } from "../ui";

export function RecoveryCodes({ codes }: { codes: string[] }) {
  const text = codes.join("\n");
  return (
    <div class="stack">
      <Alert kind="warn">Store these recovery codes somewhere safe. Each works once. They will not be shown again.</Alert>
      <ol class="codes mono">{codes.map((c) => <li key={c}>{c}</li>)}</ol>
      <div class="row"><CopyButton text={text} label="Copy codes" /></div>
    </div>
  );
}

function groups(s: string): string {
  return s.replace(/(.{4})/g, "$1 ").trim();
}

export function MfaEnrol({ onDone }: { onDone: () => void }) {
  const [pw, setPw] = useState("");
  const [secret, setSecret] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function begin(e: Event) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      setSecret(await post("/mfa/enrolment", { password: pw }));
      setPw("");
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function confirm(e: Event) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const r = await post<{ recovery_codes: string[] }>("/mfa/enrolment/confirm", { code: code.trim() });
      setCodes(r.recovery_codes);
      setSecret(null);
    } catch (e) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  if (codes) {
    return (
      <div class="stack">
        <Alert kind="ok">Two-factor authentication is enabled. Sign in again with your authenticator code.</Alert>
        <RecoveryCodes codes={codes} />
        <div><Button variant="primary" onClick={onDone}>I have stored the codes — sign in again</Button></div>
      </div>
    );
  }
  if (secret) {
    return (
      <form class="stack" onSubmit={confirm}>
        {err ? <Alert kind="error">{err}</Alert> : null}
        <p>Add this account to your authenticator app using the secret key (or the otpauth URI), then enter the current code.</p>
        <Secret label="Secret key" value={groups(secret.secret)} />
        <details>
          <summary>otpauth URI</summary>
          <div class="secret-row">
            <code class="secret-value wrap">{secret.otpauth_uri}</code>
            <CopyButton text={secret.otpauth_uri} />
          </div>
        </details>
        <Field label="Current code">
          {(id) => <input id={id} class="input mono" autoComplete="one-time-code" inputMode="numeric" maxLength={10} value={code} onInput={(e) => setCode(e.currentTarget.value)} required />}
        </Field>
        <div><Button type="submit" variant="primary" busy={busy} disabled={!code.trim()}>Confirm and enable</Button></div>
      </form>
    );
  }
  return (
    <form class="stack" onSubmit={begin}>
      {err ? <Alert kind="error">{err}</Alert> : null}
      <Field label="Confirm your password">
        {(id) => <input id={id} class="input" type="password" autoComplete="current-password" value={pw} onInput={(e) => setPw(e.currentTarget.value)} required />}
      </Field>
      <div><Button type="submit" variant="primary" busy={busy} disabled={!pw}>Begin enrolment</Button></div>
    </form>
  );
}
