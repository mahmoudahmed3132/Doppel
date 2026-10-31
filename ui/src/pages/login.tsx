// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.
//
// Login (password, then TOTP or recovery code when enrolled) and the
// enrolment-only screen shown when MFA is required but not yet set up.
import { useState } from "preact/hooks";
import { ApiError, errorText, post } from "../api";
import { Alert, Button, Field } from "../ui";
import { MfaEnrol } from "./mfa";

function lockoutText(e: ApiError): string {
  const mins = e.retryAfter ? Math.max(1, Math.ceil(e.retryAfter / 60)) : 15;
  return `Too many failed attempts. Sign-in is locked; try again in about ${mins} minute${mins === 1 ? "" : "s"}.`;
}

export function Login({ onDone, onSetup }: { onDone: () => void; onSetup: () => void }) {
  const [pw, setPw] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function submit(e: Event) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await post("/session/login", needCode ? { password: pw, code: code.trim() } : { password: pw });
      setPw("");
      setCode("");
      onDone();
    } catch (e) {
      if (!(e instanceof ApiError)) setErr(errorText(e));
      else if (e.code === "mfa_required") {
        setNeedCode(true);
        if (needCode) setErr("Enter your authenticator code or a recovery code.");
      } else if (e.code === "invalid_code") setErr("That code is not valid or has already been used.");
      else if (e.code === "invalid_credentials") setErr("Incorrect password.");
      else if (e.code === "locked" || e.status === 429) setErr(lockoutText(e));
      else if (e.code === "setup_required") onSetup();
      else setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div class="center-screen">
      <form class="auth-card" onSubmit={submit}>
        <h1>Sign in</h1>
        {err ? <Alert kind="error">{err}</Alert> : null}
        <Field label="Password">
          {(id) => (
            <input id={id} class="input" type="password" autoComplete="current-password" value={pw}
              onInput={(e) => setPw(e.currentTarget.value)} required autoFocus={!needCode} />
          )}
        </Field>
        {needCode ? (
          <Field label="Authenticator code or recovery code" hint="6-digit code from your authenticator app, or one unused recovery code.">
            {(id) => (
              <input id={id} class="input mono" autoComplete="one-time-code" inputMode="text" spellcheck={false} value={code}
                onInput={(e) => setCode(e.currentTarget.value)} required autoFocus maxLength={128} />
            )}
          </Field>
        ) : null}
        <Button type="submit" variant="primary" busy={busy} disabled={!pw || (needCode && !code.trim())}>Sign in</Button>
      </form>
    </div>
  );
}

export function EnrolOnly({ onDone }: { onDone: () => void }) {
  return (
    <div class="center-screen">
      <div class="auth-card auth-wide">
        <h1>Set up two-factor authentication</h1>
        <p class="muted">This Hub requires MFA. Finish enrolment to continue; you will then sign in again.</p>
        <MfaEnrol onDone={async () => {
          try { await post("/session/logout"); } catch { /* already gone */ }
          onDone();
        }} />
      </div>
    </div>
  );
}
