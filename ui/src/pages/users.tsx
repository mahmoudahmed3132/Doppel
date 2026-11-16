// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Users and roles (admin only). Accounts are created when someone signs in
// through SSO; this page changes their role, disables them or removes them.
// The server enforces every rule (the bootstrap administrator and the last
// enabled administrator cannot be changed); the UI only reports the result.
import { useState } from "preact/hooks";
import { del, errorText, get, patch } from "../api";
import { me } from "../app";
import { fmtTime } from "../format";
import { useStore } from "../store";
import type { Role, UserRecord } from "../types";
import { Button, Confirm, Empty, ErrorBox, Loading, PageHead, Pill, toast, useAsync } from "../ui";

const ROLES: [Role, string][] = [["admin", "Admin"], ["analyst", "Analyst"], ["viewer", "Viewer"]];

export function UsersPage() {
  const self = useStore(me);
  const list = useAsync(() => get<{ users: UserRecord[] }>("/users").then((r) => r.users), []);
  const [removing, setRemoving] = useState<UserRecord | null>(null);
  const [busy, setBusy] = useState(false);

  const change = async (u: UserRecord, body: { role?: Role; disabled?: boolean }, ok: string) => {
    try {
      await patch(`/users/${encodeURIComponent(u.id)}`, body);
      toast(ok, "ok");
      list.reload();
    } catch (e) {
      toast(errorText(e), "error");
      list.reload();
    }
  };
  const remove = async () => {
    if (!removing) return;
    setBusy(true);
    try {
      await del(`/users/${encodeURIComponent(removing.id)}`);
      toast(`${removing.username} removed`, "ok");
      setRemoving(null);
      list.reload();
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="stack-lg">
      <PageHead title="Users" sub="Roles: Admin changes anything; Analyst triages events and silences sensors; Viewer reads. Accounts appear when someone signs in through SSO." />
      <ErrorBox error={list.error} retry={list.reload} />
      {list.data ? (
        list.data.length ? (
          <div class="table-wrap">
            <table class="table">
              <thead><tr><th>User</th><th>Source</th><th>Role</th><th>Status</th><th>Last sign-in</th><th /></tr></thead>
              <tbody>
                {list.data.map((u) => {
                  const fixed = u.id === "usr_admin";
                  return (
                    <tr key={u.id}>
                      <td class="mono">{u.username}{self?.id === u.id ? " (you)" : ""}</td>
                      <td>{u.source === "oidc" ? "SSO" : "Local"}</td>
                      <td>
                        <select class="input" value={u.role} disabled={fixed} aria-label={`Role of ${u.username}`}
                          onChange={(e) => change(u, { role: e.currentTarget.value as Role }, `${u.username} is now ${e.currentTarget.value}`)}>
                          {ROLES.map(([v, l]) => <option value={v} key={v}>{l}</option>)}
                        </select>
                      </td>
                      <td>{u.disabled ? <Pill kind="bad">Disabled</Pill> : <Pill kind="ok">Active</Pill>}</td>
                      <td>{fmtTime(u.last_login_at)}</td>
                      <td>
                        {fixed ? <span class="muted">break-glass account</span> : (
                          <>
                            <Button small variant="ghost" onClick={() => change(u, { disabled: !u.disabled }, u.disabled ? `${u.username} enabled` : `${u.username} disabled`)}>
                              {u.disabled ? "Enable" : "Disable"}
                            </Button>
                            <Button small variant="danger" onClick={() => setRemoving(u)}>Remove</Button>
                          </>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : <Empty>No users.</Empty>
      ) : list.loading ? <Loading /> : null}
      <Confirm open={!!removing} title="Remove user" danger confirmLabel="Remove" busy={busy} onConfirm={remove} onClose={() => setRemoving(null)}
        body={<>Remove <strong>{removing?.username}</strong>? Their sessions end immediately. They can sign in again through SSO if their group still maps to a role.</>} />
    </div>
  );
}
