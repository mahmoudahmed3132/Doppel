# Audit actions (contract)

Spec §6.10. SIEM rules depend on these names: actions may be added, never
renamed or removed. Every record carries `time, action, method, route
(template), path, status, outcome (success if status < 400), actor_ip`.
Request bodies are never included.

| Action | Trigger | Route |
|---|---|---|
| `setup.complete` | every setup attempt (incl. failures) | `POST /api/v3/setup` |
| `session.login` | every login attempt (incl. failures, lockouts, `mfa_required`) | `POST /api/v3/session/login` |
| `session.logout` | logout | `POST /api/v3/session/logout` |
| `mfa.enrol_begin` | MFA enrolment started | `POST /api/v3/mfa/enrolment` |
| `mfa.enrol_confirm` | MFA enrolment confirmed | `POST /api/v3/mfa/enrolment/confirm` |
| `mfa.disable` | MFA disabled | `POST /api/v3/mfa/disable` |
| `mfa.recovery_codes_regenerate` | recovery codes regenerated | `POST /api/v3/mfa/recovery-codes` |
| `mfa.reset_cli` | break-glass `truesignal-hub mfa-reset`; emitted on the next Hub start (`method` = `CLI`, `actor_ip` = `local`) | — |
| `system.password_change` | admin password change | `POST /api/v3/system/password` |

Planned (reserved names, routes to follow with their features): `config.update`,
`siem.update`, `webhook.update`, `events.mark_read`, `events.archive`,
`events.delete_all`, `system.factory_reset`, `system.arm`, `node.create`,
`node.update`, `node.rotate_key`, `node.delete`, `node.upgrade`,
`sensor.create`, `sensor.update`, `sensor.upgrade`, `sensor.delete`,
`sensor.silence`, `sensor.unsilence`, `beacon.create`, `beacon.delete`,
`assets.replace`, `catalogue.refresh`.
