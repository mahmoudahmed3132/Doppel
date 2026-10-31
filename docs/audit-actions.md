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
| `node.create` | node created (key issued) | `POST /api/v3/nodes` |
| `node.update` | alias/tags changed | `PATCH /api/v3/nodes/{node}` |
| `node.rotate_key` | node key rotated | `POST /api/v3/nodes/{node}/key` |
| `node.delete` | node deleted (events kept) | `DELETE /api/v3/nodes/{node}` |
| `node.upgrade` | all sensors of a node moved to latest | `POST /api/v3/nodes/{node}/upgrade` |
| `sensor.create` | sensor added | `POST /api/v3/nodes/{node}/sensors` |
| `sensor.update` | sensor configuration changed | `PATCH /api/v3/nodes/{node}/sensors/{sensor}` |
| `sensor.upgrade` | sensor version changed | `POST /api/v3/nodes/{node}/sensors/{sensor}/upgrade` |
| `sensor.delete` | sensor deleted (events kept) | `DELETE /api/v3/nodes/{node}/sensors/{sensor}` |
| `sensor.silence` | webhooks silenced for a sensor | `POST /api/v3/nodes/{node}/sensors/{sensor}/silence` |
| `sensor.unsilence` | webhooks re-enabled | `POST /api/v3/nodes/{node}/sensors/{sensor}/unsilence` |
| `catalogue.refresh` | manual catalogue refresh | `POST /api/v3/catalogue/refresh` |

Planned (reserved names, routes to follow with their features): `config.update`,
`siem.update`, `webhook.update`, `events.mark_read`, `events.archive`,
`events.delete_all`, `system.factory_reset`, `system.arm`, `beacon.create`, `beacon.delete`,
`assets.replace`.

Read-only routes (`GET …`, and `POST /api/v3/nodes/{node}/compose/preview`,
which renders without saving) are not audited.
