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
| `secrets.sealed` | first start with `TS_KEK_FILE`: existing secrets sealed at rest (`method` = `CLI`, `actor_ip` = `local`, emitted on that start) | — |
| `secrets.kek_rotate_cli` | host command `truesignal-hub kek-rotate`; emitted on the next start | — |
| `secrets.reset_cli` | break-glass `truesignal-hub secrets-reset --destroy-secrets` (KEK lost); emitted on the next start | — |
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
| `siem.update` | SIEM output changed (also delivered to the previous destination) | `PUT /api/v3/settings/siem` |
| `siem.test` | SIEM test record sent | `POST /api/v3/settings/siem/test` |
| `webhook.update` | webhook changed | `PUT /api/v3/settings/webhook` |
| `webhook.test` | webhook test sent | `POST /api/v3/settings/webhook/test` |
| `system.arm` | armed state set (true or false) | `PUT /api/v3/system/armed` |
| `config.update` | settings changed (endpoint, registry, update checks, retention, source lists) | `PATCH /api/v3/settings` |
| `assets.replace` | asset inventory replaced | `PUT /api/v3/assets` |
| `beacon.create` / `beacon.download` / `beacon.delete` | beacon lifecycle | `POST /api/v3/beacons`, `GET /api/v3/beacons/{id}/artefact`, `DELETE /api/v3/beacons/{id}` |
| `events.mark_read` / `events.mark_read_all` | read flags | `POST /api/v3/events/{seq}/read`, `POST /api/v3/events/read-all` |
| `events.archive` / `events.archive_all` | archive | `POST /api/v3/events/{seq}/archive`, `POST /api/v3/events/archive-all` |
| `events.delete_all` | every event deleted (confirmation phrase required) | `POST /api/v3/events/delete-all` |
| `events.export` | evidence exported (JSON or CSV) | `GET /api/v3/events/export` |
| `honeytokens.export` | honeytoken inventory exported | `GET /api/v3/honeytokens/export` |
| `system.update_check` | manual update check | `POST /api/v3/system/update-check` |
| `system.cli_notice_ack` | new-CLI-release notice acknowledged | `POST /api/v3/system/cli-notice/ack` |
| `system.factory_reset` | factory reset (password + confirmation; delivered to the SIEM **before** execution, refused if undeliverable) | `POST /api/v3/system/factory-reset` |

Exports are audited although they are GET requests: they move evidence out of the Hub.

Read-only routes (`GET …`, and `POST /api/v3/nodes/{node}/compose/preview`,
which renders without saving) are not audited.
