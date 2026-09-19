# API reachability

**138 operations are published. The console requests 65 of them. 73 it never requests.**

Measured 2026-09-19 against the OpenAPI schema `create_app()` produces and every `.ts`
and `.tsx` file under `frontend/src`, comparing path shapes with parameters collapsed.

This exists because unreachable capability is indistinguishable from absent capability.
The vulnerability engine made the point: it was built, unit-tested, and wired only to a
job type nothing created, so for three phases it never ran. Nobody noticed, because
"assessed and found nothing" and "never assessed" look identical on a dashboard.

The audit is deliberately generous — a path assembled from fragments counts as a call.
A false *reachable* costs a missed finding; a false *unreachable* costs a minute. The
error is cheaper in that direction, so the 73 below is a floor, not a ceiling.

It took four passes to get there, and every error inflated the count: the matcher first
missed template literals containing ternaries, then failed to strip query strings, then —
when the pattern was loosened to compensate — let an apostrophe in prose open a match
that swallowed real path literals, and finally missed paths built from a module-level
constant (`` `${DELIVERIES}/${id}/requeue` ``). If you extend it, check a handful of
"unreferenced" entries by hand before believing the total.

---

## The finding

**NetSecOps cannot be administered from its own console.** Forty operations belong to
areas with no page at all. There is no way, through the UI, to:

- create a user, set their roles, scope or password (`/users`, 8 operations)
- store a credential or assign one to a device (`/credentials`, 8)
- define a policy, set its checks, or make it the default (`/policies`, 6)
- browse the check library or preview a check (`/checks`, 4)
- create or edit a schedule (`/schedules`, 4)
- issue or revoke an API token (`/api-tokens`, 3)
- file or withdraw a risk-acceptance exception (`/exceptions`, 3)
- manage sites, tags or device-group nesting (4)

Every one of these is a normal operator task, and every one currently requires a REST
client. Three of them — the exception register, the check library and policy authoring —
are capabilities the AlgoSec and FireMon dossiers cite as advantages over the incumbents.
An advantage nobody can reach is not one.

Only **two** of the 73 are correctly machine-only: `GET /metrics` and `GET /readyz`.

---

## Triage

Verdicts are `surface` (needs a console control), `api-only` (correct as it is), or
`delete`. Nothing is marked `delete`: every unreferenced operation is legitimate
capability, and the gap is entirely missing UI.

### Correct as API-only — 2

| Operation | Why |
|---|---|
| `GET /metrics` | Prometheus scrape target. |
| `GET /readyz` | Container readiness probe. |

### No console page exists — 40 · `surface`

| Area | Ops | Note |
|---|---:|---|
| `/users` | 8 | Roles, scope and password administration. |
| `/credentials` | 8 | Including `POST /credentials/{id}/test`, which is the only way to find out a credential works before a job depends on it. |
| `/policies` | 6 | Policy authoring and assignment. |
| `/checks` | 4 | The 103-check library is not browsable; `POST /checks/{id}/preview` is how an author sees a check's verdict before assigning it. |
| `/schedules` | 4 | Schedules can be created only by API, though the scheduler process that fires them ships. |
| `/api-tokens` | 3 | Token issuance and revocation. |
| `/exceptions` | 3 | The waiver register — justification, approver, expiry. |
| `/sites`, `/tags`, `/device-groups/{id}/parent` | 4 | Reference data and grouping. |

### A page exists but does not use the operation — 31 · `surface`

Ordered by how much the absence costs.

| Operation | Page | Cost of the gap |
|---|---|---|
| `POST /jobs/{id}/cancel` | Jobs | **A running job cannot be stopped from the console.** FR-JOB-03 cancellation is a safety control; the page renders `cancelling` and `cancelled` as status labels but offers no way to reach them. |
| `POST /vulnerabilities/feeds/import` | Vulnerabilities | **The advisory catalogue cannot be populated from the console.** With the matcher now running on every collection, an empty catalogue is the difference between an assessment and a blank. |
| `POST /vulnerabilities/feeds/sync` | Vulnerabilities | Same, for the online path. |
| `GET /vulnerabilities/devices/{id}/upgrade-path` | Vulnerabilities | KEV-first upgrade ranking, described in the README, reachable only by API. |
| `GET /vulnerabilities/cpe-coverage` | Vulnerabilities | The coverage honesty check — which platforms have no CPE mapping and so silently report zero. |
| `GET /devices/pending-review`, `POST /devices/{id}/approve`, `/archive` | Inventory, Discovery | The discovery-to-inventory promotion path. Discovery finds hosts; nothing promotes them. |
| `GET /discovery/pending/{host_id}`, `DELETE /discovery/scopes/{id}` | Discovery | Per-host detail and scope removal. |
| `POST /jobs/{id}/rerun-failed`, `GET /jobs/{id}/progress` | Jobs | Re-running only the failed devices, and live progress. |
| 5 × `/notifications` channel edit/delete, subscriptions | Settings | Settings creates channels, tests them and requeues dead deliveries, but a channel cannot be edited or removed and subscriptions have no surface at all — so who gets told what is API-only. |
| `GET /devices/{id}/checks`, `/risk` | Device config | Per-device check results and risk score. |
| `POST /devices/{id}/children/preview`, `/import` | Inventory | Managed-device import from a manager. |
| `GET /artifacts/{id}`, `/raw`, `GET /collections/{id}`, `/artifacts` | Device config | Raw evidence — the audit trail an assessor asks for. |
| `GET /audit-log/export` | Audit log | Export button. |
| `GET /settings/{key}`, `PUT /settings/{key}` | Settings | Per-key read and write; the page uses the collection endpoint only. |
| `GET /auth/roles`, `DELETE /auth/mfa` | — | Reference data for a user-admin page, and MFA reset. |
| `GET /aaa/correlation` | AAA | Correlation view. |

---

## Suggested order

1. **`POST /jobs/{id}/cancel`** — a safety control with no control.
2. **Feed import and sync** — without them the vulnerability engine has nothing to weigh,
   which now silently weakens every collection rather than only the rematch job.
3. **Credentials** — `POST /credentials/{id}/test` in particular; a credential that fails
   is currently discovered by a job failing against a live device.
4. **Users and API tokens** — first-run administration.
5. **Exceptions, checks and policies** — the differentiators.
6. Everything else.

## Re-running it

The script lives at `scripts/api_reachability.py`. It needs the backend virtualenv and a
checkout of the frontend beside it:

```bash
cd backend && python ../scripts/api_reachability.py
```

It writes `reachability.json` next to itself for diffing between runs. Treat a rise in
the unreferenced count on a PR the way you would treat a drop in coverage.
