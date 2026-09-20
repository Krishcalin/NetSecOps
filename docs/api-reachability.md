# API reachability

**141 operations are published. The console requests 106 of them. 35 it never requests.**

Measured 2026-09-20 against the OpenAPI schema `create_app()` produces and every `.ts`
and `.tsx` file under `frontend/src`, comparing path shapes with parameters collapsed —
after job cancel, re-run failed, feed import, feed sync, the credential vault, user and
API-token administration, and the check library, policies and the exception register were
closed. The published count has risen twice, both times because closing a gap needed an
endpoint that did not exist: `GET /credentials/{id}/assignments`, then `POST
/checks/preview` and `POST /checks/query`.

This exists because unreachable capability is indistinguishable from absent capability.
The vulnerability engine made the point: it was built, unit-tested, and wired only to a
job type nothing created, so for three phases it never ran. Nobody noticed, because
"assessed and found nothing" and "never assessed" look identical on a dashboard.

The audit is deliberately generous — a path assembled from fragments counts as a call.
A false *reachable* costs a missed finding; a false *unreachable* costs a minute. The
error is cheaper in that direction, so the 61 below is a floor, not a ceiling.

It took four passes to get there, and every error inflated the count: the matcher first
missed template literals containing ternaries, then failed to strip query strings, then —
when the pattern was loosened to compensate — let an apostrophe in prose open a match
that swallowed real path literals, and finally missed paths built from a module-level
constant (`` `${DELIVERIES}/${id}/requeue` ``). If you extend it, check a handful of
"unreferenced" entries by hand before believing the total.

---

## The finding

**NetSecOps could not be fully administered from its own console.** Thirty-two operations
belonged to areas with no page at all. Eight remain:

- create or edit a schedule (`/schedules`, 4)
- manage sites, tags or device-group nesting (4)

Closed since: ~~users (8)~~, ~~policies (6)~~, ~~checks (6, two of them added in the
course of closing it)~~, ~~API tokens (3)~~, ~~exceptions (3)~~.

Three of those — the exception register, the check library and policy authoring — are
capabilities the AlgoSec and FireMon dossiers cite as advantages over the incumbents. An
advantage nobody can reach is not one, which is why they went first once first-run
administration was done.

Only **two** of the 61 are correctly machine-only: `GET /metrics` and `GET /readyz`.

### Endpoints added rather than surfaced

Closing the credential vault needed `GET /credentials/{id}/assignments`, which did not
exist. `DELETE /credentials/assignments/{id}` takes an assignment id and nothing emitted
one except the response to the POST that created it — so a binding made last month could
not be withdrawn at all, from any client. For a credential vault that is the wrong way
round: granting access is recoverable, being unable to withdraw it is not.

Closing user administration needed no new endpoint but did need a new **field**.
`PUT /users/{id}/scope` wrote a Device Group scope that no response carried, so an
administrator could set one and had no way to read back what a user's scope currently
was. A checkbox cannot render state the API will not return, and an editor that opens
empty would silently clear the scope on save. `UserRead.device_group_ids` closes it.

The check library turned up a third shape, left open. `GET /checks/{id}` returns a
check's rationale, remediation and expression but not its `applicability` or its
assertion — so the console can show what a check looks at and cannot show the whole
definition. The practical cost is that a shipped check cannot be copied as the starting
point for a custom one, which is how anybody would actually write the hundred-and-fourth
check. The draft editor seeds a template instead. Closing it properly means returning the
definition, and that is an API change rather than a page.

Worth noting as a pattern. An operation being unreachable from the console is sometimes a
missing page, sometimes a gap in the API that no page could paper over, sometimes a write
whose result is unreadable, and sometimes a read that returns less than the surface needs.
This triage does not distinguish them until someone tries to build the surface.

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

### No console page exists — 8 · `surface`

| Area | Ops | Note |
|---|---:|---|
| `/schedules` | 4 | Schedules can be created only by API, though the scheduler process that fires them ships. |
| `/sites`, `/tags`, `/device-groups/{id}/parent` | 4 | Reference data and grouping. |

### Closed

| Operation | Surface |
|---|---|
| `POST /jobs/{id}/cancel` | Cancel on the Assessments row, for `queued`/`running`/`paused`. |
| `POST /jobs/{id}/rerun-failed` | Re-run failed on the same row, when a device failed. |
| `POST /vulnerabilities/feeds/import` | Bundle upload in the feed panel, with digest, vendor and product. |
| `POST /vulnerabilities/feeds/sync` | Sync from publishers, in the same panel. |
| The 8 `/credentials` operations, plus a new `GET …/assignments` | A Credentials page: store, list, assign to a device or group, revoke, test against a chosen device, delete. |
| The 8 `/users` operations, plus `GET /auth/roles` | A Users page: create, search, roles, Device Group scope, password reset, deactivate, delete. The role picker is built from the served catalogue rather than a list in the browser. |
| The 3 `/api-tokens` operations | On the profile page, not an admin one: the server classes them as self-service, and a token carries a subset of *your* permissions. The scope picker offers exactly those. |
| `DELETE /auth/mfa` | Turn off MFA, on the profile page beside enrolment. Without it, someone who loses their phone after spending their recovery codes needs a Super Admin editing the database. |
| The 6 `/checks` operations | A Checks page: browse the library filtered by platform and framework, read a check's rationale, remediation and the expression it evaluates, run it against a chosen device, ask where an expression holds across the estate, and draft a new check with a preview that writes nothing. |
| The 6 `/policies` operations | A Policies page: create, open, enable or re-grade each check in it, apply it to a device group, make it the default. States the difference between disabling a check here and filing an exception, because losing either the finding or the audit trail turns on it. |
| The 3 `/exceptions` operations | An Exceptions page: the register first — check, scope, justification, approver and days remaining — with filing and revoking beneath it. |

### A page exists but does not use the operation — 25 · `surface`

Ordered by how much the absence costs.

| Operation | Page | Cost of the gap |
|---|---|---|
| `GET /vulnerabilities/devices/{id}/upgrade-path` | Vulnerabilities | KEV-first upgrade ranking, described in the README, reachable only by API. |
| `GET /vulnerabilities/cpe-coverage` | Vulnerabilities | The coverage honesty check — which platforms have no CPE mapping and so silently report zero. |
| `GET /devices/pending-review`, `POST /devices/{id}/approve`, `/archive` | Inventory, Discovery | The discovery-to-inventory promotion path. Discovery finds hosts; nothing promotes them. |
| `GET /discovery/pending/{host_id}`, `DELETE /discovery/scopes/{id}` | Discovery | Per-host detail and scope removal. |
| `GET /jobs/{id}/progress` | Jobs | Live progress. Low value while the list already refreshes every five seconds. |
| 5 × `/notifications` channel edit/delete, subscriptions | Settings | Settings creates channels, tests them and requeues dead deliveries, but a channel cannot be edited or removed and subscriptions have no surface at all — so who gets told what is API-only. |
| `GET /devices/{id}/checks`, `/risk` | Device config | Per-device check results and risk score. |
| `POST /devices/{id}/children/preview`, `/import` | Inventory | Managed-device import from a manager. |
| `GET /artifacts/{id}`, `/raw`, `GET /collections/{id}`, `/artifacts` | Device config | Raw evidence — the audit trail an assessor asks for. |
| `GET /audit-log/export` | Audit log | Export button. |
| `GET /settings/{key}`, `PUT /settings/{key}` | Settings | Per-key read and write; the page uses the collection endpoint only. |
| `GET /aaa/correlation` | AAA | Correlation view. |

---

## Suggested order

1. ~~`POST /jobs/{id}/cancel` — a safety control with no control.~~ **Done.**
2. ~~Feed import and sync — without them the vulnerability engine has nothing to
   weigh.~~ **Done.**
3. ~~Credentials — a credential that fails is currently discovered by a job failing
   against a live device.~~ **Done.**
4. ~~Users and API tokens — first-run administration.~~ **Done.**
5. ~~Exceptions, checks and policies — the differentiators.~~ **Done.**
6. **Schedules** — the scheduler process ships and nothing can create work for it.
7. Everything else: reference data, the discovery-to-inventory promotion path, raw
   evidence, and the operations on pages that already exist.

## Re-running it

The script lives at `scripts/api_reachability.py`. It needs the backend virtualenv and a
checkout of the frontend beside it:

```bash
cd backend && python ../scripts/api_reachability.py
```

Give it a path to also write the full result as JSON, for diffing between runs. Treat a
rise in the unreferenced count on a PR the way you would treat a drop in coverage.
