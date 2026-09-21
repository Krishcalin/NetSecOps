# API reachability

**141 operations are published. The console requests 121 of them. 20 it never requests.**

**Every area of the API now has a page.** The original finding — thirty-two operations in
areas the console could not reach at all — is closed. What remains is eighteen operations
on pages that exist but do not call them, plus `GET /metrics` and `GET /readyz`, which are
correctly machine-only.

Measured 2026-09-20 against the OpenAPI schema `create_app()` produces and every `.ts`
and `.tsx` file under `frontend/src`, comparing path shapes with parameters collapsed.
The published count has risen twice, both times because closing a gap needed an endpoint
that did not exist: `GET /credentials/{id}/assignments`, then `POST /checks/preview` and
`POST /checks/query`.

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
belonged to areas with no page at all — users (8), policies (6), checks (6, two of them
added in the course of closing it), schedules (4), reference data (4), API tokens (3) and
exceptions (3). All of them now have one.

Three of those — the exception register, the check library and policy authoring — are
capabilities the AlgoSec and FireMon dossiers cite as advantages over the incumbents. An
advantage nobody can reach is not one, which is why they went first once first-run
administration was done.

Closing them turned up four defects that no test had caught, each invisible for the same
reason: nothing exercised the path, so the wrong behaviour looked exactly like the right
one. They are listed below.

Only **two** of the 61 are correctly machine-only: `GET /metrics` and `GET /readyz`.

### What building the surfaces found

Four defects, none of which any test caught, and each one invisible in the same way: the
wrong behaviour and the right one produced identical output as long as nobody looked.

**A write nothing could read back.** `PUT /users/{id}/scope` set a user's Device Group
scope and no response carried it. A checkbox cannot render state the API will not return,
and an editor that opens empty would silently clear the scope on save.

**A field accepted, returned, and never stored.** `SiteCreate` took a `location`,
`SiteRead` returned one, `sites.location` existed — and `create_site` did not pass it.
Every site read back with `location: null`, which looks exactly like a field nobody has
filled in.

**A read that returns less than a surface needs.** `GET /checks/{id}` gives a check's
expression but not its `applicability` or assertion, so a shipped check cannot be copied
as the starting point for a custom one — which is how anybody would write the
hundred-and-fourth check. Left open: closing it means returning the definition, which is
an API change rather than a page.

**Two endpoints that did not exist at all.** See below.

### Endpoints added rather than surfaced

Closing the credential vault needed `GET /credentials/{id}/assignments`, which did not
exist. `DELETE /credentials/assignments/{id}` takes an assignment id and nothing emitted
one except the response to the POST that created it — so a binding made last month could
not be withdrawn at all, from any client. For a credential vault that is the wrong way
round: granting access is recoverable, being unable to withdraw it is not.

The check library needed two that did not exist either — `POST /checks/preview` for a
definition that has not been saved, and `POST /checks/query` to ask where an expression
holds — both added while closing the draft-a-check surface.

Worth noting as a pattern. An operation being unreachable from the console is sometimes a
missing page, sometimes a gap in the API that no page could paper over, sometimes a write
whose result is unreadable, sometimes a read that returns less than the surface needs, and
sometimes a field the service quietly drops. This triage does not distinguish them until
someone tries to build the surface, which is the argument for building it.

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

### No console page exists — 0

Closed. Every area of the API has a page.

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
| The 4 `/schedules` operations | A Schedules page beside Assessments: create with a cron and a timezone, pause, resume, remove. The list leads with `next_run_at`, which the server computes from the expression, because a cron that means something other than what was intended is otherwise undetectable. |
| `GET`/`POST /sites`, `GET /tags`, `PUT /device-groups/{id}/parent` | "Sites, groups and tags", reached from Inventory. Device Groups are what user scope, policy assignment and schedule coverage are all expressed in — three pages depended on this one and none could create what they depended on. Building it found that `POST /sites` discarded the `location` it accepted. |
| `GET /vulnerabilities/cpe-coverage` | A "Can these platforms match anything?" panel on Vulnerabilities. It answers the one question no other screen can: whether a platform reports zero CVEs because it is clean or because its CPE product name matches nothing. Contradictions sort first; "no evidence" is rendered as a thin corpus rather than a fault. Building it found that `closest_match` — the field that says what the name is probably meant to be — was computed and never serialised. |
| `GET /vulnerabilities/devices/{id}/upgrade-path` | An "Upgrades" action on each Vulnerabilities row. Ranks the releases the device could move to by what each closes, with the known-exploited count separate, because one maintenance window is the constraint. `undetermined` is never folded into `eliminates`: two Cisco trains have independent fix schedules, so neither is later than the other. |
| `GET /devices/pending-review`, `POST /devices/{id}/approve` | An approval queue above the Inventory table. A device imported from a manager lands in inventory already excluded from every job, and nothing said so — so a Panorama import produced rows that looked ordinary, were never collected from and yielded no finding. The queue shows the manager's own attribution, because that is what the decision rests on. |
| `POST /devices/{id}/archive` | Archive on each Inventory row, behind a confirmation, alongside a Status column. Awaiting approval, archived and active are three different reasons for an empty "last collected" and were rendered identically. |
| `DELETE /discovery/scopes/{id}` | Remove on each scope row, asked for twice. A scope is the permission to probe a range; deleting one is how you stop probing what turned out not to be yours, and doing it by accident destroys the record of what was agreed. |
| `GET /discovery/pending/{host_id}` | The review panel re-reads the host as it opens rather than trusting the row the list was built from. The list is a snapshot of whenever it loaded, and what is decided here is the device's *platform* — which selects the collection profile and with it the command allow-list. |

### A page exists but does not use the operation — 18 · `surface`

Ordered by how much the absence costs.

| Operation | Page | Cost of the gap |
|---|---|---|
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
6. ~~Schedules — the scheduler process ships and nothing could create work for it.~~
   **Done**, along with the reference data three other pages depend on.
7. ~~The two Vulnerabilities gaps: the KEV-first upgrade ranking, and `cpe-coverage`.~~
   **Done.**
8. ~~The discovery-to-inventory promotion path — discovery finds hosts and nothing
   promotes them.~~ **Done.**
9. **The 18 operations on pages that already exist.** The five `/notifications` ones are
   next: they decide who gets told what, and a channel routed to the wrong place can be
   created from the console and not corrected from it. Then the raw-evidence reads
   (`/artifacts`, `/collections`), which are the audit trail an assessor asks for.

## Re-running it

The script lives at `scripts/api_reachability.py`. It needs the backend virtualenv and a
checkout of the frontend beside it:

```bash
cd backend && python ../scripts/api_reachability.py
```

Give it a path to also write the full result as JSON, for diffing between runs. Treat a
rise in the unreferenced count on a PR the way you would treat a drop in coverage.
