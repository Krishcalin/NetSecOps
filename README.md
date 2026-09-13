<p align="center">
  <strong>NetSecOps</strong><br/>
  <em>Read-only configuration &amp; vulnerability assessment for network and security infrastructure</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.12+"/>
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react&logoColor=black" alt="React 18"/>
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL 16"/>
  <img src="https://img.shields.io/badge/device%20access-READ--ONLY-2ea043?style=flat-square" alt="Read-only"/>
  <img src="https://img.shields.io/badge/phase-3%20of%207-orange?style=flat-square" alt="Phase 3"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT"/>
</p>

---

## Overview

NetSecOps is a self-hosted, web-based platform that assesses the configuration and
vulnerability posture of network and security devices — Cisco, Palo Alto Networks,
Fortinet and Check Point — and tracks how that posture changes over time.

It authenticates to devices over SSH and vendor HTTPS APIs, extracts running
configuration and operational state, normalises it into a vendor-neutral model, and
evaluates it against a library of hardening, firewall-hygiene, AAA and crypto checks,
correlating software versions against CVE and vendor PSIRT advisories.

### NetSecOps never changes a target device

This is a hard constraint, not a policy setting ([SRS §8](docs/SRS.md)):

- **Allow-list, not deny-list.** Every vendor adapter declares the exact set of commands
  and API operations it may issue. Anything else is rejected *before transmission*.
- **Defence in depth.** A global deny-list additionally blocks write verbs
  (`configure`, `write`, `copy`, `reload`, `set`, `commit`, …) even if an allow-list
  entry were mis-specified.
- **GET-only REST.** POST is permitted solely for authentication and for vendor APIs
  that are POST-only by design (Check Point `show-*`, FortiManager `method: "get"`).
- **No side effects.** Adapters never run `ping`, `test aaa`, `debug`, or anything that
  writes a file or sends a packet from the device.
- **No unchecked path.** Adapters hold a guarded session, not a transport. An adapter
  author cannot forget to check, because there is nothing unchecked to reach for.
- **Proven in CI.** 271 conformance assertions check what the guard *decides*, and a
  fake SSH device that records every byte it receives checks what actually *arrives*.
  The build fails on either.
- **Transparent.** Every command sent to a device is recorded in a tamper-evident audit
  log, so customers can see exactly what ran.

---

## Status — Phase 3 complete

Development follows the phase plan in [SRS §12](docs/SRS.md), strictly in order: no
phase starts before the previous one's acceptance criteria pass.

| Phase | Scope | Status |
|:-----:|-------|--------|
| **0** | Monorepo, auth/MFA/RBAC, credential vault, audit chain, CI, Docker | **Complete** |
| **1** | Inventory, credentials, job engine, read-only enforcement framework | **Complete** |
| **2** | Cisco IOS/IOS-XE/NX-OS/ASA collection, parsing, drift | **Complete** |
| **3** | Check engine + baseline library, findings, compliance mapping | **Complete** |
| 4 | Palo Alto, Fortinet, Check Point + firewall rulebase analysis | Next |
| 5 | Wireless (WLC/9800) + AAA: ISE, FortiAuthenticator, FreeRADIUS, tac_plus | Planned |
| 6 | Vulnerability assessment: NVD, CSAF, PSIRT, EoL, KEV/EPSS | Planned |
| 7 | Discovery, reporting, integrations, hardening | Planned |

### What Phase 3 delivers

- **A check engine, and three rules it never breaks.** Checks are YAML — id, severity,
  applicability, JMESPath logic over the NCM, remediation, framework mapping. A field
  the parser never found yields *Not Evaluated* and names the missing path, never a
  verdict derived from its absence. An empty list is a real answer. A broken check is
  an *Error* against that check alone, so one bad file cannot cost an assessment.
- **66 checks, all applicable to Cisco IOS** — 47 declarative, 14 Python for logic YAML
  cannot honestly express, 5 regex. Against the fixture corpus the hardened switch
  scores 56 pass / 1 high-severity fail and the weak one 41 fails; the ASA reports 39
  *Not Applicable* rather than passing switch checks it was never subject to.
- **Remediation is text, and only text.** There is no field in the schema that could be
  executed, and a test asserts none appears (SRS §8).
- **Policies** grouping checks, assignable to device groups, with per-check severity
  overrides — the customisation that matters, because severity is contextual in a way a
  shipped library cannot know. The CIS Cisco IOS L1 pack ships with 44 checks and is
  installed idempotently, then never overwritten.
- **Custom checks** written through the API against the same schema the loader uses —
  and refused if they declare Python logic, since accepting a function name from a web
  form would let a user invoke any registered callable.
- **Exceptions with a mandatory expiry.** The check still runs and its result is still
  stored; only the finding is suppressed. Hiding the result would make the compliance
  figure a fiction, and an exception without an end date is an undocumented decision.
- **Findings with a lifecycle that reflects reality.** *Resolved* is reachable only by
  the check passing on a later assessment — the API refuses to set it by hand, so the
  status stays a measurement rather than a claim. A problem that returns reopens the
  original finding instead of appearing as a first sighting.
- **A risk score that is documented and explainable.** Severity weights are widely
  spaced on purpose: under a linear scheme fourteen Low findings outrank one Critical.
  Device criticality multiplies rather than adds. *Not Evaluated* is reported as a
  separate coverage figure instead of being quietly counted as a pass.
- **Compliance pivoted by framework control**, with the percentage computed over what
  was actually decided — *Not Applicable* and *Not Evaluated* are in neither half.

### What Phase 2 delivers

- **Cisco parsers** — IOS/IOS-XE, NX-OS and ASA configurations become a vendor-neutral
  **Normalised Config Model**. Parsing is tolerant: an unrecognised stanza is kept in
  `raw_unparsed` and never fails a collection, and the percentage understood is stored
  on the snapshot so a degraded parse is visible rather than silently weakening checks.
- **Provenance on every value** — each NCM field records the artefact and line range it
  came from, so a finding can show the operator their own configuration line instead of
  asserting a conclusion.
- **Absent is not false** — a service the configuration never mentions stays `null`,
  which later reports as *Not evaluated*. Only an explicit `no ip http server` becomes
  `false`. Blurring the two produces confident, wrong findings.
- **Collection profiles** — what each platform is asked for, as data. A test asserts
  every profile command already appears in the §8.2 allow-list, so a profile can never
  widen what NetSecOps may send to a device.
- **Redaction before storage** — secrets are replaced with fingerprinted placeholders on
  every path that leaves the server. The unredacted original exists in one place, sealed,
  reachable by one endpoint that needs `config:view_unredacted` and writes an audit
  record before it answers.
- **Snapshots and drift** — identical configurations de-duplicate to one row, ignoring
  volatile lines like NVRAM timestamps and `ntp clock-period`. Pin a snapshot as the
  baseline and later collections that differ raise a drift finding with the diff
  attached, severity raised for security-relevant changes.
- **Diff, two ways** — a unified and side-by-side text diff, plus a semantic diff over
  the NCM that says *"management.services.telnet.enabled changed disabled → enabled"*
  rather than leaving an operator to derive it from ±40 lines.
- **Offline configuration upload** — assess an air-gapped or pre-onboarding device from
  an exported configuration file, through the same storage, parsing and drift path as a
  live collection.

### What Phase 1 delivers

- **Read-only enforcement** — the four-layer guard described above, 16 platform
  policies, and `netsecops-cli audit-commands` to print them for review.
- **Device sessions** — adapters hold a guarded session, never a transport, so there is
  no unchecked path to a device. SSH with host-key pin-on-first-use, jump hosts and
  per-device timeouts.
- **Inventory** — devices, hierarchical Device Groups (ltree), sites, tags, and CSV
  import with a dry-run preview that reports the offending line before anything is
  written.
- **Credential vault** — typed credentials whose secret fields are sealed and whose
  unknown fields are rejected, so a password cannot land in searchable metadata.
  Device assignments override inherited group ones, and group credentials are inherited
  down the hierarchy.
- **Job engine** — scope resolution, per-device outcomes with FR-COL-07 error classes,
  credential fallback, graceful cancel, re-run-failed, idempotency keys, and a
  WebSocket progress stream.
- **Scope enforcement** — Device Group visibility applied in the query, not by the
  caller, so a group-scoped user cannot widen their reach.

### What Phase 0 delivers

- **Authentication** — Argon2id password hashing, a configurable password policy with
  a no-reuse history window, and account lockout after repeated failures.
- **Sessions** — short-lived access tokens (≤15 min) and rotating, revocable refresh
  tokens (≤8 h), delivered as `Secure; HttpOnly; SameSite=Strict` cookies. Replaying a
  rotated refresh token revokes the whole session family and raises an audit event.
- **MFA** — RFC 6238 TOTP with single-use recovery codes; codes cannot be replayed
  inside their validity window.
- **RBAC** — the five roles from SRS §2.3 over a single permission vocabulary, with
  object-level Device Group scoping for the group-restricted roles. Endpoints declare
  a *permission*, never a role list.
- **Credential vault** — AES-256-GCM envelope encryption with per-record data keys
  wrapped by a pluggable master key, bound to the owning row so a ciphertext cannot be
  replayed into another record. Master-key rotation re-wraps without re-encrypting.
- **Audit log** — append-only and hash-chained, enforced *both* by chain verification
  and by database triggers that reject UPDATE, DELETE and TRUNCATE outright.
- **Secret scrubbing** — one central processor redacts secrets from every log line and
  audit record, including device-config idioms like `snmp-server community X`.
- **Quality gates** — `ruff`, `mypy --strict`, `pytest`, `bandit`, `pip-audit`,
  `eslint`, `tsc`, `vitest`, Trivy and Gitleaks, all wired into CI.

---

## Quick start

**Requirements:** Docker 24+ and Docker Compose. Nothing else.

```bash
git clone https://github.com/Krishcalin/NetSecOps.git
cd NetSecOps

make up              # generates keys, builds, migrates, prints the URL
make create-admin    # create the first Super Admin
```

Then open <http://localhost:8080>.

> **Back up `MASTER_KEY` separately from the database.** It wraps every stored device
> credential. Losing it means losing them all; storing it beside a database dump means
> a single stolen backup yields both.

**Port already in use?** Every published port is overridable in `.env`, which matters on
a workstation running several projects:

```bash
UI_PORT=8088     # SPA           (default 8080)
API_PORT=8010    # API           (default 8000)
DB_PORT=5442     # PostgreSQL    (default 5442, chosen to avoid a local 5432)
```

### Running without Docker

```bash
make install         # backend venv + frontend node_modules
make db              # just PostgreSQL, on host port 5442
make migrate
make dev-api         # http://localhost:8000
make dev-ui          # http://localhost:5173
```

---

## Repository layout

```
netsecops/
├─ backend/
│  ├─ netsecops/
│  │  ├─ adapters/     # read-only guard, platform policies, sessions, transports
│  │  ├─ api/          # FastAPI routers, dependencies, middleware
│  │  ├─ core/         # config, logging, crypto, security, RBAC, errors
│  │  ├─ db/           # declarative base, session, models, Alembic migrations
│  │  ├─ checks/       # the check engine, its YAML library and policy packs
│  │  ├─ ncm/          # the Normalised Config Model (NCM v1)
│  │  ├─ parsers/      # vendor config parsers, one package per vendor
│  │  ├─ schemas/      # Pydantic request/response models
│  │  ├─ services/     # business logic, independent of HTTP
│  │  ├─ workers/      # job runner, credential probe, queue abstraction
│  │  └─ cli.py        # netsecops-cli
│  └─ tests/
│     └─ fixtures/     # anonymised configs, by vendor/platform/version
├─ frontend/           # Vite + React 18 + TypeScript SPA
├─ scripts/            # smoke_test.py — post-deployment verification
├─ deploy/             # Dockerfiles, docker-compose, Caddy, Postgres init
└─ docs/               # SRS, ADRs, device-account guidance, deployment
```

Later phases add `vuln/`. Vendor-specific logic stays inside `adapters/`, `parsers/`
and the vendor packs under `checks/library/`; core services remain vendor-agnostic (C-6).

### The files worth reading first

| File | Why |
|---|---|
| [`adapters/readonly.py`](backend/netsecops/adapters/readonly.py) | The four-layer guard that enforces SRS §8 |
| [`adapters/policies.py`](backend/netsecops/adapters/policies.py) | Exactly what NetSecOps may send to each platform |
| [`adapters/session.py`](backend/netsecops/adapters/session.py) | Why there is no unchecked path to a device |
| [`adapters/profiles.py`](backend/netsecops/adapters/profiles.py) | What each platform is actually asked for, and why |
| [`ncm/models.py`](backend/netsecops/ncm/models.py) | The vendor-neutral model every check reads |
| [`services/snapshots.py`](backend/netsecops/services/snapshots.py) | How a change is told apart from noise |
| [`tests/test_readonly.py`](backend/tests/test_readonly.py) | 271 assertions that the guard decides correctly |
| [`tests/test_device_session.py`](backend/tests/test_device_session.py) | That nothing else reaches a real SSH server |
| [`tests/test_profiles.py`](backend/tests/test_profiles.py) | That a profile cannot widen the device-facing surface |
| [`checks/engine.py`](backend/netsecops/checks/engine.py) | Why a check declines to have an opinion |
| [`checks/library/`](backend/netsecops/checks/library/) | Every check, as data, with its reasoning |
| [`services/risk.py`](backend/netsecops/services/risk.py) | The risk formula, and why it is shaped that way |

---

## Development

```bash
make check       # every gate: lint, typecheck, test, security
make lint        # ruff + eslint
make typecheck   # mypy --strict + tsc
make test        # pytest + vitest
make test-cov    # backend coverage report
make security    # bandit, pip-audit, npm audit
```

Backend tests run against a real PostgreSQL instance (the schema uses JSONB, INET and
advisory locks, so a substitute engine would not test what ships). `make db` starts one;
override the target with `TEST_DATABASE_URL`.

Load tests are opt-in, because they commit real rows and take seconds rather than
milliseconds:

```bash
cd backend && ../.venv/bin/python -m pytest -m performance -s
```

They measure job-queue throughput against NFR-PERF-01 — 20 workers sustain roughly 100×
the required device-claim rate, which is the evidence behind
[ADR-001](docs/adr/ADR-001-job-queue.md).

### Conventions

- Python 3.12+, type hints everywhere, `mypy --strict` clean.
- Every schema change is an Alembic migration — no manual DDL. CI runs `alembic check`
  to catch a model that drifted from its migration.
- Every endpoint appears in the authorization matrix (`tests/test_authz_matrix.py`).
  Adding a route without an entry fails the build by design.
- All configuration via environment variables; no secrets in the repo or an image.

---

## CLI

```bash
netsecops-cli create-admin           # bootstrap the first Super Admin
netsecops-cli generate-master-key    # generate a credential-vault master key
netsecops-cli generate-secret-key    # generate a JWT signing key
netsecops-cli verify-audit-chain     # replay the hash chain, detect tampering
netsecops-cli rotate-master-key      # re-wrap every stored secret
netsecops-cli reset-password <user>  # break-glass password reset
netsecops-cli reset-mfa <user>       # break-glass: clear a lost authenticator
netsecops-cli audit-commands         # print the read-only allow-list per platform
netsecops-cli permissions            # print the role × permission matrix
netsecops-cli health-check           # database reachability + schema revision
netsecops-cli show-config            # effective configuration, secrets masked
```

### Locked out of MFA?

Disabling MFA through the API needs a session, and MFA is what blocks sign-in — so
recovery runs on the server:

```bash
docker compose -f deploy/docker-compose.yml exec api netsecops-cli reset-mfa admin
```

The user then signs in with their password alone and re-enrols from **Profile →
Two-factor authentication**. The reset is recorded in the audit log. Recovery codes
issued at enrolment also work as a second factor — each one once.

---

## Smoke-testing a deployment

```bash
python scripts/smoke_test.py \
    --api http://localhost:8000 --ui http://localhost:8080 \
    --admin-user admin --admin-password '...'
```

33 checks over the live stack: unauthenticated rejection, security headers, cookie
flags, RBAC, MFA enrolment and challenge, refresh rotation, audit-chain integrity and
the SPA. It creates a throwaway user for the destructive parts and deletes it
afterwards, so it never alters the account it signs in with.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/SRS.md](docs/SRS.md) | Full software requirements specification — the baseline |
| [docs/device-accounts.md](docs/device-accounts.md) | Recommended read-only accounts per platform |
| [docs/deployment.md](docs/deployment.md) | Deployment, sizing, backup and key management |
| [docs/adr/](docs/adr/) | Architecture decision records |

The API documents itself: OpenAPI at `/api/v1/openapi.json`, interactive docs at
`/api/v1/docs` outside production.

---

## Licence

MIT — see [LICENSE](LICENSE).
