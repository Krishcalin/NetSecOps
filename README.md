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
  <img src="https://img.shields.io/badge/phase-0%20of%207-orange?style=flat-square" alt="Phase 0"/>
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
- **Proven in CI.** A transcript-replay test asserts that every command any adapter
  emits is on its allow-list. The build fails otherwise.
- **Transparent.** Every command sent to a device is recorded in a tamper-evident audit
  log, so customers can see exactly what ran.

---

## Status — Phase 0 (Foundation) complete

Development follows the phase plan in [SRS §12](docs/SRS.md). Phase 0 is the platform
foundation everything else is built on; device access begins in Phase 1.

| Phase | Scope | Status |
|:-----:|-------|--------|
| **0** | Monorepo, auth/MFA/RBAC, credential vault, audit chain, CI, Docker | **Complete** |
| 1 | Inventory, credentials, job engine, read-only enforcement framework | Next |
| 2 | Cisco IOS/IOS-XE/NX-OS/ASA collection, parsing, drift | Planned |
| 3 | Check engine + baseline library, findings, compliance mapping | Planned |
| 4 | Palo Alto, Fortinet, Check Point + firewall rulebase analysis | Planned |
| 5 | Wireless (WLC/9800) + AAA: ISE, FortiAuthenticator, FreeRADIUS, tac_plus | Planned |
| 6 | Vulnerability assessment: NVD, CSAF, PSIRT, EoL, KEV/EPSS | Planned |
| 7 | Discovery, reporting, integrations, hardening | Planned |

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
│  │  ├─ api/          # FastAPI routers, dependencies, middleware
│  │  ├─ core/         # config, logging, crypto, security, RBAC, errors
│  │  ├─ db/           # declarative base, session, models, Alembic migrations
│  │  ├─ schemas/      # Pydantic request/response models
│  │  ├─ services/     # business logic, independent of HTTP
│  │  └─ cli.py        # netsecops-cli
│  └─ tests/
├─ frontend/           # Vite + React 18 + TypeScript SPA
├─ deploy/             # Dockerfiles, docker-compose, Caddy, Postgres init
└─ docs/               # SRS, ADRs, device-account guidance, deployment
```

Later phases add `adapters/` (per vendor), `parsers/`, `ncm/`, `checks/`, `vuln/` and
`workers/` under `backend/netsecops/`. Vendor-specific logic stays inside the adapter
and parser packages; core services remain vendor-agnostic.

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
netsecops-cli permissions            # print the role × permission matrix
netsecops-cli health-check           # database reachability + schema revision
netsecops-cli show-config            # effective configuration, secrets masked
```

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
