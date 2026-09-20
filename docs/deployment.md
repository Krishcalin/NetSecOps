# Deployment

**Audience:** operators deploying and running NetSecOps.

Covers SRS §9 (deployment), §2.4 (operating environment) and FR-ADM-02 (backup,
key rotation, health checks).

---

## Topology

```
                   ┌──────────────┐
   browser ──443──▶│    proxy     │  Caddy: TLS, security headers, SPA
                   │   (Caddy)    │
                   └──┬────────┬──┘
                      │        │
              /api/*  │        │  everything else
                      ▼        ▼
               ┌───────────┐  ┌──────────┐
               │    api    │  │  static  │
               │ (FastAPI) │  │   SPA    │
               └─────┬─────┘  └──────────┘
                     │
              ┌──────┴───────┐
              ▼              ▼
       ┌────────────┐  ┌──────────┐        ┌──────────────────┐
       │ PostgreSQL │◀─┤ worker×N │──22────▶│  target devices  │
       │     16     │  │          │──443───▶│   (read-only)    │
       └────────────┘  └──────────┘        └──────────────────┘
```

The proxy serves the SPA and the API from **one origin**. That is what makes the auth
cookies first-party and lets `SameSite=Strict` do its job (FR-AUTH-02, SEC-03). Splitting
them across origins would force `SameSite=None` and weaken CSRF defence.

---

## Sizing

| Devices | vCPU | RAM | Workers | Notes |
|--------:|:----:|:---:|:-------:|-------|
| ≤ 100 | 2 | 4 GB | 1 | Single host |
| ≤ 500 | 4 | 8 GB | 1 (20 concurrent) | Reference for NFR-PERF-01 |
| ≤ 2,000 | 8 | 16 GB | 3–4 | Scale worker replicas |
| > 2,000 | 8+ | 16 GB+ | 4+ | Add a read replica for reporting |

Collections are IO-bound — most of a device session is spent waiting on the device, not
on CPU. Scale `NETSECOPS_WORKER_CONCURRENCY` and worker replicas before adding cores.

**The small tier is the same product.** No capability is withheld from it: the check
library, path analysis, the vulnerability engine, the API and the report generator behave
identically at 20 devices and at 2,000. Worth stating because it is not the norm in this
category — see [commercial.md](commercial.md).

**Database growth** is driven by artefacts and snapshots, not by findings. A 500-device
estate collecting daily with 90-day artefact retention lands in the low tens of GB.
Identical configurations are stored once, so a stable estate grows far more slowly than
device-count × days suggests, and an estate under active change grows faster — the figure
above is an order of magnitude, not a measurement of your estate. Tune retention in
Administration → Settings (FR-ADM-01); findings history and the audit log are never
purged (DATA-02).

---

## First deployment

```bash
git clone https://github.com/Krishcalin/NetSecOps.git
cd NetSecOps
make up
make create-admin
```

`make up` copies `.env.example` to `.env`, generates `SECRET_KEY` and `MASTER_KEY`,
builds the images, starts the stack, runs migrations, and prints the URL.

### Before exposing it to users

1. **Terminate TLS.** Edit `deploy/caddy/Caddyfile`: replace `:8080` with your hostname,
   remove `auto_https off`, and uncomment the `Strict-Transport-Security` header.
2. **Set `NETSECOPS_COOKIE_SECURE=true`.** Required once you are on HTTPS, and enforced
   in production — the app refuses to start with it false when `NETSECOPS_ENV=prod`.
3. **Set `NETSECOPS_ENV=prod`.** This also disables the interactive API docs and
   rejects a wildcard CORS origin.
4. **Set `NETSECOPS_CORS_ORIGINS`** to your actual hostname.
5. **Require MFA** for privileged roles (FR-AUTH-03).

---

## Discovery and the ICMP capability

Discovery sends four of the five probes FR-DISC-02 permits: an ICMP echo, a TCP connect
to each of the scope's ports, an SSH banner read and an HTTPS certificate-and-header
fetch. Only the first needs a Linux capability, and the worker container drops every
capability by default.

**Nothing breaks without it.** Liveness falls back to TCP connect, and each run records
on itself that echo was unavailable, so a sparse result is attributable rather than
mysterious. The cost is specific: a device that is up but has **none** of the scope's TCP
ports open is not found at all.

To trade that back, uncomment `cap_add: [NET_RAW]` on the `worker` service in
`deploy/docker-compose.yml`, or on Kubernetes add it to the worker's
`securityContext.capabilities.add`. Weigh it honestly — the worker holds every stored
device credential, and `NET_RAW` lets a process that gets inside the container forge and
sniff packets on its network. On a typical management VLAN the other four probes find
everything the fifth would, so the default is to leave it dropped.

Two further limits are worth setting expectations about, because both make discovery
find *less*, never more:

- **SNMP is not read.** A scope can be flagged for it, but no SNMP credential can be
  stored against a scope yet. sysObjectID is the heaviest fingerprint signal there is, so
  more hosts will arrive in the review queue unidentified than eventually will.
- **Runs are started by a person.** Scheduling is not built; there is no cron behind the
  `schedules` table yet.

Each scope's rate limit defaults to 50 hosts a second (FR-DISC-05). It is a ceiling, not
a target — a scope full of unused addresses runs slower than its limit because probes
time out, which is normal and is reported as such.

---

## Key management

NetSecOps holds two independent keys. They do different jobs and have different
recovery stories.

| Key | Protects | If lost | If leaked |
|---|---|---|---|
| `SECRET_KEY` | JWT signatures | Everyone is signed out. Set a new one. | Rotate it; all sessions are invalidated. |
| `MASTER_KEY` | Every stored device credential | **Credentials are unrecoverable.** Re-enter them all. | Rotate with `rotate-master-key`, then re-credential. |

### Backing up MASTER_KEY

Store it in a secret manager — not in the database, not in the same backup as the
database, and not in the repository. A single stolen backup should never yield both the
ciphertext and the key that opens it.

For Vault, KMS or a mounted file, set `NETSECOPS_MASTER_KEY_PROVIDER` accordingly
(`env`, `file`, `vault`, `awskms`, `azurekv`, `gcpkms`). Only `env` and `file` are
implemented in Phase 0; the external providers arrive with FR-CRED-06 in Phase 1.

### Rotating MASTER_KEY

```bash
# 1. Back up the database first.
# 2. Set the NEW key, keeping the old one reachable until this completes.
docker compose -f deploy/docker-compose.yml exec api \
    netsecops-cli rotate-master-key --confirm
```

Rotation re-wraps each data key and issues a fresh one, so it limits the blast radius of
both a leaked master key and a leaked data key. Stored secrets are never re-encrypted
wholesale, so rotation is fast even with thousands of credentials.

---

## Account recovery (break-glass)

Both of these need server access, deliberately: they are the paths that exist precisely
because the normal ones are unavailable.

```bash
COMPOSE="docker compose -f deploy/docker-compose.yml"

# Lost authenticator — clear MFA so the user can sign in with a password and re-enrol.
$COMPOSE exec api netsecops-cli reset-mfa <username>

# Forgotten password — set a new one; the user must change it at next sign-in.
$COMPOSE exec api netsecops-cli reset-password <username>
```

Both are written to the audit log (`mfa.disabled`, `password.reset`) with the actor
recorded as `cli`, so out-of-band recovery is as visible as anything done in the UI.

A password reset also revokes every live session for that account.

> **Recovery codes are the first resort, not this.** Each user is issued ten single-use
> codes at MFA enrolment and shown them exactly once. A user who kept theirs can sign in
> without an administrator.

---

## Backup and restore

```bash
# Backup
docker compose -f deploy/docker-compose.yml exec -T db \
    pg_dump -U netsecops -Fc netsecops > netsecops-$(date +%F).dump

# Restore
docker compose -f deploy/docker-compose.yml exec -T db \
    pg_restore -U netsecops -d netsecops --clean --if-exists < netsecops-2026-09-13.dump
```

A restore is only useful with the matching `MASTER_KEY`. Test that you can restore
*and decrypt* — a backup you have never restored is a hypothesis, not a backup.

---

## Upgrades

```bash
git pull
make up
```

Migrations run automatically when the `api` container starts, guarded by a PostgreSQL
advisory lock, so several replicas starting at once cannot race the same DDL: one
applies the migration and the rest wait, then find nothing to do.

Roll back by deploying the previous image tag. Alembic downgrades exist but are a last
resort — restore from backup if a migration has already transformed data.

---

## Database roles (SEC-06)

`deploy/postgres/init/01-roles.sql` creates two least-privilege roles:

- `netsecops_migrate` — owns the schema; the only role permitted to run DDL.
- `netsecops_app` — SELECT/INSERT/UPDATE/DELETE only; can never alter the schema.

This is also what makes the audit log's append-only triggers meaningful: they belong to
the migration role, so a compromised application role cannot disable them.

For a managed database (RDS, Cloud SQL, Azure Database), run that script by hand and
point `DATABASE_URL` at `netsecops_app`.

---

## Monitoring

| Endpoint | Purpose |
|---|---|
| `/healthz` | Liveness — is the process up? |
| `/readyz` | Readiness — is the database reachable? Returns 503 when not. |
| `/metrics` | Prometheus metrics (`NETSECOPS_METRICS_ENABLED`) |

Logs are structured JSON on stdout (`NETSECOPS_LOG_FORMAT=json`). Every line carries a
`correlation_id` that follows a request through to the job and device session it caused.

`/metrics` is unauthenticated by design so a scraper needs no credentials. It exposes no
customer data — only counters and gauges. Restrict it at the proxy to your monitoring
subnet if your threat model calls for it.

### Alert on these

- `netsecops_database_up == 0` — the API cannot serve traffic.
- A `device.readonly_violation` audit action — never expected; it means an adapter tried
  to issue something outside its allow-list.
- Audit chain verification failing (`netsecops-cli verify-audit-chain`, or the dashboard
  card) — the log has been altered.
- `token.reuse_detected` — a refresh token was replayed, which suggests theft.

---

## Air-gapped deployment (C-7)

NetSecOps runs fully offline.

1. Mirror the images into your internal registry, or `docker save`/`docker load` them.
2. Set `NETSECOPS_FEEDS_OFFLINE_MODE=true`.
3. Import vulnerability data from bundles rather than fetching it (FR-VUL-08, Phase 6).

Nothing in Phase 0 requires outbound connectivity. From Phase 1, workers need reachability
to your devices on TCP/22 and TCP/443 — and to nothing else.
