# ADR-001 — Background job queue: Procrastinate vs Celery + Redis

- **Status:** Accepted (provisional — to be re-confirmed after the Phase 1 load test)
- **Date:** 2026-09-13
- **Requirement:** SRS §2.2 (technology stack), FR-JOB-05, NFR-PERF-01, Appendix D item 3

## Context

NetSecOps runs assessments as background jobs: a scan fans out to hundreds of devices,
each collection opening an authenticated read-only session that can take tens of
seconds. FR-JOB-05 requires horizontally scalable workers with at-least-once semantics
and idempotent handlers. NFR-PERF-01 sets the bar at 500 devices in ≤60 minutes with 20
workers, and 2,000 devices in ≤4 hours with horizontal scaling.

Two options were considered, as recorded in SRS §2.2.

### Option A — Procrastinate (PostgreSQL-backed)

Jobs live in PostgreSQL tables; workers wait on `LISTEN/NOTIFY` rather than polling.

- Adds no new infrastructure. The deployment stays PostgreSQL-only, which matters for
  the on-premise and air-gapped installations C-7 requires — every additional service is
  another thing a customer must deploy, patch and back up.
- Job state is transactional with application state. Enqueueing a collection and writing
  the `job_devices` row happen in one transaction, so a crash between them is impossible.
  With an external broker those two writes can diverge, and reconciling them is work we
  would have to write and maintain.
- Job history is queryable with ordinary SQL alongside the data it refers to, which
  FR-JOB-04 (per-device outcomes, durations, error classes) wants anyway.
- Throughput is bounded by the database. Published figures put PostgreSQL-backed queues
  in the low thousands of jobs per second — far above what this workload needs.

### Option B — Celery + Redis

The conventional Python choice, with more operational tooling and higher raw throughput.

- Requires Redis: another service to deploy, secure, patch and back up, and another
  failure mode in air-gapped environments.
- Redis persistence is weaker than PostgreSQL's by default. For a platform whose whole
  value proposition is an auditable record of what it did, losing queue state in a crash
  is a poor trade.
- Job state is not transactional with application state (see above).

## Decision

**Use Procrastinate.**

The deciding factor is not throughput — this workload is nowhere near either option's
limit. It is that our jobs are long, few, and IO-bound, so the queue is never the
bottleneck; the constraint that actually binds is deployment simplicity in on-premise
and air-gapped environments, and transactional consistency between job state and the
audit record.

## Consequences

- The compose and Helm deployments contain no broker. `deploy/docker-compose.yml`
  declares `worker` and `scheduler` services behind a profile, ready for Phase 1.
- Worker concurrency is `NETSECOPS_WORKER_CONCURRENCY` (default 20, per FR-COL-06).
- Per-device serialisation (FR-COL-06: never two sessions to one device) is enforced
  with a PostgreSQL advisory lock keyed on device id — the same mechanism already used
  for audit-chain appends and migration locking, so there is one concept to understand
  rather than three.
- `env.py` excludes `procrastinate_*` tables from Alembic autogenerate, so the library
  owns its own schema.

## Revisit if

- The Phase 1 load test (NFR-PERF-01, TEST-07) cannot reach 500 devices in 60 minutes
  and profiling shows queue overhead rather than device IO is responsible; or
- a deployment needs job throughput well beyond assessment scheduling — for example
  per-event streaming ingestion, which is not in scope for v1.0.

Migrating later is contained: task definitions live in `netsecops/workers/`, and the
services that enqueue work depend on a thin interface rather than on the library.
