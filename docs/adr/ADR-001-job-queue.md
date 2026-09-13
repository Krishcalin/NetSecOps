# ADR-001 — Background job queue: Procrastinate vs Celery + Redis

- **Status:** **Accepted (confirmed by measurement, 2026-09-13)**
- **Date:** 2026-09-13 — provisional; confirmed 2026-09-13 after the load test
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

## Confirmation — the load test this ADR deferred (2026-09-13)

The provisional decision rested on an argument. This is the measurement, in
`backend/tests/test_performance.py` (`pytest -m performance`).

**The requirement, restated as a rate.** NFR-PERF-01 asks for 500 devices in ≤60 minutes
with 20 workers. That is 500 ÷ 3600 s = **0.139 device-claims per second**. Writing it
this way is most of the answer: it means each worker handles one device every 144
seconds, and the queue's share of those 144 seconds is a single row claim and a status
write.

**Measured**, 200 devices claimed and completed by 20 concurrent workers against
PostgreSQL 16, four runs:

| Run | Wall time | Rate | Headroom | Projected queue time for 500 |
|---|---|---|---|---|
| 1 | 14.56 s | 13.7 claims/s | 99× | 36.4 s |
| 2 | 14.23 s | 14.1 claims/s | 101× | 35.6 s |
| 3 | 14.49 s | 13.8 claims/s | 99× | 36.2 s |
| 4 | 14.29 s | 14.0 claims/s | 101× | 35.7 s |

Repeated because DB-heavy timings on this hardware vary by roughly ±25%; the spread here
was under 3%, so the figure is not an artefact of one lucky run.

**Reading.** The queue can sustain about **100× the required rate**. Of the 3600-second
budget for 500 devices, queue coordination consumes roughly **36 seconds — about 1%**.
The remaining 99% is SSH: connecting, authenticating and waiting for a device to render
its configuration. Nothing about choosing Celery and Redis would reduce that; it is a
property of the customer's network and their equipment.

**What this does not show.** It does not show that 500 real devices complete in an hour.
The workers here do no device IO, deliberately — the question ADR-001 asks is which
queue, and mixing SSH into the measurement would answer a different one. The end-to-end
figure needs real hardware and belongs in the Phase 7 performance harness (TEST-07).

A second test asserts the correctness half: under the same 20-way contention, no device
is ever claimed twice (FR-COL-06). Throughput would be worthless without it — two
workers collecting one device would mean the audit trail shows two sessions where the
operator authorised one.

**Conclusion: Procrastinate is confirmed.** The measurement does not merely clear the
bar, it makes the bar irrelevant to the choice, which is what the original argument
predicted. Adding Redis would buy throughput this workload will never ask for, at the
cost of a service every on-premise and air-gapped customer must deploy, secure, patch
and back up (C-7).

## Revisit if

- The Phase 7 end-to-end harness cannot reach 500 devices in 60 minutes **and** profiling
  attributes it to queue overhead rather than device IO — the measurement above says
  that is a 1% share, so suspect the other 99% first; or
- a deployment needs job throughput well beyond assessment scheduling — for example
  per-event streaming ingestion, which is not in scope for v1.0.

Migrating later is contained: task definitions live in `netsecops/workers/`, and the
services that enqueue work depend on a thin interface rather than on the library.
