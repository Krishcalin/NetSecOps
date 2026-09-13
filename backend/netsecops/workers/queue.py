"""Job queue abstraction (ADR-001).

ADR-001 chose Procrastinate, and recorded that "the services that enqueue work depend
on a thin interface rather than on the library". This is that interface.

Two implementations ship:

- :class:`InlineQueue` runs the task immediately, in the caller's transaction. It is
  what tests and single-process development use, and it is what makes the job engine
  testable without standing up a worker.
- :class:`ProcrastinateQueue` defers to the real queue. It is a thin adapter, which is
  the point: if ADR-001 is revisited after the Phase 1 load test, only this class and
  ``workers/app.py`` change.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from typing import Any, Protocol

from netsecops.core.logging import get_logger

log = get_logger(__name__)


class DeferrableTask(Protocol):
    """The one method NetSecOps needs from a queue library's task object."""

    async def defer_async(self, **kwargs: Any) -> Any: ...


class JobQueue(ABC):
    """Somewhere to put work so a worker picks it up."""

    @abstractmethod
    async def enqueue_job(self, job_id: uuid.UUID, **context: Any) -> None:
        """Schedule execution of an already-created job row."""


class InlineQueue(JobQueue):
    """Runs the job now, in-process.

    Used by tests and by ``NETSECOPS_INLINE_JOBS=true`` development. Not for production:
    a long collection would hold an HTTP request open for its whole duration.
    """

    def __init__(self) -> None:
        self.enqueued: list[uuid.UUID] = []

    async def enqueue_job(self, job_id: uuid.UUID, **context: Any) -> None:
        from netsecops.workers.runner import run_job

        self.enqueued.append(job_id)
        log.info("queue.inline_run", job_id=str(job_id))
        await run_job(job_id, **context)


class DeferredQueue(JobQueue):
    """Records what would be enqueued without running it.

    Lets a test assert that an endpoint queued the right work without also executing a
    device session — the two concerns are worth separating.
    """

    def __init__(self) -> None:
        self.enqueued: list[tuple[uuid.UUID, dict[str, Any]]] = []

    async def enqueue_job(self, job_id: uuid.UUID, **context: Any) -> None:
        self.enqueued.append((job_id, context))


class ProcrastinateQueue(JobQueue):
    """Hands the job to Procrastinate (ADR-001).

    Deliberately thin: everything about *how* a job runs lives in ``workers/runner.py``,
    so the queue library owns delivery and nothing else.

    The deferrable task is injected rather than imported, so this module has no
    dependency on Procrastinate being installed — which is what lets the default
    deployment run without a worker at all, and what keeps ADR-001's "migrating later
    is contained" promise honest.
    """

    def __init__(self, task: DeferrableTask) -> None:
        self.task = task

    async def enqueue_job(self, job_id: uuid.UUID, **context: Any) -> None:
        await self.task.defer_async(job_id=str(job_id), **context)
        log.info("queue.deferred", job_id=str(job_id))


_queue: JobQueue | None = None


def get_queue() -> JobQueue:
    """The process-wide queue.

    Defaults to inline so that a fresh checkout works with no broker and no worker;
    ``set_queue`` swaps in the real one at startup when workers are configured.
    """
    global _queue
    if _queue is None:
        _queue = InlineQueue()
    return _queue


def set_queue(queue: JobQueue | None) -> None:
    global _queue
    _queue = queue
