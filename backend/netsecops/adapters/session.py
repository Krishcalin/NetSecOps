"""Device sessions — the only route from NetSecOps to a device.

Adapters never hold a transport. They hold a :class:`DeviceSession`, and every command
it sends passes through the read-only guard first and lands in the audit log after
(SRS §8.1 items 1 and 8, FR-COL-04, FR-AUD-01).

That ordering is the whole design: an adapter author cannot forget to check, because
there is no unchecked path to reach. If a future adapter needs a command, the way to
get it is to add it to ``policies.py`` where a reviewer will see it — not to work
around the session.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Self

from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.core.errors import ReadOnlyViolationError
from netsecops.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class CommandResult:
    command: str
    output: str
    duration_ms: int
    exit_status: int | None = None

    @property
    def succeeded(self) -> bool:
        return self.exit_status in (None, 0)


@dataclass(frozen=True, slots=True)
class HttpResult:
    method: str
    path: str
    status_code: int
    body: str
    duration_ms: int

    @property
    def succeeded(self) -> bool:
        return 200 <= self.status_code < 300


class Transport(ABC):
    """Moves bytes to a device. Deliberately ignorant of what is allowed.

    Keeping the transport dumb is what lets the guard be the single point of control:
    a transport that knew about policy could be asked to make exceptions.
    """

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def disconnect(self) -> None: ...

    @abstractmethod
    async def send(self, command: str, *, timeout: int) -> tuple[str, int | None]:
        """Send one command, return ``(output, exit_status)``."""

    async def request(
        self, method: str, path: str, *, body: Any = None, timeout: int
    ) -> tuple[int, str]:
        """Issue one HTTP request, return ``(status_code, body)``."""
        raise NotImplementedError(f"{type(self).__name__} does not support HTTP")


class CommandRecorder(ABC):
    """Receives every command issued, for the audit trail (FR-AUD-01)."""

    @abstractmethod
    async def record(
        self,
        *,
        command: str,
        device_id: uuid.UUID | None,
        succeeded: bool,
        duration_ms: int,
        detail: str | None = None,
    ) -> None: ...

    @abstractmethod
    async def record_violation(
        self, *, command: str, device_id: uuid.UUID | None, reason: str, context: dict[str, Any]
    ) -> None: ...


@dataclass
class NullRecorder(CommandRecorder):
    """Collects in memory. For tests and the conformance harness, never production."""

    commands: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)

    async def record(
        self,
        *,
        command: str,
        device_id: uuid.UUID | None,
        succeeded: bool,
        duration_ms: int,
        detail: str | None = None,
    ) -> None:
        self.commands.append(command)

    async def record_violation(
        self, *, command: str, device_id: uuid.UUID | None, reason: str, context: dict[str, Any]
    ) -> None:
        self.violations.append(command)


class DeviceSession:
    """A guarded, audited session against one device.

    Use as an async context manager; ``__aexit__`` always disconnects, because SRS
    §8.1 item 6 requires sessions to be closed cleanly even when a collection fails.
    """

    def __init__(
        self,
        transport: Transport,
        guard: ReadOnlyGuard,
        *,
        recorder: CommandRecorder | None = None,
        device_id: uuid.UUID | None = None,
        command_timeout: int = 60,
    ) -> None:
        self.transport = transport
        self.guard = guard
        self.recorder = recorder or NullRecorder()
        self.device_id = device_id
        self.command_timeout = command_timeout
        self._connected = False
        self._commands_sent = 0

    @property
    def commands_sent(self) -> int:
        return self._commands_sent

    async def __aenter__(self) -> Self:
        await self.transport.connect()
        self._connected = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

    async def close(self) -> None:
        if self._connected:
            try:
                await self.transport.disconnect()
            finally:
                self._connected = False

    # ── commands ────────────────────────────────────────────────────────

    async def run(self, command: str, *, timeout: int | None = None) -> CommandResult:
        """Send one command, after the guard permits it.

        A :class:`ReadOnlyViolationError` here is recorded and re-raised: it aborts the
        collection rather than being retried, because it means NetSecOps attempted
        something it guarantees it never does (FR-COL-04).
        """
        try:
            self.guard.check_command(command)
        except ReadOnlyViolationError as violation:
            await self.recorder.record_violation(
                command=command,
                device_id=self.device_id,
                reason=str(violation),
                context=violation.extra,
            )
            log.error(
                "readonly.violation",
                command=command,
                device_id=str(self.device_id) if self.device_id else None,
                platform=self.guard.policy.platform,
            )
            raise

        started = time.perf_counter()
        output, exit_status = await self.transport.send(
            command, timeout=timeout or self.command_timeout
        )
        duration_ms = int((time.perf_counter() - started) * 1000)
        self._commands_sent += 1

        result = CommandResult(
            command=command, output=output, duration_ms=duration_ms, exit_status=exit_status
        )

        # The command text is audited; the output is not. Device output routinely
        # contains secrets, and belongs in an encrypted artefact (FR-AUD-01).
        await self.recorder.record(
            command=command,
            device_id=self.device_id,
            succeeded=result.succeeded,
            duration_ms=duration_ms,
        )
        return result

    async def run_all(self, commands: Sequence[str]) -> list[CommandResult]:
        """Run commands in order. Stops at the first read-only violation, by design."""
        return [await self.run(command) for command in commands]

    # ── HTTP ────────────────────────────────────────────────────────────

    async def request(
        self, method: str, path: str, *, body: Any = None, timeout: int | None = None
    ) -> HttpResult:
        try:
            self.guard.check_request(method, path, body=body)
        except ReadOnlyViolationError as violation:
            await self.recorder.record_violation(
                command=f"{method.upper()} {path}",
                device_id=self.device_id,
                reason=str(violation),
                context=violation.extra,
            )
            log.error(
                "readonly.violation",
                method=method,
                path=path,
                device_id=str(self.device_id) if self.device_id else None,
                platform=self.guard.policy.platform,
            )
            raise

        started = time.perf_counter()
        status_code, response_body = await self.transport.request(
            method, path, body=body, timeout=timeout or self.command_timeout
        )
        duration_ms = int((time.perf_counter() - started) * 1000)
        self._commands_sent += 1

        result = HttpResult(
            method=method.upper(),
            path=path,
            status_code=status_code,
            body=response_body,
            duration_ms=duration_ms,
        )
        await self.recorder.record(
            command=f"{result.method} {path}",
            device_id=self.device_id,
            succeeded=result.succeeded,
            duration_ms=duration_ms,
            detail=f"HTTP {status_code}",
        )
        return result
