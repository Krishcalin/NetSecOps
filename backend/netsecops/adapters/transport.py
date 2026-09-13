"""Transports (FR-COL-02, FR-COL-05, FR-COL-09, FR-COL-10).

These move bytes and nothing more. Policy lives in :mod:`netsecops.adapters.readonly`;
a transport that made its own decisions about what may be sent would defeat the point
of having one guard.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import dataclass
from typing import Any

import asyncssh

from netsecops.adapters.session import Transport
from netsecops.core.errors import ProblemError
from netsecops.core.logging import get_logger

log = get_logger(__name__)


class DeviceUnreachableError(ProblemError):
    status_code = 502
    title = "Device unreachable"
    problem_type = "device-unreachable"


class DeviceAuthError(ProblemError):
    status_code = 502
    title = "Device authentication failed"
    problem_type = "device-auth-failed"


class HostKeyChangedError(ProblemError):
    """FR-COL-10 — a changed host key is reported, never silently accepted."""

    status_code = 502
    title = "Device host key changed"
    problem_type = "host-key-changed"


@dataclass(slots=True)
class SSHCredentials:
    username: str
    password: str | None = None
    private_key: str | None = None
    passphrase: str | None = None


@dataclass(slots=True)
class JumpHost:
    """SSH bastion between the worker and the device (FR-COL-09)."""

    host: str
    port: int
    credentials: SSHCredentials


def fingerprint(key: asyncssh.SSHKey) -> str:
    """SHA-256 fingerprint in the form OpenSSH prints, so operators can compare it."""
    digest = hashlib.sha256(key.public_data).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class SSHTransport(Transport):
    """asyncssh client for CLI-driven platforms.

    Host-key policy (FR-COL-10): the first connection pins the key; later connections
    compare against the pin and refuse on change. ``accept_new`` records without
    refusing, for onboarding a fleet whose keys are not yet known.
    """

    def __init__(
        self,
        host: str,
        credentials: SSHCredentials,
        *,
        port: int = 22,
        known_fingerprint: str | None = None,
        strict_host_key: bool = True,
        connect_timeout: int = 15,
        jump_host: JumpHost | None = None,
        legacy_algorithms: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.credentials = credentials
        self.known_fingerprint = known_fingerprint
        self.strict_host_key = strict_host_key
        self.connect_timeout = connect_timeout
        self.jump_host = jump_host
        self.legacy_algorithms = legacy_algorithms

        self._conn: asyncssh.SSHClientConnection | None = None
        self._tunnel: asyncssh.SSHClientConnection | None = None
        self._observed_fingerprint: str | None = None

    @property
    def observed_fingerprint(self) -> str | None:
        """The key seen on this connection, for pinning on first use."""
        return self._observed_fingerprint

    def _connect_options(self, credentials: SSHCredentials) -> dict[str, Any]:
        options: dict[str, Any] = {
            "username": credentials.username,
            # Verification is done explicitly after connecting, against our own pin.
            "known_hosts": None,
            "connect_timeout": self.connect_timeout,
        }
        if credentials.password:
            options["password"] = credentials.password
        if credentials.private_key:
            options["client_keys"] = [
                asyncssh.import_private_key(credentials.private_key, credentials.passphrase)
            ]

        if self.legacy_algorithms:
            # Only when a device is explicitly flagged. Enabling these is itself
            # reported as a finding (SRS §4.3), so it is never silent.
            options["encryption_algs"] = ["*"]
            options["kex_algs"] = ["*"]
            options["mac_algs"] = ["*"]

        return options

    async def connect(self) -> None:
        try:
            if self.jump_host is not None:
                self._tunnel = await asyncssh.connect(
                    self.jump_host.host,
                    port=self.jump_host.port,
                    **self._connect_options(self.jump_host.credentials),
                )
                self._conn = await self._tunnel.connect_ssh(
                    self.host, port=self.port, **self._connect_options(self.credentials)
                )
            else:
                self._conn = await asyncssh.connect(
                    self.host, port=self.port, **self._connect_options(self.credentials)
                )
        except asyncssh.PermissionDenied as exc:
            raise DeviceAuthError("The device rejected the supplied credentials.") from exc
        except (OSError, asyncssh.Error, TimeoutError) as exc:
            raise DeviceUnreachableError(f"Could not reach {self.host}:{self.port}.") from exc

        try:
            self._verify_host_key()
        except Exception:
            # The connection is already open at this point. Leaving it open on a failed
            # host-key check would hold a session to a device we have just decided we
            # do not trust (SRS §8.1.6).
            await self.disconnect()
            raise

    def _verify_host_key(self) -> None:
        if self._conn is None:  # pragma: no cover - connect() guarantees this
            raise DeviceUnreachableError("Host key verification ran without a connection.")

        server_key = self._conn.get_server_host_key()
        if server_key is None:  # pragma: no cover - only for null-auth test servers
            return

        self._observed_fingerprint = fingerprint(server_key)

        if self.known_fingerprint is None:
            log.info("ssh.host_key_pinned", host=self.host, fingerprint=self._observed_fingerprint)
            return

        if self._observed_fingerprint != self.known_fingerprint:
            detail = (
                f"Expected {self.known_fingerprint}, got {self._observed_fingerprint}. "
                "This may be a legitimate rebuild or a man-in-the-middle."
            )
            if self.strict_host_key:
                raise HostKeyChangedError(f"Host key for {self.host} has changed. {detail}")
            log.warning("ssh.host_key_changed", host=self.host, detail=detail)

    async def disconnect(self) -> None:
        for connection in (self._conn, self._tunnel):
            if connection is not None:
                connection.close()
        for connection in (self._conn, self._tunnel):
            if connection is not None:
                await connection.wait_closed()
        self._conn = None
        self._tunnel = None

    async def send(self, command: str, *, timeout: int) -> tuple[str, int | None]:
        if self._conn is None:
            raise DeviceUnreachableError("SSH session is not connected.")

        try:
            result = await asyncio.wait_for(self._conn.run(command, check=False), timeout=timeout)
        except TimeoutError as exc:
            raise DeviceUnreachableError(f"Command timed out after {timeout}s: {command}") from exc

        stdout = result.stdout if isinstance(result.stdout, str) else ""
        stderr = result.stderr if isinstance(result.stderr, str) else ""
        # Network CLIs often answer on stderr; the caller wants what the device said.
        return (stdout or stderr), result.exit_status
