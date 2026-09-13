"""An in-process fake SSH device (TEST-02: no live devices in CI).

Phase 1 acceptance requires testing a credential "against a fake SSH server". This is
that server. It is deliberately more than a stub:

- it authenticates, so credential failures are real failures;
- it answers a small set of ``show`` commands with plausible output;
- and, most importantly, it **records every command it receives**, so a test can assert
  what NetSecOps actually put on the wire rather than trusting the guard in isolation.

That last point is what makes the read-only guarantee testable end to end: the
conformance tests check the guard's decisions, and these check that nothing reaches a
device except what the guard approved.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import asyncssh

#: Canned responses. Anything not listed answers like a real device does for an
#: unknown command, so an adapter cannot accidentally depend on silence.
DEFAULT_RESPONSES: dict[str, str] = {
    "show version": (
        "Cisco IOS XE Software, Version 17.09.04a\n"
        "cisco C9300-48P (X86) processor with 1341000K bytes of physical memory.\n"
        "System serial number: FCW2140L0GH\n"
    ),
    "show inventory": 'NAME: "Switch1", DESCR: "C9300-48P"\nPID: C9300-48P, SN: FCW2140L0GH\n',
    "show running-config": (
        "!\nhostname lab-sw-01\n!\nservice password-encryption\n!\n"
        "snmp-server community S3cr3tRO RO\n!\nline vty 0 4\n exec-timeout 10 0\n!\nend\n"
    ),
    "show clock": "09:41:12.345 UTC Sat Sep 13 2026\n",
    "terminal length 0": "",
    "enable": "",
}


@dataclass
class FakeDeviceServer:
    """A running fake device. Use :func:`fake_device` rather than constructing directly."""

    host: str
    port: int
    #: Every command the server received, in order. The point of the whole fixture.
    received: list[str] = field(default_factory=list)
    #: What the device answers. Mutable so a test can change the device's
    #: configuration between collections, which is what drift detection is about.
    responses: dict[str, str] = field(default_factory=dict)
    _server: asyncssh.SSHAcceptor | None = None

    def set_response(self, command: str, output: str) -> None:
        """Change what the device says, as a real configuration change would."""
        self.responses[command.strip().lower()] = output

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port

    def commands_matching(self, needle: str) -> list[str]:
        return [c for c in self.received if needle in c]

    def assert_never_received(self, *forbidden: str) -> None:
        """Assert none of ``forbidden`` ever reached the device."""
        for command in self.received:
            for word in forbidden:
                assert word.lower() not in command.lower(), (
                    f"the device received a forbidden command: {command!r}"
                )


def _make_handler(record: FakeDeviceServer):
    """Build the per-connection process handler.

    ``process_factory`` is asyncssh's high-level server API: it hands us the requested
    command and simple stdout/stderr streams, rather than the raw channel callbacks.
    """

    async def handle(process: asyncssh.SSHServerProcess) -> None:  # pragma: no cover
        command = process.command

        if command is None:
            # An interactive shell. Real read-only accounts often have one, but
            # NetSecOps never opens one, so refuse and make that visible if it changes.
            process.stderr.write("interactive shell is not available\n")
            process.exit(1)
            return

        record.received.append(command)

        response = record.responses.get(command.strip().lower())
        if response is None:
            # Match how an IOS device rejects an unknown command, so the unhappy path
            # is exercised rather than assumed.
            process.stderr.write("% Invalid input detected at '^' marker.\n")
            process.exit(1)
            return

        process.stdout.write(response)
        process.exit(0)

    return handle


class _Server(asyncssh.SSHServer):  # pragma: no cover - asyncssh callback API
    def __init__(self, record: FakeDeviceServer, username: str, password: str) -> None:
        self._record = record
        self._username = username
        self._password = password

    def begin_auth(self, username: str) -> bool:
        return True  # a password is always required

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == self._username and password == self._password


async def start_fake_device(
    *,
    username: str = "netsecops",
    password: str = "device-pass",  # noqa: S107 - fixture credential
    responses: dict[str, str] | None = None,
    host: str = "127.0.0.1",
) -> FakeDeviceServer:
    """Start a fake device on an ephemeral port."""
    record = FakeDeviceServer(
        host=host, port=0, responses={**DEFAULT_RESPONSES, **(responses or {})}
    )

    # A throwaway host key, generated per server so tests never share one.
    host_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)

    acceptor = await asyncssh.create_server(
        lambda: _Server(record, username, password),
        host,
        0,
        server_host_keys=[host_key],
        process_factory=_make_handler(record),
    )

    record.port = acceptor.get_port()
    record._server = acceptor
    return record


async def stop_fake_device(server: FakeDeviceServer) -> None:
    if server._server is None:
        return

    server._server.close()
    try:
        # A client that never disconnected would otherwise keep the acceptor open
        # forever. Bounding the wait turns that into a fast failure rather than a
        # hung test run.
        await asyncio.wait_for(server._server.wait_closed(), timeout=5)
    except TimeoutError:  # pragma: no cover - only when a test leaks a connection
        pass
    finally:
        server._server = None


async def fake_device(**kwargs: object) -> AsyncIterator[FakeDeviceServer]:
    """Async generator form, for use as a pytest fixture."""
    server = await start_fake_device(**kwargs)  # type: ignore[arg-type]
    try:
        yield server
    finally:
        await stop_fake_device(server)
        # Give asyncssh's transport a tick to finish closing before the loop ends.
        await asyncio.sleep(0)
