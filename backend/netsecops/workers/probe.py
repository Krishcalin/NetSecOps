"""Credential probe (FR-CRED-05).

"Test credential" must be the smallest thing that proves a session works: authenticate,
issue one allow-listed read, disconnect. Anything more would make a test indistinguishable
from a collection, and an operator clicking "test" does not expect to touch the device
more than necessary.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.policies import get_policy
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.adapters.recorder import AuditingRecorder
from netsecops.adapters.session import DeviceSession
from netsecops.adapters.transport import (
    DeviceAuthError,
    DeviceUnreachableError,
    HostKeyChangedError,
    SSHCredentials,
    SSHTransport,
)
from netsecops.core.config import get_settings
from netsecops.core.crypto import SecretVault
from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal
from netsecops.db.models.inventory import Credential, CredentialType, Device
from netsecops.services.audit import AuditService
from netsecops.services.credentials import CredentialService
from netsecops.workers.runner import PROBE_COMMANDS

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    succeeded: bool
    detail: str | None = None
    #: The single command issued, echoed back so the operator sees what ran.
    command: str | None = None
    host_key_fingerprint: str | None = None


async def probe_credential(
    session: AsyncSession,
    *,
    device: Device,
    credential: Credential,
    actor: Principal,
    vault: SecretVault | None = None,
) -> ProbeResult:
    settings = get_settings()
    credentials = CredentialService(session, vault=vault)

    platform = device.effective_platform
    if not platform:
        return ProbeResult(
            succeeded=False,
            detail="This device has no platform set, so no read-only policy applies.",
        )

    probe_command = PROBE_COMMANDS.get(platform)
    if probe_command is None:
        return ProbeResult(
            succeeded=False, detail=f"No probe command is defined for platform '{platform}'."
        )

    credential_type = CredentialType(credential.credential_type)
    if credential_type not in {CredentialType.SSH_PASSWORD, CredentialType.SSH_KEY}:
        return ProbeResult(
            succeeded=False,
            detail=f"'{credential.name}' is a {credential_type.value}; "
            "SSH probing needs an SSH password or key.",
        )

    secret = credentials.open_secret(credential)
    transport = SSHTransport(
        str(device.mgmt_ip),
        SSHCredentials(
            username=str(credential.metadata_.get("username", "")),
            password=secret.get("password"),
            private_key=secret.get("private_key"),
            passphrase=secret.get("passphrase"),
        ),
        port=device.ssh_port,
        known_fingerprint=device.host_key_fingerprint,
        strict_host_key=True,
        connect_timeout=device.connect_timeout or settings.device_connect_timeout,
        legacy_algorithms=settings.allow_legacy_ssh_ciphers,
    )

    device_session = DeviceSession(
        transport,
        ReadOnlyGuard(get_policy(platform)),
        recorder=AuditingRecorder(AuditService(session), actor=actor, org_id=device.org_id),
        device_id=device.id,
        command_timeout=device.command_timeout or settings.device_command_timeout,
    )

    try:
        async with device_session:
            # First contact pins the host key (FR-COL-10), so a later change is visible.
            if device.host_key_fingerprint is None and transport.observed_fingerprint:
                device.host_key_fingerprint = transport.observed_fingerprint
                await session.flush()

            result = await device_session.run(probe_command)

        return ProbeResult(
            succeeded=result.succeeded,
            detail=(
                "Authenticated and read successfully."
                if result.succeeded
                else "Authenticated, but the device rejected the read command."
            ),
            command=probe_command,
            host_key_fingerprint=transport.observed_fingerprint,
        )

    except DeviceAuthError as exc:
        return ProbeResult(succeeded=False, detail=str(exc), command=probe_command)
    except HostKeyChangedError as exc:
        # Deliberately distinct from an auth failure: this one may mean interception,
        # and an operator must not read it as "wrong password".
        return ProbeResult(succeeded=False, detail=str(exc), command=probe_command)
    except DeviceUnreachableError as exc:
        return ProbeResult(succeeded=False, detail=str(exc), command=probe_command)
    except ValidationProblem as exc:
        return ProbeResult(succeeded=False, detail=str(exc), command=probe_command)


__all__ = ["ProbeResult", "probe_credential"]
