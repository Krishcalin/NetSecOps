"""Collecting from an API-driven platform, end to end (FR-COL-02, FR-COL-05).

This is the gap the HTTP transport closes. Before it, `_build_transport` returned an
`SSHTransport` unconditionally, so a collection against a PAN-OS firewall opened a shell
and tried to send `GET /api/?type=config&action=show` as a command. It failed closed on
the read-only guard — the `panos` policy carries HTTP rules and no command rules — but
it failed, and PAN-OS and the Check Point management server could not be collected from
at all. Which is to say: Phase 4's rulebase analysis could only ever be fed by hand for
the two vendors whose policy lives behind an API.

The transport's own behaviour is covered in `test_http_transport.py`. What is asserted
here is the *wiring*: that the profile's transport decides which one is built, that the
login happens through the guarded session, that profile entries are issued as requests
rather than commands, and that the result becomes a real snapshot with a parsed rulebase.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.http_transport import HttpCredentials, HttpTransport
from netsecops.core.crypto import SecretVault
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device
from netsecops.db.models.inventory import CredentialType, DeviceClass, Vendor
from netsecops.db.models.jobs import DeviceJobStatus, JobDevice, JobStatus, JobType
from netsecops.services.credentials import CredentialService
from netsecops.services.inventory import InventoryService
from netsecops.services.jobs import JobScope, JobService
from netsecops.services.snapshots import SnapshotService
from netsecops.workers import runner
from netsecops.workers.runner import execute_job
from tests.conftest import make_user

FIXTURES = Path(__file__).parent / "fixtures"
PANOS_CONFIG = (FIXTURES / "paloalto/panos/11.0/perimeter_fw.xml").read_text(encoding="utf-8")

#: What the fake Panorama/PAN-OS answers, by the path it was asked for. Anything not
#: listed gets an empty success, which is how a real device behaves for an op command
#: whose feature is unlicensed — and is what FR-COL-08 calls a partial collection.
PANOS_RESPONSES = {
    "keygen": (
        200,
        "<response status='success'><result><key>TEST-API-KEY</key></result></response>",
    ),
    "type=config&action=show": (200, PANOS_CONFIG),
}


class RecordingHttp(HttpTransport):
    """An HttpTransport with a canned wire, so the runner's wiring is what is tested."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.sent: list[tuple[str, str, Any]] = []

    async def connect(self) -> None:
        self._client = object()  # type: ignore[assignment]
        # A real connection observes the peer certificate; this stands in for it so the
        # pinning path in the runner is exercised rather than skipped.
        self.observed_fingerprint = "SHA256:AA:BB:CC"

    async def disconnect(self) -> None:
        self._client = None

    async def request(
        self, method: str, path: str, *, body: Any = None, timeout: int
    ) -> tuple[int, str]:
        # The token merging is replicated rather than skipped, because it is the part
        # most likely to be wrong and a fake that quietly dropped it would record the
        # pre-authentication path and report the wiring as broken when it is not.
        merged = {**body, **self.token.body_fields} if self.token.body_fields and body else body

        target = path
        if self.token.query:
            separator = "&" if "?" in target else "?"
            target += separator + "&".join(f"{k}={v}" for k, v in self.token.query.items())

        self.sent.append((method.upper(), target, merged))

        for marker, response in PANOS_RESPONSES.items():
            if marker in target:
                return response
        return 200, "<response status='success'><result/></response>"


@pytest.fixture
def http_devices(monkeypatch: pytest.MonkeyPatch) -> list[RecordingHttp]:
    """Replace the real HTTP transport, keeping the runner's selection logic intact."""
    built: list[RecordingHttp] = []

    def build(device, credential, credentials, settings, platform):  # type: ignore[no-untyped-def]
        secret = credentials.open_secret(credential)
        public = credential.metadata_
        transport = RecordingHttp(
            str(device.mgmt_ip),
            HttpCredentials(
                username=str(public.get("username", "")) or None,
                password=secret.get("password"),
                api_key=secret.get("api_key"),
            ),
            port=device.https_port,
            known_fingerprint=device.tls_cert_fingerprint,
        )
        built.append(transport)
        return transport

    monkeypatch.setattr(runner, "_build_http_transport", build)
    return built


@pytest.fixture
async def analyst(session: AsyncSession) -> Principal:
    user = await make_user(session, username="api_collect_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def onboard(
    session: AsyncSession,
    actor: Principal,
    vault: SecretVault,
    *,
    credential_type: CredentialType = CredentialType.API_USERNAME_PASSWORD,
    secret: dict[str, str] | None = None,
) -> Device:
    inventory = InventoryService(session)
    credentials = CredentialService(session, vault=vault)

    device = await inventory.create_device(
        mgmt_ip="198.51.100.40",
        actor=actor,
        hostname="perimeter-fw-01",
        vendor=Vendor.PALOALTO,
        platform="panos",
        device_class=DeviceClass.FIREWALL,
    )
    credential = await credentials.create(
        name="panos-readonly",
        credential_type=credential_type,
        secret_data=secret or {"username": "netsecops", "password": "device-pass"},
        actor=actor,
    )
    await credentials.assign(credential, device_id=device.id, actor=actor)
    return device


async def collect(session: AsyncSession, device: Device, actor: Principal, vault: SecretVault):
    job = await JobService(session).create(
        job_type=JobType.COLLECT, scope=JobScope(device_ids=(device.id,)), actor=actor
    )
    return await execute_job(session, job.id, vault=vault)


async def device_row(session: AsyncSession, job_id, device: Device) -> JobDevice:
    """The per-device result of a job, which is where success and error text live."""
    return (
        await session.execute(
            select(JobDevice).where(JobDevice.job_id == job_id, JobDevice.device_id == device.id)
        )
    ).scalar_one()


class TestTheWiring:
    async def test_an_api_platform_gets_an_http_transport(
        self,
        session: AsyncSession,
        analyst: Principal,
        vault: SecretVault,
        http_devices: list[RecordingHttp],
    ) -> None:
        """The fix. Chosen from the collection profile, not from the credential — a
        PAN-OS device with an SSH password must still be collected over its API, because
        that is where its configuration is."""
        device = await onboard(session, analyst, vault)
        await collect(session, device, analyst, vault)

        assert len(http_devices) == 1

    async def test_the_configuration_arrives_and_becomes_a_parsed_snapshot(
        self,
        session: AsyncSession,
        analyst: Principal,
        vault: SecretVault,
        http_devices: list[RecordingHttp],
    ) -> None:
        """The whole point: Phase 4's PAN-OS analysis now has a live source."""
        device = await onboard(session, analyst, vault)
        job = await collect(session, device, analyst, vault)

        assert job.status == JobStatus.SUCCEEDED.value

        snapshot = await SnapshotService(session, vault=vault).latest(device)
        assert snapshot is not None
        assert snapshot.parser_platform == "panos"
        assert snapshot.ncm["device"]["hostname"] == "perimeter-fw-01"
        # The rulebase parsed, which is what the firewall analysis consumes.
        assert len(snapshot.ncm["firewall"]["security_rules"]) == 8

    async def test_the_login_goes_through_the_session_first(
        self,
        session: AsyncSession,
        analyst: Principal,
        vault: SecretVault,
        http_devices: list[RecordingHttp],
    ) -> None:
        """Performing the login inside the transport would route a device-facing call
        around the read-only guard and out of the audit trail — the one property the
        session design exists to hold."""
        device = await onboard(session, analyst, vault)
        await collect(session, device, analyst, vault)

        sent = http_devices[0].sent
        assert "keygen" in sent[0][1], "the first call was not the login"

    async def test_profile_entries_are_issued_as_requests_not_commands(
        self,
        session: AsyncSession,
        analyst: Principal,
        vault: SecretVault,
        http_devices: list[RecordingHttp],
    ) -> None:
        device = await onboard(session, analyst, vault)
        await collect(session, device, analyst, vault)

        paths = [path for _method, path, _body in http_devices[0].sent]
        assert any("type=config&action=show" in p for p in paths)
        assert all(p.startswith("/api/") for p in paths)

    async def test_the_api_key_is_attached_to_every_call_after_the_login(
        self,
        session: AsyncSession,
        analyst: Principal,
        vault: SecretVault,
        http_devices: list[RecordingHttp],
    ) -> None:
        device = await onboard(session, analyst, vault)
        await collect(session, device, analyst, vault)

        after_login = [path for _m, path, _b in http_devices[0].sent[1:]]
        assert after_login
        assert all("key=TEST-API-KEY" in path for path in after_login)

    async def test_a_pre_issued_key_skips_the_login_entirely(
        self,
        session: AsyncSession,
        analyst: Principal,
        vault: SecretVault,
        http_devices: list[RecordingHttp],
    ) -> None:
        """The better shape: NetSecOps never holds the administrator's password."""
        device = await onboard(
            session,
            analyst,
            vault,
            credential_type=CredentialType.API_KEY,
            secret={"api_key": "PRE-ISSUED"},
        )
        await collect(session, device, analyst, vault)

        sent = http_devices[0].sent
        assert not any("keygen" in path for _m, path, _b in sent)
        assert all("key=PRE-ISSUED" in path for _m, path, _b in sent)

    async def test_the_certificate_is_pinned_on_first_contact(
        self,
        session: AsyncSession,
        analyst: Principal,
        vault: SecretVault,
        http_devices: list[RecordingHttp],
    ) -> None:
        """FR-COL-10, the TLS half. Stored in its own column rather than over the SSH
        host key: they are different facts about different protocols."""
        device = await onboard(session, analyst, vault)
        await collect(session, device, analyst, vault)

        await session.refresh(device)
        assert device.tls_cert_fingerprint == "SHA256:AA:BB:CC"
        assert device.host_key_fingerprint is None

    async def test_a_credential_test_stops_at_the_login(
        self,
        session: AsyncSession,
        analyst: Principal,
        vault: SecretVault,
        http_devices: list[RecordingHttp],
    ) -> None:
        """Authenticating *is* the proof for an API platform. Reading the whole
        configuration to answer "do these credentials work" would be a needless read of
        sensitive data (FR-CRED-05)."""
        device = await onboard(session, analyst, vault)
        job = await JobService(session).create(
            job_type=JobType.CREDENTIAL_TEST,
            scope=JobScope(device_ids=(device.id,)),
            actor=analyst,
        )
        completed = await execute_job(session, job.id, vault=vault)

        assert completed.status == JobStatus.SUCCEEDED.value
        paths = [path for _m, path, _b in http_devices[0].sent]
        assert not any("type=config" in p for p in paths)

    async def test_an_ssh_credential_on_an_api_platform_says_what_to_do(
        self, session: AsyncSession, analyst: Principal, vault: SecretVault
    ) -> None:
        """Caught before a connection is attempted, so the error names the fix rather
        than surfacing as an authentication failure from the device."""
        device = await onboard(
            session,
            analyst,
            vault,
            credential_type=CredentialType.SSH_PASSWORD,
            secret={"username": "a", "password": "b"},
        )
        job = await collect(session, device, analyst, vault)
        row = await device_row(session, job.id, device)

        assert row.status == DeviceJobStatus.FAILED.value
        assert "Assign an API credential" in (row.error_message or "")

    async def test_a_cisco_device_still_uses_ssh(
        self, session: AsyncSession, analyst: Principal, vault: SecretVault
    ) -> None:
        """The transport switch must not catch anything else: every platform delivered
        before this change is collected over SSH, and silently moving one to HTTP would
        break the working majority to fix the broken minority."""
        from netsecops.adapters.profiles import Transport, get_profile

        for platform in ("cisco_ios", "cisco_nxos", "cisco_asa", "fortios", "checkpoint_gaia"):
            assert get_profile(platform).transport is Transport.CLI, (
                f"{platform} would now be collected over HTTP"
            )
